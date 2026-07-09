//! SHARK²-style word-gesture ("swipe") decoding for the on-screen keyboard.
//!
//! Classic template matching (Kristensson & Zhai, UIST 2004): each dictionary
//! word is an ideal path through its letters' key centres; a swipe is scored
//! against candidate templates. We prune hard by first/last letter (the keys
//! nearest the swipe's ends — 10k words → ~a hundred), resample gesture and
//! templates to a fixed point count, normalise (translate + scale) so sloppy
//! swipes still match, then rank by shape distance blended with word frequency.
//! No neural model; the whole decode is well under a millisecond.

/// Frequency-ranked word list (google-10000-english, public domain), embedded.
const WORDS_RAW: &str = include_str!("words-en.txt");
/// Points that both the gesture and each template are resampled to.
const N: usize = 32;
/// Weight of the frequency prior relative to the (≈0..1) shape distance. Higher
/// favours common words; lower trusts the gesture shape more. Kept low so a clean
/// gesture for a rare-but-real word (e.g. "pig", rank ~8000) still beats a common
/// word with a worse-matching shape, instead of being buried by frequency.
const FREQ_WEIGHT: f64 = 0.12;

pub struct SwipeDecoder {
    /// a–z words (length ≥ 2), in descending frequency — the index is the rank.
    words: Vec<&'static str>,
    /// (first,last) letter → word indices; keyed by `first * 26 + last`.
    buckets: Vec<Vec<u32>>,
}

impl SwipeDecoder {
    pub fn new() -> Self {
        let mut words: Vec<&'static str> = Vec::new();
        let mut buckets: Vec<Vec<u32>> = vec![Vec::new(); 26 * 26];
        for w in WORDS_RAW.lines() {
            let w = w.trim();
            if w.len() < 2 || !w.bytes().all(|b| b.is_ascii_lowercase()) {
                continue;
            }
            let b = w.as_bytes();
            let f = (b[0] - b'a') as usize;
            let l = (b[b.len() - 1] - b'a') as usize;
            buckets[f * 26 + l].push(words.len() as u32);
            words.push(w);
        }
        Self { words, buckets }
    }

    /// Decode a swipe. `gesture` = raw path points (client px). `key_xy` = the 26
    /// letter-key centres indexed by `letter - 'a'`, in the SAME coordinate space
    /// as the gesture (rendered rects, so rotation is already baked in). Returns up
    /// to `top` candidate words, best first; empty if the gesture is too short or
    /// nothing matches.
    pub fn decode(
        &self,
        gesture: &[(f64, f64)],
        key_xy: &[(f64, f64); 26],
        top: usize,
    ) -> Vec<&'static str> {
        if gesture.len() < 2 {
            return Vec::new();
        }
        let starts = nearest2(gesture[0], key_xy);
        let ends = nearest2(*gesture.last().unwrap(), key_xy);

        // Candidate words = those whose first/last letter is near the swipe's ends.
        let mut cand: Vec<u32> = Vec::new();
        for &f in &starts {
            for &l in &ends {
                cand.extend_from_slice(&self.buckets[f as usize * 26 + l as usize]);
            }
        }
        if cand.is_empty() {
            return Vec::new();
        }
        cand.sort_unstable();
        cand.dedup();

        let g = normalize(&resample(gesture));
        let nwords = self.words.len() as f64;
        let mut scored: Vec<(f64, u32)> = Vec::with_capacity(cand.len());
        for &ci in &cand {
            let word = self.words[ci as usize];
            let template: Vec<(f64, f64)> = word
                .bytes()
                .map(|b| key_xy[(b - b'a') as usize])
                .collect();
            let t = normalize(&resample(&template));
            let shape = mean_dist(&g, &t);
            // Blend with a frequency prior (rank/N) so common words win close calls.
            scored.push((shape + FREQ_WEIGHT * (ci as f64 / nwords), ci));
        }
        scored.sort_by(|a, b| a.0.partial_cmp(&b.0).unwrap_or(std::cmp::Ordering::Equal));
        scored
            .iter()
            .take(top)
            .map(|&(_, ci)| self.words[ci as usize])
            .collect()
    }
}

/// The nearest letter index (`letter - 'a'`) to a point — for hit-testing a tap
/// or counting the distinct keys a path crosses.
pub fn nearest_letter(p: (f64, f64), key_xy: &[(f64, f64); 26]) -> u8 {
    nearest2(p, key_xy)[0]
}

/// The two nearest key indices (`letter - 'a'`) to a point.
fn nearest2(p: (f64, f64), key_xy: &[(f64, f64); 26]) -> [u8; 2] {
    let (mut b0, mut d0) = (0usize, f64::MAX);
    let (mut b1, mut d1) = (1usize, f64::MAX);
    for (i, &k) in key_xy.iter().enumerate() {
        let d = (p.0 - k.0).powi(2) + (p.1 - k.1).powi(2);
        if d < d0 {
            d1 = d0;
            b1 = b0;
            d0 = d;
            b0 = i;
        } else if d < d1 {
            d1 = d;
            b1 = i;
        }
    }
    [b0 as u8, b1 as u8]
}

/// Resample a polyline to exactly `N` points equally spaced by arc length
/// (the $1-recognizer method: walk the path, inserting interpolated points).
fn resample(points: &[(f64, f64)]) -> Vec<(f64, f64)> {
    if points.len() < 2 {
        return vec![*points.first().unwrap_or(&(0.0, 0.0)); N];
    }
    let total: f64 = points.windows(2).map(|w| dist(w[0], w[1])).sum();
    if total <= 1e-9 {
        return vec![points[0]; N];
    }
    let interval = total / (N as f64 - 1.0);
    let mut pts: Vec<(f64, f64)> = points.to_vec();
    let mut out: Vec<(f64, f64)> = vec![pts[0]];
    let mut d = 0.0;
    let mut i = 1;
    while i < pts.len() {
        let (prev, cur) = (pts[i - 1], pts[i]);
        let dd = dist(prev, cur);
        if d + dd >= interval {
            let t = (interval - d) / dd;
            let q = (prev.0 + t * (cur.0 - prev.0), prev.1 + t * (cur.1 - prev.1));
            out.push(q);
            pts.insert(i, q); // q is the new "current" — measure the rest from here
            d = 0.0;
        } else {
            d += dd;
        }
        i += 1;
    }
    // Floating-point drift can leave us one short.
    while out.len() < N {
        out.push(*pts.last().unwrap());
    }
    out.truncate(N);
    out
}

/// Translate the centroid to the origin and scale the longer bounding-box side to
/// 1, making the shape position- and scale-invariant.
fn normalize(pts: &[(f64, f64)]) -> Vec<(f64, f64)> {
    let n = pts.len() as f64;
    let cx = pts.iter().map(|p| p.0).sum::<f64>() / n;
    let cy = pts.iter().map(|p| p.1).sum::<f64>() / n;
    let (mut minx, mut maxx, mut miny, mut maxy) = (f64::MAX, f64::MIN, f64::MAX, f64::MIN);
    for &(x, y) in pts {
        minx = minx.min(x - cx);
        maxx = maxx.max(x - cx);
        miny = miny.min(y - cy);
        maxy = maxy.max(y - cy);
    }
    let scale = (maxx - minx).max(maxy - miny).max(1e-6);
    pts.iter().map(|&(x, y)| ((x - cx) / scale, (y - cy) / scale)).collect()
}

/// Mean point-to-point Euclidean distance between two equal-length paths.
fn mean_dist(a: &[(f64, f64)], b: &[(f64, f64)]) -> f64 {
    a.iter().zip(b).map(|(&p, &q)| dist(p, q)).sum::<f64>() / a.len() as f64
}

fn dist(a: (f64, f64), b: (f64, f64)) -> f64 {
    ((a.0 - b.0).powi(2) + (a.1 - b.1).powi(2)).sqrt()
}

#[cfg(test)]
mod tests {
    use super::*;

    // A perfect straight swipe from 't' to 'o' across the top row should decode to
    // a common word starting 't' ending 'o' (e.g. "to" / "two" / "tomorrow"…).
    #[test]
    fn decodes_endpoints() {
        let dec = SwipeDecoder::new();
        // Fake top-row-ish layout: place a–z on a rough QWERTY grid.
        let mut xy = [(0.0, 0.0); 26];
        let rows = ["qwertyuiop", "asdfghjkl", "zxcvbnm"];
        for (r, row) in rows.iter().enumerate() {
            for (c, ch) in row.bytes().enumerate() {
                xy[(ch - b'a') as usize] = (c as f64 * 30.0 + r as f64 * 12.0, r as f64 * 34.0);
            }
        }
        let t = xy[(b't' - b'a') as usize];
        let o = xy[(b'o' - b'a') as usize];
        let gesture = vec![t, ((t.0 + o.0) / 2.0, (t.1 + o.1) / 2.0), o];
        let out = dec.decode(&gesture, &xy, 3);
        assert!(!out.is_empty(), "expected candidates");
        assert!(out.iter().all(|w| w.starts_with('t') && w.ends_with('o')));
    }
}
