//! Resumable file transfer over the (reliable, ordered) control channel.
//!
//! Either peer may send a file. The flow is:
//!
//! 1. Sender emits [`FileOffer`](proto::FileOffer) (`transfer_id`, name, size).
//! 2. Receiver opens `<download_dir>/<name>.part`, and replies with
//!    [`FileAck`](proto::FileAck) at the byte offset it already has — `0` for a
//!    fresh transfer, or the length of an existing `.part` to **resume**.
//! 3. Sender streams [`FileChunk`](proto::FileChunk)s from that offset, keeping a
//!    bounded window of unacked bytes in flight; the receiver appends each chunk
//!    and periodically acks its new length (flow control + resume checkpoint).
//! 4. Sender emits [`FileComplete`](proto::FileComplete) with a SHA-256 prefix.
//!    The receiver verifies its own digest, renames `.part` → final, and reports
//!    [`FileEvent::Completed`].
//!
//! The data channel is reliable and ordered (SCTP), so chunks arrive in sequence
//! with no gaps — the receiver writes sequentially and the window is pure flow
//! control, not loss recovery.
//!
//! [`FileTransfers`] is single-threaded (lives on the session's control loop);
//! each outbound transfer runs on its own thread, paced by acks.

use rmd_protocol as proto;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::Sender;
use std::sync::Arc;
use std::time::Duration;

/// Bytes per chunk. Kept well under the SCTP message ceiling.
const CHUNK: usize = 16 * 1024;
/// Max unacked bytes in flight (sender window).
const WINDOW: u64 = 1024 * 1024;
/// Receiver acks at least this often (bytes) to advance the window / checkpoint.
const ACK_EVERY: u64 = 256 * 1024;

/// Configuration for received files.
#[derive(Clone, Debug)]
pub struct FileTransferConfig {
    /// Directory incoming files are written to.
    pub download_dir: PathBuf,
}

impl Default for FileTransferConfig {
    fn default() -> Self {
        let dir = dirs_download_dir().unwrap_or_else(std::env::temp_dir);
        Self { download_dir: dir }
    }
}

/// An event surfaced to the UI about a transfer.
#[derive(Clone, Debug)]
pub enum FileEvent {
    /// An incoming transfer was offered and started.
    Offered {
        transfer_id: String,
        name: String,
        size: u64,
    },
    /// Progress update (`transferred` of `total` bytes), either direction.
    Progress {
        transfer_id: String,
        transferred: u64,
        total: u64,
    },
    /// A transfer finished; `path` is set for received files.
    Completed {
        transfer_id: String,
        path: Option<PathBuf>,
    },
    /// A transfer failed or was cancelled.
    Failed { transfer_id: String, reason: String },
}

/// Shared state between the manager and an outbound send thread.
struct SendShared {
    /// Highest contiguous byte offset the receiver has acked.
    acked: AtomicU64,
    /// Set once the first ack (resume offset) has arrived.
    started: AtomicBool,
    /// Cancel signal.
    cancel: AtomicBool,
}

/// Receiver-side state for one active incoming transfer.
struct RecvState {
    file: File,
    part_path: PathBuf,
    final_path: PathBuf,
    written: u64,
    size: u64,
    last_ack: u64,
    hasher: Sha256,
}

type OutFn = Arc<dyn Fn(proto::Envelope) + Send + Sync>;

/// Manages inbound and outbound file transfers for one session.
pub struct FileTransfers {
    out: OutFn,
    events: Sender<FileEvent>,
    cfg: FileTransferConfig,
    recvs: HashMap<String, RecvState>,
    sends: HashMap<String, Arc<SendShared>>,
    seq: u64,
}

impl FileTransfers {
    /// Create a manager. `out` transmits an envelope to the peer; `events`
    /// receives progress/completion notifications for the UI.
    pub fn new(out: OutFn, events: Sender<FileEvent>, cfg: FileTransferConfig) -> Self {
        Self {
            out,
            events,
            cfg,
            recvs: HashMap::new(),
            sends: HashMap::new(),
            seq: 0,
        }
    }

    /// Begin sending a local file. Returns the new `transfer_id`.
    pub fn send_file(&mut self, path: PathBuf) -> anyhow::Result<String> {
        let meta = std::fs::metadata(&path)?;
        let size = meta.len();
        let name = path
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "file".into());
        self.seq += 1;
        // transfer_id is unique without a clock: session-local counter + name.
        let transfer_id = format!("tx-{}-{}", self.seq, name);
        let mime = mime_for(&path);

        let shared = Arc::new(SendShared {
            acked: AtomicU64::new(0),
            started: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
        });
        self.sends.insert(transfer_id.clone(), shared.clone());

        // Offer first; the receiver's FileAck unblocks the stream thread.
        (self.out)(proto::file_offer(&transfer_id, &name, size, mime));

        let out = self.out.clone();
        let events = self.events.clone();
        let tid = transfer_id.clone();
        std::thread::Builder::new()
            .name("rmd-filesend".into())
            .spawn(move || send_loop(path, tid, size, out, events, shared))
            .ok();

        Ok(transfer_id)
    }

    /// Handle an inbound file-transfer envelope. Returns `true` if it was one.
    pub fn handle(&mut self, payload: &proto::pb::envelope::Payload) -> bool {
        use proto::pb::envelope::Payload;
        match payload {
            Payload::FileOffer(o) => {
                self.on_offer(o);
                true
            }
            Payload::FileChunk(c) => {
                self.on_chunk(c);
                true
            }
            Payload::FileAck(a) => {
                self.on_ack(a);
                true
            }
            Payload::FileComplete(c) => {
                self.on_complete(c);
                true
            }
            Payload::FileCancel(c) => {
                self.on_cancel(c);
                true
            }
            _ => false,
        }
    }

    fn on_offer(&mut self, o: &proto::FileOffer) {
        let final_path = self.cfg.download_dir.join(sanitize(&o.name));
        let part_path = with_ext(&final_path, "part");

        if let Err(e) = std::fs::create_dir_all(&self.cfg.download_dir) {
            self.fail(&o.transfer_id, format!("mkdir: {e}"));
            return;
        }

        // Resume: if a .part exists, adopt its length as the start offset and
        // re-hash its contents so the final integrity check is correct.
        let mut hasher = Sha256::new();
        let existing = std::fs::metadata(&part_path).map(|m| m.len()).unwrap_or(0);
        let resume = existing.min(o.size);
        if resume > 0 {
            if let Ok(mut f) = File::open(&part_path) {
                let mut buf = vec![0u8; CHUNK];
                let mut left = resume;
                while left > 0 {
                    let want = (left as usize).min(buf.len());
                    match f.read(&mut buf[..want]) {
                        Ok(0) => break,
                        Ok(n) => {
                            hasher.update(&buf[..n]);
                            left -= n as u64;
                        }
                        Err(_) => break,
                    }
                }
            }
        }

        let file = match OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .truncate(false)
            .open(&part_path)
        {
            Ok(f) => f,
            Err(e) => {
                self.fail(&o.transfer_id, format!("open .part: {e}"));
                return;
            }
        };
        // Truncate any bytes past the resume point (partial/garbage tail).
        let _ = file.set_len(resume);
        let mut file = file;
        let _ = file.seek(SeekFrom::Start(resume));

        self.recvs.insert(
            o.transfer_id.clone(),
            RecvState {
                file,
                part_path,
                final_path,
                written: resume,
                size: o.size,
                last_ack: resume,
                hasher,
            },
        );
        let _ = self.events.send(FileEvent::Offered {
            transfer_id: o.transfer_id.clone(),
            name: o.name.clone(),
            size: o.size,
        });
        // Tell the sender where to start.
        (self.out)(proto::file_ack(&o.transfer_id, resume));
    }

    fn on_chunk(&mut self, c: &proto::FileChunk) {
        let Some(st) = self.recvs.get_mut(&c.transfer_id) else {
            return;
        };
        // Ordered channel: a chunk at our exact write cursor is expected. Ignore
        // duplicates (offset < written) and refuse gaps (offset > written).
        if c.offset != st.written {
            if c.offset < st.written {
                return; // duplicate/replayed after a resume ack
            }
            self.fail(&c.transfer_id, "chunk gap".into());
            return;
        }
        if st.file.write_all(&c.data).is_err() {
            self.fail(&c.transfer_id, "write".into());
            return;
        }
        st.hasher.update(&c.data);
        st.written += c.data.len() as u64;
        let (written, size, last_ack) = (st.written, st.size, st.last_ack);
        let _ = self.events.send(FileEvent::Progress {
            transfer_id: c.transfer_id.clone(),
            transferred: written,
            total: size,
        });
        if written - last_ack >= ACK_EVERY || written == size {
            if let Some(st) = self.recvs.get_mut(&c.transfer_id) {
                st.last_ack = written;
            }
            (self.out)(proto::file_ack(&c.transfer_id, written));
        }
    }

    fn on_complete(&mut self, c: &proto::FileComplete) {
        let Some(st) = self.recvs.remove(&c.transfer_id) else {
            return;
        };
        let _ = st.file.sync_all();
        if st.written != st.size {
            self.fail(&c.transfer_id, "short transfer".into());
            let _ = std::fs::remove_file(&st.part_path);
            return;
        }
        let digest: [u8; 32] = st.hasher.finalize().into();
        // Full 32-byte SHA-256 (a public integrity digest, not a MAC).
        if digest.as_slice() != c.sha256.as_slice() {
            self.fail(&c.transfer_id, "integrity check failed".into());
            let _ = std::fs::remove_file(&st.part_path);
            return;
        }
        if let Err(e) = std::fs::rename(&st.part_path, &st.final_path) {
            self.fail(&c.transfer_id, format!("finalize: {e}"));
            return;
        }
        let _ = self.events.send(FileEvent::Completed {
            transfer_id: c.transfer_id.clone(),
            path: Some(st.final_path),
        });
    }

    fn on_ack(&mut self, a: &proto::FileAck) {
        if let Some(shared) = self.sends.get(&a.transfer_id) {
            shared.acked.store(a.offset, Ordering::Release);
            shared.started.store(true, Ordering::Release);
        }
    }

    fn on_cancel(&mut self, c: &proto::FileCancel) {
        if let Some(shared) = self.sends.remove(&c.transfer_id) {
            shared.cancel.store(true, Ordering::Release);
        }
        // Keep any .part for a future resume rather than deleting it.
        self.recvs.remove(&c.transfer_id);
        self.fail(&c.transfer_id, c.reason.clone());
    }

    /// Cancel an in-flight transfer we initiated or are receiving.
    pub fn cancel(&mut self, transfer_id: &str, reason: &str) {
        if let Some(shared) = self.sends.remove(transfer_id) {
            shared.cancel.store(true, Ordering::Release);
        }
        self.recvs.remove(transfer_id);
        (self.out)(proto::file_cancel(transfer_id, reason));
    }

    fn fail(&self, transfer_id: &str, reason: String) {
        tracing::warn!(%transfer_id, %reason, "file transfer failed");
        let _ = self.events.send(FileEvent::Failed {
            transfer_id: transfer_id.to_string(),
            reason,
        });
    }
}

/// Outbound stream loop: waits for the resume ack, then sends chunks within the
/// window until the whole file is acked, and finishes with `FileComplete`.
fn send_loop(
    path: PathBuf,
    transfer_id: String,
    size: u64,
    out: OutFn,
    events: Sender<FileEvent>,
    shared: Arc<SendShared>,
) {
    // Compute the whole-file digest up front (a single extra read) so the
    // completion prefix is correct even when the receiver resumes mid-file.
    let digest = match hash_file(&path) {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(error=%e, "hash file for transfer failed");
            return;
        }
    };

    let mut file = match File::open(&path) {
        Ok(f) => f,
        Err(e) => {
            tracing::warn!(error=%e, "open file for transfer failed");
            return;
        }
    };

    // Wait for the receiver's first ack (the resume offset).
    while !shared.started.load(Ordering::Acquire) {
        if shared.cancel.load(Ordering::Acquire) {
            return;
        }
        std::thread::sleep(Duration::from_millis(5));
    }
    let mut next = shared.acked.load(Ordering::Acquire);
    if file.seek(SeekFrom::Start(next)).is_err() {
        return;
    }

    let mut buf = vec![0u8; CHUNK];
    loop {
        if shared.cancel.load(Ordering::Acquire) {
            return;
        }
        let acked = shared.acked.load(Ordering::Acquire);

        if next >= size {
            // All bytes sent; wait for the final ack, then complete.
            if acked >= size {
                (out)(proto::file_complete(&transfer_id, digest));
                let _ = events.send(FileEvent::Completed {
                    transfer_id: transfer_id.clone(),
                    path: None,
                });
                return;
            }
            std::thread::sleep(Duration::from_millis(4));
            continue;
        }

        // Respect the receiver's window.
        if next.saturating_sub(acked) >= WINDOW {
            std::thread::sleep(Duration::from_millis(2));
            continue;
        }

        let want = ((size - next) as usize).min(CHUNK);
        match file.read(&mut buf[..want]) {
            Ok(0) => return,
            Ok(n) => {
                (out)(proto::file_chunk(&transfer_id, next, buf[..n].to_vec()));
                next += n as u64;
                let _ = events.send(FileEvent::Progress {
                    transfer_id: transfer_id.clone(),
                    transferred: next,
                    total: size,
                });
            }
            Err(e) => {
                tracing::warn!(error=%e, "read during transfer failed");
                return;
            }
        }
    }
}

fn hash_file(path: &Path) -> std::io::Result<[u8; 32]> {
    let mut f = File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(hasher.finalize().into())
}

fn mime_for(path: &Path) -> String {
    match path.extension().and_then(|e| e.to_str()) {
        Some("txt") => "text/plain",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("pdf") => "application/pdf",
        Some("zip") => "application/zip",
        _ => "application/octet-stream",
    }
    .to_string()
}

/// Strip path separators from an offered filename so a peer can't write outside
/// the download directory.
fn sanitize(name: &str) -> String {
    let base = name.rsplit(['/', '\\']).next().unwrap_or(name);
    let base = base.trim_matches('.');
    if base.is_empty() {
        "file".into()
    } else {
        base.to_string()
    }
}

fn with_ext(path: &Path, ext: &str) -> PathBuf {
    let mut s = path.to_path_buf().into_os_string();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

/// Best-effort `~/Downloads` (or `$HOME/Downloads`) without pulling in the
/// `dirs` crate.
fn dirs_download_dir() -> Option<PathBuf> {
    let home = std::env::var_os("HOME").map(PathBuf::from)?;
    let dl = home.join("Downloads");
    if dl.is_dir() {
        Some(dl)
    } else {
        Some(home)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::mpsc;

    fn payload(len: usize) -> Vec<u8> {
        (0..len as u32)
            .map(|i| (i.wrapping_mul(31).wrapping_add(7)) as u8)
            .collect()
    }

    /// Drive a full send→receive between two managers wired to each other by a
    /// pair of envelope queues, and verify the received file matches byte-for-byte.
    #[test]
    fn transfer_roundtrip() {
        let dir = std::env::temp_dir().join(format!("rmd-xfer-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("payload.bin");
        let content = payload(700_000); // ~700 KiB spans many chunks + windows
        std::fs::write(&src, &content).unwrap();
        let recv_dir = dir.join("downloads");

        let (to_recv_tx, to_recv_rx) = mpsc::channel::<proto::Envelope>();
        let (to_send_tx, to_send_rx) = mpsc::channel::<proto::Envelope>();
        let (ev_send_tx, _ev_send_rx) = mpsc::channel();
        let (ev_recv_tx, ev_recv_rx) = mpsc::channel();

        let sender_out: OutFn = Arc::new(move |e| {
            let _ = to_recv_tx.send(e);
        });
        let receiver_out: OutFn = Arc::new(move |e| {
            let _ = to_send_tx.send(e);
        });

        let mut sender = FileTransfers::new(sender_out, ev_send_tx, FileTransferConfig::default());
        let mut receiver = FileTransfers::new(
            receiver_out,
            ev_recv_tx,
            FileTransferConfig {
                download_dir: recv_dir.clone(),
            },
        );

        let tid = sender.send_file(src.clone()).unwrap();
        assert!(tid.contains("payload.bin"));

        let mut completed_path = None;
        for _ in 0..500_000 {
            let mut progressed = false;
            while let Ok(env) = to_recv_rx.try_recv() {
                if let Some(p) = env.payload {
                    receiver.handle(&p);
                    progressed = true;
                }
            }
            while let Ok(env) = to_send_rx.try_recv() {
                if let Some(p) = env.payload {
                    sender.handle(&p);
                    progressed = true;
                }
            }
            while let Ok(ev) = ev_recv_rx.try_recv() {
                match ev {
                    FileEvent::Completed { path, .. } => completed_path = path,
                    FileEvent::Failed { reason, .. } => panic!("transfer failed: {reason}"),
                    _ => {}
                }
            }
            if completed_path.is_some() {
                break;
            }
            if !progressed {
                std::thread::sleep(Duration::from_millis(1));
            }
        }

        let path = completed_path.expect("transfer did not complete");
        assert_eq!(std::fs::read(&path).unwrap(), content, "content mismatch");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A receiver dropped mid-transfer leaves a `.part`; a fresh receiver given
    /// the same offer must ack at the partial length and finish correctly.
    #[test]
    fn resume_from_partial() {
        let dir = std::env::temp_dir().join(format!("rmd-resume-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let recv_dir = dir.join("downloads");
        let content = payload(400_000);
        let size = content.len() as u64;
        let digest: [u8; 32] = Sha256::digest(&content).into();
        let tid = "tx-1-file.bin";
        let name = "file.bin";

        let feed_chunks = |mgr: &mut FileTransfers, from: u64, to: u64| {
            let mut off = from;
            while off < to {
                let n = ((to - off) as usize).min(CHUNK);
                let end = off as usize + n;
                let env = proto::file_chunk(tid, off, content[off as usize..end].to_vec());
                mgr.handle(&env.payload.unwrap());
                off += n as u64;
            }
            off
        };

        // Receiver #1: accept the offer, take the first ~150 KiB, then drop.
        let stop = (size / 3 / CHUNK as u64) * CHUNK as u64; // chunk-aligned
        let partial;
        {
            let (out_tx, _out_rx) = mpsc::channel::<proto::Envelope>();
            let (ev_tx, _ev_rx) = mpsc::channel();
            let out: OutFn = Arc::new(move |e| {
                let _ = out_tx.send(e);
            });
            let mut r1 = FileTransfers::new(
                out,
                ev_tx,
                FileTransferConfig {
                    download_dir: recv_dir.clone(),
                },
            );
            let offer = proto::file_offer(tid, name, size, "application/octet-stream");
            r1.handle(&offer.payload.unwrap());
            partial = feed_chunks(&mut r1, 0, stop);
        }
        let part = recv_dir.join("file.bin.part");
        assert_eq!(std::fs::metadata(&part).unwrap().len(), partial);

        // Receiver #2: same offer must resume at `partial`.
        let (out_tx, out_rx) = mpsc::channel::<proto::Envelope>();
        let (ev_tx, ev_rx) = mpsc::channel();
        let out: OutFn = Arc::new(move |e| {
            let _ = out_tx.send(e);
        });
        let mut r2 = FileTransfers::new(
            out,
            ev_tx,
            FileTransferConfig {
                download_dir: recv_dir.clone(),
            },
        );
        let offer = proto::file_offer(tid, name, size, "application/octet-stream");
        r2.handle(&offer.payload.unwrap());

        // Its first outgoing envelope is the resume ack at `partial`.
        let ack = out_rx.recv().unwrap();
        match ack.payload.unwrap() {
            proto::pb::envelope::Payload::FileAck(a) => {
                assert_eq!(a.offset, partial, "did not resume at partial length")
            }
            other => panic!("expected FileAck, got {other:?}"),
        }

        feed_chunks(&mut r2, partial, size);
        let complete = proto::file_complete(tid, digest);
        r2.handle(&complete.payload.unwrap());

        let mut final_path = None;
        while let Ok(ev) = ev_rx.try_recv() {
            match ev {
                FileEvent::Completed { path, .. } => final_path = path,
                FileEvent::Failed { reason, .. } => panic!("resume failed: {reason}"),
                _ => {}
            }
        }
        let path = final_path.expect("resume did not complete");
        assert_eq!(
            std::fs::read(&path).unwrap(),
            content,
            "resumed content mismatch"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sanitize_blocks_traversal() {
        assert_eq!(sanitize("../../etc/passwd"), "passwd");
        assert_eq!(sanitize("/abs/evil"), "evil");
        assert_eq!(sanitize("plain.txt"), "plain.txt");
        assert_eq!(sanitize(".."), "file");
    }
}
