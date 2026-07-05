//! In-memory login throttle: exponential backoff / lockout after repeated
//! password failures, to slow credential stuffing beyond the per-IP rate limit
//! (which an attacker can dodge by rotating IPs — this is keyed by username).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Failures before backoff kicks in.
const FREE_ATTEMPTS: u32 = 5;
/// Cap on a single lockout window.
const MAX_BACKOFF: Duration = Duration::from_secs(3600);
/// Forget an entry after this long idle (housekeeping).
const IDLE_TTL: Duration = Duration::from_secs(6 * 3600);

#[derive(Default)]
struct Attempt {
    fails: u32,
    locked_until: Option<Instant>,
    last: Option<Instant>,
}

/// Per-username failure tracker.
#[derive(Default)]
pub struct LoginThrottle {
    inner: Mutex<HashMap<String, Attempt>>,
}

impl LoginThrottle {
    pub fn new() -> Self {
        Self::default()
    }

    /// If the user is currently locked out, returns `Err(retry_after_secs)`.
    pub fn check(&self, user: &str) -> Result<(), u64> {
        let m = self.inner.lock().unwrap();
        if let Some(a) = m.get(user) {
            if let Some(until) = a.locked_until {
                let now = Instant::now();
                if now < until {
                    return Err((until - now).as_secs() + 1);
                }
            }
        }
        Ok(())
    }

    /// Record a failed attempt; arms backoff once past [`FREE_ATTEMPTS`].
    pub fn record_failure(&self, user: &str) {
        let mut m = self.inner.lock().unwrap();
        let now = Instant::now();
        let a = m.entry(user.to_string()).or_default();
        a.fails += 1;
        a.last = Some(now);
        if a.fails > FREE_ATTEMPTS {
            let secs = 2u64
                .saturating_pow(a.fails - FREE_ATTEMPTS)
                .min(MAX_BACKOFF.as_secs());
            a.locked_until = Some(now + Duration::from_secs(secs));
        }
        // Opportunistic housekeeping.
        m.retain(|_, v| {
            v.last
                .map(|t| now.duration_since(t) < IDLE_TTL)
                .unwrap_or(false)
        });
    }

    /// Clear a user's failures after a successful login.
    pub fn record_success(&self, user: &str) {
        self.inner.lock().unwrap().remove(user);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn locks_out_after_repeated_failures() {
        let t = LoginThrottle::new();
        assert!(t.check("bob").is_ok());
        for _ in 0..FREE_ATTEMPTS {
            t.record_failure("bob");
        }
        // Still ok at exactly FREE_ATTEMPTS (backoff arms on the next one).
        assert!(t.check("bob").is_ok());
        t.record_failure("bob");
        assert!(t.check("bob").is_err(), "should be locked out now");
        // A success clears it.
        t.record_success("bob");
        assert!(t.check("bob").is_ok());
    }
}
