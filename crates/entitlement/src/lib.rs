//! Relay-entitlement extension point.
//!
//! The public rendezvous is **fully open by default**: any registered device may
//! obtain TURN relay credentials from `GET /api/ice`. But relayed media flows
//! through — and bills — the operator's bandwidth, so anyone running this as a
//! *paid hosted service* wants to gate relay access behind a subscription.
//!
//! Rather than bake billing into the open-source core, the core depends on this
//! tiny, dependency-free crate and holds an `Arc<dyn RelayEntitlement>`. The
//! default [`AllowAll`] policy preserves today's behavior (self-host = open). A
//! private plugin can supply its own [`RelayEntitlement`] (e.g. Stripe-backed)
//! and inject it when composing the server — see `rmd_rendezvous::AppState::new`.
//!
//! The trait uses a boxed future rather than `async fn` so it stays
//! object-safe (`dyn RelayEntitlement`) with **no proc-macro dependency**.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

/// A `Send` boxed future, the return type of the async trait method.
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// Outcome of an entitlement check for relay (TURN) access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDecision {
    /// The device may use the TURN relay — mint credentials.
    Allow,
    /// No active subscription — return STUN-only (peers still connect P2P).
    DenyNoSubscription,
    /// Subscribed but over the fair-use cap this cycle — STUN-only until reset.
    DenyFairUse,
    /// Subscribed and within fair-use, but already at the plan's limit of
    /// *concurrent* relay sessions — STUN-only until one frees up.
    DenyConcurrencyLimit,
}

impl RelayDecision {
    /// Whether relay credentials should be minted.
    #[inline]
    pub fn allowed(self) -> bool {
        matches!(self, RelayDecision::Allow)
    }

    /// A short, machine-readable reason for a denial, for the console/UI hint.
    /// `None` when relay is allowed.
    #[inline]
    pub fn reason(self) -> Option<&'static str> {
        match self {
            RelayDecision::Allow => None,
            RelayDecision::DenyNoSubscription => Some("no_subscription"),
            RelayDecision::DenyFairUse => Some("fair_use_exceeded"),
            RelayDecision::DenyConcurrencyLimit => Some("concurrency_limit"),
        }
    }
}

/// Decides whether a given user may use the TURN relay for a session.
///
/// Called on the session-setup path (`GET /api/ice`), so implementations should
/// be cheap — a single indexed DB read at most. A denial never fails the request:
/// the caller falls back to STUN-only so the session can still go peer-to-peer.
pub trait RelayEntitlement: Send + Sync {
    /// Resolve the relay policy for `user_id` (the owner of the device token).
    fn allow_relay(&self, user_id: i64) -> BoxFuture<'_, RelayDecision>;
}

/// Default open policy: everyone may relay. This is the self-host behavior and
/// keeps the public build free of any billing/plan concepts.
pub struct AllowAll;

impl RelayEntitlement for AllowAll {
    fn allow_relay(&self, _user_id: i64) -> BoxFuture<'_, RelayDecision> {
        Box::pin(async { RelayDecision::Allow })
    }
}

/// Convenience constructor for the default (open) provider.
pub fn allow_all() -> Arc<dyn RelayEntitlement> {
    Arc::new(AllowAll)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decision_helpers() {
        assert!(RelayDecision::Allow.allowed());
        assert!(!RelayDecision::DenyNoSubscription.allowed());
        assert!(!RelayDecision::DenyFairUse.allowed());
        assert_eq!(RelayDecision::Allow.reason(), None);
        assert_eq!(
            RelayDecision::DenyNoSubscription.reason(),
            Some("no_subscription")
        );
        assert_eq!(
            RelayDecision::DenyFairUse.reason(),
            Some("fair_use_exceeded")
        );
        assert!(!RelayDecision::DenyConcurrencyLimit.allowed());
        assert_eq!(
            RelayDecision::DenyConcurrencyLimit.reason(),
            Some("concurrency_limit")
        );
    }

    #[tokio::test]
    async fn allow_all_allows() {
        let p = allow_all();
        assert_eq!(p.allow_relay(1).await, RelayDecision::Allow);
    }
}
