# rmd-entitlement

The relay-entitlement **extension point** for the ReachMyDevice rendezvous.

Relayed media (TURN) flows through — and bills — the operator's bandwidth, so an
operator running a *paid hosted service* wants to decide **who** may relay.
Rather than bake billing into the open-source server, the server depends on this
tiny, dependency-free crate and holds an `Arc<dyn RelayEntitlement>`.

- **Default policy — [`AllowAll`]:** every registered device may relay. This is
  the self-host behavior; the open build has no notion of plans or billing.
- **Custom policy:** a downstream (e.g. a private, separately-licensed paid
  build) implements [`RelayEntitlement`] and injects it via
  `rmd_rendezvous::AppState::new(pool, cfg, entitlement)`.

```rust
use rmd_entitlement::{BoxFuture, RelayDecision, RelayEntitlement};

struct MyPolicy;
impl RelayEntitlement for MyPolicy {
    fn allow_relay(&self, user_id: i64) -> BoxFuture<'_, RelayDecision> {
        Box::pin(async move {
            if is_subscribed(user_id).await { RelayDecision::Allow }
            else { RelayDecision::DenyNoSubscription }
        })
    }
}
```

`GET /api/ice` calls `allow_relay` before minting coturn credentials. A denial is
never a hard error — the endpoint still returns STUN so the session can go
peer-to-peer — it just withholds the relay creds and annotates the response.

The trait returns a boxed future rather than using `async fn` so it stays
object-safe (`dyn RelayEntitlement`) with **zero dependencies**.
