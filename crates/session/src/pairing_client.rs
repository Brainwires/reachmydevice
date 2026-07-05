//! Client orchestration for direct pairing over the stateless relay mailbox
//! (`/pair?code=<channel>`). Runs the SPAKE2 exchange, derives + confirms the
//! shared key, and exchanges identity keys — all end-to-end, the relay only
//! forwarding opaque frames.
//!
//! On success both sides learn each other's authenticated device identity, which
//! the caller pins (TOFU) or turns into the minimal unattended anchor.

use crate::identity::DeviceIdentity;
use crate::pairing;
use futures::{SinkExt, StreamExt};
use serde::{Deserialize, Serialize};
use tokio_tungstenite::tungstenite::Message;

/// The peer learned from a successful pairing.
#[derive(Clone, Debug)]
pub struct PairedPeer {
    pub device_id: String,
    pub public_key: [u8; 32],
    pub name: String,
}

/// Our pairing messages, carried opaquely by the relay inside `{"payload": …}`.
#[derive(Serialize, Deserialize)]
#[serde(tag = "t")]
enum PairMsg {
    /// SPAKE2 message + our identity (exchanged before key derivation, since the
    /// key is bound to both public keys).
    Hello {
        m: String,      // hex SPAKE2 message
        pubkey: String, // hex ed25519 public key
        name: String,
    },
    /// Key-confirmation tag (detects a mistyped code before trusting the key).
    Confirm { tag: String },
}

/// Pair with a peer over `relay_ws_base` (e.g. `ws://host:port`) using `code`.
pub async fn pair_pake(
    relay_ws_base: &str,
    code: &str,
    identity: &DeviceIdentity,
    device_name: &str,
) -> anyhow::Result<PairedPeer> {
    let (channel, secret) = pairing::split_code(code)?;
    let url = format!(
        "{}/pair?code={}",
        relay_ws_base.trim_end_matches('/'),
        channel
    );
    let (ws, _) = tokio_tungstenite::connect_async(&url).await?;
    let (mut sink, mut stream) = ws.split();

    // Send one of our PairMsgs, relay-wrapped.
    async fn send<S>(sink: &mut S, msg: &PairMsg) -> anyhow::Result<()>
    where
        S: SinkExt<Message> + Unpin,
        S::Error: std::error::Error + Send + Sync + 'static,
    {
        let wrapped = serde_json::json!({ "payload": msg }).to_string();
        sink.send(Message::Text(wrapped.into())).await?;
        Ok(())
    }

    // Receive the next PairMsg, skipping relay control frames (`{"peer":…}`).
    async fn recv<S>(stream: &mut S) -> anyhow::Result<PairMsg>
    where
        S: StreamExt<Item = Result<Message, tokio_tungstenite::tungstenite::Error>> + Unpin,
    {
        while let Some(msg) = stream.next().await {
            let Message::Text(text) = msg? else { continue };
            let v: serde_json::Value = serde_json::from_str(&text)?;
            if let Some(payload) = v.get("payload") {
                return Ok(serde_json::from_value(payload.clone())?);
            }
            // else: {"peer":"joined"|"left"} / {"error":…} — keep waiting.
            if v.get("error").is_some() {
                anyhow::bail!("relay: {text}");
            }
        }
        anyhow::bail!("pairing socket closed before peer responded");
    }

    // 1. Start SPAKE2 and announce ourselves (msg + identity).
    let (exchange, pake_msg) = pairing::pake_start(&secret);
    let our_pubkey = identity.public_key_bytes();
    send(
        &mut sink,
        &PairMsg::Hello {
            m: hex::encode(pake_msg),
            pubkey: hex::encode(our_pubkey),
            name: device_name.to_string(),
        },
    )
    .await?;

    // 2. Receive the peer's Hello.
    let (peer_msg, peer_pubkey, peer_name) = loop {
        match recv(&mut stream).await? {
            PairMsg::Hello { m, pubkey, name } => {
                let pk: [u8; 32] = hex::decode(&pubkey)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("peer public key must be 32 bytes"))?;
                break (hex::decode(&m)?, pk, name);
            }
            PairMsg::Confirm { .. } => continue,
        }
    };

    // 3. Derive the shared key (bound to both identities).
    let key = pairing::pake_finish(exchange, &peer_msg, &our_pubkey, &peer_pubkey)?;

    // 4. Exchange **directional** confirmation tags. We send the tag for our role
    //    and require the peer's tag for *their* role — so an attacker who doesn't
    //    hold the key cannot pass by reflecting the tag we sent.
    let (our_role, peer_role) = pairing::role_labels(&our_pubkey, &peer_pubkey);
    let our_tag = pairing::confirmation(&key, our_role);
    let expected_peer_tag = pairing::confirmation(&key, peer_role);
    send(
        &mut sink,
        &PairMsg::Confirm {
            tag: hex::encode(our_tag),
        },
    )
    .await?;
    let peer_tag = loop {
        match recv(&mut stream).await? {
            PairMsg::Confirm { tag } => break hex::decode(&tag)?,
            PairMsg::Hello { .. } => continue,
        }
    };
    anyhow::ensure!(
        pairing::tags_equal(&peer_tag, &expected_peer_tag),
        "pairing confirmation failed — codes did not match (or a MITM attempt)"
    );

    Ok(PairedPeer {
        device_id: crate::identity::device_id_from_public_key(&peer_pubkey),
        public_key: peer_pubkey,
        name: peer_name,
    })
}
