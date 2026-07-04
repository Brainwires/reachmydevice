//! Bidirectional clipboard sync (text), loop-guarded.
//!
//! A background thread owns the OS clipboard (`arboard`), polls it for local
//! changes, and forwards them to the peer as [`ClipboardUpdate`]s; incoming
//! remote updates are applied to the local clipboard. A content hash
//! (`origin_hash`) is remembered so applying a remote value doesn't bounce back
//! as a "local change" — breaking sync loops.
//!
//! v1 syncs UTF-8 text. Images (`CLIPBOARD_KIND_IMAGE_PNG`) are wired in the
//! protocol and are a straightforward extension here.

use openreach_protocol as proto;
use openreach_protocol::ClipboardKind;
use std::sync::mpsc::{self, Sender};
use std::time::Duration;

/// How often the local clipboard is polled for changes.
const POLL: Duration = Duration::from_millis(600);

/// Handle to the clipboard-sync thread.
pub struct ClipboardSync {
    incoming: Sender<proto::ClipboardUpdate>,
}

impl ClipboardSync {
    /// Start syncing. `send_to_peer` is called with an envelope to transmit when
    /// the local clipboard changes; call [`apply_remote`](Self::apply_remote)
    /// with updates received from the peer.
    pub fn spawn<F>(send_to_peer: F) -> Self
    where
        F: Fn(proto::Envelope) + Send + 'static,
    {
        let (incoming_tx, incoming_rx) = mpsc::channel();
        std::thread::Builder::new()
            .name("openreach-clipboard".into())
            .spawn(move || run(send_to_peer, incoming_rx))
            .ok();
        Self {
            incoming: incoming_tx,
        }
    }

    /// Apply a clipboard update received from the peer.
    pub fn apply_remote(&self, update: proto::ClipboardUpdate) {
        let _ = self.incoming.send(update);
    }
}

fn run<F>(send_to_peer: F, incoming: mpsc::Receiver<proto::ClipboardUpdate>)
where
    F: Fn(proto::Envelope),
{
    let mut clipboard = match arboard::Clipboard::new() {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error=%e, "clipboard unavailable; sync disabled");
            return;
        }
    };
    // Hash of the content we last set or sent — anything matching it is not
    // (re)propagated, which is what breaks the echo loop.
    let mut last_hash: u64 = 0;
    let mut seq: u64 = 0;

    loop {
        // 1. Apply remote updates to the local clipboard.
        while let Ok(update) = incoming.try_recv() {
            if update.kind == ClipboardKind::Text as i32 {
                if let Ok(text) = String::from_utf8(update.data.clone()) {
                    if clipboard.set_text(text).is_ok() {
                        // Remember it so our own poll doesn't echo it back.
                        last_hash = update.origin_hash;
                    }
                }
            }
        }

        // 2. Detect a local change and forward it.
        if let Ok(text) = clipboard.get_text() {
            if !text.is_empty() {
                let h = proto::fnv1a(text.as_bytes());
                if h != last_hash {
                    last_hash = h;
                    seq += 1;
                    send_to_peer(proto::clipboard_text(text, seq));
                }
            }
        }

        std::thread::sleep(POLL);
    }
}
