//! Fuzz the file-transfer state machine against hostile peer messages
//! (arbitrary offsets, sizes, names, chunk ordering). Decodes an `Envelope` from
//! the input and drives `FileTransfers::handle`; must never panic.
#![no_main]
use libfuzzer_sys::fuzz_target;
use openreach_protocol::Envelope;
use openreach_session::filexfer::FileTransfers;
use openreach_session::FileTransferConfig;
use std::sync::{mpsc, Arc};

fuzz_target!(|data: &[u8]| {
    let Ok(env) = openreach_protocol::decode(data) else {
        return;
    };
    let Some(payload) = env.payload else {
        return;
    };
    let (ev_tx, _ev_rx) = mpsc::channel();
    let out: Arc<dyn Fn(Envelope) + Send + Sync> = Arc::new(|_| {});
    let dir = std::env::temp_dir().join("openreach-fuzz-xfer");
    let mut files = FileTransfers::new(
        out,
        ev_tx,
        FileTransferConfig {
            download_dir: dir.clone(),
        },
    );
    let _ = files.handle(&payload);
    let _ = std::fs::remove_dir_all(&dir);
});
