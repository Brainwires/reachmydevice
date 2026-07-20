//! Stable companion to the `filexfer_handle` cargo-fuzz target: drive the
//! file-transfer state machine with random/hostile messages (huge offsets,
//! mismatched sizes, path-traversal names, out-of-order chunks) and assert it
//! never panics. Writes only under a temp dir; path-traversal is sanitized.

use rmd_protocol as proto;
use rmd_session::FileTransferConfig;
use rmd_session::filexfer::FileTransfers;
use std::sync::{Arc, mpsc};

fn xorshift(state: &mut u64) -> u64 {
    let mut x = *state;
    x ^= x << 13;
    x ^= x >> 7;
    x ^= x << 17;
    *state = x;
    x
}

#[test]
fn filexfer_handle_never_panics_on_hostile_messages() {
    let dir = std::env::temp_dir().join(format!("or-fuzz-xfer-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (tx, _rx) = mpsc::channel();
    let out: Arc<dyn Fn(proto::Envelope) + Send + Sync> = Arc::new(|_| {});
    let mut files = FileTransfers::new(
        out,
        tx,
        FileTransferConfig {
            download_dir: dir.clone(),
        },
    );

    let names = [
        "ok.bin",
        "../../etc/passwd",
        "..\\..\\win.ini",
        "",
        ".",
        "..",
        "with space.txt",
        "unicode-\u{202e}evil",
    ];
    let mut s: u64 = 0xDEAD_BEEF_CAFE_1234;
    for _ in 0..8000 {
        let tid = format!("tx-{}", xorshift(&mut s) % 6);
        let env = match xorshift(&mut s) % 6 {
            0 => {
                let name = names[(xorshift(&mut s) as usize) % names.len()];
                proto::file_offer(
                    &tid,
                    name,
                    xorshift(&mut s) % 1_000_000,
                    "application/octet-stream",
                )
            }
            1 => {
                let len = (xorshift(&mut s) % 64) as usize;
                let data: Vec<u8> = (0..len).map(|_| xorshift(&mut s) as u8).collect();
                proto::file_chunk(&tid, xorshift(&mut s) % 2_000_000, data)
            }
            2 => proto::file_ack(&tid, xorshift(&mut s) % 2_000_000),
            3 => {
                let mut digest = [0u8; 32];
                for b in &mut digest {
                    *b = xorshift(&mut s) as u8;
                }
                proto::file_complete(&tid, digest)
            }
            4 => proto::file_cancel(&tid, "fuzz"),
            _ => proto::file_offer("../../../evil", "../../../evil", 10, "x"),
        };
        if let Some(p) = env.payload {
            files.handle(&p);
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
