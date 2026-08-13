//! System-mode **broker**: the always-on network endpoint.
//!
//! `rmdd broker` runs as a system service (dedicated non-root `rmd` user) and owns
//! the WebRTC transport, rendezvous signaling, device identity/token, and input
//! injection — everything except screen capture. Capture comes from a per-session
//! [agent](crate::agent) over a Unix socket ([`rmd_ipc`]); the broker forwards the
//! active agent's encoded frames to the viewer and relays capture control back.
//!
//! Because the broker keeps the viewer's peer connection alive while agents come
//! and go, a login (greeter agent → user-session agent) is a seamless **handover**:
//! the new agent connects, becomes the active provider, and the video continues.
//!
//! [`BrokerVideoPlane`] implements [`VideoPlane`](crate::host::VideoPlane), so the
//! shared [`run_host_core`](crate::host::run_host_core) drives it exactly like the
//! local capture plane — the auth handshake, input, clipboard, and files are all
//! reused unchanged.

use std::os::unix::fs::PermissionsExt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use rmd_ipc::{AgentMsg, BrokerMsg, DisplayDesc};
use tokio::io::AsyncWriteExt;
use tokio::net::{UnixListener, UnixStream};
use tokio::sync::mpsc;

use crate::host::{HostConfig, HostStatus, VideoPlane, run_host_core, spawn_host_transport};
use rmd_transport::TransportSender;

/// Sentinel for "no active agent" in the shared `active_id`.
const NO_AGENT: u64 = u64::MAX;

/// Run the system-mode broker: identical session semantics to the single-process
/// host, but the video plane is fed by per-session agents over a Unix socket.
pub fn run_broker<F>(cfg: HostConfig, signal: Box<dyn crate::Signaling>, on_status: F) -> anyhow::Result<()>
where
    F: Fn(HostStatus),
{
    let transport = spawn_host_transport(&cfg)?;
    let authorized = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // The broker never applies digital zoom (it has no raw frames) — keep it FULL
    // so input coordinates map through unchanged. A future SetZoom relay to the
    // agent could enable zoom; for now it's a no-op.
    let zoom = Arc::new(Mutex::new(rmd_codec::CropRect::FULL));
    let video: Box<dyn VideoPlane> = Box::new(BrokerVideoPlane::start(transport.sender())?);
    run_host_core(cfg, signal, on_status, transport, authorized, zoom, video)
}

/// Plane → broker-thread control commands (the [`VideoPlane`] surface).
#[derive(Debug, Clone, Copy)]
enum PlaneCmd {
    /// Start/stop capturing (viewer authorized / gone). Tracked by the broker so a
    /// new agent joining mid-session is told to start capturing immediately.
    SetCapturing(bool),
    Select(u32),
    SetShowCursor(bool),
    Keyframe,
}

/// Broker-thread → plane state, updated when the active agent changes.
#[derive(Default)]
struct BrokerShared {
    displays: Vec<DisplayDesc>,
    monitor_rect: Option<rmd_input::MonitorRect>,
    /// Bumped whenever the captured session's geometry changes (new active agent),
    /// so the plane's `poll_geometry_changed` can rebuild the input injector.
    geometry_gen: u64,
}

/// [`VideoPlane`] backed by per-session agents over the Unix socket. Owns a
/// dedicated tokio runtime thread ([`broker_loop`]); the plane methods just push
/// [`PlaneCmd`]s into it and read shared state.
struct BrokerVideoPlane {
    cmd_tx: mpsc::UnboundedSender<PlaneCmd>,
    shared: Arc<Mutex<BrokerShared>>,
    last_geometry_gen: u64,
}

impl BrokerVideoPlane {
    fn start(sender: TransportSender) -> anyhow::Result<Self> {
        let shared = Arc::new(Mutex::new(BrokerShared::default()));
        let (cmd_tx, cmd_rx) = mpsc::unbounded_channel::<PlaneCmd>();
        let shared_thread = shared.clone();
        // The broker's socket I/O is async; run it on its own current-thread tokio
        // runtime (like RendezvousClient), bridged to the sync core via channels.
        std::thread::Builder::new()
            .name("rmd-broker-ipc".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        tracing::error!(error=%e, "broker: failed to build tokio runtime");
                        return;
                    }
                };
                if let Err(e) = rt.block_on(broker_loop(sender, shared_thread, cmd_rx)) {
                    tracing::error!(error=%e, "broker: IPC loop exited");
                }
            })?;
        Ok(Self {
            cmd_tx,
            shared,
            last_geometry_gen: 0,
        })
    }

    fn send(&self, cmd: PlaneCmd) {
        // The receiver lives for the process lifetime; a send error means the
        // broker thread died, which is already logged.
        let _ = self.cmd_tx.send(cmd);
    }
}

impl VideoPlane for BrokerVideoPlane {
    fn descriptors(&self) -> Vec<rmd_protocol::DisplayDescriptor> {
        self.shared
            .lock()
            .unwrap()
            .displays
            .iter()
            .map(|d| rmd_protocol::DisplayDescriptor {
                id: d.id,
                width: d.width,
                height: d.height,
                name: d.name.clone(),
                primary: d.primary,
            })
            .collect()
    }
    fn resume(&mut self) {
        self.send(PlaneCmd::SetCapturing(true));
    }
    fn pause(&mut self) {
        self.send(PlaneCmd::SetCapturing(false));
    }
    fn select(&mut self, id: u32) {
        self.send(PlaneCmd::Select(id));
    }
    fn set_show_cursor(&mut self, show: bool) {
        self.send(PlaneCmd::SetShowCursor(show));
    }
    fn request_keyframe(&mut self) {
        self.send(PlaneCmd::Keyframe);
    }
    fn monitor_rect(&self) -> Option<rmd_input::MonitorRect> {
        self.shared.lock().unwrap().monitor_rect
    }
    fn poll_geometry_changed(&mut self) -> Option<Option<rmd_input::MonitorRect>> {
        let s = self.shared.lock().unwrap();
        if s.geometry_gen != self.last_geometry_gen {
            self.last_geometry_gen = s.geometry_gen;
            Some(s.monitor_rect)
        } else {
            None
        }
    }
}

/// An event an agent connection reports to the broker loop.
enum AgentEvent {
    Hello {
        id: u64,
        phase: rmd_ipc::SessionPhase,
        backend: rmd_ipc::BackendKind,
        monitor_rect: Option<rmd_input::MonitorRect>,
        displays: Vec<DisplayDesc>,
    },
    Displays {
        id: u64,
        displays: Vec<DisplayDesc>,
    },
    Closed {
        id: u64,
    },
}

/// The active agent's control channel.
struct ActiveAgent {
    id: u64,
    ctrl_tx: mpsc::UnboundedSender<BrokerMsg>,
}

async fn broker_loop(
    sender: TransportSender,
    shared: Arc<Mutex<BrokerShared>>,
    mut cmd_rx: mpsc::UnboundedReceiver<PlaneCmd>,
) -> anyhow::Result<()> {
    let sock = rmd_ipc::socket_path();
    if let Some(parent) = sock.parent() {
        // Best-effort: the systemd RuntimeDirectory usually creates it.
        let _ = std::fs::create_dir_all(parent);
    }
    // Remove a stale socket from a previous run so bind() doesn't fail.
    let _ = std::fs::remove_file(&sock);
    let listener = UnixListener::bind(&sock)
        .map_err(|e| anyhow::anyhow!("broker: bind {}: {e}", sock.display()))?;
    // World-connectable socket, gated by the SO_PEERCRED uid check below — NOT by
    // file permissions. The display-manager greeter (e.g. GDM) launches with a
    // stripped supplementary-group set, so it does NOT inherit the `rmd` group and
    // a group-gated (0660) socket would lock the greeter agent out (EACCES). Peer
    // credentials are the real gate: only root, regular users, and greeter accounts
    // are accepted (see `AllowedUids`).
    let _ = std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o666));
    tracing::info!(socket = %sock.display(), "broker: listening for capture agents");

    let allowed = AllowedUids::detect();
    let active_id = Arc::new(AtomicU64::new(NO_AGENT));
    let mut active: Option<ActiveAgent> = None;
    let mut pending: std::collections::HashMap<u64, mpsc::UnboundedSender<BrokerMsg>> =
        std::collections::HashMap::new();
    let mut capturing = false;
    let mut next_id: u64 = 0;

    let (ev_tx, mut ev_rx) = mpsc::unbounded_channel::<AgentEvent>();
    let mut bitrate_tick = tokio::time::interval(Duration::from_millis(500));

    loop {
        tokio::select! {
            accept = listener.accept() => {
                let stream = match accept {
                    Ok((s, _)) => s,
                    Err(e) => { tracing::warn!(error=%e, "broker: accept failed"); continue; }
                };
                match stream.peer_cred() {
                    Ok(cred) if allowed.permits(cred.uid()) => {
                        let id = next_id;
                        next_id += 1;
                        let (ctrl_tx, ctrl_rx) = mpsc::unbounded_channel::<BrokerMsg>();
                        pending.insert(id, ctrl_tx);
                        tokio::spawn(agent_conn(
                            id,
                            stream,
                            ctrl_rx,
                            ev_tx.clone(),
                            sender.clone(),
                            active_id.clone(),
                        ));
                    }
                    Ok(cred) => {
                        tracing::warn!(uid = cred.uid(), "broker: rejected agent (uid not allowed)");
                    }
                    Err(e) => tracing::warn!(error=%e, "broker: could not read peer credentials"),
                }
            }
            ev = ev_rx.recv() => {
                let Some(ev) = ev else { break };
                match ev {
                    AgentEvent::Hello { id, phase, backend, monitor_rect, displays } => {
                        // Last Hello wins: the newest agent becomes the active
                        // provider (this is the greeter -> user handover).
                        let Some(ctrl_tx) = pending.remove(&id) else { continue };
                        {
                            let mut s = shared.lock().unwrap();
                            s.displays = displays;
                            s.monitor_rect = monitor_rect;
                            s.geometry_gen = s.geometry_gen.wrapping_add(1);
                        }
                        active_id.store(id, Ordering::Relaxed);
                        active = Some(ActiveAgent { id, ctrl_tx });
                        tracing::info!(?phase, ?backend, agent = id, "broker: agent is now the active provider");
                        // If a viewer is already watching, start the new agent
                        // capturing right away and force a keyframe so the stream
                        // recovers instantly across the handover.
                        if capturing {
                            if let Some(a) = &active {
                                let _ = a.ctrl_tx.send(BrokerMsg::SetCapturing(true));
                                let _ = a.ctrl_tx.send(BrokerMsg::ForceKeyframe);
                            }
                        }
                    }
                    AgentEvent::Displays { id, displays } => {
                        if active_id.load(Ordering::Relaxed) == id {
                            let mut s = shared.lock().unwrap();
                            s.displays = displays;
                        }
                    }
                    AgentEvent::Closed { id } => {
                        pending.remove(&id);
                        if active.as_ref().map(|a| a.id) == Some(id) {
                            active = None;
                            active_id.store(NO_AGENT, Ordering::Relaxed);
                            let mut s = shared.lock().unwrap();
                            s.displays.clear();
                            s.geometry_gen = s.geometry_gen.wrapping_add(1);
                            tracing::info!(agent = id, "broker: active agent disconnected; awaiting handover");
                        }
                    }
                }
            }
            cmd = cmd_rx.recv() => {
                let Some(cmd) = cmd else { break };
                match cmd {
                    PlaneCmd::SetCapturing(on) => {
                        capturing = on;
                        if let Some(a) = &active {
                            let _ = a.ctrl_tx.send(BrokerMsg::SetCapturing(on));
                        }
                    }
                    PlaneCmd::Select(display) => {
                        if let Some(a) = &active {
                            let _ = a.ctrl_tx.send(BrokerMsg::SelectDisplay(display));
                        }
                    }
                    PlaneCmd::SetShowCursor(show) => {
                        if let Some(a) = &active {
                            let _ = a.ctrl_tx.send(BrokerMsg::SetShowCursor(show));
                        }
                    }
                    PlaneCmd::Keyframe => {
                        if let Some(a) = &active {
                            let _ = a.ctrl_tx.send(BrokerMsg::ForceKeyframe);
                        }
                    }
                }
            }
            _ = bitrate_tick.tick() => {
                if capturing {
                    if let Some(a) = &active {
                        let _ = a.ctrl_tx.send(BrokerMsg::SetBitrate(sender.target_bitrate_bps()));
                    }
                }
            }
        }
    }
    Ok(())
}

/// One agent connection: forwards its encoded frames to the transport (when it's
/// the active provider) and relays broker control messages down to it.
async fn agent_conn(
    id: u64,
    stream: UnixStream,
    mut ctrl_rx: mpsc::UnboundedReceiver<BrokerMsg>,
    ev_tx: mpsc::UnboundedSender<AgentEvent>,
    sender: TransportSender,
    active_id: Arc<AtomicU64>,
) {
    let (mut rd, mut wr) = stream.into_split();
    // Writer task: broker control -> socket.
    let writer = tokio::spawn(async move {
        while let Some(msg) = ctrl_rx.recv().await {
            if rmd_ipc::write_msg(&mut wr, &msg).await.is_err() {
                break;
            }
        }
        let _ = wr.shutdown().await;
    });

    loop {
        match rmd_ipc::read_msg::<_, AgentMsg>(&mut rd).await {
            Ok(AgentMsg::Hello { phase, backend, uid, monitor_rect, displays }) => {
                tracing::debug!(agent = id, uid, "broker: agent hello");
                let rect = monitor_rect.map(|r| rmd_input::MonitorRect {
                    ox: r.ox,
                    oy: r.oy,
                    mw: r.mw,
                    mh: r.mh,
                    dw: r.dw,
                    dh: r.dh,
                });
                if ev_tx
                    .send(AgentEvent::Hello { id, phase, backend, monitor_rect: rect, displays })
                    .is_err()
                {
                    break;
                }
            }
            Ok(AgentMsg::Video { annexb, is_keyframe, capture_ts_micros }) => {
                // Only the active provider's frames reach the viewer; a stale
                // greeter agent lingering after handover is silently dropped.
                if active_id.load(Ordering::Relaxed) == id {
                    sender.send_video(Bytes::from(annexb), is_keyframe, capture_ts_micros);
                }
            }
            Ok(AgentMsg::Displays(displays)) => {
                if ev_tx.send(AgentEvent::Displays { id, displays }).is_err() {
                    break;
                }
            }
            Err(_) => break, // EOF / peer closed / decode error
        }
    }
    let _ = ev_tx.send(AgentEvent::Closed { id });
    writer.abort();
}

/// Which peer uids may feed the broker. Socket file permissions are the primary
/// gate (rmd-group only); this is defense in depth.
struct AllowedUids {
    /// Greeter accounts (gdm/sddm/lightdm) resolved at startup.
    greeters: Vec<u32>,
}

impl AllowedUids {
    fn detect() -> Self {
        let greeters = ["gdm", "sddm", "lightdm"]
            .iter()
            .filter_map(|n| uid_of(n))
            .collect();
        Self { greeters }
    }

    /// Accept root, regular users (uid ≥ 1000), and the display-manager greeter
    /// accounts. Rejects other system accounts.
    fn permits(&self, uid: u32) -> bool {
        uid == 0 || uid >= 1000 || self.greeters.contains(&uid)
    }
}

/// Resolve a username to its uid via libc, or `None` if the account doesn't exist.
fn uid_of(name: &str) -> Option<u32> {
    let cname = std::ffi::CString::new(name).ok()?;
    // SAFETY: getpwnam returns a pointer into a static buffer; we only read pw_uid
    // immediately and copy it out. Single-threaded startup call.
    unsafe {
        let pw = libc::getpwnam(cname.as_ptr());
        if pw.is_null() {
            None
        } else {
            Some((*pw).pw_uid)
        }
    }
}
