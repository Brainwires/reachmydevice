//! ReachMyDevice viewer app.
//!
//! A winit 0.30 + wgpu 29 window that renders decoded remote-desktop frames and
//! forwards local input back to the host, with an [`egui`] UI layered over the
//! same wgpu surface. The heavy lifting (transport, decode, signaling, account
//! REST) lives in [`rmd_session`]; this binary is the UI shell.
//!
//! - [`Gpu`] owns the wgpu surface/device/pipeline. Each frame it blits the
//!   latest RGBA frame onto a fullscreen quad (aspect-preserving letterbox — see
//!   `shader.wgsl`) and then paints the egui overlay on top.
//! - [`App`] implements winit's [`ApplicationHandler`] and drives a small state
//!   machine — [`Screen::Login`] → [`Screen::Devices`] → [`Screen::Connecting`]
//!   (with SAS/TOFU confirmation) → [`Screen::InSession`] (video + HUD).
//!
//! Network calls (sign-in, device list, device registration) run on background
//! threads so the GUI never blocks; results arrive over a channel ([`Job`]).
//!
//! ## Quick-connect (headless/scripted) fallback
//! If `RMD_TOKEN` and `RMD_PEER_DEVICE_ID` are set the login/device
//! screens are skipped and the app connects straight through, matching the old
//! env-driven behaviour (`RMD_RENDEZVOUS_URL` as the ws URL, or
//! `RMD_SIGNAL_ADDR` for the LAN relay).

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rmd_protocol as proto;
use rmd_protocol::input_event::Event as InputEvent;
use rmd_protocol::DisplayDescriptor;
use rmd_protocol::{KeyEvent, MouseButton, MouseMove, MouseScroll};
use rmd_session::rendezvous::RendezvousClient;
use rmd_session::{
    identity::known_peers, pairing::generate_pairing_code, pairing_client::pair_pake,
    AccountClient, DeviceIdentity, DeviceInfo, FileEvent, SignalClient, Signaling, ViewerConfig,
    ViewerSession, ViewerUpdate,
};
use rmd_transport::IceServer;

use egui_wgpu::ScreenDescriptor;
use winit::application::ApplicationHandler;
use winit::dpi::PhysicalPosition;
use winit::event::{ElementState, MouseButton as WinitMouseButton, MouseScrollDelta, WindowEvent};
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::keyboard::{KeyCode, PhysicalKey};
use winit::window::{Fullscreen, Window, WindowId};

/// How often, when idle, we wake to poll the session for new frames. Small
/// enough to keep latency low, large enough to not spin the CPU.
const POLL_INTERVAL: Duration = Duration::from_millis(4);

/// How often the viewer probes the host for round-trip latency.
const PING_INTERVAL: Duration = Duration::from_secs(1);

/// Default rendezvous server shown in the login form (overridable in the field
/// or via `RMD_RENDEZVOUS_URL`).
const DEFAULT_SERVER: &str = "https://app.reachmy.dev";

fn main() {
    // Lightweight flags before opening a window, so `--version` works headless.
    for a in std::env::args().skip(1) {
        match a.as_str() {
            "--version" | "-V" => {
                println!("rmd {}", env!("CARGO_PKG_VERSION"));
                return;
            }
            "--help" | "-h" => {
                println!(
                    "rmd {} — ReachMyDevice viewer/client\n\n\
                     A windowed viewer. Sign in and pick a host from the device list,\n\
                     or pair directly. Server via RMD_SERVER (default https://app.reachmy.dev).",
                    env!("CARGO_PKG_VERSION")
                );
                return;
            }
            _ => {}
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
        )
        .init();

    let event_loop = match EventLoop::new() {
        Ok(el) => el,
        Err(e) => {
            tracing::error!(error = %e, "failed to create event loop; exiting");
            std::process::exit(1);
        }
    };
    event_loop.set_control_flow(ControlFlow::Wait);

    let mut app = App::new();
    if let Err(e) = event_loop.run_app(&mut app) {
        tracing::error!(error = %e, "event loop terminated with error");
        std::process::exit(1);
    }
}

// --- Application state machine ---------------------------------------------

/// Which screen the UI is showing.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Screen {
    /// Server URL + credentials; sign in or create an account.
    Login,
    /// The user's device list + this-device identity.
    Devices,
    /// SAS/TOFU confirmation and the "establishing" spinner.
    Connecting,
    /// Live video with a HUD overlay.
    InSession,
    /// Direct device pairing (QR/PAKE): show or enter a one-time code.
    Pair,
}

/// Sub-state of [`Screen::Connecting`].
enum ConnState {
    /// Awaiting the user's out-of-band SAS confirmation before dialing.
    Confirm(Tofu),
    /// Session started; waiting for the data channel / pairing.
    Establishing,
    /// The host asked for a connection password; prompt the user. `retry` is set
    /// after a wrong attempt.
    NeedPassword { retry: bool },
}

/// TOFU verdict for the host we're about to connect to.
#[derive(Clone, Copy)]
enum Tofu {
    /// Never seen this device before — show the SAS for first-use verification.
    FirstUse,
    /// Known and the key matches what we remembered.
    Trusted,
    /// Known but the key CHANGED — refuse (possible MITM).
    Changed,
}

/// Result of a background network job, delivered to the UI thread.
enum Job {
    /// Sign-in: on success we already fetched the device list.
    SignedIn(Result<Vec<DeviceInfo>, String>),
    /// Account creation.
    Registered(Result<(), String>),
    /// Device-list refresh.
    Devices(Result<Vec<DeviceInfo>, String>),
    /// This viewer device registered — carries the freshly issued token.
    ThisDevice(Result<String, String>),
    /// A device was deleted — carries the removed device_id.
    Deleted(Result<String, String>),
    /// Direct pairing finished — `(device_id, public_key_hex, name)` or an error.
    Paired(Result<(String, String, String), String>),
}

/// The winit application: window/GPU (created on `resumed`), egui state, the app
/// flow state machine, the active session, and input bookkeeping.
struct App {
    // rendering / windowing
    window: Option<Arc<Window>>,
    gpu: Option<Gpu>,
    egui_ctx: egui::Context,
    egui_state: Option<egui_winit::State>,

    // flow
    screen: Screen,

    // login form
    server_url: String,
    username: String,
    password: String,

    // authenticated account (in memory only)
    account: Option<AccountClient>,
    creds: Option<(String, String)>,
    devices: Vec<DeviceInfo>,

    // this device
    identity: DeviceIdentity,
    this_device_id: String,
    device_name: String,
    viewer_token: Option<String>,
    known_peers_path: PathBuf,
    ice_servers: Vec<IceServer>,

    // direct pairing (QR/PAKE)
    pair_code: String,
    /// True when we generated the code (and are showing it); false when entering one.
    pair_generated: bool,
    pair_status: Option<String>,
    bind_addr: String,

    // connecting / session
    selected_host: Option<DeviceInfo>,
    conn: ConnState,
    session: Option<ViewerSession>,
    paired: Option<bool>,
    /// Connection-password entry (host with a password set).
    host_password: String,
    /// Whether we've already submitted a password this session (→ "wrong password").
    pw_submitted: bool,
    /// Whether the host's DTLS-bound identity proof verified this session.
    host_verified: Option<bool>,
    latency: Option<Duration>,
    last_ping: Instant,

    // in-session UI
    view_only: bool,
    hud_visible: bool,
    /// Latest file-transfer status line, shown in the HUD.
    file_status: Option<String>,
    /// The host's displays (multi-monitor picker); empty until advertised.
    displays: Vec<DisplayDescriptor>,
    /// The display id currently selected in the picker.
    active_display: u32,
    /// Whether to play host audio (opt-in; set via `RMD_AUDIO`).
    enable_audio: bool,

    // input bookkeeping
    /// Current keyboard modifier bitmask (`rmd_protocol::modifiers`).
    modifiers: u32,
    /// Last cursor position, normalized to [0, 1] over the window.
    last_cursor: (f64, f64),

    // async jobs + banners
    job: Option<Receiver<Job>>,
    busy: Option<String>,
    error: Option<String>,
    info: Option<String>,
}

impl App {
    fn new() -> Self {
        let config_dir = config_dir();
        let known_peers_path = config_dir.join("known_peers");

        // Load (or first-run generate) this device's long-lived identity.
        let identity_path = config_dir.join("identity.key");
        let (identity, id_err) = match DeviceIdentity::load_or_create(&identity_path) {
            Ok(id) => (id, None),
            Err(e) => {
                // Fall back to an ephemeral in-memory identity so the app still
                // runs; surface the failure in the UI.
                let id = DeviceIdentity::generate().expect("CSPRNG identity generation");
                (
                    id,
                    Some(format!("could not load identity: {e} (using ephemeral)")),
                )
            }
        };
        let this_device_id = identity.device_id();

        let device_name = std::env::var("RMD_NAME").unwrap_or_else(|_| "rmd-viewer".into());
        let ice_servers: Vec<IceServer> = std::env::var("RMD_ICE")
            .map(|s| {
                s.split(',')
                    .map(|x| x.trim())
                    .filter(|x| !x.is_empty())
                    .map(|u| IceServer::urls(vec![u.to_string()]))
                    .collect()
            })
            .unwrap_or_default();
        let bind_addr = std::env::var("RMD_BIND").unwrap_or_else(|_| "0.0.0.0:0".into());
        let server_url = std::env::var("RMD_RENDEZVOUS_URL")
            .ok()
            .filter(|u| u.starts_with("http"))
            .unwrap_or_else(|| DEFAULT_SERVER.into());

        let mut app = Self {
            window: None,
            gpu: None,
            egui_ctx: egui::Context::default(),
            egui_state: None,
            screen: Screen::Login,
            server_url,
            username: String::new(),
            password: String::new(),
            account: None,
            creds: None,
            devices: Vec::new(),
            identity,
            this_device_id,
            device_name,
            viewer_token: None,
            known_peers_path,
            ice_servers,
            pair_code: String::new(),
            pair_generated: false,
            pair_status: None,
            bind_addr,
            selected_host: None,
            conn: ConnState::Establishing,
            session: None,
            paired: None,
            host_password: String::new(),
            pw_submitted: false,
            host_verified: None,
            latency: None,
            last_ping: Instant::now(),
            view_only: false,
            hud_visible: true,
            file_status: None,
            displays: Vec::new(),
            active_display: 0,
            enable_audio: std::env::var("RMD_AUDIO").is_ok(),
            modifiers: 0,
            last_cursor: (0.0, 0.0),
            job: None,
            busy: None,
            error: id_err,
            info: None,
        };

        // Headless/scripted fallback: if the env carries a token + peer (or a LAN
        // relay addr), skip the login UI and connect straight through.
        if let Some(result) = quick_connect_signaling() {
            match result {
                Ok(signaling) => {
                    app.screen = Screen::Connecting;
                    app.conn = ConnState::Establishing;
                    app.start_session(signaling);
                }
                Err(e) => {
                    app.error = Some(format!("quick-connect failed: {e}"));
                }
            }
        }

        app
    }

    // --- session lifecycle -------------------------------------------------

    /// Start a [`ViewerSession`] over the given signaling backend and move to the
    /// "establishing" state. Errors surface in the UI banner.
    fn start_session(&mut self, signaling: Box<dyn Signaling>) {
        // Effective ICE = manual `RMD_ICE` base + whatever TURN/STUN the rendezvous
        // mints for this device. Without a relay, cross-NAT hosts may not connect.
        let mut ice = self.ice_servers.clone();
        if let (Some(account), Some(token)) = (&self.account, &self.viewer_token) {
            match account.ice_servers(token) {
                Ok(mut fetched) if !fetched.is_empty() => {
                    tracing::info!(count = fetched.len(), "fetched ICE servers from rendezvous");
                    ice.append(&mut fetched);
                }
                Ok(_) => {}
                Err(e) => tracing::warn!(error = %e, "could not fetch ICE servers from rendezvous"),
            }
        }
        let cfg = ViewerConfig {
            device_name: self.device_name.clone(),
            ice_servers: ice,
            bind_addr: self.bind_addr.clone(),
            enable_audio: self.enable_audio,
            // Share our identity so we can prove it (bound to the DTLS session)
            // to hosts that enforce unattended access.
            identity: Some(std::sync::Arc::new(self.identity.clone())),
        };
        match ViewerSession::start(cfg, signaling) {
            Ok(session) => {
                self.session = Some(session);
                self.paired = None;
                self.host_password.clear();
                self.pw_submitted = false;
                self.latency = None;
                self.last_ping = Instant::now();
                self.conn = ConnState::Establishing;
                self.screen = Screen::Connecting;
                self.error = None;
            }
            Err(e) => {
                self.error = Some(format!("failed to start session: {e}"));
                self.leave_session();
            }
        }
    }

    /// Tear down any active session and return to a sensible screen.
    fn leave_session(&mut self) {
        self.session = None;
        self.selected_host = None;
        self.paired = None;
        self.host_verified = None;
        self.latency = None;
        self.view_only = false;
        self.hud_visible = true;
        self.file_status = None;
        self.displays.clear();
        self.active_display = 0;
        // Drop fullscreen so the user isn't stranded.
        if let Some(win) = &self.window {
            win.set_fullscreen(None);
        }
        self.screen = if self.account.is_some() {
            Screen::Devices
        } else {
            Screen::Login
        };
    }

    /// Handle one update drained from the active session.
    fn handle_session_update(&mut self, update: ViewerUpdate) {
        match update {
            ViewerUpdate::Frame(frame) => {
                if let Some(gpu) = self.gpu.as_mut() {
                    gpu.upload_frame(&frame);
                }
                if let Some(win) = self.window.as_ref() {
                    win.request_redraw();
                }
            }
            ViewerUpdate::Connected => {
                tracing::info!("connected to host");
                // Data channel is up: reveal the video + HUD.
                self.screen = Screen::InSession;
            }
            ViewerUpdate::Paired(accepted) => {
                self.paired = Some(accepted);
                if accepted {
                    self.screen = Screen::InSession;
                } else {
                    self.error = Some("host rejected pairing (protocol version mismatch)".into());
                    self.leave_session();
                }
            }
            ViewerUpdate::PasswordRequired { reason } => {
                // Host wants a connection password (or ours was wrong). Prompt.
                if !reason.is_empty() {
                    tracing::info!(%reason, "host requires a connection password");
                }
                let retry = self.pw_submitted;
                self.host_password.clear();
                self.conn = ConnState::NeedPassword { retry };
                self.screen = Screen::Connecting;
            }
            ViewerUpdate::HostIdentity {
                device_id,
                public_key,
                verified,
            } => {
                // A valid self-proof is necessary but NOT sufficient: a MITM relay
                // could present its own key + a valid proof over its own DTLS
                // fingerprint. So we also require the proven identity to match the
                // host we intended to reach — the device the user selected AND the
                // key pinned for it (established out-of-band via SAS/TOFU or the
                // QR/PAKE pairing flow). Anything else is a possible MITM.
                let public_key_hex = hex::encode(&public_key);
                let dialed_ok = self
                    .selected_host
                    .as_ref()
                    .map(|h| h.device_id == device_id)
                    .unwrap_or(false);
                let pin_ok = known_peers::get(&self.known_peers_path, &device_id)
                    .map(|pinned| pinned == public_key_hex)
                    .unwrap_or(false);
                let ok = verified && dialed_ok && pin_ok;
                self.host_verified = Some(ok);
                if ok {
                    tracing::info!(%device_id, "host identity verified against the pinned key");
                } else {
                    let why = if !verified {
                        "proof invalid"
                    } else if !dialed_ok {
                        "identity does not match the device you selected"
                    } else {
                        "key does not match the one pinned for this host"
                    };
                    self.error = Some(format!(
                        "host verification failed ({why}) — refusing (possible MITM)"
                    ));
                    self.leave_session();
                }
            }
            ViewerUpdate::Latency(rtt) => {
                self.latency = Some(rtt);
            }
            ViewerUpdate::File(ev) => {
                self.file_status = Some(match ev {
                    FileEvent::Offered { name, size, .. } => {
                        format!("receiving {name} ({})", human_bytes(size))
                    }
                    FileEvent::Progress {
                        transferred, total, ..
                    } => {
                        let pct = transferred
                            .checked_mul(100)
                            .and_then(|v| v.checked_div(total))
                            .unwrap_or(0);
                        format!("transfer {pct}%")
                    }
                    FileEvent::Completed { path, .. } => match path {
                        Some(p) => format!("received {}", p.display()),
                        None => "file sent".into(),
                    },
                    FileEvent::Failed { reason, .. } => format!("transfer failed: {reason}"),
                });
            }
            ViewerUpdate::Displays(displays) => {
                self.displays = displays;
            }
            ViewerUpdate::Disconnected => {
                if self.screen == Screen::InSession {
                    self.info = Some("session ended (host disconnected)".into());
                } else {
                    self.error = Some("disconnected before the session was established".into());
                }
                self.leave_session();
            }
        }
    }

    // --- background jobs ---------------------------------------------------

    /// Spawn a background job (no-op if one is already in flight).
    fn spawn<F>(&mut self, label: &str, f: F)
    where
        F: FnOnce() -> Job + Send + 'static,
    {
        if self.busy.is_some() {
            return;
        }
        self.error = None;
        self.info = None;
        self.busy = Some(label.to_string());
        let (tx, rx) = mpsc::channel();
        self.job = Some(rx);
        std::thread::Builder::new()
            .name("rmd-viewer-job".into())
            .spawn(move || {
                let _ = tx.send(f());
            })
            .ok();
    }

    /// Poll the in-flight job (if any) and apply its result.
    fn poll_job(&mut self) {
        let Some(result) = self.job.as_ref().and_then(|rx| rx.try_recv().ok()) else {
            return;
        };
        self.job = None;
        self.busy = None;
        match result {
            Job::SignedIn(Ok(devices)) => {
                self.devices = devices;
                self.screen = Screen::Devices;
                self.info = Some("signed in".into());
                self.password.clear();
            }
            Job::SignedIn(Err(e)) => {
                self.account = None;
                self.creds = None;
                self.error = Some(e);
            }
            Job::Registered(Ok(())) => {
                self.info = Some("account created — you can sign in now".into());
            }
            Job::Registered(Err(e)) => self.error = Some(e),
            Job::Devices(Ok(devices)) => self.devices = devices,
            Job::Devices(Err(e)) => self.error = Some(e),
            Job::ThisDevice(Ok(token)) => {
                self.viewer_token = Some(token);
                self.info = Some("this device is registered — you can connect".into());
                self.refresh_devices();
            }
            Job::ThisDevice(Err(e)) => self.error = Some(e),
            Job::Deleted(Ok(id)) => {
                self.devices.retain(|d| d.device_id != id);
                self.info = Some("device removed".into());
            }
            Job::Deleted(Err(e)) => self.error = Some(e),
            Job::Paired(Ok((device_id, public_key_hex, name))) => {
                // Pin the newly-paired peer (TOFU); a later key change is refused.
                match known_peers::trust_on_first_use(
                    &self.known_peers_path,
                    &device_id,
                    &public_key_hex,
                ) {
                    Ok(_) => {
                        self.pair_status =
                            Some(format!("✓ paired with {name} ({})", short(&device_id)));
                        self.info = Some(format!("paired with {name}"));
                    }
                    Err(e) => self.pair_status = Some(format!("paired, but pinning failed: {e}")),
                }
            }
            Job::Paired(Err(e)) => self.pair_status = Some(format!("pairing failed: {e}")),
        }
        if let Some(win) = &self.window {
            win.request_redraw();
        }
    }

    // --- direct pairing (QR/PAKE) ------------------------------------------

    /// Open the pairing screen fresh.
    fn open_pairing(&mut self) {
        self.pair_code.clear();
        self.pair_generated = false;
        self.pair_status = None;
        self.screen = Screen::Pair;
    }

    /// Start pairing with `self.pair_code` over the configured relay. Both devices
    /// run this with the same code; on success the peer is pinned (TOFU).
    fn start_pairing(&mut self) {
        let code = self.pair_code.trim().to_string();
        if code.is_empty() {
            self.pair_status = Some("enter or generate a code first".into());
            return;
        }
        let base = ws_base(&self.server_url);
        let identity = self.identity.clone();
        let name = self.device_name.clone();
        self.pair_status = Some("waiting for the other device…".into());
        self.spawn("pairing", move || {
            let rt = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(rt) => rt,
                Err(e) => return Job::Paired(Err(format!("runtime: {e}"))),
            };
            let res = rt.block_on(pair_pake(&base, &code, &identity, &name));
            Job::Paired(
                res.map(|p| (p.device_id, hex::encode(p.public_key), p.name))
                    .map_err(|e| e.to_string()),
            )
        });
    }

    /// The "Pair a device" screen: generate or enter a one-time code, then pair.
    fn ui_pair(&mut self, ui: &mut egui::Ui) {
        ui.vertical_centered(|ui| {
            ui.add_space(20.0);
            ui.heading("Pair a device");
            ui.label(
                "Establish trust directly — no account needed. Both devices use the same \
                 one-time code (say it over the phone, or scan the QR when together).",
            );
            ui.add_space(12.0);

            ui.horizontal(|ui| {
                if ui.button("Generate a code").clicked() {
                    match generate_pairing_code() {
                        Ok(c) => {
                            self.pair_code = c;
                            self.pair_generated = true;
                            self.pair_status = None;
                        }
                        Err(e) => self.pair_status = Some(format!("could not generate: {e}")),
                    }
                }
                ui.label("— or enter the other device's code:");
            });
            ui.add(
                egui::TextEdit::singleline(&mut self.pair_code)
                    .hint_text("e.g. 417-k7mq3xry")
                    .desired_width(260.0),
            );

            if self.pair_generated {
                ui.add_space(8.0);
                ui.label("Share this code with the other device:");
                ui.heading(&self.pair_code);
            }

            ui.add_space(12.0);
            let busy = self.busy.is_some();
            if ui.add_enabled(!busy, egui::Button::new("Pair")).clicked() {
                self.start_pairing();
            }
            if busy {
                ui.spinner();
            }
            if let Some(s) = &self.pair_status {
                ui.add_space(8.0);
                ui.label(s);
            }

            ui.add_space(16.0);
            if ui.button("Back").clicked() {
                self.screen = if self.account.is_some() {
                    Screen::Devices
                } else {
                    Screen::Login
                };
            }
        });
    }

    // --- user actions ------------------------------------------------------

    fn action_sign_in(&mut self) {
        let (user, pass) = (self.username.trim().to_string(), self.password.clone());
        if user.is_empty() || pass.is_empty() {
            self.error = Some("enter a username and password".into());
            return;
        }
        let client = AccountClient::new(self.server_url.trim());
        // Optimistically remember the account; SignedIn(Err) clears it.
        self.account = Some(client.clone());
        self.creds = Some((user.clone(), pass.clone()));
        self.spawn("Signing in…", move || {
            Job::SignedIn(client.list_devices(&user, &pass).map_err(|e| e.to_string()))
        });
    }

    fn action_create_account(&mut self) {
        let (user, pass) = (self.username.trim().to_string(), self.password.clone());
        if user.is_empty() || pass.len() < 8 {
            self.error = Some("username required; password must be at least 8 characters".into());
            return;
        }
        let client = AccountClient::new(self.server_url.trim());
        self.spawn("Creating account…", move || {
            Job::Registered(client.register(&user, &pass).map_err(|e| e.to_string()))
        });
    }

    fn refresh_devices(&mut self) {
        let (Some(client), Some((user, pass))) = (self.account.clone(), self.creds.clone()) else {
            return;
        };
        self.spawn("Loading devices…", move || {
            Job::Devices(client.list_devices(&user, &pass).map_err(|e| e.to_string()))
        });
    }

    /// Register THIS viewer device to obtain a signaling bearer token.
    fn action_register_this_device(&mut self) {
        let (Some(client), Some((user, pass))) = (self.account.clone(), self.creds.clone()) else {
            return;
        };
        let device_id = self.this_device_id.clone();
        let name = self.device_name.clone();
        let public_key = self.identity.public_key_hex();
        self.spawn("Registering this device…", move || {
            Job::ThisDevice(
                client
                    .register_device(&user, &pass, &device_id, &name, &public_key, "viewer")
                    .map_err(|e| e.to_string()),
            )
        });
    }

    fn action_delete_device(&mut self, device_id: String) {
        let (Some(client), Some((user, pass))) = (self.account.clone(), self.creds.clone()) else {
            return;
        };
        self.spawn("Removing device…", move || {
            Job::Deleted(
                client
                    .delete_device(&user, &pass, &device_id)
                    .map(|()| device_id)
                    .map_err(|e| e.to_string()),
            )
        });
    }

    fn action_sign_out(&mut self) {
        self.account = None;
        self.creds = None;
        self.devices.clear();
        self.viewer_token = None;
        self.password.clear();
        self.screen = Screen::Login;
    }

    /// Begin connecting to `host`: compute the SAS and the TOFU verdict, then move
    /// to the confirmation screen.
    fn action_begin_connect(&mut self, host: DeviceInfo) {
        let sas_peer_key = host.public_key.clone();
        let tofu = match known_peers::get(&self.known_peers_path, &host.device_id) {
            None => Tofu::FirstUse,
            Some(k) if k == sas_peer_key => Tofu::Trusted,
            Some(_) => Tofu::Changed,
        };
        self.selected_host = Some(host);
        self.conn = ConnState::Confirm(tofu);
        self.screen = Screen::Connecting;
        self.error = None;
        self.info = None;
    }

    /// The user confirmed the SAS (or it was already trusted): remember the peer
    /// (TOFU) and dial.
    fn action_confirm_connect(&mut self) {
        let (Some(host), Some(account), Some(token)) = (
            self.selected_host.clone(),
            self.account.clone(),
            self.viewer_token.clone(),
        ) else {
            self.error = Some("register this device to get a token before connecting".into());
            self.leave_session();
            return;
        };

        // TOFU: record (first use) / verify (known); refuse on a changed key.
        match known_peers::trust_on_first_use(
            &self.known_peers_path,
            &host.device_id,
            &host.public_key,
        ) {
            Ok(_) => {}
            Err(e) => {
                self.error = Some(e.to_string());
                self.leave_session();
                return;
            }
        }

        match RendezvousClient::connect(&account.ws_url(), &token, Some(host.device_id.clone())) {
            Ok(client) => self.start_session(Box::new(client)),
            Err(e) => {
                self.error = Some(format!("could not open signaling: {e}"));
                self.leave_session();
            }
        }
    }

    // --- rendering ---------------------------------------------------------

    /// Run egui for this frame and paint video + overlay to the surface.
    fn render(&mut self) {
        let (Some(window), Some(state)) = (self.window.clone(), self.egui_state.as_mut()) else {
            return;
        };
        let raw_input = state.take_egui_input(&window);

        // Clone the context so the UI closure can borrow `self` mutably. egui 0.35
        // hands the closure a root `&mut Ui`; panels are shown into it.
        let ctx = self.egui_ctx.clone();
        let full_output = ctx.run_ui(raw_input, |ui| self.build_ui(ui));

        // `state` was re-borrowed above; fetch it again for platform output.
        if let Some(state) = self.egui_state.as_mut() {
            state.handle_platform_output(&window, full_output.platform_output);
        }

        let paint_jobs = ctx.tessellate(full_output.shapes, full_output.pixels_per_point);
        let screen = ScreenDescriptor {
            size_in_pixels: {
                let s = window.inner_size();
                [s.width.max(1), s.height.max(1)]
            },
            pixels_per_point: full_output.pixels_per_point,
        };

        if let Some(gpu) = self.gpu.as_mut() {
            gpu.render(&paint_jobs, &full_output.textures_delta, &screen);
        }

        // Keep animating while egui wants to (spinners), else the poll loop wakes us.
        if let Some(delay) = full_output
            .viewport_output
            .get(&egui::ViewportId::ROOT)
            .map(|v| v.repaint_delay)
        {
            if delay.is_zero() {
                window.request_redraw();
            }
        }
    }

    // --- egui UI -----------------------------------------------------------

    fn build_ui(&mut self, ui: &mut egui::Ui) {
        match self.screen {
            Screen::Login => self.ui_login(ui),
            Screen::Devices => self.ui_devices(ui),
            Screen::Connecting => self.ui_connecting(ui),
            Screen::InSession => self.ui_session(ui),
            Screen::Pair => self.ui_pair(ui),
        }
    }

    /// Shared error/info banner drawn at the top of a panel.
    fn banners(&mut self, ui: &mut egui::Ui) {
        if let Some(err) = self.error.clone() {
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::from_rgb(220, 80, 80), format!("⚠ {err}"));
                if ui.small_button("dismiss").clicked() {
                    self.error = None;
                }
            });
        }
        if let Some(info) = self.info.clone() {
            ui.horizontal(|ui| {
                ui.colored_label(egui::Color32::from_rgb(120, 200, 120), info);
                if ui.small_button("dismiss").clicked() {
                    self.info = None;
                }
            });
        }
    }

    fn ui_login(&mut self, root: &mut egui::Ui) {
        egui::CentralPanel::default().show(root, |ui| {
            ui.add_space(24.0);
            ui.vertical_centered(|ui| {
                ui.heading("ReachMyDevice");
                ui.label("Sign in to your rendezvous server");
            });
            ui.add_space(16.0);
            self.banners(ui);
            ui.add_space(8.0);

            let busy = self.busy.is_some();
            egui::Grid::new("login_grid")
                .num_columns(2)
                .spacing([12.0, 10.0])
                .show(ui, |ui| {
                    ui.label("Server");
                    ui.add_enabled(
                        !busy,
                        egui::TextEdit::singleline(&mut self.server_url).desired_width(320.0),
                    );
                    ui.end_row();

                    ui.label("Username");
                    ui.add_enabled(
                        !busy,
                        egui::TextEdit::singleline(&mut self.username).desired_width(320.0),
                    );
                    ui.end_row();

                    ui.label("Password");
                    ui.add_enabled(
                        !busy,
                        egui::TextEdit::singleline(&mut self.password)
                            .password(true)
                            .desired_width(320.0),
                    );
                    ui.end_row();
                });

            ui.add_space(12.0);
            ui.horizontal(|ui| {
                if let Some(label) = self.busy.clone() {
                    ui.spinner();
                    ui.label(label);
                } else {
                    if ui.button("Sign in").clicked() {
                        self.action_sign_in();
                    }
                    if ui.button("Create account").clicked() {
                        self.action_create_account();
                    }
                }
            });

            ui.add_space(8.0);
            if ui.button("Pair a device directly (no account)").clicked() {
                self.open_pairing();
            }

            ui.add_space(16.0);
            ui.separator();
            ui.label(format!("This device id: {}", short(&self.this_device_id)));
            ui.label(format!(
                "Fingerprint: {}",
                short(&self.identity.fingerprint())
            ));
        });
    }

    fn ui_devices(&mut self, root: &mut egui::Ui) {
        // Header: this-device identity + account actions.
        egui::Panel::top("devices_top").show(root, |ui| {
            ui.add_space(6.0);
            ui.horizontal(|ui| {
                ui.heading("Devices");
                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Sign out").clicked() {
                        self.action_sign_out();
                    }
                    let can = self.busy.is_none();
                    if ui.add_enabled(can, egui::Button::new("Refresh")).clicked() {
                        self.refresh_devices();
                    }
                    if ui.button("Pair a device").clicked() {
                        self.open_pairing();
                    }
                });
            });
            ui.horizontal_wrapped(|ui| {
                ui.label("This device:");
                ui.monospace(short(&self.this_device_id));
                ui.separator();
                match &self.viewer_token {
                    Some(_) => {
                        ui.colored_label(egui::Color32::from_rgb(120, 200, 120), "registered ✓");
                    }
                    None => {
                        let can = self.busy.is_none();
                        if ui
                            .add_enabled(can, egui::Button::new("Register this device"))
                            .on_hover_text("Obtain a signaling token so this viewer can connect")
                            .clicked()
                        {
                            self.action_register_this_device();
                        }
                    }
                }
            });
            ui.add_space(6.0);
        });

        egui::CentralPanel::default().show(root, |ui| {
            self.banners(ui);
            if let Some(label) = self.busy.clone() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(label);
                });
            }
            ui.add_space(6.0);

            if self.devices.is_empty() {
                ui.label("No devices yet. Register a host (or this device) to get started.");
                return;
            }

            let has_token = self.viewer_token.is_some();
            let busy = self.busy.is_some();
            // Collect actions to run after the immutable borrow of `self.devices`.
            let mut connect: Option<DeviceInfo> = None;
            let mut delete: Option<String> = None;
            let devices = self.devices.clone();

            egui::ScrollArea::vertical().show(ui, |ui| {
                for d in &devices {
                    ui.group(|ui| {
                        ui.horizontal(|ui| {
                            ui.strong(&d.name);
                            ui.weak(format!("[{}]", d.role));
                            ui.with_layout(
                                egui::Layout::right_to_left(egui::Align::Center),
                                |ui| {
                                    if ui.small_button("Delete").clicked() {
                                        delete = Some(d.device_id.clone());
                                    }
                                    let is_self = d.device_id == self.this_device_id;
                                    let connectable = d.is_connectable() && !is_self;
                                    let enabled = connectable && has_token && !busy;
                                    let btn = ui.add_enabled(enabled, egui::Button::new("Connect"));
                                    let btn = if is_self {
                                        btn.on_hover_text("This is the viewer device")
                                    } else if !d.is_connectable() {
                                        btn.on_hover_text("Not a host (role is viewer-only)")
                                    } else if !has_token {
                                        btn.on_hover_text("Register this device first")
                                    } else {
                                        btn
                                    };
                                    if btn.clicked() {
                                        connect = Some(d.clone());
                                    }
                                },
                            );
                        });
                        ui.horizontal_wrapped(|ui| {
                            ui.weak("id");
                            ui.monospace(short(&d.device_id));
                            ui.weak("key");
                            ui.monospace(short(&d.public_key));
                            ui.weak("last seen");
                            ui.label(fmt_last_seen(d.last_seen));
                        });
                    });
                }
            });

            if let Some(host) = connect {
                self.action_begin_connect(host);
            }
            if let Some(id) = delete {
                self.action_delete_device(id);
            }
        });
    }

    fn ui_connecting(&mut self, root: &mut egui::Ui) {
        egui::CentralPanel::default().show(root, |ui| {
            ui.add_space(24.0);
            self.banners(ui);
            let host_name = self
                .selected_host
                .as_ref()
                .map(|h| h.name.clone())
                .unwrap_or_else(|| "host".into());

            // Snapshot the connection sub-state into owned values so the UI
            // closures can still call `&mut self` action methods below.
            enum View {
                Confirm(Tofu),
                Password { retry: bool },
                Establishing,
            }
            let view = match &self.conn {
                ConnState::Confirm(tofu) => View::Confirm(*tofu),
                ConnState::NeedPassword { retry } => View::Password { retry: *retry },
                ConnState::Establishing => View::Establishing,
            };

            match view {
                View::Confirm(tofu) => {
                    ui.vertical_centered(|ui| {
                        ui.heading(format!("Connect to {host_name}"));
                    });
                    ui.add_space(12.0);

                    // Compute the SAS over our key and the host's key.
                    let sas = self
                        .selected_host
                        .as_ref()
                        .map(|h| self.identity.sas(&h.public_key));

                    match tofu {
                        Tofu::Changed => {
                            ui.colored_label(
                                egui::Color32::from_rgb(230, 60, 60),
                                "⚠ THIS DEVICE PRESENTED A DIFFERENT KEY THAN REMEMBERED.",
                            );
                            ui.label(
                                "The host's identity key does not match the one you previously \
                                 trusted. This can happen after a reinstall — or it can indicate a \
                                 machine-in-the-middle. Connection refused.",
                            );
                            ui.add_space(8.0);
                            if ui.button("Back").clicked() {
                                self.leave_session();
                            }
                        }
                        Tofu::Trusted | Tofu::FirstUse => {
                            if matches!(tofu, Tofu::Trusted) {
                                ui.colored_label(
                                    egui::Color32::from_rgb(120, 200, 120),
                                    "Previously verified (trusted on first use).",
                                );
                            } else {
                                ui.label(
                                    "First connection to this host. Verify the code below matches \
                                     the one shown on the host, out-of-band, before connecting.",
                                );
                            }
                            ui.add_space(8.0);
                            ui.horizontal(|ui| {
                                ui.label("Security code (SAS):");
                                ui.heading(sas.as_deref().unwrap_or("------"));
                            });
                            if let Some(h) = &self.selected_host {
                                ui.horizontal_wrapped(|ui| {
                                    ui.weak("host key");
                                    ui.monospace(short(&h.public_key));
                                });
                            }
                            ui.add_space(12.0);
                            ui.horizontal(|ui| {
                                let confirm = if matches!(tofu, Tofu::Trusted) {
                                    "Connect"
                                } else {
                                    "The code matches — Trust & Connect"
                                };
                                if ui.button(confirm).clicked() {
                                    self.action_confirm_connect();
                                }
                                if ui.button("Cancel").clicked() {
                                    self.leave_session();
                                }
                            });
                        }
                    }
                }
                View::Password { retry } => {
                    ui.vertical_centered(|ui| {
                        ui.heading(format!("Password for {host_name}"));
                    });
                    ui.add_space(12.0);
                    if retry {
                        ui.colored_label(
                            egui::Color32::from_rgb(230, 60, 60),
                            "Wrong password — try again.",
                        );
                    } else {
                        ui.label("This host requires a connection password.");
                    }
                    ui.add_space(8.0);
                    let mut submit = false;
                    ui.horizontal(|ui| {
                        ui.label("Password");
                        let resp = ui.add(
                            egui::TextEdit::singleline(&mut self.host_password)
                                .password(true)
                                .desired_width(220.0),
                        );
                        if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) {
                            submit = true;
                        }
                    });
                    ui.add_space(12.0);
                    let mut cancel = false;
                    ui.horizontal(|ui| {
                        if ui.button("Connect").clicked() {
                            submit = true;
                        }
                        if ui.button("Cancel").clicked() {
                            cancel = true;
                        }
                    });
                    if cancel {
                        self.leave_session();
                    } else if submit {
                        self.action_submit_host_password();
                    }
                }
                View::Establishing => {
                    ui.vertical_centered(|ui| {
                        ui.add_space(24.0);
                        ui.spinner();
                        ui.label(format!("Connecting to {host_name}…"));
                        ui.add_space(8.0);
                        if ui.button("Cancel").clicked() {
                            self.leave_session();
                        }
                    });
                }
            }
        });
    }

    /// Submit the entered connection password: hand it to the session (which
    /// re-sends the Hello with it) and show the spinner while the host verifies.
    fn action_submit_host_password(&mut self) {
        if self.host_password.is_empty() {
            return;
        }
        let pw = std::mem::take(&mut self.host_password);
        self.pw_submitted = true;
        if let Some(s) = &self.session {
            s.submit_password(pw);
        }
        self.conn = ConnState::Establishing;
    }

    fn ui_session(&mut self, root: &mut egui::Ui) {
        if !self.hud_visible {
            return; // immersive: video only (F1 restores the HUD)
        }
        egui::Panel::top("hud").show(root, |ui| {
            ui.horizontal(|ui| {
                // Connection / pairing state.
                let state = match self.paired {
                    Some(true) => ("paired", egui::Color32::from_rgb(120, 200, 120)),
                    Some(false) => ("rejected", egui::Color32::from_rgb(230, 60, 60)),
                    None => ("connected", egui::Color32::from_rgb(200, 200, 120)),
                };
                ui.colored_label(state.1, format!("● {}", state.0));
                ui.separator();

                // Latency (RTT from data-channel Ping/Pong).
                match self.latency {
                    Some(rtt) => ui.label(format!("latency {} ms", rtt.as_millis())),
                    None => ui.label("latency —"),
                };
                ui.separator();

                ui.checkbox(&mut self.view_only, "View only");
                ui.separator();

                // Multi-monitor picker (only when the host has more than one).
                if self.displays.len() > 1 {
                    let current = self.active_display;
                    let label = self
                        .displays
                        .iter()
                        .find(|d| d.id == current)
                        .map(|d| d.name.clone())
                        .unwrap_or_else(|| "Display".into());
                    egui::ComboBox::from_id_salt("display-picker")
                        .selected_text(label)
                        .show_ui(ui, |ui| {
                            for d in &self.displays {
                                let text = format!("{} ({}×{})", d.name, d.width, d.height);
                                if ui.selectable_label(d.id == current, text).clicked()
                                    && d.id != current
                                {
                                    self.active_display = d.id;
                                    if let Some(s) = self.session.as_ref() {
                                        s.select_display(d.id);
                                        s.request_keyframe();
                                    }
                                }
                            }
                        });
                    ui.separator();
                }

                // File transfer: status + hint (drop a file on the window to send).
                match &self.file_status {
                    Some(s) => ui.label(format!("📁 {s}")),
                    None => ui.weak("drop a file to send"),
                };
                ui.separator();

                let is_fs = self.window.as_ref().and_then(|w| w.fullscreen()).is_some();
                if ui
                    .button(if is_fs { "Windowed" } else { "Fullscreen" })
                    .clicked()
                {
                    if let Some(win) = &self.window {
                        win.set_fullscreen(if is_fs {
                            None
                        } else {
                            Some(Fullscreen::Borderless(None))
                        });
                    }
                }

                ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                    if ui.button("Disconnect").clicked() {
                        self.leave_session();
                    }
                    ui.weak("F1: toggle HUD");
                });
            });
        });
    }

    // --- input translation -------------------------------------------------

    /// Whether local input should be forwarded to the host right now.
    fn forwarding_input(&self, egui_consumed: bool) -> bool {
        self.screen == Screen::InSession
            && self.session.is_some()
            && !self.view_only
            && !egui_consumed
    }

    /// Normalize a cursor position to [0, 1] over the current window inner size.
    fn normalize_cursor(
        &self,
        position: PhysicalPosition<f64>,
        last: &mut (f64, f64),
    ) -> (f64, f64) {
        let (w, h) = self.window.as_ref().map_or((1.0, 1.0), |win| {
            let s = win.inner_size();
            (f64::from(s.width.max(1)), f64::from(s.height.max(1)))
        });
        let x = (position.x / w).clamp(0.0, 1.0);
        let y = (position.y / h).clamp(0.0, 1.0);
        *last = (x, y);
        (x, y)
    }
}

impl ApplicationHandler for App {
    fn resumed(&mut self, event_loop: &ActiveEventLoop) {
        if self.window.is_some() {
            return;
        }
        let attrs = Window::default_attributes().with_title("ReachMyDevice Viewer");
        let window = match event_loop.create_window(attrs) {
            Ok(w) => Arc::new(w),
            Err(e) => {
                tracing::error!(error = %e, "failed to create window; exiting");
                event_loop.exit();
                return;
            }
        };

        match pollster::block_on(Gpu::new(window.clone())) {
            Ok(gpu) => {
                let egui_state = egui_winit::State::new(
                    self.egui_ctx.clone(),
                    egui::ViewportId::ROOT,
                    window.as_ref(),
                    Some(window.scale_factor() as f32),
                    None,
                    None,
                );
                self.egui_ctx.set_visuals(egui::Visuals::dark());
                self.gpu = Some(gpu);
                self.egui_state = Some(egui_state);
                self.window = Some(window);
            }
            Err(e) => {
                tracing::error!(error = %e, "failed to initialize wgpu; exiting");
                event_loop.exit();
            }
        }
    }

    fn window_event(&mut self, event_loop: &ActiveEventLoop, _id: WindowId, event: WindowEvent) {
        let Some(window) = self.window.clone() else {
            return;
        };

        // Feed the event to egui first; it tells us whether it consumed it.
        let egui_consumed = if let Some(state) = self.egui_state.as_mut() {
            let resp = state.on_window_event(&window, &event);
            if resp.repaint {
                window.request_redraw();
            }
            resp.consumed
        } else {
            false
        };

        match event {
            WindowEvent::CloseRequested => {
                tracing::info!("close requested; exiting");
                event_loop.exit();
            }
            WindowEvent::Resized(size) => {
                if let Some(gpu) = self.gpu.as_mut() {
                    gpu.resize(size.width, size.height);
                }
                window.request_redraw();
            }
            WindowEvent::RedrawRequested => self.render(),

            // Drop a file on the window to send it to the host.
            WindowEvent::DroppedFile(path) => {
                if let Some(session) = self.session.as_ref() {
                    let name = path
                        .file_name()
                        .map(|n| n.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    self.file_status = Some(format!("sending {name}…"));
                    session.send_file(path);
                    window.request_redraw();
                }
            }

            // --- input translation (viewer -> host) ------------------------
            WindowEvent::CursorMoved { position, .. } => {
                let mut last = self.last_cursor;
                let (x, y) = self.normalize_cursor(position, &mut last);
                self.last_cursor = last;
                if self.forwarding_input(egui_consumed) {
                    if let Some(s) = &self.session {
                        s.send_input(InputEvent::MouseMove(MouseMove { x, y }));
                    }
                }
            }
            WindowEvent::MouseInput { state, button, .. } => {
                if self.forwarding_input(egui_consumed) {
                    if let (Some(btn), Some(s)) = (map_mouse_button(button), &self.session) {
                        let (x, y) = self.last_cursor;
                        s.send_input(InputEvent::MouseButton(MouseButton {
                            button: btn,
                            pressed: state == ElementState::Pressed,
                            x,
                            y,
                        }));
                    }
                }
            }
            WindowEvent::MouseWheel { delta, .. } => {
                if self.forwarding_input(egui_consumed) {
                    let (dx, dy) = match delta {
                        MouseScrollDelta::LineDelta(x, y) => {
                            (f64::from(x) * 10.0, f64::from(y) * 10.0)
                        }
                        MouseScrollDelta::PixelDelta(p) => (p.x, p.y),
                    };
                    if let Some(s) = &self.session {
                        s.send_input(InputEvent::MouseScroll(MouseScroll { dx, dy }));
                    }
                }
            }
            WindowEvent::ModifiersChanged(mods) => {
                self.modifiers = map_modifiers(mods.state());
            }
            WindowEvent::KeyboardInput { event, .. } => {
                // F1 toggles the HUD in-session; it is never forwarded.
                if self.screen == Screen::InSession
                    && event.state == ElementState::Pressed
                    && event.physical_key == PhysicalKey::Code(KeyCode::F1)
                {
                    self.hud_visible = !self.hud_visible;
                    window.request_redraw();
                    return;
                }
                if self.forwarding_input(egui_consumed) {
                    if let PhysicalKey::Code(code) = event.physical_key {
                        if let (Some(hid_usage), Some(s)) =
                            (winit_keycode_to_hid(code), &self.session)
                        {
                            s.send_input(InputEvent::Key(KeyEvent {
                                hid_usage,
                                pressed: event.state == ElementState::Pressed,
                                modifiers: self.modifiers,
                            }));
                        }
                    }
                }
            }
            _ => {}
        }
    }

    fn about_to_wait(&mut self, event_loop: &ActiveEventLoop) {
        // Drain session updates.
        loop {
            let Some(update) = self.session.as_ref().and_then(|s| s.poll_update()) else {
                break;
            };
            self.handle_session_update(update);
        }

        // Apply any completed background job.
        self.poll_job();

        // Probe latency periodically while in a live session.
        if self.screen == Screen::InSession && self.last_ping.elapsed() >= PING_INTERVAL {
            if let Some(s) = &self.session {
                s.send_ping();
            }
            self.last_ping = Instant::now();
        }

        // Keep spinners animating while a job is in flight or we're establishing.
        let animating = self.busy.is_some()
            || matches!(
                (self.screen, &self.conn),
                (Screen::Connecting, ConnState::Establishing)
            );
        if animating {
            if let Some(win) = &self.window {
                win.request_redraw();
            }
        }

        event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + POLL_INTERVAL));
    }
}

// --- env quick-connect -----------------------------------------------------

/// If the environment carries connect-through credentials, build the signaling
/// backend (rendezvous by token+peer, else LAN relay). Returns `None` to fall
/// back to the login UI.
fn quick_connect_signaling() -> Option<anyhow::Result<Box<dyn Signaling>>> {
    if let (Ok(token), Ok(peer)) = (
        std::env::var("RMD_TOKEN"),
        std::env::var("RMD_PEER_DEVICE_ID"),
    ) {
        let ws = std::env::var("RMD_RENDEZVOUS_URL")
            .unwrap_or_else(|_| "wss://app.reachmy.dev/ws".into());
        tracing::info!(%ws, %peer, "quick-connect via rendezvous");
        return Some(
            RendezvousClient::connect(&ws, &token, Some(peer))
                .map(|c| Box::new(c) as Box<dyn Signaling>),
        );
    }
    if let Ok(addr) = std::env::var("RMD_SIGNAL_ADDR") {
        tracing::info!(%addr, "quick-connect via LAN relay");
        return Some(SignalClient::connect(&addr).map(|c| Box::new(c) as Box<dyn Signaling>));
    }
    None
}

// --- small helpers ---------------------------------------------------------

/// The config directory for identity + known-peers (`$XDG_CONFIG_HOME/rmd`
/// or `~/.config/rmd`).
fn config_dir() -> PathBuf {
    if let Some(xdg) = std::env::var_os("XDG_CONFIG_HOME") {
        return PathBuf::from(xdg).join("rmd");
    }
    if let Some(home) = std::env::var_os("HOME") {
        return PathBuf::from(home).join(".config").join("rmd");
    }
    PathBuf::from(".rmd")
}

/// Human-readable byte count (e.g. `3.2 MB`).
fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = n as f64;
    let mut u = 0;
    while v >= 1024.0 && u < UNITS.len() - 1 {
        v /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{n} B")
    } else {
        format!("{v:.1} {}", UNITS[u])
    }
}

/// Derive the pairing WebSocket base (`ws(s)://host`) from the configured server
/// URL, stripping any trailing `/ws` — `pair_pake` appends `/pair`.
fn ws_base(server_url: &str) -> String {
    let s = server_url.trim().trim_end_matches('/');
    let s = s.strip_suffix("/ws").unwrap_or(s);
    if let Some(rest) = s.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = s.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if s.starts_with("ws://") || s.starts_with("wss://") {
        s.to_string()
    } else {
        format!("wss://{s}")
    }
}

/// Truncate a long hex id to `head…tail` for display.
fn short(s: &str) -> String {
    if s.len() <= 20 {
        s.to_string()
    } else {
        format!("{}…{}", &s[..12], &s[s.len() - 6..])
    }
}

/// Format a unix-seconds `last_seen` as a coarse "time ago", or "never".
fn fmt_last_seen(ts: Option<i64>) -> String {
    let Some(ts) = ts else {
        return "never".into();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(ts);
    let secs = (now - ts).max(0);
    if secs < 60 {
        format!("{secs}s ago")
    } else if secs < 3600 {
        format!("{}m ago", secs / 60)
    } else if secs < 86_400 {
        format!("{}h ago", secs / 3600)
    } else {
        format!("{}d ago", secs / 86_400)
    }
}

// --- GPU / renderer --------------------------------------------------------

/// A single uploaded frame texture plus its bind group and dimensions.
struct FrameTexture {
    width: u32,
    height: u32,
    texture: wgpu::Texture,
    bind_group: wgpu::BindGroup,
}

/// The wgpu renderer: surface, device/queue, the blit pipeline, the (optional)
/// frame texture, and the egui overlay renderer. Until the first frame the video
/// layer simply clears to black; egui always paints on top.
struct Gpu {
    surface: wgpu::Surface<'static>,
    device: wgpu::Device,
    queue: wgpu::Queue,
    config: wgpu::SurfaceConfiguration,
    pipeline: wgpu::RenderPipeline,
    bind_group_layout: wgpu::BindGroupLayout,
    sampler: wgpu::Sampler,
    uniform_buf: wgpu::Buffer,
    frame: Option<FrameTexture>,
    egui_renderer: egui_wgpu::Renderer,
}

/// Scale uniform consumed by the vertex shader for aspect-preserving letterbox.
#[repr(C)]
#[derive(Clone, Copy, bytemuck::Pod, bytemuck::Zeroable)]
struct Uniforms {
    scale: [f32; 2],
    _pad: [f32; 2],
}

impl Gpu {
    async fn new(window: Arc<Window>) -> anyhow::Result<Self> {
        let size = window.inner_size();
        let (width, height) = (size.width.max(1), size.height.max(1));

        let instance = wgpu::Instance::default();
        let surface = instance.create_surface(window)?;

        let adapter = instance
            .request_adapter(&wgpu::RequestAdapterOptions {
                compatible_surface: Some(&surface),
                ..Default::default()
            })
            .await?;

        let (device, queue) = adapter
            .request_device(&wgpu::DeviceDescriptor {
                label: Some("rmd-viewer device"),
                required_features: wgpu::Features::empty(),
                required_limits: wgpu::Limits::default(),
                experimental_features: wgpu::ExperimentalFeatures::disabled(),
                memory_hints: wgpu::MemoryHints::default(),
                trace: wgpu::Trace::Off,
            })
            .await?;

        // Prefer an sRGB surface so the sample/present gamma round-trips.
        let caps = surface.get_capabilities(&adapter);
        let format = caps
            .formats
            .iter()
            .copied()
            .find(wgpu::TextureFormat::is_srgb)
            .unwrap_or(caps.formats[0]);

        let config = wgpu::SurfaceConfiguration {
            usage: wgpu::TextureUsages::RENDER_ATTACHMENT,
            format,
            width,
            height,
            present_mode: caps.present_modes[0],
            alpha_mode: caps.alpha_modes[0],
            view_formats: vec![],
            desired_maximum_frame_latency: 2,
        };
        surface.configure(&device, &config);

        let bind_group_layout = device.create_bind_group_layout(&wgpu::BindGroupLayoutDescriptor {
            label: Some("rmd-viewer bind group layout"),
            entries: &[
                wgpu::BindGroupLayoutEntry {
                    binding: 0,
                    visibility: wgpu::ShaderStages::VERTEX,
                    ty: wgpu::BindingType::Buffer {
                        ty: wgpu::BufferBindingType::Uniform,
                        has_dynamic_offset: false,
                        min_binding_size: None,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 1,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Texture {
                        sample_type: wgpu::TextureSampleType::Float { filterable: true },
                        view_dimension: wgpu::TextureViewDimension::D2,
                        multisampled: false,
                    },
                    count: None,
                },
                wgpu::BindGroupLayoutEntry {
                    binding: 2,
                    visibility: wgpu::ShaderStages::FRAGMENT,
                    ty: wgpu::BindingType::Sampler(wgpu::SamplerBindingType::Filtering),
                    count: None,
                },
            ],
        });

        let shader = device.create_shader_module(wgpu::ShaderModuleDescriptor {
            label: Some("rmd-viewer blit shader"),
            source: wgpu::ShaderSource::Wgsl(include_str!("shader.wgsl").into()),
        });

        let pipeline_layout = device.create_pipeline_layout(&wgpu::PipelineLayoutDescriptor {
            label: Some("rmd-viewer pipeline layout"),
            bind_group_layouts: &[Some(&bind_group_layout)],
            immediate_size: 0,
        });

        let pipeline = device.create_render_pipeline(&wgpu::RenderPipelineDescriptor {
            label: Some("rmd-viewer blit pipeline"),
            layout: Some(&pipeline_layout),
            vertex: wgpu::VertexState {
                module: &shader,
                entry_point: Some("vs_main"),
                buffers: &[],
                compilation_options: wgpu::PipelineCompilationOptions::default(),
            },
            fragment: Some(wgpu::FragmentState {
                module: &shader,
                entry_point: Some("fs_main"),
                targets: &[Some(wgpu::ColorTargetState {
                    format,
                    blend: Some(wgpu::BlendState::REPLACE),
                    write_mask: wgpu::ColorWrites::ALL,
                })],
                compilation_options: wgpu::PipelineCompilationOptions::default(),
            }),
            primitive: wgpu::PrimitiveState::default(),
            depth_stencil: None,
            multisample: wgpu::MultisampleState::default(),
            multiview_mask: None,
            cache: None,
        });

        let sampler = device.create_sampler(&wgpu::SamplerDescriptor {
            label: Some("rmd-viewer sampler"),
            mag_filter: wgpu::FilterMode::Linear,
            min_filter: wgpu::FilterMode::Linear,
            ..Default::default()
        });

        let uniform_buf = device.create_buffer(&wgpu::BufferDescriptor {
            label: Some("rmd-viewer uniforms"),
            size: std::mem::size_of::<Uniforms>() as u64,
            usage: wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST,
            mapped_at_creation: false,
        });

        // egui paints into the same surface format, one sample, no depth.
        let egui_renderer = egui_wgpu::Renderer::new(
            &device,
            format,
            egui_wgpu::RendererOptions {
                msaa_samples: 1,
                depth_stencil_format: None,
                ..Default::default()
            },
        );

        Ok(Self {
            surface,
            device,
            queue,
            config,
            pipeline,
            bind_group_layout,
            sampler,
            uniform_buf,
            frame: None,
            egui_renderer,
        })
    }

    fn reconfigure(&mut self) {
        self.surface.configure(&self.device, &self.config);
    }

    fn resize(&mut self, width: u32, height: u32) {
        self.config.width = width.max(1);
        self.config.height = height.max(1);
        self.surface.configure(&self.device, &self.config);
    }

    /// Upload a decoded RGBA frame, (re)creating the texture and bind group when
    /// the incoming dimensions change.
    fn upload_frame(&mut self, frame: &rmd_codec::DecodedFrame) {
        let (w, h) = (frame.width.max(1), frame.height.max(1));
        let needs_new = self
            .frame
            .as_ref()
            .is_none_or(|f| f.width != w || f.height != h);

        if needs_new {
            let texture = self.device.create_texture(&wgpu::TextureDescriptor {
                label: Some("rmd-viewer frame texture"),
                size: wgpu::Extent3d {
                    width: w,
                    height: h,
                    depth_or_array_layers: 1,
                },
                mip_level_count: 1,
                sample_count: 1,
                dimension: wgpu::TextureDimension::D2,
                format: wgpu::TextureFormat::Rgba8UnormSrgb,
                usage: wgpu::TextureUsages::TEXTURE_BINDING | wgpu::TextureUsages::COPY_DST,
                view_formats: &[],
            });
            let view = texture.create_view(&wgpu::TextureViewDescriptor::default());
            let bind_group = self.device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some("rmd-viewer bind group"),
                layout: &self.bind_group_layout,
                entries: &[
                    wgpu::BindGroupEntry {
                        binding: 0,
                        resource: self.uniform_buf.as_entire_binding(),
                    },
                    wgpu::BindGroupEntry {
                        binding: 1,
                        resource: wgpu::BindingResource::TextureView(&view),
                    },
                    wgpu::BindGroupEntry {
                        binding: 2,
                        resource: wgpu::BindingResource::Sampler(&self.sampler),
                    },
                ],
            });
            self.frame = Some(FrameTexture {
                width: w,
                height: h,
                texture,
                bind_group,
            });
        }

        let Some(frame_tex) = self.frame.as_ref() else {
            return;
        };
        self.queue.write_texture(
            wgpu::TexelCopyTextureInfo {
                texture: &frame_tex.texture,
                mip_level: 0,
                origin: wgpu::Origin3d::ZERO,
                aspect: wgpu::TextureAspect::All,
            },
            &frame.data,
            wgpu::TexelCopyBufferLayout {
                offset: 0,
                bytes_per_row: Some(w * 4),
                rows_per_image: Some(h),
            },
            wgpu::Extent3d {
                width: w,
                height: h,
                depth_or_array_layers: 1,
            },
        );
    }

    /// Blit the current video frame (or clear to black) and paint egui on top.
    fn render(
        &mut self,
        paint_jobs: &[egui::ClippedPrimitive],
        textures_delta: &egui::TexturesDelta,
        screen: &ScreenDescriptor,
    ) {
        let surface_tex = match self.surface.get_current_texture() {
            wgpu::CurrentSurfaceTexture::Success(t) => t,
            wgpu::CurrentSurfaceTexture::Suboptimal(t) => {
                self.reconfigure();
                t
            }
            wgpu::CurrentSurfaceTexture::Outdated | wgpu::CurrentSurfaceTexture::Lost => {
                self.reconfigure();
                return;
            }
            wgpu::CurrentSurfaceTexture::Timeout | wgpu::CurrentSurfaceTexture::Occluded => return,
            wgpu::CurrentSurfaceTexture::Validation => {
                tracing::warn!("surface texture acquisition failed validation");
                return;
            }
        };
        let view = surface_tex
            .texture
            .create_view(&wgpu::TextureViewDescriptor::default());

        // egui: upload changed textures, then buffers (into our encoder).
        for (id, delta) in &textures_delta.set {
            self.egui_renderer
                .update_texture(&self.device, &self.queue, *id, delta);
        }

        let mut encoder = self
            .device
            .create_command_encoder(&wgpu::CommandEncoderDescriptor {
                label: Some("rmd-viewer encoder"),
            });

        let user_cmd_bufs = self.egui_renderer.update_buffers(
            &self.device,
            &self.queue,
            &mut encoder,
            paint_jobs,
            screen,
        );

        // Pass 1: clear + video blit.
        {
            let mut pass = encoder.begin_render_pass(&wgpu::RenderPassDescriptor {
                label: Some("rmd-viewer blit pass"),
                color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                    view: &view,
                    resolve_target: None,
                    depth_slice: None,
                    ops: wgpu::Operations {
                        load: wgpu::LoadOp::Clear(wgpu::Color::BLACK),
                        store: wgpu::StoreOp::Store,
                    },
                })],
                depth_stencil_attachment: None,
                timestamp_writes: None,
                occlusion_query_set: None,
                multiview_mask: None,
            });

            if let Some(frame) = self.frame.as_ref() {
                let uniforms = Uniforms {
                    scale: letterbox_scale(
                        self.config.width,
                        self.config.height,
                        frame.width,
                        frame.height,
                    ),
                    _pad: [0.0, 0.0],
                };
                self.queue
                    .write_buffer(&self.uniform_buf, 0, bytemuck::bytes_of(&uniforms));
                pass.set_pipeline(&self.pipeline);
                pass.set_bind_group(0, &frame.bind_group, &[]);
                pass.draw(0..6, 0..1);
            }
        }

        // Pass 2: egui overlay (load — don't clear the video).
        {
            let mut pass = encoder
                .begin_render_pass(&wgpu::RenderPassDescriptor {
                    label: Some("rmd-viewer egui pass"),
                    color_attachments: &[Some(wgpu::RenderPassColorAttachment {
                        view: &view,
                        resolve_target: None,
                        depth_slice: None,
                        ops: wgpu::Operations {
                            load: wgpu::LoadOp::Load,
                            store: wgpu::StoreOp::Store,
                        },
                    })],
                    depth_stencil_attachment: None,
                    timestamp_writes: None,
                    occlusion_query_set: None,
                    multiview_mask: None,
                })
                .forget_lifetime();
            self.egui_renderer.render(&mut pass, paint_jobs, screen);
        }

        self.queue.submit(
            user_cmd_bufs
                .into_iter()
                .chain(std::iter::once(encoder.finish())),
        );
        surface_tex.present();

        for id in &textures_delta.free {
            self.egui_renderer.free_texture(id);
        }
    }
}

/// Per-axis NDC scale that fits `img` inside `win` while preserving aspect ratio.
fn letterbox_scale(win_w: u32, win_h: u32, img_w: u32, img_h: u32) -> [f32; 2] {
    let win_aspect = win_w as f32 / win_h.max(1) as f32;
    let img_aspect = img_w as f32 / img_h.max(1) as f32;
    if win_aspect > img_aspect {
        [img_aspect / win_aspect, 1.0]
    } else {
        [1.0, win_aspect / img_aspect]
    }
}

// --- Input mapping helpers -------------------------------------------------

/// winit mouse button -> protocol button code (1=Left, 2=Right, 3=Middle).
fn map_mouse_button(button: WinitMouseButton) -> Option<i32> {
    match button {
        WinitMouseButton::Left => Some(1),
        WinitMouseButton::Right => Some(2),
        WinitMouseButton::Middle => Some(3),
        _ => None,
    }
}

/// winit modifier state -> protocol modifier bitmask.
fn map_modifiers(state: winit::keyboard::ModifiersState) -> u32 {
    use proto::modifiers as m;
    let mut bits = 0;
    if state.shift_key() {
        bits |= m::SHIFT;
    }
    if state.control_key() {
        bits |= m::CONTROL;
    }
    if state.alt_key() {
        bits |= m::ALT;
    }
    if state.super_key() {
        bits |= m::META;
    }
    bits
}

/// Map a winit physical [`KeyCode`] to a USB HID usage code (Keyboard page 0x07).
///
/// Covers the common set the host supports: letters, digits, whitespace/edit
/// keys, punctuation, CapsLock, F1-F12, arrows, navigation, and the left/right
/// modifier keys. Unmapped keys return `None` (dropped rather than mis-sent).
fn winit_keycode_to_hid(code: KeyCode) -> Option<u32> {
    use KeyCode as K;
    let hid = match code {
        K::KeyA => 0x04,
        K::KeyB => 0x05,
        K::KeyC => 0x06,
        K::KeyD => 0x07,
        K::KeyE => 0x08,
        K::KeyF => 0x09,
        K::KeyG => 0x0A,
        K::KeyH => 0x0B,
        K::KeyI => 0x0C,
        K::KeyJ => 0x0D,
        K::KeyK => 0x0E,
        K::KeyL => 0x0F,
        K::KeyM => 0x10,
        K::KeyN => 0x11,
        K::KeyO => 0x12,
        K::KeyP => 0x13,
        K::KeyQ => 0x14,
        K::KeyR => 0x15,
        K::KeyS => 0x16,
        K::KeyT => 0x17,
        K::KeyU => 0x18,
        K::KeyV => 0x19,
        K::KeyW => 0x1A,
        K::KeyX => 0x1B,
        K::KeyY => 0x1C,
        K::KeyZ => 0x1D,
        K::Digit1 => 0x1E,
        K::Digit2 => 0x1F,
        K::Digit3 => 0x20,
        K::Digit4 => 0x21,
        K::Digit5 => 0x22,
        K::Digit6 => 0x23,
        K::Digit7 => 0x24,
        K::Digit8 => 0x25,
        K::Digit9 => 0x26,
        K::Digit0 => 0x27,
        K::Enter => 0x28,
        K::Escape => 0x29,
        K::Backspace => 0x2A,
        K::Tab => 0x2B,
        K::Space => 0x2C,
        K::Minus => 0x2D,
        K::Equal => 0x2E,
        K::BracketLeft => 0x2F,
        K::BracketRight => 0x30,
        K::Backslash => 0x31,
        K::Semicolon => 0x33,
        K::Quote => 0x34,
        K::Backquote => 0x35,
        K::Comma => 0x36,
        K::Period => 0x37,
        K::Slash => 0x38,
        K::CapsLock => 0x39,
        K::F1 => 0x3A,
        K::F2 => 0x3B,
        K::F3 => 0x3C,
        K::F4 => 0x3D,
        K::F5 => 0x3E,
        K::F6 => 0x3F,
        K::F7 => 0x40,
        K::F8 => 0x41,
        K::F9 => 0x42,
        K::F10 => 0x43,
        K::F11 => 0x44,
        K::F12 => 0x45,
        K::Home => 0x4A,
        K::PageUp => 0x4B,
        K::Delete => 0x4C,
        K::End => 0x4D,
        K::PageDown => 0x4E,
        K::ArrowRight => 0x4F,
        K::ArrowLeft => 0x50,
        K::ArrowDown => 0x51,
        K::ArrowUp => 0x52,
        K::ControlLeft => 0xE0,
        K::ShiftLeft => 0xE1,
        K::AltLeft => 0xE2,
        K::SuperLeft => 0xE3,
        K::ControlRight => 0xE4,
        K::ShiftRight => 0xE5,
        K::AltRight => 0xE6,
        K::SuperRight => 0xE7,
        _ => return None,
    };
    Some(hid)
}
