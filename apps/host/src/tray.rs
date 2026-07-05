//! Optional desktop tray companion for the host (feature `tray`).
//!
//! Shows a menu-bar / system-tray icon reflecting session state — grey when
//! waiting, green when a remote is connected — with a **Quit** item. The session
//! ([`run_host_reporting`]) runs on a background thread and reports state over a
//! channel; the tray owns the main thread (required on macOS) and runs a minimal
//! winit event loop to pump tray/menu events.
//!
//! Headless/server hosts simply don't build this feature and run
//! [`rmd_session::run_host`] directly.

use rmd_session::{run_host_reporting, HostConfig, HostStatus, Signaling};
use std::sync::mpsc::{self, Receiver};
use std::time::{Duration, Instant};
use tray_icon::menu::{Menu, MenuEvent, MenuItem};
use tray_icon::{Icon, TrayIcon, TrayIconBuilder};
use winit::application::ApplicationHandler;
use winit::event::StartCause;
use winit::event_loop::{ActiveEventLoop, ControlFlow, EventLoop};
use winit::window::WindowId;

/// Run the host with a tray companion. Blocks until the tray is quit or the
/// session ends. Returns any error from the session thread.
pub fn run_with_tray(cfg: HostConfig, signal: Box<dyn Signaling>) -> anyhow::Result<()> {
    // Session on a background thread; state flows back over `status_rx`.
    let (status_tx, status_rx) = mpsc::channel::<HostStatus>();
    let (done_tx, done_rx) = mpsc::channel::<anyhow::Result<()>>();
    std::thread::Builder::new()
        .name("rmd-host-session".into())
        .spawn(move || {
            let result = run_host_reporting(cfg, signal, move |s| {
                let _ = status_tx.send(s);
            });
            let _ = done_tx.send(result);
        })?;

    let event_loop = EventLoop::new()?;
    event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + POLL));
    let mut app = TrayApp {
        tray: None,
        quit_id: None,
        status_rx,
        done_rx,
        result: Ok(()),
    };
    event_loop.run_app(&mut app)?;
    // Surface a session error if one ended the loop.
    std::mem::replace(&mut app.result, Ok(()))
}

/// Tray poll cadence.
const POLL: Duration = Duration::from_millis(200);

struct TrayApp {
    tray: Option<TrayIcon>,
    quit_id: Option<tray_icon::menu::MenuId>,
    status_rx: Receiver<HostStatus>,
    done_rx: Receiver<anyhow::Result<()>>,
    result: anyhow::Result<()>,
}

impl TrayApp {
    fn build_tray(&mut self) {
        let quit = MenuItem::new("Quit ReachMyDevice host", true, None);
        self.quit_id = Some(quit.id().clone());
        let menu = Menu::new();
        let _ = menu.append(&quit);
        match TrayIconBuilder::new()
            .with_menu(Box::new(menu))
            .with_tooltip("ReachMyDevice host — waiting")
            .with_icon(status_icon(HostStatus::Waiting))
            .build()
        {
            Ok(t) => self.tray = Some(t),
            Err(e) => tracing::warn!(error=%e, "failed to create tray icon"),
        }
    }

    fn apply_status(&self, status: HostStatus) {
        let Some(tray) = self.tray.as_ref() else {
            return;
        };
        let tip = match status {
            HostStatus::Active => "ReachMyDevice host — ● remote connected",
            HostStatus::Waiting | HostStatus::Ended => "ReachMyDevice host — waiting",
        };
        let _ = tray.set_tooltip(Some(tip));
        let _ = tray.set_icon(Some(status_icon(status)));
    }
}

impl ApplicationHandler for TrayApp {
    fn new_events(&mut self, event_loop: &ActiveEventLoop, cause: StartCause) {
        if cause == StartCause::Init {
            // Tray must be created once the event loop is live (macOS main thread).
            self.build_tray();
        }

        // Drain session status → tray.
        while let Ok(status) = self.status_rx.try_recv() {
            self.apply_status(status);
        }
        // Session ended (error or clean) → exit.
        if let Ok(result) = self.done_rx.try_recv() {
            self.result = result;
            event_loop.exit();
        }
        // Quit menu clicked?
        while let Ok(ev) = MenuEvent::receiver().try_recv() {
            if self.quit_id.as_ref() == Some(&ev.id) {
                tracing::info!("tray: quit requested");
                event_loop.exit();
            }
        }
        event_loop.set_control_flow(ControlFlow::WaitUntil(Instant::now() + POLL));
    }

    // No windows — the tray needs no per-window events.
    fn resumed(&mut self, _event_loop: &ActiveEventLoop) {}
    fn window_event(
        &mut self,
        _event_loop: &ActiveEventLoop,
        _id: WindowId,
        _event: winit::event::WindowEvent,
    ) {
    }
}

/// A simple 32×32 RGBA dot: green when active, grey otherwise.
fn status_icon(status: HostStatus) -> Icon {
    const N: u32 = 32;
    let (r, g, b) = match status {
        HostStatus::Active => (60u8, 200, 90),
        HostStatus::Waiting | HostStatus::Ended => (150, 150, 150),
    };
    let mut rgba = vec![0u8; (N * N * 4) as usize];
    let c = (N as f32 - 1.0) / 2.0;
    let radius = c - 1.0;
    for y in 0..N {
        for x in 0..N {
            let dx = x as f32 - c;
            let dy = y as f32 - c;
            let inside = dx * dx + dy * dy <= radius * radius;
            let i = ((y * N + x) * 4) as usize;
            if inside {
                rgba[i] = r;
                rgba[i + 1] = g;
                rgba[i + 2] = b;
                rgba[i + 3] = 255;
            }
        }
    }
    Icon::from_rgba(rgba, N, N).expect("build tray icon")
}
