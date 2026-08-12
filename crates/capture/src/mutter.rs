//! GNOME Wayland screen capture via mutter's **private** ScreenCast D-Bus API
//! (`org.gnome.Mutter.ScreenCast`) — the same interface `gnome-remote-desktop`
//! uses.
//!
//! Why not the xdg-desktop-portal (see [`crate::wayland`])? On GNOME the portal
//! shows a consent prompt every session and leaks the ScreenCast session so the
//! "screen is being shared" indicator stays lit after disconnect (mutter/portal
//! bug: `Session.Close` isn't honored). Talking to mutter directly avoids both:
//! there is **no consent prompt**, and the session is bound to our D-Bus
//! connection — calling `Session.Stop` (or dropping the connection) tears it down
//! cleanly, so the indicator reflects reality (on only while connected).
//!
//! Flow, on one persistent connection: `CreateSession` → `RecordMonitor`
//! (dual-use) or `RecordVirtual` (headless) → subscribe `PipeWireStreamAdded` →
//! `Start` → node id. mutter exposes no `OpenPipeWireRemote`, so we connect to the
//! session's default PipeWire socket and reuse [`crate::wayland::pw_run`] with
//! that node id. GNOME-only; other compositors use the portal backend.

use crate::wayland::{pw_run, PwConnect};
use crate::{CaptureConfig, CaptureSession, CaptureSource, DisplayInfo, FrameSink};
use futures_util::StreamExt;
use pipewire as pw;
use std::collections::HashMap;
use std::thread::JoinHandle;
use zbus::zvariant::{OwnedValue, Value};

const DEST: &str = "org.gnome.Mutter.ScreenCast";
const SC_PATH: &str = "/org/gnome/Mutter/ScreenCast";
const SC_IFACE: &str = "org.gnome.Mutter.ScreenCast";
const SESSION_IFACE: &str = "org.gnome.Mutter.ScreenCast.Session";
const STREAM_IFACE: &str = "org.gnome.Mutter.ScreenCast.Stream";

/// Wayland can't enumerate monitors without interaction; the mutter session picks
/// the source. Advertise a single logical display (real size comes from PipeWire
/// format negotiation).
pub fn list_displays() -> anyhow::Result<Vec<DisplayInfo>> {
    Ok(vec![DisplayInfo { index: 0, width: 0, height: 0 }])
}

/// A running mutter-direct capture. Dropping (or [`stop`](CaptureSession::stop))
/// signals both threads; the D-Bus thread calls `Session.Stop` for clean teardown.
pub struct MutterCaptureSession {
    pw_quit: pw::channel::Sender<()>,
    shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    pw_thread: Option<JoinHandle<()>>,
    dbus_thread: Option<JoinHandle<()>>,
}

impl CaptureSession for MutterCaptureSession {
    fn stop(self: Box<Self>) {
        // Drop does the work.
    }
}

impl Drop for MutterCaptureSession {
    fn drop(&mut self) {
        // Signal both threads; the D-Bus thread's `shutdown` await then calls
        // Session.Stop (clean teardown / indicator off). Detach, don't join —
        // mirroring the portal backend, to never wedge the session thread.
        let _ = self.pw_quit.send(());
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        self.pw_thread.take();
        self.dbus_thread.take();
    }
}

/// Start GNOME mutter-direct capture. Non-blocking: the D-Bus handshake and the
/// PipeWire stream run on background threads (no consent dialog to wait on).
pub fn start_capture(
    config: CaptureConfig,
    _display_index: usize,
    sink: FrameSink,
) -> anyhow::Result<Box<dyn CaptureSession>> {
    let want_virtual = matches!(config.capture_source, CaptureSource::Virtual);
    let show_cursor = config.show_cursor;
    let fps = config.fps.max(1);
    let width = config.width.max(1);
    let height = config.height.max(1);

    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<u32, String>>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();

    let dbus_thread = std::thread::Builder::new()
        .name("rmd-mutter".into())
        .spawn(move || dbus_thread_main(want_virtual, show_cursor, ready_tx, shutdown_rx))?;

    let (pw_quit, pw_quit_rx) = pw::channel::channel::<()>();
    let pw_thread = std::thread::Builder::new()
        .name("rmd-pw-capture".into())
        .spawn(move || {
            let node_id = match ready_rx.recv() {
                Ok(Ok(n)) => n,
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "mutter ScreenCast setup failed");
                    return;
                }
                Err(_) => return, // dbus thread gone
            };
            tracing::info!(node_id, "mutter-direct capture streaming");
            if let Err(e) = pw_run(PwConnect::Default, node_id, fps, width, height, sink, pw_quit_rx) {
                tracing::error!(error = %e, "PipeWire capture loop ended with error");
            }
        })?;

    tracing::info!(virtual_source = want_virtual, "GNOME mutter-direct capture started");
    Ok(Box::new(MutterCaptureSession {
        pw_quit,
        shutdown: Some(shutdown_tx),
        pw_thread: Some(pw_thread),
        dbus_thread: Some(dbus_thread),
    }))
}

/// D-Bus thread: drive the mutter ScreenCast handshake on a current-thread tokio
/// runtime over ONE connection, hand the PipeWire node id back, keep the session
/// alive until shutdown, then explicitly `Session.Stop` (clean teardown).
fn dbus_thread_main(
    want_virtual: bool,
    show_cursor: bool,
    ready_tx: std::sync::mpsc::Sender<Result<u32, String>>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready_tx.send(Err(format!("tokio runtime: {e}")));
            return;
        }
    };

    rt.block_on(async move {
        let handshake = async {
            let conn = zbus::Connection::session().await?;

            // CreateSession -> session object path.
            let sess: zbus::zvariant::OwnedObjectPath = conn
                .call_method(Some(DEST), SC_PATH, Some(SC_IFACE), "CreateSession", &(empty_props(),))
                .await?
                .body()
                .deserialize()?;
            let sess = sess.as_str().to_owned();

            // RecordMonitor (dual-use) or RecordVirtual (headless). `cursor-mode`
            // bakes the cursor into the frames (1=embedded) or hides it (0).
            let mut props = HashMap::<&str, Value>::new();
            props.insert("cursor-mode", Value::U32(if show_cursor { 1 } else { 0 }));
            let stream: zbus::zvariant::OwnedObjectPath = if want_virtual {
                conn.call_method(Some(DEST), sess.as_str(), Some(SESSION_IFACE), "RecordVirtual", &(props,))
                    .await?
                    .body()
                    .deserialize()?
            } else {
                let connector = primary_connector(&conn)
                    .await
                    .ok_or_else(|| anyhow::anyhow!("could not determine a monitor connector"))?;
                conn.call_method(
                    Some(DEST),
                    sess.as_str(),
                    Some(SESSION_IFACE),
                    "RecordMonitor",
                    &(connector, props),
                )
                .await?
                .body()
                .deserialize()?
            };
            let stream = stream.as_str().to_owned();

            // Subscribe to PipeWireStreamAdded BEFORE Start so we don't miss it.
            let stream_proxy =
                zbus::Proxy::new(&conn, DEST, stream.as_str(), STREAM_IFACE).await?;
            let mut added = stream_proxy.receive_signal("PipeWireStreamAdded").await?;

            conn.call_method(Some(DEST), sess.as_str(), Some(SESSION_IFACE), "Start", &())
                .await?;

            let node_id: u32 = added
                .next()
                .await
                .ok_or_else(|| anyhow::anyhow!("PipeWireStreamAdded never arrived"))?
                .body()
                .deserialize()?;

            anyhow::Ok((conn, sess, node_id))
        }
        .await;

        match handshake {
            Ok((conn, sess, node_id)) => {
                if ready_tx.send(Ok(node_id)).is_err() {
                    stop_session(&conn, &sess).await;
                    return;
                }
                // Hold the session (and its connection) open until told to stop,
                // then explicitly Stop it so mutter tears it down and the indicator
                // clears — dropping alone is not enough.
                let _ = shutdown_rx.await;
                stop_session(&conn, &sess).await;
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e.to_string()));
            }
        }
    });
}

async fn stop_session(conn: &zbus::Connection, sess: &str) {
    if let Err(e) = conn
        .call_method(Some(DEST), sess, Some(SESSION_IFACE), "Stop", &())
        .await
    {
        tracing::debug!(error = %e, "mutter Session.Stop failed (already gone?)");
    }
}

fn empty_props() -> HashMap<&'static str, Value<'static>> {
    HashMap::new()
}

/// The primary monitor's mutter connector name (e.g. `HDMI-2`), for
/// `RecordMonitor`. Honors `RMD_MONITOR_CONNECTOR` as an override/escape hatch;
/// otherwise reads `org.gnome.Mutter.DisplayConfig.GetCurrentState`.
async fn primary_connector(conn: &zbus::Connection) -> Option<String> {
    if let Ok(c) = std::env::var("RMD_MONITOR_CONNECTOR") {
        if !c.is_empty() {
            return Some(c);
        }
    }

    // GetCurrentState signature:
    //   (u  a((ssss)a(siiddada{sv})a{sv})  a(iiduba(ssss)a{sv})  a{sv})
    type MonId = (String, String, String, String);
    type Mode = (String, i32, i32, f64, f64, Vec<f64>, HashMap<String, OwnedValue>);
    type Monitor = (MonId, Vec<Mode>, HashMap<String, OwnedValue>);
    type Logical = (i32, i32, f64, u32, bool, Vec<MonId>, HashMap<String, OwnedValue>);
    type State = (u32, Vec<Monitor>, Vec<Logical>, HashMap<String, OwnedValue>);

    let reply = conn
        .call_method(
            Some("org.gnome.Mutter.DisplayConfig"),
            "/org/gnome/Mutter/DisplayConfig",
            Some("org.gnome.Mutter.DisplayConfig"),
            "GetCurrentState",
            &(),
        )
        .await
        .ok()?;
    let state: State = reply.body().deserialize().ok()?;

    // Prefer the connector of the primary logical monitor; else the first monitor.
    if let Some(primary) = state.2.iter().find(|l| l.4) {
        if let Some(id) = primary.5.first() {
            return Some(id.0.clone());
        }
    }
    state.1.first().map(|m| (m.0).0.clone())
}
