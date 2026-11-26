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

use crate::wayland::{PwConnect, pw_run};
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

/// Upper bound on the mutter ScreenCast handshake (CreateSession → Start →
/// first `PipeWireStreamAdded`). If it's exceeded the attempt is abandoned and
/// torn down, rather than blocking the D-Bus thread — and the indicator — forever.
const HANDSHAKE_TIMEOUT_SECS: u64 = 10;

/// Wayland can't enumerate monitors without interaction; the mutter session picks
/// the source. Advertise a single logical display (real size comes from PipeWire
/// format negotiation).
pub fn list_displays() -> anyhow::Result<Vec<DisplayInfo>> {
    Ok(vec![DisplayInfo {
        index: 0,
        width: 0,
        height: 0,
    }])
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
            if let Err(e) = pw_run(
                PwConnect::Default,
                node_id,
                fps,
                width,
                height,
                sink,
                pw_quit_rx,
            ) {
                tracing::error!(error = %e, "PipeWire capture loop ended with error");
            }
        })?;

    tracing::info!(
        virtual_source = want_virtual,
        "GNOME mutter-direct capture started"
    );
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
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready_tx.send(Err(format!("tokio runtime: {e}")));
            return;
        }
    };

    rt.block_on(async move {
        let mut shutdown_rx = shutdown_rx;
        let handshake = async {
            let conn = zbus::Connection::session().await?;

            // CreateSession -> session object path.
            let sess: zbus::zvariant::OwnedObjectPath = conn
                .call_method(
                    Some(DEST),
                    SC_PATH,
                    Some(SC_IFACE),
                    "CreateSession",
                    &(empty_props(),),
                )
                .await?
                .body()
                .deserialize()?;
            let sess = sess.as_str().to_owned();

            // RecordMonitor (dual-use) or RecordVirtual (headless). `cursor-mode`
            // bakes the cursor into the frames (1=embedded) or hides it (0).
            let mut props = HashMap::<&str, Value>::new();
            props.insert("cursor-mode", Value::U32(if show_cursor { 1 } else { 0 }));
            let stream: zbus::zvariant::OwnedObjectPath = if want_virtual {
                conn.call_method(
                    Some(DEST),
                    sess.as_str(),
                    Some(SESSION_IFACE),
                    "RecordVirtual",
                    &(props,),
                )
                .await?
                .body()
                .deserialize()?
            } else {
                let connector = primary_connector(&conn).await.ok_or_else(|| {
                    anyhow::anyhow!(
                        "no monitor connector available to capture — the desktop has no \
                         active display (monitor unplugged / headless boot). Attach a \
                         display, run `rmdd setup-linux --display` to make a connector \
                         survive unplug, or `rmdd set capture_source virtual` to capture a \
                         headless virtual monitor instead."
                    )
                })?;
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
            let stream_proxy = zbus::Proxy::new(&conn, DEST, stream.as_str(), STREAM_IFACE).await?;
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
        };

        // Race the handshake against a timeout AND an early shutdown. Without the
        // timeout, a stream that never emits `PipeWireStreamAdded` would block
        // this thread forever — so `Session.Stop` never runs and the "screen is
        // being shared" indicator stays lit after the peer is gone (B2). On
        // either non-completion path the handshake future is dropped, which drops
        // its D-Bus connection; the mutter session is bound to that connection, so
        // dropping it tears the (partial) session down.
        let handshake = tokio::select! {
            biased;
            _ = &mut shutdown_rx => {
                tracing::debug!("mutter: shutdown requested during handshake");
                return;
            }
            _ = tokio::time::sleep(std::time::Duration::from_secs(HANDSHAKE_TIMEOUT_SECS)) => {
                let _ = ready_tx.send(Err(format!(
                    "mutter ScreenCast handshake timed out after {HANDSHAKE_TIMEOUT_SECS}s \
                     (no PipeWireStreamAdded)"
                )));
                return;
            }
            r = handshake => r,
        };

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

/// Whether mutter's private ScreenCast bus name currently has an owner.
///
/// Cheap synchronous pre-flight so the caller can fall back to the
/// xdg-desktop-portal backend when the private API is unavailable (e.g. a
/// non-GNOME session mis-detected as GNOME, or `org.gnome.Mutter.ScreenCast`
/// disabled) instead of starting a capture that can never hand back a stream.
pub(crate) fn screencast_available() -> bool {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        rt.block_on(async {
            let conn = zbus::Connection::session().await.ok()?;
            let reply = conn
                .call_method(
                    Some("org.freedesktop.DBus"),
                    "/org/freedesktop/DBus",
                    Some("org.freedesktop.DBus"),
                    "NameHasOwner",
                    &(DEST,),
                )
                .await
                .ok()?;
            reply.body().deserialize::<bool>().ok()
        })
    })
    .join()
    .ok()
    .flatten()
    .unwrap_or(false)
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

// `org.gnome.Mutter.DisplayConfig.GetCurrentState` reply signature:
//   (u  a((ssss)a(siiddada{sv})a{sv})  a(iiduba(ssss)a{sv})  a{sv})
type MonId = (String, String, String, String);
type Mode = (
    String,
    i32,
    i32,
    f64,
    f64,
    Vec<f64>,
    HashMap<String, OwnedValue>,
);
type Monitor = (MonId, Vec<Mode>, HashMap<String, OwnedValue>);
type Logical = (
    i32,
    i32,
    f64,
    u32,
    bool,
    Vec<MonId>,
    HashMap<String, OwnedValue>,
);
type DisplayState = (u32, Vec<Monitor>, Vec<Logical>, HashMap<String, OwnedValue>);

async fn get_current_state(conn: &zbus::Connection) -> Option<DisplayState> {
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
    reply.body().deserialize().ok()
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

    let state = get_current_state(conn).await?;

    // Prefer the connector of the primary logical monitor; else the first monitor.
    if let Some(primary) = state.2.iter().find(|l| l.4) {
        if let Some(id) = primary.5.first() {
            return Some(id.0.clone());
        }
    }
    state.1.first().map(|m| (m.0).0.clone())
}

/// The captured output's rect within the desktop bounding box (logical pixels),
/// for multi-monitor absolute-pointer mapping. Blocking wrapper for the sync
/// host thread: runs a one-shot D-Bus query on a throwaway current-thread
/// runtime (its own thread, so it never nests inside an existing runtime).
pub(crate) fn primary_monitor_rect_blocking() -> Option<crate::MonitorRect> {
    std::thread::spawn(|| {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        rt.block_on(async {
            let conn = zbus::Connection::session().await.ok()?;
            compute_monitor_rect(&conn).await
        })
    })
    .join()
    .ok()
    .flatten()
}

/// Compute the captured output's rect within the desktop bounding box from
/// `GetCurrentState`. All geometry is in **logical** coordinates (post-scaling),
/// matching the space libinput uses to map an absolute device across the desktop.
async fn compute_monitor_rect(conn: &zbus::Connection) -> Option<crate::MonitorRect> {
    let state = get_current_state(conn).await?;
    if state.2.is_empty() {
        return None;
    }

    // Pixel size of a monitor's current mode (the mode flagged `is-current`,
    // else its first/preferred mode).
    let mode_px = |mon_id: &MonId| -> Option<(f64, f64)> {
        let m = state.1.iter().find(|mm| &mm.0 == mon_id)?;
        let cur =
            m.1.iter()
                .find(|md| {
                    md.6.get("is-current")
                        .and_then(|v| bool::try_from(v).ok())
                        .unwrap_or(false)
                })
                .or_else(|| m.1.first())?;
        Some((cur.1 as f64, cur.2 as f64))
    };

    // Logical rect (x, y, w, h) + primary flag + connector for each logical monitor.
    struct LRect {
        x: f64,
        y: f64,
        w: f64,
        h: f64,
        primary: bool,
        connector: Option<String>,
    }
    let mut rects: Vec<LRect> = Vec::with_capacity(state.2.len());
    for l in &state.2 {
        let (x, y, scale, transform, primary) = (l.0 as f64, l.1 as f64, l.2, l.3, l.4);
        let mon_id = l.5.first();
        let connector = mon_id.map(|id| id.0.clone());
        let (pw, ph) = mon_id.and_then(mode_px).unwrap_or((0.0, 0.0));
        // Logical size = pixels / scale; a 90/270° rotation swaps the axes.
        let (mut w, mut h) = (pw / scale, ph / scale);
        if matches!(transform, 1 | 3 | 5 | 7) {
            std::mem::swap(&mut w, &mut h);
        }
        rects.push(LRect {
            x,
            y,
            w,
            h,
            primary,
            connector,
        });
    }

    // Desktop bounding box (union of all logical monitor rects).
    let min_x = rects.iter().map(|r| r.x).fold(f64::INFINITY, f64::min);
    let min_y = rects.iter().map(|r| r.y).fold(f64::INFINITY, f64::min);
    let max_x = rects
        .iter()
        .map(|r| r.x + r.w)
        .fold(f64::NEG_INFINITY, f64::max);
    let max_y = rects
        .iter()
        .map(|r| r.y + r.h)
        .fold(f64::NEG_INFINITY, f64::max);
    let dw = max_x - min_x;
    let dh = max_y - min_y;
    if !(dw.is_finite() && dh.is_finite() && dw > 0.0 && dh > 0.0) {
        return None;
    }

    // Pick the captured output — same precedence as `primary_connector`:
    // env override → primary logical monitor → first.
    let want = std::env::var("RMD_MONITOR_CONNECTOR")
        .ok()
        .filter(|s| !s.is_empty());
    let target = want
        .as_deref()
        .and_then(|w| rects.iter().find(|r| r.connector.as_deref() == Some(w)))
        .or_else(|| rects.iter().find(|r| r.primary))
        .or_else(|| rects.first())?;
    if !(target.w > 0.0 && target.h > 0.0) {
        return None;
    }

    Some(crate::MonitorRect {
        ox: target.x - min_x,
        oy: target.y - min_y,
        mw: target.w,
        mh: target.h,
        dw,
        dh,
    })
}
