//! Wayland screen capture via xdg-desktop-portal ScreenCast + PipeWire.
//!
//! On a real Wayland session there is no grabbable X11 root window (XWayland runs
//! rootless — `XGetImage` on the root fails `BadMatch`), so the X11 backend in
//! [`crate::linux`] cannot see the desktop. This backend instead asks the
//! compositor for frames the sanctioned way:
//!
//! 1. **Portal handshake** ([`ashpd`], async/tokio): open the `ScreenCast`
//!    portal, create a session, `select_sources` (monitor), and `start` it. The
//!    compositor shows a one-time "share your screen" consent dialog. On success
//!    we get a PipeWire node id and a file descriptor to the PipeWire remote.
//! 2. **PipeWire stream** ([`pipewire`]): connect to that fd, negotiate a
//!    `video/raw` format (we ask for BGRA/BGRx/RGBA/RGBx, CPU-mapped buffers),
//!    and copy each frame into a BGRA [`Frame`] for the codec.
//!
//! Threads: the portal session must stay alive for the capture's lifetime, so a
//! dedicated "portal" thread owns a current-thread tokio runtime and parks on a
//! shutdown signal (dropping the session closes the portal). A second "pw"
//! thread owns the PipeWire main loop. Stopping the session signals both.

use crate::{CaptureConfig, CaptureSession, CaptureSource, DisplayInfo, Frame, FrameSink, PixelFormat};
use bytes::Bytes;
use std::sync::{Arc, Mutex};
use pipewire as pw;
use pw::spa;
use rmd_protocol::monotonic_micros;
use spa::pod::Pod;
use std::os::fd::OwnedFd;
use std::thread::JoinHandle;

/// The portal handshake result handed from the portal thread to the PipeWire
/// thread: the PipeWire remote fd, the stream's node id, and an optional restore
/// token to persist for next time.
type PortalReady = Result<(OwnedFd, u32, Option<String>), String>;

/// Wayland can't enumerate monitors without user interaction (the portal picks
/// the source via its dialog), so advertise a single logical display. The real
/// resolution is discovered during PipeWire format negotiation.
pub fn list_displays() -> anyhow::Result<Vec<DisplayInfo>> {
    Ok(vec![DisplayInfo { index: 0, width: 0, height: 0 }])
}

/// A running Wayland capture. Dropping (or [`stop`](CaptureSession::stop)) tears
/// down the PipeWire loop and closes the portal session.
pub struct WaylandCaptureSession {
    /// Fires the PipeWire main loop's quit (attached to its loop, thread-safe).
    pw_quit: pw::channel::Sender<()>,
    /// Drops the portal session on the portal thread (closes the ScreenCast).
    portal_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    pw_thread: Option<JoinHandle<()>>,
    portal_thread: Option<JoinHandle<()>>,
    /// Restore token the portal issued for this grant; filled by the PipeWire
    /// thread once the background handshake resolves, read back for persistence.
    restore_token: Arc<Mutex<Option<String>>>,
}

impl CaptureSession for WaylandCaptureSession {
    fn stop(self: Box<Self>) {
        // Drop does the work (see below).
    }

    fn restore_token(&self) -> Option<String> {
        // Poison-tolerant: a panicked writer thread must not take this down.
        self.restore_token
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .clone()
    }
}

impl Drop for WaylandCaptureSession {
    fn drop(&mut self) {
        // Signal both background threads to stop, but do NOT join them. This Drop
        // runs on the session thread; joining a portal handshake still waiting on
        // the compositor would block the session and wedge reconnects. Detach and
        // let the threads exit on their own once the signals land.
        let _ = self.pw_quit.send(());
        if let Some(tx) = self.portal_shutdown.take() {
            let _ = tx.send(());
        }
        self.pw_thread.take();
        self.portal_thread.take();
    }
}

/// Start capturing the Wayland desktop. Returns **immediately** — the portal
/// handshake (which may show a one-time consent dialog, or re-grant silently from
/// a stored token) and the PipeWire stream run on background threads. Making this
/// non-blocking is the fix for reconnects hanging: a slow or interactive portal
/// can no longer wedge the caller (the session handshake). Frames simply start
/// flowing once the grant resolves.
pub fn start_capture(
    config: CaptureConfig,
    _display_index: usize,
    sink: FrameSink,
) -> anyhow::Result<Box<dyn CaptureSession>> {
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<PortalReady>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let show_cursor = config.show_cursor;
    let restore_token_in = config.restore_token.clone();
    let want_virtual = matches!(config.capture_source, CaptureSource::Virtual);
    let fps = config.fps.max(1);
    // Preferred capture size. For a VIRTUAL source this also sizes the virtual
    // monitor the compositor creates, so it matches the configured resolution
    // instead of the format default.
    let width = config.width.max(1);
    let height = config.height.max(1);

    let portal_thread = std::thread::Builder::new()
        .name("rmd-portal".into())
        .spawn(move || {
            portal_thread_main(show_cursor, want_virtual, restore_token_in, ready_tx, shutdown_rx)
        })?;

    let (pw_quit, pw_quit_rx) = pw::channel::channel::<()>();
    let restore_token: Arc<Mutex<Option<String>>> = Arc::new(Mutex::new(None));
    let restore_token_bg = restore_token.clone();

    // The PipeWire thread waits for the portal handshake result, THEN streams.
    // Doing that wait here (off the caller's thread) is what keeps start_capture
    // non-blocking.
    let pw_thread = std::thread::Builder::new()
        .name("rmd-pw-capture".into())
        .spawn(move || {
            let (fd, node_id, token) = match ready_rx.recv() {
                Ok(Ok(v)) => v,
                Ok(Err(e)) => {
                    tracing::error!(error = %e, "Wayland ScreenCast portal failed");
                    return;
                }
                Err(_) => return, // portal thread gone before handshake
            };
            if token.is_some() {
                *restore_token_bg.lock().unwrap_or_else(|e| e.into_inner()) = token;
            }
            tracing::info!(node_id, "Wayland PipeWire capture streaming");
            if let Err(e) = pw_run(PwConnect::Fd(fd), node_id, fps, width, height, sink, pw_quit_rx) {
                tracing::error!(error = %e, "PipeWire capture loop ended with error");
            }
        })?;

    Ok(Box::new(WaylandCaptureSession {
        pw_quit,
        portal_shutdown: Some(shutdown_tx),
        pw_thread: Some(pw_thread),
        portal_thread: Some(portal_thread),
        restore_token,
    }))
}

/// Portal thread: drive the async ScreenCast handshake on a current-thread tokio
/// runtime, hand the (fd, node id) back, then keep the session alive until told
/// to shut down. `proxy` and `session` must stay in scope together — the session
/// borrows the proxy, and dropping either closes the portal stream.
fn portal_thread_main(
    show_cursor: bool,
    want_virtual: bool,
    restore_token_in: Option<String>,
    ready_tx: std::sync::mpsc::Sender<PortalReady>,
    shutdown_rx: tokio::sync::oneshot::Receiver<()>,
) {
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            let _ = ready_tx.send(Err(format!("failed to build tokio runtime: {e}")));
            return;
        }
    };

    rt.block_on(async move {
        use ashpd::desktop::screencast::{CursorMode, Screencast, SourceType};
        use ashpd::desktop::PersistMode;
        use ashpd::WindowIdentifier;

        // Create the proxy + session up front so we hold a handle we can always
        // Close on error. If `select_sources`/`start` fail *after* the session
        // exists, letting it drop would leak a lit portal session — mutter doesn't
        // forward the Closed signal (xdg-desktop-portal#508), so we must Close it
        // ourselves on every path (H3).
        let (proxy, session) = match async {
            let proxy = Screencast::new().await?;
            let session = proxy.create_session().await?;
            anyhow::Ok((proxy, session))
        }
        .await
        {
            Ok(v) => v,
            Err(e) => {
                let _ = ready_tx.send(Err(e.to_string()));
                return;
            }
        };

        let handshake = async {
            let cursor = if show_cursor { CursorMode::Embedded } else { CursorMode::Hidden };
            // Pick the source per config. `Monitor` (default) captures the real
            // display — shown locally and remotely (dual-use) — but dies if the
            // monitor is unplugged. `Virtual` asks the compositor for a virtual
            // monitor that survives with no physical display (headless), the
            // Wayland equivalent of an Xvfb framebuffer. Virtual falls back to
            // Monitor if the portal can't provide it.
            let source = if want_virtual {
                let avail = proxy
                    .available_source_types()
                    .await
                    .unwrap_or_else(|_| SourceType::Monitor.into());
                if avail.contains(SourceType::Virtual) {
                    SourceType::Virtual
                } else {
                    SourceType::Monitor
                }
            } else {
                SourceType::Monitor
            };
            tracing::info!(
                source = if matches!(source, SourceType::Virtual) { "virtual" } else { "monitor" },
                "selecting Wayland ScreenCast source"
            );
            proxy
                .select_sources(
                    &session,
                    cursor,
                    source.into(),
                    false,                        // single source
                    restore_token_in.as_deref(), // reuse this run's grant if we have one
                    // Persist the approval only while rmdd runs (NOT ExplicitlyRevoked,
                    // which leaves a permanent session mutter keeps alive across
                    // restarts — the lingering "screen is being shared" indicator).
                    // Application scope: approve once per service run via the dialog's
                    // "remember" checkbox, sessions close cleanly on disconnect, and
                    // nothing survives an rmdd stop. Re-approve after a restart/reboot.
                    PersistMode::Application,
                )
                .await?;
            let streams = proxy
                .start(&session, &WindowIdentifier::default())
                .await?
                .response()?;
            // The portal may hand back a fresh restore token (rotated on each use)
            // to persist for next time.
            let restore_token_out = streams.restore_token().map(str::to_string);
            let stream = streams
                .streams()
                .first()
                .ok_or_else(|| anyhow::anyhow!("portal returned no streams"))?;
            let node_id = stream.pipe_wire_node_id();
            let fd = proxy.open_pipe_wire_remote(&session).await?;
            anyhow::Ok((fd, node_id, restore_token_out))
        }
        .await;

        match handshake {
            Ok((fd, node_id, restore_token_out)) => {
                if ready_tx.send(Ok((fd, node_id, restore_token_out))).is_err() {
                    let _ = session.close().await; // caller gave up — still close cleanly
                    return;
                }
                // Keep proxy/session alive until shutdown, THEN explicitly Close the
                // portal session. Dropping it does NOT close it: mutter keeps the
                // ScreenCast/RemoteDesktop session (and the "screen is being shared"
                // indicator) alive and can refuse new sessions — the Closed signal
                // isn't forwarded to clients (xdg-desktop-portal#508). So we must
                // send Close ourselves on teardown.
                let _ = shutdown_rx.await;
                let _ = session.close().await;
            }
            Err(e) => {
                // The session exists (created above) but select_sources/start
                // failed — Close it so we don't leak a lit portal session.
                let _ = session.close().await;
                let _ = ready_tx.send(Err(e.to_string()));
            }
        }
        // `proxy` is held to here so the session stays valid for Close.
        drop(proxy);
    });
}

/// User data shared with the PipeWire stream callbacks.
struct StreamData {
    format: spa::param::video::VideoInfoRaw,
    sink: FrameSink,
}

/// How the PipeWire thread reaches the daemon. The xdg portal hands us a
/// restricted remote fd (`open_pipe_wire_remote`); mutter's direct ScreenCast API
/// gives only a node id, so we connect to the session's default PipeWire socket.
pub(crate) enum PwConnect {
    /// Connect to the portal's remote via this fd (`context.connect_fd`).
    Fd(OwnedFd),
    /// Connect to the default session PipeWire socket (`context.connect`).
    Default,
}

/// PipeWire thread: connect (portal fd or default socket), attach a stream to
/// `node_id`, and pump frames into `sink` until `quit_rx` fires. Shared by the
/// portal ([`start_capture`]) and mutter-direct ([`crate::mutter`]) backends.
pub(crate) fn pw_run(
    conn: PwConnect,
    node_id: u32,
    fps: u32,
    width: u32,
    height: u32,
    sink: FrameSink,
    quit_rx: pw::channel::Receiver<()>,
) -> anyhow::Result<()> {
    pw::init();

    let mainloop = pw::main_loop::MainLoop::new(None)?;
    let context = pw::context::Context::new(&mainloop)?;
    let core = match conn {
        PwConnect::Fd(fd) => context.connect_fd(fd, None)?,
        PwConnect::Default => context.connect(None)?,
    };

    let stream = pw::stream::Stream::new(
        &core,
        "rmd-screencast",
        pw::properties::properties! {
            *pw::keys::MEDIA_TYPE => "Video",
            *pw::keys::MEDIA_CATEGORY => "Capture",
            *pw::keys::MEDIA_ROLE => "Screen",
        },
    )?;

    let data = StreamData { format: Default::default(), sink };

    // Clones so the stream callbacks (which run on the loop thread) can stop the
    // loop: on a fatal stream Error or a mid-session disconnect (B3), and when
    // the frame sink is closed (M7cap).
    let ml_state = mainloop.clone();
    let ml_proc = mainloop.clone();
    // Whether we've reached Streaming at least once, so a later `Unconnected`
    // (node removed — e.g. monitor unplugged) is distinguished from the benign
    // initial Unconnected before connect.
    let streaming = std::rc::Rc::new(std::cell::Cell::new(false));

    let _listener = stream
        .add_local_listener_with_user_data(data)
        .state_changed(move |_, _, old, new| {
            tracing::debug!(?old, ?new, "PipeWire stream state changed");
            match &new {
                pw::stream::StreamState::Streaming => streaming.set(true),
                pw::stream::StreamState::Error(e) => {
                    tracing::warn!(error = %e, "PipeWire stream entered Error; stopping capture");
                    ml_state.quit();
                }
                pw::stream::StreamState::Unconnected if streaming.get() => {
                    tracing::warn!("PipeWire stream disconnected mid-session (source removed?); stopping capture");
                    ml_state.quit();
                }
                _ => {}
            }
        })
        .param_changed(|_, user, id, param| {
            let Some(param) = param else { return };
            if id != pw::spa::param::ParamType::Format.as_raw() {
                return;
            }
            let Ok((media_type, media_subtype)) =
                pw::spa::param::format_utils::parse_format(param)
            else {
                return;
            };
            if media_type != pw::spa::param::format::MediaType::Video
                || media_subtype != pw::spa::param::format::MediaSubtype::Raw
            {
                return;
            }
            if user.format.parse(param).is_err() {
                tracing::warn!("failed to parse negotiated video format");
                return;
            }
            tracing::info!(
                width = user.format.size().width,
                height = user.format.size().height,
                format = ?user.format.format(),
                "PipeWire negotiated video format",
            );
        })
        .process(move |stream, user| {
            let Some(mut buffer) = stream.dequeue_buffer() else { return };
            let datas = buffer.datas_mut();
            let Some(data) = datas.first_mut() else { return };

            // Read chunk geometry before borrowing the pixel slice mutably.
            let chunk = data.chunk();
            let stride = chunk.stride().max(0) as usize;
            let size = chunk.size() as usize;
            let offset = chunk.offset() as usize;
            if size == 0 {
                return;
            }
            let width = user.format.size().width;
            let height = user.format.size().height;
            let vfmt = user.format.format();

            let Some(bytes) = data.data() else { return }; // DmaBuf (unmapped) -> skip
            let Some(frame) = to_bgra_frame(bytes, offset, stride, width, height, vfmt) else {
                return;
            };
            // Lagging receiver: drop the frame. Fully closed receiver (host tore
            // down the session): stop the loop instead of spinning (M7cap).
            if user.sink.send(frame).is_err() {
                tracing::info!("frame sink closed; stopping PipeWire capture loop");
                ml_proc.quit();
            }
        })
        .register()?;

    // Ask for CPU-readable BGRA-family formats at the monitor's size. We do NOT
    // advertise DMA-BUF modifiers, so the server hands us memfd/memptr buffers we
    // can map (MAP_BUFFERS) and read on the CPU.
    let format_pod = build_format_pod(fps, width, height);
    let mut params = [Pod::from_bytes(&format_pod).expect("valid format pod")];

    stream.connect(
        spa::utils::Direction::Input,
        Some(node_id),
        pw::stream::StreamFlags::AUTOCONNECT | pw::stream::StreamFlags::MAP_BUFFERS,
        &mut params,
    )?;

    // Quit the loop when the session is dropped. The receiver is attached to this
    // loop, so the callback runs on this (the loop's) thread — safe to `quit()`.
    let ml = mainloop.clone();
    let _recv = quit_rx.attach(mainloop.loop_(), move |_| ml.quit());

    mainloop.run();
    Ok(())
}

/// Convert one captured frame to a tightly-packed BGRA [`Frame`].
///
/// The portal/compositor delivers one of BGRA/BGRx/RGBA/RGBx. BGRA/BGRx are
/// already in our byte order (the codec ignores the 4th byte); RGBA/RGBx need R/B
/// swapped. Anything else we don't understand is dropped.
fn to_bgra_frame(
    bytes: &[u8],
    offset: usize,
    stride: usize,
    width: u32,
    height: u32,
    vfmt: spa::param::video::VideoFormat,
) -> Option<Frame> {
    use spa::param::video::VideoFormat as F;

    let w = width as usize;
    let h = height as usize;
    if w == 0 || h == 0 {
        return None;
    }
    let row_bytes = w.checked_mul(4)?;
    let stride = if stride >= row_bytes { stride } else { row_bytes };

    // Ensure the source actually holds `height` rows at this stride.
    let needed = offset.checked_add(stride.checked_mul(h)?)?;
    if bytes.len() < needed {
        return None;
    }

    let swap_rb = match vfmt {
        F::BGRA | F::BGRx => false,
        F::RGBA | F::RGBx => true,
        _ => {
            tracing::warn!(format = ?vfmt, "unsupported PipeWire pixel format; dropping frame");
            return None;
        }
    };

    let mut out = vec![0u8; row_bytes * h];
    for y in 0..h {
        let src_row = &bytes[offset + y * stride..offset + y * stride + row_bytes];
        let dst_row = &mut out[y * row_bytes..(y + 1) * row_bytes];
        if swap_rb {
            for x in 0..w {
                let s = &src_row[x * 4..x * 4 + 4];
                let d = &mut dst_row[x * 4..x * 4 + 4];
                d[0] = s[2]; // B <- R
                d[1] = s[1]; // G
                d[2] = s[0]; // R <- B
                d[3] = 255; // opaque
            }
        } else {
            dst_row.copy_from_slice(src_row);
        }
    }

    Some(Frame {
        width,
        height,
        bytes_per_row: row_bytes as u32,
        format: PixelFormat::Bgra,
        data: Bytes::from(out),
        capture_ts_micros: monotonic_micros(),
    })
}

/// Build the `EnumFormat` pod advertising the BGRA-family formats and a size
/// range whose preferred value is `width`x`height` (which also sizes a virtual
/// monitor), at up to `fps`.
fn build_format_pod(fps: u32, width: u32, height: u32) -> Vec<u8> {
    use pw::spa::param::format::{FormatProperties, MediaSubtype, MediaType};
    use pw::spa::param::video::VideoFormat;
    use pw::spa::param::ParamType;
    use pw::spa::pod::{object, property, serialize::PodSerializer, Value};
    use pw::spa::utils::{Fraction, Rectangle, SpaTypes};

    let obj = object!(
        SpaTypes::ObjectParamFormat,
        ParamType::EnumFormat,
        property!(FormatProperties::MediaType, Id, MediaType::Video),
        property!(FormatProperties::MediaSubtype, Id, MediaSubtype::Raw),
        property!(
            FormatProperties::VideoFormat,
            Choice,
            Enum,
            Id,
            VideoFormat::BGRx, // default
            VideoFormat::BGRx,
            VideoFormat::BGRA,
            VideoFormat::RGBx,
            VideoFormat::RGBA,
        ),
        property!(
            FormatProperties::VideoSize,
            Choice,
            Range,
            Rectangle,
            Rectangle { width, height }, // default (also sizes a virtual monitor)
            Rectangle { width: 1, height: 1 },       // min
            Rectangle { width: 8192, height: 8192 }  // max
        ),
        property!(
            FormatProperties::VideoFramerate,
            Choice,
            Range,
            Fraction,
            Fraction { num: fps, denom: 1 }, // default
            Fraction { num: 0, denom: 1 },   // min
            Fraction { num: 1000, denom: 1 } // max
        ),
    );

    PodSerializer::serialize(std::io::Cursor::new(Vec::new()), &Value::Object(obj))
        .expect("serialize format pod")
        .0
        .into_inner()
}
