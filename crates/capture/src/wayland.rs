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

use crate::{CaptureConfig, CaptureError, CaptureSession, DisplayInfo, Frame, FrameSink, PixelFormat};
use bytes::Bytes;
use pipewire as pw;
use pw::spa;
use rmd_protocol::monotonic_micros;
use spa::pod::Pod;
use std::os::fd::OwnedFd;
use std::thread::JoinHandle;

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
}

impl CaptureSession for WaylandCaptureSession {
    fn stop(self: Box<Self>) {
        // Drop does the work (see below).
    }
}

impl Drop for WaylandCaptureSession {
    fn drop(&mut self) {
        // Quit the PipeWire loop, then close the portal session.
        let _ = self.pw_quit.send(());
        if let Some(tx) = self.portal_shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.pw_thread.take() {
            let _ = h.join();
        }
        if let Some(h) = self.portal_thread.take() {
            let _ = h.join();
        }
    }
}

/// Start capturing the Wayland desktop. Blocks until the user answers the portal
/// consent dialog (or it fails), because we can't stream before that resolves.
pub fn start_capture(
    config: CaptureConfig,
    _display_index: usize,
    sink: FrameSink,
) -> anyhow::Result<Box<dyn CaptureSession>> {
    // Channel carrying the handshake result (fd + node id) back from the portal
    // thread to here.
    let (ready_tx, ready_rx) = std::sync::mpsc::channel::<Result<(OwnedFd, u32), String>>();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let show_cursor = config.show_cursor;

    let portal_thread = std::thread::Builder::new()
        .name("rmd-portal".into())
        .spawn(move || portal_thread_main(show_cursor, ready_tx, shutdown_rx))?;

    // Wait for the portal handshake (this is where the consent dialog is shown).
    let (fd, node_id) = match ready_rx.recv() {
        Ok(Ok(v)) => v,
        Ok(Err(e)) => {
            let _ = portal_thread.join();
            return Err(CaptureError::Backend(format!(
                "Wayland ScreenCast portal failed: {e}. Is xdg-desktop-portal (and \
                 the -gnome/-kde backend) running, and did you approve the screen-share prompt?"
            ))
            .into());
        }
        Err(_) => {
            let _ = portal_thread.join();
            return Err(CaptureError::Backend(
                "Wayland ScreenCast portal thread exited before handshake".into(),
            )
            .into());
        }
    };

    let (pw_quit, pw_quit_rx) = pw::channel::channel::<()>();
    let fps = config.fps.max(1);
    let pw_thread = std::thread::Builder::new()
        .name("rmd-pw-capture".into())
        .spawn(move || {
            if let Err(e) = pw_run(fd, node_id, fps, sink, pw_quit_rx) {
                tracing::error!(error = %e, "PipeWire capture loop ended with error");
            }
        })?;

    tracing::info!(node_id, "Wayland PipeWire capture started");
    Ok(Box::new(WaylandCaptureSession {
        pw_quit,
        portal_shutdown: Some(shutdown_tx),
        pw_thread: Some(pw_thread),
        portal_thread: Some(portal_thread),
    }))
}

/// Portal thread: drive the async ScreenCast handshake on a current-thread tokio
/// runtime, hand the (fd, node id) back, then keep the session alive until told
/// to shut down. `proxy` and `session` must stay in scope together — the session
/// borrows the proxy, and dropping either closes the portal stream.
fn portal_thread_main(
    show_cursor: bool,
    ready_tx: std::sync::mpsc::Sender<Result<(OwnedFd, u32), String>>,
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

        let handshake = async {
            let proxy = Screencast::new().await?;
            let session = proxy.create_session().await?;
            let cursor = if show_cursor { CursorMode::Embedded } else { CursorMode::Hidden };
            proxy
                .select_sources(
                    &session,
                    cursor,
                    SourceType::Monitor.into(),
                    false, // single source
                    None,  // no restore token (v1: prompt each session)
                    PersistMode::DoNot,
                )
                .await?;
            let streams = proxy
                .start(&session, &WindowIdentifier::default())
                .await?
                .response()?;
            let stream = streams
                .streams()
                .first()
                .ok_or_else(|| anyhow::anyhow!("portal returned no streams"))?;
            let node_id = stream.pipe_wire_node_id();
            let fd = proxy.open_pipe_wire_remote(&session).await?;
            anyhow::Ok((proxy, session, fd, node_id))
        }
        .await;

        match handshake {
            Ok((_proxy, _session, fd, node_id)) => {
                if ready_tx.send(Ok((fd, node_id))).is_err() {
                    return; // caller gave up
                }
                // Keep _proxy/_session alive until shutdown; dropping them ends
                // the portal session (and the PipeWire stream feeding it).
                let _ = shutdown_rx.await;
            }
            Err(e) => {
                let _ = ready_tx.send(Err(e.to_string()));
            }
        }
    });
}

/// User data shared with the PipeWire stream callbacks.
struct StreamData {
    format: spa::param::video::VideoInfoRaw,
    sink: FrameSink,
}

/// PipeWire thread: connect to the portal's remote fd, attach a stream to
/// `node_id`, and pump frames into `sink` until `quit_rx` fires.
fn pw_run(
    fd: OwnedFd,
    node_id: u32,
    fps: u32,
    sink: FrameSink,
    quit_rx: pw::channel::Receiver<()>,
) -> anyhow::Result<()> {
    pw::init();

    let mainloop = pw::main_loop::MainLoop::new(None)?;
    let context = pw::context::Context::new(&mainloop)?;
    let core = context.connect_fd(fd, None)?;

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

    let _listener = stream
        .add_local_listener_with_user_data(data)
        .state_changed(|_, _, old, new| {
            tracing::debug!(?old, ?new, "PipeWire stream state changed");
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
        .process(|stream, user| {
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
            // Lagging/closed receiver: drop the frame rather than block the loop.
            let _ = user.sink.send(frame);
        })
        .register()?;

    // Ask for CPU-readable BGRA-family formats at the monitor's size. We do NOT
    // advertise DMA-BUF modifiers, so the server hands us memfd/memptr buffers we
    // can map (MAP_BUFFERS) and read on the CPU.
    let format_pod = build_format_pod(fps);
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
/// range (the portal fills in the real monitor size), at up to `fps`.
fn build_format_pod(fps: u32) -> Vec<u8> {
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
            Rectangle { width: 1920, height: 1080 }, // default
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
