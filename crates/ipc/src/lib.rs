//! Local broker↔agent IPC for the ReachMyDevice system-session split.
//!
//! In `system` mode `rmdd` runs as two cooperating processes:
//!
//! * a **broker** (system service, dedicated non-root `rmd` user) that owns the
//!   network side (WebRTC + rendezvous + identity/token) and input injection, and
//! * one or more **capture agents** (per graphical session — the `gdm` greeter,
//!   then the logged-in user) that capture+encode the screen and stream encoded
//!   H.264 to the broker.
//!
//! They talk over a Unix-domain socket (default [`DEFAULT_SOCKET_PATH`]). Each
//! message is a little-endian `u32` length prefix followed by a postcard-encoded
//! [`AgentMsg`] (agent→broker) or [`BrokerMsg`] (broker→agent). Video frames are
//! the only high-rate message; everything else is occasional control traffic.
//!
//! The broker keeps the viewer's WebRTC peer connection alive while agents come
//! and go, swapping which agent's frames it forwards — this is the greeter→user
//! **handover**. Because only encoded H.264 crosses the socket, the broker is
//! fully compositor-agnostic (it never learns whether the frames came from mutter,
//! the portal, or X11).

use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Default path the broker listens on and agents connect to.
pub const DEFAULT_SOCKET_PATH: &str = "/run/rmd/agent.sock";

/// Environment override for the socket path (both broker and agent honor it).
pub const SOCKET_PATH_ENV: &str = "RMD_AGENT_SOCKET";

/// Hard cap on a single framed message (safety against a corrupt/huge length
/// prefix). 64 MiB is far above any real encoded access unit.
const MAX_FRAME_BYTES: u32 = 64 * 1024 * 1024;

/// Resolve the socket path: [`SOCKET_PATH_ENV`] if set, else [`DEFAULT_SOCKET_PATH`].
pub fn socket_path() -> std::path::PathBuf {
    std::env::var_os(SOCKET_PATH_ENV)
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| std::path::PathBuf::from(DEFAULT_SOCKET_PATH))
}

/// Which graphical session an agent is capturing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SessionPhase {
    /// The display-manager greeter (login screen) — e.g. GDM, running as `gdm`.
    Greeter,
    /// A logged-in user session.
    User,
}

/// The capture backend the agent auto-detected for its session (mirrors
/// `rmd_capture`'s internal `SessionKind`). Informational: it lets the broker log
/// which path is live and surface an actionable error for an unsupported session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BackendKind {
    /// X11 XGetImage (any X11 session).
    X11,
    /// GNOME Wayland via mutter's private ScreenCast D-Bus API.
    GnomeWayland,
    /// Other Wayland (KDE Plasma, wlroots) via xdg-desktop-portal.
    OtherWayland,
    /// Could not be determined / not applicable.
    Unknown,
}

/// The captured output's rectangle within the desktop bounding box (pixels).
///
/// A field-for-field mirror of `rmd_capture::MonitorRect` / `rmd_input::MonitorRect`
/// so the broker can build an input `MonitorRect` for absolute-pointer mapping
/// from the agent's `Hello` without depending on those crates.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct MonitorRect {
    pub ox: f64,
    pub oy: f64,
    pub mw: f64,
    pub mh: f64,
    pub dw: f64,
    pub dh: f64,
}

/// One capturable display (mirrors `rmd_protocol::DisplayDescriptor`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DisplayDesc {
    pub id: u32,
    pub width: u32,
    pub height: u32,
    pub name: String,
    pub primary: bool,
}

/// Agent → broker.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AgentMsg {
    /// First message on a new connection: identifies the session and provides the
    /// geometry the broker needs for input mapping and the display list it relays
    /// to the viewer.
    Hello {
        phase: SessionPhase,
        backend: BackendKind,
        /// Real uid the agent runs as (belt-and-suspenders alongside the socket's
        /// `SO_PEERCRED` check; the broker trusts peer-cred, not this field).
        uid: u32,
        /// Absolute-pointer mapping rect for the captured output, if known.
        monitor_rect: Option<MonitorRect>,
        /// Capturable displays at connect time.
        displays: Vec<DisplayDesc>,
    },
    /// One encoded H.264 access unit (Annex-B). The high-rate message.
    Video {
        annexb: Vec<u8>,
        is_keyframe: bool,
        capture_ts_micros: u64,
    },
    /// Updated display list (hotplug / mode change).
    Displays(Vec<DisplayDesc>),
}

/// Broker → agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BrokerMsg {
    /// Start (`true`) or stop (`false`) capturing. Gated on viewer authorization:
    /// an agent MUST NOT capture until told to, so the screen isn't grabbed (nor
    /// the OS screen-share indicator lit) while no authorized viewer is watching.
    SetCapturing(bool),
    /// New target bitrate (bits/sec) from the transport's congestion controller.
    SetBitrate(u32),
    /// Emit an IDR now (viewer join / decoder PLI).
    ForceKeyframe,
    /// Switch the captured display.
    SelectDisplay(u32),
    /// Whether to bake the OS cursor into the captured video.
    SetShowCursor(bool),
}

/// Write one length-prefixed, postcard-encoded message.
pub async fn write_msg<W, M>(w: &mut W, msg: &M) -> anyhow::Result<()>
where
    W: AsyncWriteExt + Unpin,
    M: Serialize,
{
    let buf = postcard::to_stdvec(msg)?;
    let len = u32::try_from(buf.len())
        .map_err(|_| anyhow::anyhow!("ipc message too large: {} bytes", buf.len()))?;
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("ipc message too large: {len} bytes (cap {MAX_FRAME_BYTES})");
    }
    w.write_all(&len.to_le_bytes()).await?;
    w.write_all(&buf).await?;
    w.flush().await?;
    Ok(())
}

/// Read one length-prefixed, postcard-encoded message.
///
/// Returns an error on EOF (`read_exact` fails) — callers treat that as a clean
/// peer disconnect.
pub async fn read_msg<R, M>(r: &mut R) -> anyhow::Result<M>
where
    R: AsyncReadExt + Unpin,
    M: DeserializeOwned,
{
    let mut len_buf = [0u8; 4];
    r.read_exact(&mut len_buf).await?;
    let len = u32::from_le_bytes(len_buf);
    if len > MAX_FRAME_BYTES {
        anyhow::bail!("ipc frame too large: {len} bytes (cap {MAX_FRAME_BYTES})");
    }
    let mut buf = vec![0u8; len as usize];
    r.read_exact(&mut buf).await?;
    Ok(postcard::from_bytes(&buf)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn roundtrip_agent_and_broker_msgs() {
        // A duplex pipe stands in for the Unix socket.
        let (mut a, mut b) = tokio::io::duplex(1 << 20);

        let hello = AgentMsg::Hello {
            phase: SessionPhase::Greeter,
            backend: BackendKind::GnomeWayland,
            uid: 975,
            monitor_rect: Some(MonitorRect {
                ox: 0.0,
                oy: 0.0,
                mw: 1440.0,
                mh: 900.0,
                dw: 1440.0,
                dh: 900.0,
            }),
            displays: vec![DisplayDesc {
                id: 0,
                width: 1440,
                height: 900,
                name: "Display 1".into(),
                primary: true,
            }],
        };
        write_msg(&mut a, &hello).await.unwrap();
        let got: AgentMsg = read_msg(&mut b).await.unwrap();
        match got {
            AgentMsg::Hello { phase, backend, uid, monitor_rect, displays } => {
                assert_eq!(phase, SessionPhase::Greeter);
                assert_eq!(backend, BackendKind::GnomeWayland);
                assert_eq!(uid, 975);
                assert_eq!(monitor_rect.unwrap().mw, 1440.0);
                assert_eq!(displays.len(), 1);
            }
            other => panic!("unexpected: {other:?}"),
        }

        let video = AgentMsg::Video {
            annexb: vec![0, 0, 0, 1, 0x65, 0xAA, 0xBB],
            is_keyframe: true,
            capture_ts_micros: 123_456,
        };
        write_msg(&mut a, &video).await.unwrap();
        let got: AgentMsg = read_msg(&mut b).await.unwrap();
        match got {
            AgentMsg::Video { annexb, is_keyframe, capture_ts_micros } => {
                assert_eq!(annexb, vec![0, 0, 0, 1, 0x65, 0xAA, 0xBB]);
                assert!(is_keyframe);
                assert_eq!(capture_ts_micros, 123_456);
            }
            other => panic!("unexpected: {other:?}"),
        }

        // Reverse direction.
        write_msg(&mut b, &BrokerMsg::SetBitrate(2_500_000)).await.unwrap();
        let got: BrokerMsg = read_msg(&mut a).await.unwrap();
        assert!(matches!(got, BrokerMsg::SetBitrate(2_500_000)));

        write_msg(&mut b, &BrokerMsg::ForceKeyframe).await.unwrap();
        let got: BrokerMsg = read_msg(&mut a).await.unwrap();
        assert!(matches!(got, BrokerMsg::ForceKeyframe));
    }

    #[tokio::test]
    async fn read_after_close_errors() {
        let (a, mut b) = tokio::io::duplex(64);
        drop(a); // peer hangs up
        let r: anyhow::Result<AgentMsg> = read_msg(&mut b).await;
        assert!(r.is_err());
    }
}
