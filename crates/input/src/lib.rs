//! ReachMyDevice input injection.
//!
//! Turns wire [`InputEvent`](rmd_protocol::input_event::Event)s (from the
//! viewer, over the data channel) into synthetic OS input on the host. The
//! platform-neutral [`Injector`] trait has a macOS backend ([`mac`], CGEvent);
//! other platforms return [`InputError::Unsupported`] until Phase 3.
//!
//! Pointer coordinates arrive normalized to `[0,1]`; the backend maps them onto
//! the host's main-display pixel bounds. Keys arrive as USB HID usage codes and
//! are mapped to native keycodes via [`keymap`] (a common-key subset in v1 —
//! unmapped keys are logged and dropped; see `docs/macos-permissions.md`).

use rmd_protocol::input_event::Event as InputEvent;

pub mod keymap;
#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "linux")]
pub mod uinput;
#[cfg(target_os = "macos")]
pub mod mac;

/// Errors from input injection.
#[derive(Debug, thiserror::Error)]
pub enum InputError {
    #[error("input injection is not yet supported on this platform (Phase 3)")]
    Unsupported,
    #[error("input backend error: {0}")]
    Backend(String),
}

/// The captured output's rectangle within the desktop bounding box, in pixels.
///
/// An absolute pointer device is mapped by the compositor across the *whole*
/// desktop bounding box, so to land a click on the captured output we translate
/// the viewer's normalized `[0,1]` coordinates (which are relative to that one
/// output) into a fraction of the full desktop. On a single output at the origin
/// this is the identity map, so callers pass `None` and get the previous
/// behaviour.
#[derive(Debug, Clone, Copy)]
pub struct MonitorRect {
    /// Captured output origin X within the desktop bounding box (px).
    pub ox: f64,
    /// Captured output origin Y within the desktop bounding box (px).
    pub oy: f64,
    /// Captured output width (px).
    pub mw: f64,
    /// Captured output height (px).
    pub mh: f64,
    /// Full desktop bounding-box width (px).
    pub dw: f64,
    /// Full desktop bounding-box height (px).
    pub dh: f64,
}

impl MonitorRect {
    /// Parse `RMD_INPUT_MONITOR_RECT="ox,oy,mw,mh,dw,dh"` (pixels). Returns
    /// `None` when unset; logs and returns `None` when malformed.
    pub fn from_env() -> Option<Self> {
        let raw = std::env::var("RMD_INPUT_MONITOR_RECT").ok()?;
        let parts: Vec<f64> = raw
            .split(',')
            .map(|s| s.trim().parse::<f64>())
            .collect::<Result<Vec<_>, _>>()
            .ok()?;
        if let [ox, oy, mw, mh, dw, dh] = parts[..] {
            if [ox, oy, mw, mh, dw, dh].iter().all(|v| v.is_finite())
                && mw > 0.0
                && mh > 0.0
                && dw > 0.0
                && dh > 0.0
            {
                return Some(Self { ox, oy, mw, mh, dw, dh });
            }
        }
        tracing::warn!(value = %raw, "ignoring malformed RMD_INPUT_MONITOR_RECT (expected ox,oy,mw,mh,dw,dh)");
        None
    }
}

/// Injects synthetic keyboard/mouse events on the host.
///
/// Not required to be `Send`: platform event sources are thread-affine, so the
/// host injects on the thread that owns the injector (it receives input events
/// over a `Send` channel).
pub trait Injector {
    /// Inject one input event. View-only sessions simply never call this.
    fn inject(&mut self, event: &InputEvent) -> anyhow::Result<()>;

    /// Release everything currently held down (keys and mouse buttons).
    ///
    /// Called when a viewer disconnects so a key or button that was down at
    /// disconnect can't leak — stuck — into the next session. The default is a
    /// no-op for stateless backends; stateful ones (uinput/XTEST) override it.
    fn release_all(&mut self) {}
}

/// Construct the platform injector.
///
/// `monitor_rect` describes the captured output's placement within the desktop
/// bounding box, used for multi-monitor absolute-pointer mapping (uinput only).
/// `None` = span the whole desktop (correct for a single output at the origin).
/// The `RMD_INPUT_MONITOR_RECT` env override, if set, takes precedence.
pub fn new_injector(monitor_rect: Option<MonitorRect>) -> anyhow::Result<Box<dyn Injector>> {
    #[cfg(target_os = "macos")]
    {
        let _ = monitor_rect;
        Ok(Box::new(mac::MacInjector::new()?))
    }
    #[cfg(target_os = "linux")]
    {
        // Prefer uinput (native on X11 + every Wayland compositor; reaches native
        // Wayland windows). Fall back to XTEST if /dev/uinput isn't accessible.
        // `RMD_INPUT=xtest` forces the X11 path; `RMD_INPUT=uinput` disables the
        // fallback (surfaces the permission error instead).
        let want = std::env::var("RMD_INPUT").unwrap_or_default();
        if !want.is_empty() && want != "xtest" && want != "uinput" {
            tracing::warn!(value = %want, "unknown RMD_INPUT value; expected 'uinput' or 'xtest' — ignoring");
        }
        if want == "xtest" {
            return Ok(Box::new(linux::X11Injector::new()?));
        }
        let rect = MonitorRect::from_env().or(monitor_rect);
        match uinput::UinputInjector::new(rect) {
            Ok(inj) => {
                tracing::info!("input backend: uinput (native, all compositors)");
                Ok(Box::new(inj))
            }
            Err(e) if want == "uinput" => Err(e),
            Err(e) => {
                tracing::warn!(error = %e, "uinput unavailable; falling back to X11 XTEST (native-Wayland windows may not receive input)");
                match linux::X11Injector::new() {
                    Ok(inj) => Ok(Box::new(inj)),
                    Err(x11_err) => {
                        // Both backends failed. Surface the uinput permission
                        // error — it's the actionable one on Wayland; the X11
                        // failure is usually just "no X server".
                        tracing::warn!(error = %x11_err, "X11 XTEST fallback also failed");
                        Err(e)
                    }
                }
            }
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = monitor_rect;
        Err(InputError::Unsupported.into())
    }
}
