//! OpenReach input injection.
//!
//! Turns wire [`InputEvent`](openreach_protocol::input_event::Event)s (from the
//! viewer, over the data channel) into synthetic OS input on the host. The
//! platform-neutral [`Injector`] trait has a macOS backend ([`mac`], CGEvent);
//! other platforms return [`InputError::Unsupported`] until Phase 3.
//!
//! Pointer coordinates arrive normalized to `[0,1]`; the backend maps them onto
//! the host's main-display pixel bounds. Keys arrive as USB HID usage codes and
//! are mapped to native keycodes via [`keymap`] (a common-key subset in v1 —
//! unmapped keys are logged and dropped; see `docs/macos-permissions.md`).

use openreach_protocol::input_event::Event as InputEvent;

pub mod keymap;
#[cfg(target_os = "linux")]
pub mod linux;
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

/// Injects synthetic keyboard/mouse events on the host.
///
/// Not required to be `Send`: platform event sources are thread-affine, so the
/// host injects on the thread that owns the injector (it receives input events
/// over a `Send` channel).
pub trait Injector {
    /// Inject one input event. View-only sessions simply never call this.
    fn inject(&mut self, event: &InputEvent) -> anyhow::Result<()>;
}

/// Construct the platform injector.
pub fn new_injector() -> anyhow::Result<Box<dyn Injector>> {
    #[cfg(target_os = "macos")]
    {
        Ok(Box::new(mac::MacInjector::new()?))
    }
    #[cfg(target_os = "linux")]
    {
        Ok(Box::new(linux::X11Injector::new()?))
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Err(InputError::Unsupported.into())
    }
}
