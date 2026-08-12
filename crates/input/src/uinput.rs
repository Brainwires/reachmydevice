//! Linux input injection via a **uinput** kernel virtual device.
//!
//! Unlike the XTEST backend ([`crate::linux`]) — which talks to an X server and
//! therefore only reaches XWayland/X11 windows under a Wayland session — a uinput
//! virtual device is a real kernel input device, so the compositor delivers its
//! events to **native-Wayland windows** too. It works identically on X11 and on
//! every Wayland compositor (GNOME, KDE, wlroots), with no consent prompt. This
//! is how tools like `ydotool` inject on Wayland.
//!
//! Requires write access to `/dev/uinput` (ship `deploy/60-rmd-uinput.rules` or
//! add the user to the `input` group). If it can't be opened, the caller falls
//! back to XTEST.
//!
//! Pointer motion uses an **absolute** axis over `0..=ABS_MAX`; the viewer sends
//! coordinates normalized to `[0,1]`, so the compositor maps them across the
//! desktop regardless of resolution.

use crate::keymap;
use crate::Injector;
use evdev::{
    uinput::{VirtualDevice, VirtualDeviceBuilder},
    AbsInfo, AbsoluteAxisType, AttributeSet, EventType, InputEvent as EvEvent, Key,
    RelativeAxisType, UinputAbsSetup,
};
use rmd_protocol::input_event::Event as WireEvent;

/// Logical span of the absolute pointer axes (compositor scales to the desktop).
const ABS_MAX: i32 = 65535;

/// uinput virtual-device injector.
pub struct UinputInjector {
    dev: VirtualDevice,
}

impl UinputInjector {
    pub fn new() -> anyhow::Result<Self> {
        // Declare every capability the device will emit up front — the kernel
        // rejects events for undeclared codes.
        let mut keys = AttributeSet::<Key>::new();
        keys.insert(Key::BTN_LEFT);
        keys.insert(Key::BTN_RIGHT);
        keys.insert(Key::BTN_MIDDLE);
        // All keyboard usages our keymap can produce (evdev codes ≤ 248).
        for code in 1u16..=248 {
            keys.insert(Key(code));
        }

        let mut rel = AttributeSet::<RelativeAxisType>::new();
        rel.insert(RelativeAxisType::REL_WHEEL);
        rel.insert(RelativeAxisType::REL_HWHEEL);

        let abs = AbsInfo::new(0, 0, ABS_MAX, 0, 0, 0);
        let abs_x = UinputAbsSetup::new(AbsoluteAxisType::ABS_X, abs);
        let abs_y = UinputAbsSetup::new(AbsoluteAxisType::ABS_Y, abs);

        let dev = VirtualDeviceBuilder::new()
            .map_err(|e| {
                crate::InputError::Backend(format!(
                    "open /dev/uinput failed ({e}). Grant access — install \
                     deploy/60-rmd-uinput.rules (udev) or add the user to the `input` \
                     group — or set RMD_INPUT=xtest to force the X11 fallback."
                ))
            })?
            .name("ReachMyDevice virtual input")
            .with_keys(&keys)?
            .with_relative_axes(&rel)?
            .with_absolute_axis(&abs_x)?
            .with_absolute_axis(&abs_y)?
            .build()?;

        Ok(Self { dev })
    }

    fn emit(&mut self, events: &[EvEvent]) -> anyhow::Result<()> {
        self.dev
            .emit(events)
            .map_err(|e| crate::InputError::Backend(format!("uinput emit: {e}")))?;
        Ok(())
    }

    fn abs_xy(x_norm: f64, y_norm: f64) -> (EvEvent, EvEvent) {
        let x = (x_norm.clamp(0.0, 1.0) * ABS_MAX as f64) as i32;
        let y = (y_norm.clamp(0.0, 1.0) * ABS_MAX as f64) as i32;
        (
            EvEvent::new(EventType::ABSOLUTE, AbsoluteAxisType::ABS_X.0, x),
            EvEvent::new(EventType::ABSOLUTE, AbsoluteAxisType::ABS_Y.0, y),
        )
    }
}

impl Injector for UinputInjector {
    fn inject(&mut self, event: &WireEvent) -> anyhow::Result<()> {
        match event {
            WireEvent::MouseMove(m) => {
                let (ex, ey) = Self::abs_xy(m.x, m.y);
                self.emit(&[ex, ey])?;
            }
            WireEvent::MouseButton(b) => {
                // proto: 1=Left, 2=Right, 3=Middle.
                let btn = match b.button {
                    2 => Key::BTN_RIGHT,
                    3 => Key::BTN_MIDDLE,
                    _ => Key::BTN_LEFT,
                };
                // Position first so the click lands where the viewer pointed.
                let (ex, ey) = Self::abs_xy(b.x, b.y);
                self.emit(&[
                    ex,
                    ey,
                    EvEvent::new(EventType::KEY, btn.code(), i32::from(b.pressed)),
                ])?;
            }
            WireEvent::MouseScroll(s) => {
                let mut evs = Vec::with_capacity(2);
                if s.dy != 0.0 {
                    let dir = if s.dy > 0.0 { 1 } else { -1 };
                    evs.push(EvEvent::new(EventType::RELATIVE, RelativeAxisType::REL_WHEEL.0, dir));
                }
                if s.dx != 0.0 {
                    let dir = if s.dx > 0.0 { 1 } else { -1 };
                    evs.push(EvEvent::new(EventType::RELATIVE, RelativeAxisType::REL_HWHEEL.0, dir));
                }
                if !evs.is_empty() {
                    self.emit(&evs)?;
                }
            }
            WireEvent::Key(k) => {
                let Some(code) = keymap::hid_to_evdev(k.hid_usage) else {
                    tracing::trace!(hid = k.hid_usage, "unmapped key usage; dropped");
                    return Ok(());
                };
                self.emit(&[EvEvent::new(EventType::KEY, code, i32::from(k.pressed))])?;
            }
        }
        Ok(())
    }
}
