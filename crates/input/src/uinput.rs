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
//! Pointer motion uses an **absolute** axis over `0..=ABS_MAX`. The viewer sends
//! coordinates normalized to `[0,1]` over the *captured* output. The compositor
//! maps an absolute device across the whole-desktop bounding box, so on a
//! multi-monitor host we translate the captured output's normalized coordinates
//! into desktop-fraction via the captured output's rect (see [`MonitorRect`]).

use crate::keymap;
use crate::{Injector, MonitorRect};
use evdev::{
    AbsInfo, AbsoluteAxisType, AttributeSet, EventType, InputEvent as EvEvent, Key, PropType,
    RelativeAxisType, UinputAbsSetup,
    uinput::{VirtualDevice, VirtualDeviceBuilder},
};
use rmd_protocol::input_event::Event as WireEvent;
use std::collections::HashSet;

/// Logical span of the absolute pointer axes (compositor scales to the desktop).
const ABS_MAX: i32 = 65535;

/// uinput virtual-device injector.
pub struct UinputInjector {
    dev: VirtualDevice,
    /// Captured-output rect within the desktop bounding box, for multi-monitor
    /// absolute mapping. `None` = span the whole desktop (correct for a single
    /// output at the origin).
    rect: Option<MonitorRect>,
    /// evdev codes currently held down (keys + buttons), so a viewer disconnect
    /// can release everything and never leak a stuck key/button (B1).
    pressed: HashSet<u16>,
    /// Last absolute position emitted, reused on a button release that carries
    /// stale/zero coordinates so releases don't teleport the pointer (M7).
    last_x: i32,
    last_y: i32,
}

impl UinputInjector {
    pub fn new(rect: Option<MonitorRect>) -> anyhow::Result<Self> {
        // Declare every capability the device will emit up front — the kernel
        // rejects events for undeclared codes.
        let mut keys = AttributeSet::<Key>::new();
        keys.insert(Key::BTN_LEFT);
        keys.insert(Key::BTN_RIGHT);
        keys.insert(Key::BTN_MIDDLE);
        // Classification hint: a device carrying BTN_TOOL_MOUSE alongside the ABS
        // axes reads as a mouse-like tool rather than a touchscreen (H4).
        keys.insert(Key::BTN_TOOL_MOUSE);
        // All keyboard usages our keymap can produce (evdev codes ≤ 248).
        for code in 1u16..=248 {
            keys.insert(Key(code));
        }

        let mut rel = AttributeSet::<RelativeAxisType>::new();
        rel.insert(RelativeAxisType::REL_WHEEL);
        rel.insert(RelativeAxisType::REL_HWHEEL);
        // High-resolution scroll companions (120 units/detent) for smooth,
        // proportional wheel handling on modern compositors (M8).
        rel.insert(RelativeAxisType::REL_WHEEL_HI_RES);
        rel.insert(RelativeAxisType::REL_HWHEEL_HI_RES);

        // INPUT_PROP_POINTER tells libinput the ABS axes describe a pointer, not
        // a direct-touch surface — so more compositors honour absolute motion
        // instead of ignoring the device (H4).
        let mut props = AttributeSet::<PropType>::new();
        props.insert(PropType::POINTER);

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
            .with_properties(&props)?
            .with_relative_axes(&rel)?
            .with_absolute_axis(&abs_x)?
            .with_absolute_axis(&abs_y)?
            .build()?;

        if let Some(r) = rect {
            tracing::info!(
                origin = format!("({},{})", r.ox, r.oy),
                size = format!("{}x{}", r.mw, r.mh),
                desktop = format!("{}x{}", r.dw, r.dh),
                "uinput: multi-monitor absolute mapping active"
            );
        }

        Ok(Self {
            dev,
            rect,
            pressed: HashSet::new(),
            last_x: ABS_MAX / 2,
            last_y: ABS_MAX / 2,
        })
    }

    fn emit(&mut self, events: &[EvEvent]) -> anyhow::Result<()> {
        self.dev
            .emit(events)
            .map_err(|e| crate::InputError::Backend(format!("uinput emit: {e}")))?;
        Ok(())
    }

    /// Map viewer-normalized coordinates (over the captured output) to absolute
    /// axis values over the desktop bounding box. Returns `None` for non-finite
    /// input so a bad packet can't move the pointer to a garbage location.
    fn map(&self, x_norm: f64, y_norm: f64) -> Option<(i32, i32)> {
        if !x_norm.is_finite() || !y_norm.is_finite() {
            return None;
        }
        let (fx, fy) = match &self.rect {
            Some(r) => (
                (r.ox + x_norm.clamp(0.0, 1.0) * r.mw) / r.dw,
                (r.oy + y_norm.clamp(0.0, 1.0) * r.mh) / r.dh,
            ),
            None => (x_norm, y_norm),
        };
        let x = (fx.clamp(0.0, 1.0) * ABS_MAX as f64) as i32;
        let y = (fy.clamp(0.0, 1.0) * ABS_MAX as f64) as i32;
        Some((x, y))
    }

    fn abs_events(x: i32, y: i32) -> [EvEvent; 2] {
        [
            EvEvent::new(EventType::ABSOLUTE, AbsoluteAxisType::ABS_X.0, x),
            EvEvent::new(EventType::ABSOLUTE, AbsoluteAxisType::ABS_Y.0, y),
        ]
    }

    /// Decompose a wheel delta into a notch count and a high-resolution value.
    /// Notches keep the classic ±1-per-detent behaviour but scale with magnitude
    /// so a fast flick scrolls farther; hi-res carries the fractional remainder.
    fn scroll_axes(v: f64) -> (i32, i32) {
        if !v.is_finite() || v == 0.0 {
            return (0, 0);
        }
        let v = v.clamp(-30.0, 30.0);
        let notch = {
            let n = v.round() as i32;
            if n == 0 {
                if v > 0.0 { 1 } else { -1 }
            } else {
                n
            }
        };
        let hires = (v * 120.0).round() as i32;
        (notch, hires)
    }
}

impl Injector for UinputInjector {
    fn inject(&mut self, event: &WireEvent) -> anyhow::Result<()> {
        match event {
            WireEvent::MouseMove(m) => {
                let Some((x, y)) = self.map(m.x, m.y) else {
                    return Ok(());
                };
                self.last_x = x;
                self.last_y = y;
                let ev = Self::abs_events(x, y);
                self.emit(&ev)?;
            }
            WireEvent::MouseButton(b) => {
                // proto: 1=Left, 2=Right, 3=Middle.
                let btn = match b.button {
                    2 => Key::BTN_RIGHT,
                    3 => Key::BTN_MIDDLE,
                    _ => Key::BTN_LEFT,
                };
                // Reposition to the event's coordinates, except an exact (0,0)
                // on the packet is treated as "no position" (some viewers send
                // it on button-up) — reuse the last position so a release at the
                // end of a drag doesn't teleport to the top-left corner (M7).
                let (x, y) = if b.x == 0.0 && b.y == 0.0 {
                    (self.last_x, self.last_y)
                } else {
                    match self.map(b.x, b.y) {
                        Some(p) => p,
                        None => (self.last_x, self.last_y),
                    }
                };
                self.last_x = x;
                self.last_y = y;
                let code = btn.code();
                if b.pressed {
                    self.pressed.insert(code);
                } else {
                    self.pressed.remove(&code);
                }
                let [ex, ey] = Self::abs_events(x, y);
                self.emit(&[
                    ex,
                    ey,
                    EvEvent::new(EventType::KEY, code, i32::from(b.pressed)),
                ])?;
            }
            WireEvent::MouseScroll(s) => {
                let mut evs = Vec::with_capacity(4);
                let (notch, hires) = Self::scroll_axes(s.dy);
                if notch != 0 {
                    evs.push(EvEvent::new(
                        EventType::RELATIVE,
                        RelativeAxisType::REL_WHEEL.0,
                        notch,
                    ));
                    evs.push(EvEvent::new(
                        EventType::RELATIVE,
                        RelativeAxisType::REL_WHEEL_HI_RES.0,
                        hires,
                    ));
                }
                let (hnotch, hhires) = Self::scroll_axes(s.dx);
                if hnotch != 0 {
                    evs.push(EvEvent::new(
                        EventType::RELATIVE,
                        RelativeAxisType::REL_HWHEEL.0,
                        hnotch,
                    ));
                    evs.push(EvEvent::new(
                        EventType::RELATIVE,
                        RelativeAxisType::REL_HWHEEL_HI_RES.0,
                        hhires,
                    ));
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
                if k.pressed {
                    self.pressed.insert(code);
                } else {
                    self.pressed.remove(&code);
                }
                self.emit(&[EvEvent::new(EventType::KEY, code, i32::from(k.pressed))])?;
            }
        }
        Ok(())
    }

    fn release_all(&mut self) {
        if self.pressed.is_empty() {
            return;
        }
        let ups: Vec<EvEvent> = self
            .pressed
            .drain()
            .map(|code| EvEvent::new(EventType::KEY, code, 0))
            .collect();
        tracing::debug!(count = ups.len(), "uinput: releasing held keys/buttons");
        if let Err(e) = self.dev.emit(&ups) {
            tracing::warn!(error = %e, "uinput: release_all emit failed");
        }
    }
}
