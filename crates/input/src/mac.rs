//! macOS input injection via CGEvent.
//!
//! Posts synthetic mouse/keyboard events to the HID event tap. Requires the
//! **Accessibility** TCC permission (see `docs/macos-permissions.md`); without
//! it the events are silently ignored by the system.
//!
//! Normalized pointer coordinates are mapped onto the main display's bounds (in
//! points, matching CGEvent's global coordinate space). Held-button moves are
//! sent as drag events so drag operations work.

use crate::Injector;
use crate::keymap;
use core_graphics::display::CGDisplay;
use core_graphics::event::{
    CGEvent, CGEventFlags, CGEventTapLocation, CGEventType, CGMouseButton, ScrollEventUnit,
};
use core_graphics::event_source::{CGEventSource, CGEventSourceStateID};
use core_graphics::geometry::CGPoint;
use rmd_protocol::input_event::Event as InputEvent;
use rmd_protocol::modifiers as m;

/// macOS CGEvent injector.
pub struct MacInjector {
    source: CGEventSource,
    /// Main-display bounds in points (CGEvent global coordinate space).
    width: f64,
    height: f64,
    // Button state so pointer moves become drags while a button is held.
    left_down: bool,
    right_down: bool,
    other_down: bool,
}

impl MacInjector {
    pub fn new() -> anyhow::Result<Self> {
        let source = CGEventSource::new(CGEventSourceStateID::HIDSystemState)
            .map_err(|()| crate::InputError::Backend("CGEventSource::new failed".into()))?;
        let bounds = CGDisplay::main().bounds();
        Ok(Self {
            source,
            width: bounds.size.width,
            height: bounds.size.height,
            left_down: false,
            right_down: false,
            other_down: false,
        })
    }

    fn point(&self, x: f64, y: f64) -> CGPoint {
        CGPoint::new(x * self.width, y * self.height)
    }

    fn post(&self, event: CGEvent) {
        event.post(CGEventTapLocation::HID);
    }
}

/// Map wire modifier bits to CGEvent flags.
fn cg_flags(modifiers: u32) -> CGEventFlags {
    let mut f = CGEventFlags::empty();
    if modifiers & m::SHIFT != 0 {
        f |= CGEventFlags::CGEventFlagShift;
    }
    if modifiers & m::CONTROL != 0 {
        f |= CGEventFlags::CGEventFlagControl;
    }
    if modifiers & m::ALT != 0 {
        f |= CGEventFlags::CGEventFlagAlternate;
    }
    if modifiers & m::META != 0 {
        f |= CGEventFlags::CGEventFlagCommand;
    }
    if modifiers & m::CAPS_LOCK != 0 {
        f |= CGEventFlags::CGEventFlagAlphaShift;
    }
    f
}

impl Injector for MacInjector {
    fn inject(&mut self, event: &InputEvent) -> anyhow::Result<()> {
        match event {
            InputEvent::MouseMove(mv) => {
                let pt = self.point(mv.x, mv.y);
                let etype = if self.left_down {
                    CGEventType::LeftMouseDragged
                } else if self.right_down {
                    CGEventType::RightMouseDragged
                } else if self.other_down {
                    CGEventType::OtherMouseDragged
                } else {
                    CGEventType::MouseMoved
                };
                let ev =
                    CGEvent::new_mouse_event(self.source.clone(), etype, pt, CGMouseButton::Left)
                        .map_err(|()| crate::InputError::Backend("new_mouse_event".into()))?;
                self.post(ev);
            }
            InputEvent::MouseButton(b) => {
                let pt = self.point(b.x, b.y);
                // 1=Left, 2=Right, 3=Middle (proto MouseBtn).
                let (etype, button) = match (b.button, b.pressed) {
                    (2, true) => {
                        self.right_down = true;
                        (CGEventType::RightMouseDown, CGMouseButton::Right)
                    }
                    (2, false) => {
                        self.right_down = false;
                        (CGEventType::RightMouseUp, CGMouseButton::Right)
                    }
                    (3, true) => {
                        self.other_down = true;
                        (CGEventType::OtherMouseDown, CGMouseButton::Center)
                    }
                    (3, false) => {
                        self.other_down = false;
                        (CGEventType::OtherMouseUp, CGMouseButton::Center)
                    }
                    (_, true) => {
                        self.left_down = true;
                        (CGEventType::LeftMouseDown, CGMouseButton::Left)
                    }
                    (_, false) => {
                        self.left_down = false;
                        (CGEventType::LeftMouseUp, CGMouseButton::Left)
                    }
                };
                let ev = CGEvent::new_mouse_event(self.source.clone(), etype, pt, button)
                    .map_err(|()| crate::InputError::Backend("new_mouse_event".into()))?;
                self.post(ev);
            }
            InputEvent::MouseScroll(s) => {
                // wheel1 = vertical, wheel2 = horizontal.
                let ev = CGEvent::new_scroll_event(
                    self.source.clone(),
                    ScrollEventUnit::PIXEL,
                    2,
                    s.dy as i32,
                    s.dx as i32,
                    0,
                )
                .map_err(|()| crate::InputError::Backend("new_scroll_event".into()))?;
                self.post(ev);
            }
            InputEvent::Key(k) => {
                let Some(keycode) = keymap::hid_to_macos(k.hid_usage) else {
                    tracing::trace!(hid = k.hid_usage, "unmapped key usage; dropped");
                    return Ok(());
                };
                let ev = CGEvent::new_keyboard_event(self.source.clone(), keycode, k.pressed)
                    .map_err(|()| crate::InputError::Backend("new_keyboard_event".into()))?;
                // ALWAYS set the flags explicitly — even to empty. A fresh CGEvent
                // inherits the current modifier state, so a previous shifted key
                // (e.g. one-shot Shift) leaks its Shift flag onto the next key unless
                // we overwrite it with exactly this event's modifiers. This is the
                // fix for "Shift stays on for the letter after the shifted one".
                ev.set_flags(cg_flags(k.modifiers));
                self.post(ev);
            }
        }
        Ok(())
    }
}
