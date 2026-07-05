//! Linux X11 input injection via the XTEST extension.
//!
//! Synthesizes pointer motion, button, scroll, and key events into the X server.
//! Keys arrive as USB HID usages and are mapped to X keycodes ([`keymap::hid_to_x_keycode`]).
//! Modifier state is driven by the viewer sending the modifier keys themselves
//! (as their own key events), so the `modifiers` bitmask is not applied here.
//!
//! Wayland injection (libei / wlroots virtual pointer) is a separate backend.

use crate::keymap;
use crate::Injector;
use rmd_protocol::input_event::Event as InputEvent;
use x11rb::connection::Connection;
use x11rb::protocol::xproto::Window;
use x11rb::protocol::xtest::ConnectionExt as XtestExt;
use x11rb::rust_connection::RustConnection;

// Core X event codes used by XTEST fake input.
const KEY_PRESS: u8 = 2;
const KEY_RELEASE: u8 = 3;
const BUTTON_PRESS: u8 = 4;
const BUTTON_RELEASE: u8 = 5;
const MOTION_NOTIFY: u8 = 6;

/// X11 XTEST injector.
pub struct X11Injector {
    conn: RustConnection,
    root: Window,
    width: f64,
    height: f64,
}

impl X11Injector {
    pub fn new() -> anyhow::Result<Self> {
        let (conn, screen_num) = x11rb::connect(None)
            .map_err(|e| crate::InputError::Backend(format!("connect: {e}")))?;
        // Verify XTEST is available (also negotiates the version).
        conn.xtest_get_version(2, 1)
            .map_err(|e| crate::InputError::Backend(format!("XTEST query: {e}")))?
            .reply()
            .map_err(|e| crate::InputError::Backend(format!("XTEST unavailable: {e}")))?;

        let screen = &conn.setup().roots[screen_num];
        Ok(Self {
            root: screen.root,
            width: screen.width_in_pixels as f64,
            height: screen.height_in_pixels as f64,
            conn,
        })
    }

    fn fake(&self, ty: u8, detail: u8, x: i16, y: i16) -> anyhow::Result<()> {
        // time=0 (server does it now), deviceid=0 (default).
        self.conn
            .xtest_fake_input(ty, detail, 0, self.root, x, y, 0)
            .map_err(|e| crate::InputError::Backend(format!("fake_input: {e}")))?;
        self.conn.flush()?;
        Ok(())
    }

    fn click(&self, button: u8) -> anyhow::Result<()> {
        self.fake(BUTTON_PRESS, button, 0, 0)?;
        self.fake(BUTTON_RELEASE, button, 0, 0)
    }
}

impl Injector for X11Injector {
    fn inject(&mut self, event: &InputEvent) -> anyhow::Result<()> {
        match event {
            InputEvent::MouseMove(m) => {
                let x = (m.x * self.width) as i16;
                let y = (m.y * self.height) as i16;
                self.fake(MOTION_NOTIFY, 0 /* absolute */, x, y)?;
            }
            InputEvent::MouseButton(b) => {
                // proto: 1=Left,2=Right,3=Middle  ->  X: 1=left,2=middle,3=right.
                let x_button = match b.button {
                    2 => 3, // Right
                    3 => 2, // Middle
                    _ => 1, // Left / default
                };
                // Position the pointer first so the click lands where expected.
                let x = (b.x * self.width) as i16;
                let y = (b.y * self.height) as i16;
                self.fake(MOTION_NOTIFY, 0, x, y)?;
                let ty = if b.pressed {
                    BUTTON_PRESS
                } else {
                    BUTTON_RELEASE
                };
                self.fake(ty, x_button, 0, 0)?;
            }
            InputEvent::MouseScroll(s) => {
                // X scroll wheel = buttons 4(up)/5(down)/6(left)/7(right).
                if s.dy > 0.0 {
                    self.click(4)?;
                } else if s.dy < 0.0 {
                    self.click(5)?;
                }
                if s.dx > 0.0 {
                    self.click(7)?;
                } else if s.dx < 0.0 {
                    self.click(6)?;
                }
            }
            InputEvent::Key(k) => {
                let Some(keycode) = keymap::hid_to_x_keycode(k.hid_usage) else {
                    tracing::trace!(hid = k.hid_usage, "unmapped key usage; dropped");
                    return Ok(());
                };
                let ty = if k.pressed { KEY_PRESS } else { KEY_RELEASE };
                self.fake(ty, keycode, 0, 0)?;
            }
        }
        Ok(())
    }
}
