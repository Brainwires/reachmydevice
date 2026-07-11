//! Browser input → `rmd-protocol` encoding.
//!
//! Mouse position is normalized to [0,1] over the canvas (the host maps it onto
//! its own resolution). Keyboard events map the browser `KeyboardEvent.code` to
//! USB HID usage codes — the platform-neutral representation the host injects.

use rmd_protocol as proto;
use rmd_protocol::pb::{input_event::Event, KeyEvent, MouseButton, MouseMove, MouseScroll};

/// Encode a normalized mouse move.
pub fn mouse_move(x: f64, y: f64) -> Vec<u8> {
    proto::encode(&proto::input(Event::MouseMove(MouseMove {
        x: x.clamp(0.0, 1.0),
        y: y.clamp(0.0, 1.0),
    })))
}

/// Encode a mouse button press/release at a normalized position.
pub fn mouse_button(button: i32, pressed: bool, x: f64, y: f64) -> Vec<u8> {
    proto::encode(&proto::input(Event::MouseButton(MouseButton {
        button,
        pressed,
        x: x.clamp(0.0, 1.0),
        y: y.clamp(0.0, 1.0),
    })))
}

/// Encode a scroll delta.
pub fn mouse_scroll(dx: f64, dy: f64) -> Vec<u8> {
    proto::encode(&proto::input(Event::MouseScroll(MouseScroll { dx, dy })))
}

// NB: the host also supports a `SetZoom` crop message (server-side digital zoom),
// but the browser viewer does zoom LOCALLY (a CSS transform on #zoomwrap — instant,
// no round-trip), so it doesn't send SetZoom. Re-add a `set_zoom` encoder here to
// drive host-side crop again (worthwhile only on a much higher-res display where
// streaming the whole frame is too costly).

/// Encode a key event (HID usage + modifier bitmask).
pub fn key(hid_usage: u32, pressed: bool, modifiers: u32) -> Vec<u8> {
    proto::encode(&proto::input(Event::Key(KeyEvent {
        hid_usage,
        pressed,
        modifiers,
    })))
}

/// The modifier bit for a special-key-bar modifier name (`ctrl`/`alt`/`super`/
/// `shift`), matching `rmd_protocol::modifiers`. Unknown names → 0.
pub fn mod_bit(name: &str) -> u32 {
    use proto::modifiers;
    match name {
        "ctrl" => modifiers::CONTROL,
        "alt" => modifiers::ALT,
        "super" | "meta" => modifiers::META,
        "shift" => modifiers::SHIFT,
        _ => 0,
    }
}

/// Map a typed character (from the mobile soft keyboard's `input`/`beforeinput`
/// events) to a US-QWERTY HID usage code + whether Shift is required. Covers the
/// printable ASCII a physical US keyboard produces; other characters → `None`.
/// (The soft keyboard gives us characters, not `KeyboardEvent.code`, so this is
/// the only way to translate mobile typing into HID.)
pub fn char_to_hid(c: char) -> Option<(u32, bool)> {
    // Letters.
    if c.is_ascii_lowercase() {
        return Some((0x04 + (c as u32 - 'a' as u32), false));
    }
    if c.is_ascii_uppercase() {
        return Some((0x04 + (c as u32 - 'A' as u32), true));
    }
    // Digit row (unshifted digits, shifted symbols share the same usage).
    let (usage, shift) = match c {
        '1' => (0x1E, false),
        '2' => (0x1F, false),
        '3' => (0x20, false),
        '4' => (0x21, false),
        '5' => (0x22, false),
        '6' => (0x23, false),
        '7' => (0x24, false),
        '8' => (0x25, false),
        '9' => (0x26, false),
        '0' => (0x27, false),
        '!' => (0x1E, true),
        '@' => (0x1F, true),
        '#' => (0x20, true),
        '$' => (0x21, true),
        '%' => (0x22, true),
        '^' => (0x23, true),
        '&' => (0x24, true),
        '*' => (0x25, true),
        '(' => (0x26, true),
        ')' => (0x27, true),
        // Whitespace + common punctuation.
        ' ' => (0x2C, false),
        '\n' | '\r' => (0x28, false), // Enter
        '\t' => (0x2B, false),        // Tab
        '-' => (0x2D, false),
        '_' => (0x2D, true),
        '=' => (0x2E, false),
        '+' => (0x2E, true),
        '[' => (0x2F, false),
        '{' => (0x2F, true),
        ']' => (0x30, false),
        '}' => (0x30, true),
        '\\' => (0x31, false),
        '|' => (0x31, true),
        ';' => (0x33, false),
        ':' => (0x33, true),
        '\'' => (0x34, false),
        '"' => (0x34, true),
        '`' => (0x35, false),
        '~' => (0x35, true),
        ',' => (0x36, false),
        '<' => (0x36, true),
        '.' => (0x37, false),
        '>' => (0x37, true),
        '/' => (0x38, false),
        '?' => (0x38, true),
        _ => return None,
    };
    Some((usage, shift))
}

/// Map a DOM `MouseEvent.button` (0=left,1=middle,2=right) to the protocol enum.
pub fn dom_button_to_proto(dom_button: i16) -> i32 {
    use rmd_protocol::pb::MouseBtn;
    match dom_button {
        0 => MouseBtn::Left as i32,
        1 => MouseBtn::Middle as i32,
        2 => MouseBtn::Right as i32,
        _ => MouseBtn::Unspecified as i32,
    }
}

/// Modifier bitmask from a `KeyboardEvent`'s modifier state (matches
/// `rmd_protocol::modifiers`).
pub fn modifier_mask(shift: bool, ctrl: bool, alt: bool, meta: bool, caps: bool) -> u32 {
    use proto::modifiers;
    let mut m = 0;
    if shift {
        m |= modifiers::SHIFT;
    }
    if ctrl {
        m |= modifiers::CONTROL;
    }
    if alt {
        m |= modifiers::ALT;
    }
    if meta {
        m |= modifiers::META;
    }
    if caps {
        m |= modifiers::CAPS_LOCK;
    }
    m
}

/// Map a browser `KeyboardEvent.code` to a USB HID usage code (Keyboard/Keypad
/// page 0x07). Covers the common desktop keys; unknown codes return `None`.
pub fn code_to_hid(code: &str) -> Option<u32> {
    let u = match code {
        "KeyA" => 0x04,
        "KeyB" => 0x05,
        "KeyC" => 0x06,
        "KeyD" => 0x07,
        "KeyE" => 0x08,
        "KeyF" => 0x09,
        "KeyG" => 0x0A,
        "KeyH" => 0x0B,
        "KeyI" => 0x0C,
        "KeyJ" => 0x0D,
        "KeyK" => 0x0E,
        "KeyL" => 0x0F,
        "KeyM" => 0x10,
        "KeyN" => 0x11,
        "KeyO" => 0x12,
        "KeyP" => 0x13,
        "KeyQ" => 0x14,
        "KeyR" => 0x15,
        "KeyS" => 0x16,
        "KeyT" => 0x17,
        "KeyU" => 0x18,
        "KeyV" => 0x19,
        "KeyW" => 0x1A,
        "KeyX" => 0x1B,
        "KeyY" => 0x1C,
        "KeyZ" => 0x1D,
        "Digit1" => 0x1E,
        "Digit2" => 0x1F,
        "Digit3" => 0x20,
        "Digit4" => 0x21,
        "Digit5" => 0x22,
        "Digit6" => 0x23,
        "Digit7" => 0x24,
        "Digit8" => 0x25,
        "Digit9" => 0x26,
        "Digit0" => 0x27,
        "Enter" => 0x28,
        "Escape" => 0x29,
        "Backspace" => 0x2A,
        "Tab" => 0x2B,
        "Space" => 0x2C,
        "Minus" => 0x2D,
        "Equal" => 0x2E,
        "BracketLeft" => 0x2F,
        "BracketRight" => 0x30,
        "Backslash" => 0x31,
        "Semicolon" => 0x33,
        "Quote" => 0x34,
        "Backquote" => 0x35,
        "Comma" => 0x36,
        "Period" => 0x37,
        "Slash" => 0x38,
        "CapsLock" => 0x39,
        "F1" => 0x3A,
        "F2" => 0x3B,
        "F3" => 0x3C,
        "F4" => 0x3D,
        "F5" => 0x3E,
        "F6" => 0x3F,
        "F7" => 0x40,
        "F8" => 0x41,
        "F9" => 0x42,
        "F10" => 0x43,
        "F11" => 0x44,
        "F12" => 0x45,
        "PrintScreen" => 0x46,
        "ScrollLock" => 0x47,
        "Pause" => 0x48,
        "Insert" => 0x49,
        "Home" => 0x4A,
        "PageUp" => 0x4B,
        "Delete" => 0x4C,
        "End" => 0x4D,
        "PageDown" => 0x4E,
        "ArrowRight" => 0x4F,
        "ArrowLeft" => 0x50,
        "ArrowDown" => 0x51,
        "ArrowUp" => 0x52,
        "ControlLeft" => 0xE0,
        "ShiftLeft" => 0xE1,
        "AltLeft" => 0xE2,
        "MetaLeft" => 0xE3,
        "ControlRight" => 0xE4,
        "ShiftRight" => 0xE5,
        "AltRight" => 0xE6,
        "MetaRight" => 0xE7,
        _ => return None,
    };
    Some(u)
}
