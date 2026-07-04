//! Keyboard keycode mapping.
//!
//! The wire carries **USB HID usage codes** (Keyboard/Keypad page 0x07) so the
//! representation is layout- and OS-neutral. Each host backend maps them to its
//! native keycodes: [`hid_to_macos`] (Carbon virtual keycodes) and
//! [`hid_to_x_keycode`] (X11, evdev+8). v1 covers the common keys; unmapped
//! usages return `None` and the backend drops them (documented limitation).

/// Map a USB HID keyboard usage code to a macOS virtual keycode (`CGKeyCode`).
///
/// Returns `None` for usages outside the v1 common set.
#[cfg(target_os = "macos")]
pub fn hid_to_macos(hid: u32) -> Option<u16> {
    let code: u16 = match hid {
        // Letters a..z (HID 0x04..0x1D)
        0x04 => 0,  // a
        0x05 => 11, // b
        0x06 => 8,  // c
        0x07 => 2,  // d
        0x08 => 14, // e
        0x09 => 3,  // f
        0x0A => 5,  // g
        0x0B => 4,  // h
        0x0C => 34, // i
        0x0D => 38, // j
        0x0E => 40, // k
        0x0F => 37, // l
        0x10 => 46, // m
        0x11 => 45, // n
        0x12 => 31, // o
        0x13 => 35, // p
        0x14 => 12, // q
        0x15 => 15, // r
        0x16 => 1,  // s
        0x17 => 17, // t
        0x18 => 32, // u
        0x19 => 9,  // v
        0x1A => 13, // w
        0x1B => 7,  // x
        0x1C => 16, // y
        0x1D => 6,  // z
        // Digits 1..9 0 (HID 0x1E..0x27)
        0x1E => 18,
        0x1F => 19,
        0x20 => 20,
        0x21 => 21,
        0x22 => 23,
        0x23 => 22,
        0x24 => 26,
        0x25 => 28,
        0x26 => 25,
        0x27 => 29,
        // Control / whitespace
        0x28 => 36, // Return
        0x29 => 53, // Escape
        0x2A => 51, // Backspace (Delete)
        0x2B => 48, // Tab
        0x2C => 49, // Space
        // Punctuation
        0x2D => 27, // -
        0x2E => 24, // =
        0x2F => 33, // [
        0x30 => 30, // ]
        0x31 => 42, // \
        0x33 => 41, // ;
        0x34 => 39, // '
        0x35 => 50, // `
        0x36 => 43, // ,
        0x37 => 47, // .
        0x38 => 44, // /
        0x39 => 57, // CapsLock
        // Function row F1..F12 (HID 0x3A..0x45)
        0x3A => 122,
        0x3B => 120,
        0x3C => 99,
        0x3D => 118,
        0x3E => 96,
        0x3F => 97,
        0x40 => 98,
        0x41 => 100,
        0x42 => 101,
        0x43 => 109,
        0x44 => 103,
        0x45 => 111,
        // Navigation
        0x4A => 115, // Home
        0x4B => 116, // PageUp
        0x4C => 117, // Delete Forward
        0x4D => 119, // End
        0x4E => 121, // PageDown
        0x4F => 124, // Right
        0x50 => 123, // Left
        0x51 => 125, // Down
        0x52 => 126, // Up
        // Keypad (HID 0x53..0x63, 0x67)
        0x53 => 71,  // NumLock/Clear
        0x54 => 75,  // KP /
        0x55 => 67,  // KP *
        0x56 => 78,  // KP -
        0x57 => 69,  // KP +
        0x58 => 76,  // KP Enter
        0x59 => 83,  // KP 1
        0x5A => 84,  // KP 2
        0x5B => 85,  // KP 3
        0x5C => 86,  // KP 4
        0x5D => 87,  // KP 5
        0x5E => 88,  // KP 6
        0x5F => 89,  // KP 7
        0x60 => 91,  // KP 8
        0x61 => 92,  // KP 9
        0x62 => 82,  // KP 0
        0x63 => 65,  // KP .
        0x67 => 81,  // KP =
        // Modifiers
        0xE0 => 59, // Left Control
        0xE1 => 56, // Left Shift
        0xE2 => 58, // Left Option (Alt)
        0xE3 => 55, // Left Command (GUI)
        0xE4 => 62, // Right Control
        0xE5 => 60, // Right Shift
        0xE6 => 61, // Right Option
        0xE7 => 54, // Right Command
        _ => return None,
    };
    Some(code)
}

/// Map a USB HID keyboard usage code to an X11 keycode.
///
/// On Xorg with the evdev driver, an X keycode is the Linux evdev key code + 8.
/// Returns `None` for usages outside the v1 common set.
#[cfg(target_os = "linux")]
pub fn hid_to_x_keycode(hid: u32) -> Option<u8> {
    // HID usage -> Linux evdev key code (input-event-codes.h).
    let evdev: u16 = match hid {
        0x04 => 30,
        0x05 => 48,
        0x06 => 46,
        0x07 => 32,
        0x08 => 18,
        0x09 => 33,
        0x0A => 34,
        0x0B => 35,
        0x0C => 23,
        0x0D => 36,
        0x0E => 37,
        0x0F => 38,
        0x10 => 50,
        0x11 => 49,
        0x12 => 24,
        0x13 => 25,
        0x14 => 16,
        0x15 => 19,
        0x16 => 31,
        0x17 => 20,
        0x18 => 22,
        0x19 => 47,
        0x1A => 17,
        0x1B => 45,
        0x1C => 21,
        0x1D => 44,
        0x1E => 2,
        0x1F => 3,
        0x20 => 4,
        0x21 => 5,
        0x22 => 6,
        0x23 => 7,
        0x24 => 8,
        0x25 => 9,
        0x26 => 10,
        0x27 => 11,
        0x28 => 28, // Enter
        0x29 => 1,  // Esc
        0x2A => 14, // Backspace
        0x2B => 15, // Tab
        0x2C => 57, // Space
        0x2D => 12,
        0x2E => 13,
        0x2F => 26,
        0x30 => 27,
        0x31 => 43,
        0x33 => 39,
        0x34 => 40,
        0x35 => 41,
        0x36 => 51,
        0x37 => 52,
        0x38 => 53,
        0x39 => 58, // CapsLock
        0x3A => 59, // F1
        0x3B => 60,
        0x3C => 61,
        0x3D => 62,
        0x3E => 63,
        0x3F => 64,
        0x40 => 65,
        0x41 => 66,
        0x42 => 67,
        0x43 => 68,
        0x44 => 87,  // F11
        0x45 => 88,  // F12
        0x4A => 102, // Home
        0x4B => 104, // PageUp
        0x4C => 111, // Delete
        0x4D => 107, // End
        0x4E => 109, // PageDown
        0x4F => 106, // Right
        0x50 => 105, // Left
        0x51 => 108, // Down
        0x52 => 103, // Up
        // Keypad (HID 0x53..0x63, 0x67) -> Linux evdev codes
        0x53 => 69,  // NumLock
        0x54 => 98,  // KP /
        0x55 => 55,  // KP *
        0x56 => 74,  // KP -
        0x57 => 78,  // KP +
        0x58 => 96,  // KP Enter
        0x59 => 79,  // KP 1
        0x5A => 80,  // KP 2
        0x5B => 81,  // KP 3
        0x5C => 75,  // KP 4
        0x5D => 76,  // KP 5
        0x5E => 77,  // KP 6
        0x5F => 71,  // KP 7
        0x60 => 72,  // KP 8
        0x61 => 73,  // KP 9
        0x62 => 82,  // KP 0
        0x63 => 83,  // KP .
        0x67 => 117, // KP =
        0xE0 => 29,  // LeftCtrl
        0xE1 => 42,  // LeftShift
        0xE2 => 56,  // LeftAlt
        0xE3 => 125, // LeftMeta
        0xE4 => 97,  // RightCtrl
        0xE5 => 54,  // RightShift
        0xE6 => 100, // RightAlt
        0xE7 => 126, // RightMeta
        _ => return None,
    };
    Some((evdev + 8) as u8)
}

#[cfg(test)]
mod tests {
    #[cfg(target_os = "macos")]
    #[test]
    fn common_keys_map() {
        use super::hid_to_macos;
        assert_eq!(hid_to_macos(0x04), Some(0)); // 'a'
        assert_eq!(hid_to_macos(0x28), Some(36)); // Return
        assert_eq!(hid_to_macos(0x2C), Some(49)); // Space
        assert_eq!(hid_to_macos(0x4F), Some(124)); // Right arrow
        assert_eq!(hid_to_macos(0xFFFF), None); // unmapped
    }
}
