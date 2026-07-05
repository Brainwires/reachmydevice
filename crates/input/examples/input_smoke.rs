//! Input injection smoke test (Linux/X11).
//!
//! Injects a pointer move to the screen centre via the XTEST backend, then reads
//! the pointer position back with a separate X connection to confirm the event
//! landed. Also injects a key press/release (no crash = ok). Run under a real or
//! virtual (Xvfb) X server:
//!
//! ```sh
//! Xvfb :99 -screen 0 1280x720x24 &
//! DISPLAY=:99 cargo run -p rmd-input --example input_smoke
//! ```

#[cfg(target_os = "linux")]
fn main() -> anyhow::Result<()> {
    use rmd_input::new_injector;
    use rmd_protocol::input_event::Event;
    use rmd_protocol::{KeyEvent, MouseMove};
    use x11rb::connection::Connection;
    use x11rb::protocol::xproto::ConnectionExt;

    let mut injector = new_injector()?;

    // Move the pointer to the centre (0.5, 0.5).
    injector.inject(&Event::MouseMove(MouseMove { x: 0.5, y: 0.5 }))?;

    // Read the pointer back on a fresh connection.
    let (conn, screen_num) = x11rb::connect(None)?;
    let screen = &conn.setup().roots[screen_num];
    let (w, h) = (
        screen.width_in_pixels as i32,
        screen.height_in_pixels as i32,
    );
    let ptr = conn.query_pointer(screen.root)?.reply()?;
    println!(
        "screen {w}x{h}; pointer at ({}, {})",
        ptr.root_x, ptr.root_y
    );

    let (cx, cy) = (w / 2, h / 2);
    let (dx, dy) = (
        (ptr.root_x as i32 - cx).abs(),
        (ptr.root_y as i32 - cy).abs(),
    );
    anyhow::ensure!(
        dx <= 2 && dy <= 2,
        "pointer did not land at centre ({cx},{cy}); got ({},{})",
        ptr.root_x,
        ptr.root_y
    );

    // Inject a key press/release ('a' = HID 0x04); no focused window, just verify no error.
    injector.inject(&Event::Key(KeyEvent {
        hid_usage: 0x04,
        pressed: true,
        modifiers: 0,
    }))?;
    injector.inject(&Event::Key(KeyEvent {
        hid_usage: 0x04,
        pressed: false,
        modifiers: 0,
    }))?;

    println!("input injection OK (pointer moved to centre; key event accepted)");
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("input_smoke is Linux/X11-only");
}
