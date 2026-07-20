//! Keep an always-on host reachable by inhibiting **system idle sleep** while
//! it's running (a suspended machine drops every session and can't accept an
//! unattended connection). [`prevent_sleep`] returns an RAII guard; dropping it
//! releases the inhibition.
//!
//! Best-effort and per-platform: macOS IOKit power assertion, Linux
//! `systemd-inhibit`, Windows `SetThreadExecutionState`. On anything else (or on
//! failure) it's a no-op with a warning — the operator must then disable sleep
//! themselves. It prevents *idle system* sleep, not display sleep, and does not
//! stop a user closing a laptop lid.

/// RAII guard; holds the sleep inhibition for its lifetime.
pub struct KeepAwake(#[allow(dead_code)] Option<imp::Guard>);

/// Inhibit system idle sleep for as long as the returned guard lives.
pub fn prevent_sleep(reason: &str) -> KeepAwake {
    match imp::keep_awake(reason) {
        Some(g) => {
            tracing::info!(%reason, "system idle-sleep inhibited");
            KeepAwake(Some(g))
        }
        None => {
            tracing::warn!(
                "could not inhibit system sleep — ensure this machine is configured not to sleep"
            );
            KeepAwake(None)
        }
    }
}

#[cfg(target_os = "macos")]
mod imp {
    use std::ffi::{CString, c_void};

    type IoReturn = i32;
    type IoPmAssertionId = u32;
    type CfStringRef = *const c_void;

    // kIOPMAssertionLevelOn; kCFStringEncodingUTF8.
    const ASSERTION_LEVEL_ON: u32 = 255;
    const CF_ENCODING_UTF8: u32 = 0x0800_0100;

    // Both frameworks are required (IOKit for the assertion API, CoreFoundation
    // for the CFString/CFRelease symbols we call directly).
    #[allow(clippy::duplicated_attributes)]
    #[link(name = "IOKit", kind = "framework")]
    #[link(name = "CoreFoundation", kind = "framework")]
    unsafe extern "C" {
        fn IOPMAssertionCreateWithName(
            assertion_type: CfStringRef,
            assertion_level: u32,
            assertion_name: CfStringRef,
            assertion_id: *mut IoPmAssertionId,
        ) -> IoReturn;
        fn IOPMAssertionRelease(assertion_id: IoPmAssertionId) -> IoReturn;
        fn CFStringCreateWithCString(
            alloc: *const c_void,
            c_str: *const i8,
            encoding: u32,
        ) -> CfStringRef;
        fn CFRelease(cf: *const c_void);
    }

    pub struct Guard(IoPmAssertionId);
    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: FFI; releasing a valid assertion id we created.
            unsafe { IOPMAssertionRelease(self.0) };
        }
    }

    /// SAFETY: builds a CoreFoundation string from `s`; caller CFReleases it.
    unsafe fn cfstr(s: &str) -> CfStringRef {
        unsafe {
            match CString::new(s) {
                Ok(c) => CFStringCreateWithCString(std::ptr::null(), c.as_ptr(), CF_ENCODING_UTF8),
                Err(_) => std::ptr::null(),
            }
        }
    }

    pub fn keep_awake(reason: &str) -> Option<Guard> {
        // SAFETY: FFI. Both CF strings are released before returning; on success
        // we own the assertion id and release it in Drop.
        unsafe {
            let atype = cfstr("PreventUserIdleSystemSleep"); // kIOPMAssertionTypePreventUserIdleSystemSleep
            let name = cfstr(reason);
            if atype.is_null() || name.is_null() {
                if !atype.is_null() {
                    CFRelease(atype);
                }
                if !name.is_null() {
                    CFRelease(name);
                }
                return None;
            }
            let mut id: IoPmAssertionId = 0;
            let r = IOPMAssertionCreateWithName(atype, ASSERTION_LEVEL_ON, name, &mut id);
            CFRelease(atype);
            CFRelease(name);
            (r == 0).then_some(Guard(id))
        }
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::process::{Child, Command, Stdio};

    /// Holds a logind idle+sleep inhibitor lock via a `systemd-inhibit` child;
    /// killing it on drop releases the lock.
    pub struct Guard(Option<Child>);
    impl Drop for Guard {
        fn drop(&mut self) {
            if let Some(mut c) = self.0.take() {
                let _ = c.kill();
                let _ = c.wait();
            }
        }
    }

    pub fn keep_awake(reason: &str) -> Option<Guard> {
        let child = Command::new("systemd-inhibit")
            .args([
                "--what=idle:sleep",
                "--who=ReachMyDevice",
                &format!("--why={reason}"),
                "--mode=block",
                "sleep",
                "infinity",
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .ok()?;
        Some(Guard(Some(child)))
    }
}

#[cfg(windows)]
mod imp {
    const ES_CONTINUOUS: u32 = 0x8000_0000;
    const ES_SYSTEM_REQUIRED: u32 = 0x0000_0001;

    extern "system" {
        fn SetThreadExecutionState(es_flags: u32) -> u32;
    }

    pub struct Guard;
    impl Drop for Guard {
        fn drop(&mut self) {
            // SAFETY: FFI; clear the requirement, allowing normal idle sleep again.
            unsafe { SetThreadExecutionState(ES_CONTINUOUS) };
        }
    }

    pub fn keep_awake(_reason: &str) -> Option<Guard> {
        // SAFETY: FFI. Returns 0 only on failure.
        let prev = unsafe { SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED) };
        (prev != 0).then_some(Guard)
    }
}

#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
mod imp {
    pub struct Guard;
    pub fn keep_awake(_reason: &str) -> Option<Guard> {
        None
    }
}
