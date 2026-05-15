//! Tiny test init binary used by the handoff integration test.
//!
//! Behaviour:
//! - Reaps zombie children in a `waitpid(-1, ...)` loop, mirroring what
//!   any sane init does.
//! - Installs handlers for `SIGRTMIN+4`, `SIGTERM`, and `SIGINT` that
//!   set a flag; the main loop observes the flag and exits cleanly so
//!   the kernel panics PID 1 → VMM tears down → host sees clean
//!   shutdown.
//!
//! Built as a static Linux binary and patched into a guest rootfs at
//! `/sbin/init` by the integration test.

use std::sync::atomic::{AtomicI32, Ordering};

#[cfg(not(target_os = "linux"))]
fn main() {
    // The binary is only meaningful inside a Linux guest. Compiling on
    // other hosts is allowed (saves cargo from refusing to build the
    // workspace on macOS) but running it makes no sense.
    eprintln!("test-init is Linux-only");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
static SHUTDOWN: AtomicI32 = AtomicI32::new(0);

#[cfg(target_os = "linux")]
extern "C" fn handle_shutdown(sig: i32) {
    SHUTDOWN.store(sig, Ordering::SeqCst);
}

#[cfg(target_os = "linux")]
fn install_handler(sig: i32) {
    use std::mem;
    unsafe {
        let mut sa: libc::sigaction = mem::zeroed();
        sa.sa_sigaction = handle_shutdown as *const () as usize;
        libc::sigemptyset(&mut sa.sa_mask);
        sa.sa_flags = 0;
        libc::sigaction(sig, &sa, std::ptr::null_mut());
    }
}

#[cfg(target_os = "linux")]
fn main() {
    // Install shutdown handlers.
    let rtmin4 = libc::SIGRTMIN() + 4;
    install_handler(rtmin4);
    install_handler(libc::SIGTERM);
    install_handler(libc::SIGINT);

    // Reap loop. Sleep briefly between waitpid attempts; the signal
    // handler will interrupt us and set SHUTDOWN.
    loop {
        if SHUTDOWN.load(Ordering::SeqCst) != 0 {
            // Exiting from PID 1 panics the kernel and triggers
            // VMM-level shutdown.
            std::process::exit(0);
        }

        // Reap any pending zombies non-blockingly.
        loop {
            let mut status: i32 = 0;
            let pid = unsafe { libc::waitpid(-1, &mut status, libc::WNOHANG) };
            if pid <= 0 {
                break;
            }
        }

        // Sleep ~100ms.
        unsafe {
            let ts = libc::timespec {
                tv_sec: 0,
                tv_nsec: 100_000_000,
            };
            libc::nanosleep(&ts, std::ptr::null_mut());
        }
    }
}
