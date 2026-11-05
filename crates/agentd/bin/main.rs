//! Binary entry point for `microsandbox-agentd`.
//!
//! Runs as PID 1 inside the microVM guest. Performs synchronous init
//! (mount filesystems, prepare runtime directories), then enters the async agent loop.

use std::process;

#[cfg(target_os = "linux")]
use microsandbox_agentd::{AgentdError, BootParams, agent, clock, handoff, init};

//--------------------------------------------------------------------------------------------------
// Functions: main
//--------------------------------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("agentd is only supported on Linux");
    process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    // Capture CLOCK_BOOTTIME immediately — this represents kernel boot duration.
    let boot_time_ns = clock::boottime_ns();

    // Mount only what console discovery needs, then receive the typed
    // bootstrap frame that the host queued before entering the VM.
    if let Err(e) = init::prepare_bootstrap_console() {
        eprintln!("agentd: early init failed: {e}");
        process::exit(1);
    }
    let port = match agent::open_serial_port() {
        Ok(port) => port,
        Err(e) => {
            eprintln!("agentd: console open failed: {e}");
            process::exit(1);
        }
    };
    let (bootstrap, mut boot_console) = match agent::receive_bootstrap(&port) {
        Ok(result) => result,
        Err(e) => {
            exit_startup_failure(
                &port,
                &mut agent::BootConsoleState::default(),
                "bootstrap receive",
                &e,
            );
        }
    };
    let (mut boot, config) = match BootParams::from_bootstrap(bootstrap) {
        Ok(result) => result,
        Err(e) => {
            exit_startup_failure(&port, &mut boot_console, "bootstrap validation", &e);
        }
    };
    config.install_default_env();

    // Extract handoff spec (if any) before `init::init` consumes
    // `BootParams` by value. The handoff itself fires after init so
    // the new init inherits a fully-prepared filesystem.
    let handoff_spec = boot.take_handoff_init();

    // Phase 1: Synchronous init (mount filesystems, prepare runtime directories).
    let init_start = clock::boottime_ns();
    if let Err(e) = init::init(boot, || {
        agent::report_init_context(&port, &mut boot_console, config.user())
    }) {
        exit_startup_failure(&port, &mut boot_console, "init", &e);
    }
    let init_time_ns = clock::boottime_ns() - init_start;

    // Phase 1.5: Optional PID 1 handoff. Returns only in the child;
    // the parent execve's into the new init and never returns here.
    if let Some(spec) = handoff_spec
        && let Err(e) = handoff::do_handoff(spec)
    {
        exit_startup_failure(&port, &mut boot_console, "handoff", &e);
    }

    // Phase 2: Build a single-threaded tokio runtime and run the agent loop.
    let rt = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => exit_startup_failure(&port, &mut boot_console, "async runtime setup", &e.into()),
    };

    let bulk_port = match agent::open_and_bind_bulk_port() {
        Ok(port) => port,
        Err(e) => {
            exit_startup_failure(&port, &mut boot_console, "bulk transport binding", &e);
        }
    };

    rt.block_on(async {
        match agent::run(
            boot_time_ns,
            init_time_ns,
            &config,
            port,
            boot_console,
            bulk_port,
        )
        .await
        {
            Ok(()) => {}
            Err(AgentdError::Shutdown) => {}
            Err(e) => {
                eprintln!("agentd: agent loop error: {e}");
                process::exit(1);
            }
        }
    });

    process::exit(0);
}

#[cfg(target_os = "linux")]
fn exit_startup_failure(
    port: &std::fs::File,
    boot_console: &mut agent::BootConsoleState,
    stage: &str,
    error: &AgentdError,
) -> ! {
    let message = format!("{stage} failed: {error}");
    eprintln!("agentd: {message}");
    if let Err(report_error) = agent::report_init_failure(port, boot_console, &message, error) {
        eprintln!("agentd: could not report startup failure: {report_error}");
    }
    process::exit(1);
}
