//! Binary entry point for `microsandbox-agentd`.
//!
//! Runs as PID 1 inside the microVM guest. Performs synchronous init
//! (mount filesystems, prepare runtime directories), then enters the async agent loop.

use std::process;

#[cfg(target_os = "linux")]
use microsandbox_agentd::{AgentdConfig, AgentdError, agent, clock, init};

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

    // Read all MSB_* environment variables once at startup and parse.
    let config = match AgentdConfig::from_env() {
        Ok(c) => c,
        Err(e) => {
            eprintln!("agentd: config parse failed: {e}");
            process::exit(1);
        }
    };

    // Phase 1: Synchronous init (mount filesystems, prepare runtime directories).
    let init_start = clock::boottime_ns();
    if let Err(e) = init::init(&config) {
        eprintln!("agentd: init failed: {e}");
        process::exit(1);
    }
    let init_time_ns = clock::boottime_ns() - init_start;

    // Phase 2: Build a single-threaded tokio runtime and run the agent loop.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("agentd: failed to build tokio runtime");

    rt.block_on(async {
        match agent::run(boot_time_ns, init_time_ns, &config).await {
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
