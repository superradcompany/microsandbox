//! Binary entry point for `microsandbox-agentd`.
//!
//! Runs as PID 1 inside the microVM guest. Performs synchronous init
//! (mount filesystems, prepare runtime directories), then enters the async agent loop.

//--------------------------------------------------------------------------------------------------
// Functions: main
//--------------------------------------------------------------------------------------------------

#[cfg(not(target_os = "linux"))]
fn main() {
    eprintln!("agentd is only supported on Linux");
    std::process::exit(1);
}

#[cfg(target_os = "linux")]
fn main() {
    // Capture CLOCK_BOOTTIME immediately — this represents kernel boot duration.
    let boot_time_ns = microsandbox_agentd::clock::boottime_ns();

    if let Err(e) = microsandbox_agentd::init::apply_default_rlimits() {
        eprintln!("agentd: failed to apply default rlimits: {e}");
        std::process::exit(1);
    }

    // Phase 1: Synchronous init (mount filesystems, prepare runtime directories).
    let init_start = microsandbox_agentd::clock::boottime_ns();
    if let Err(e) = microsandbox_agentd::init::init() {
        eprintln!("agentd: init failed: {e}");
        std::process::exit(1);
    }
    let init_time_ns = microsandbox_agentd::clock::boottime_ns() - init_start;

    // Phase 2: Build a single-threaded tokio runtime and run the agent loop.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("agentd: failed to build tokio runtime");

    rt.block_on(async {
        match microsandbox_agentd::agent::run(boot_time_ns, init_time_ns).await {
            Ok(()) => {}
            Err(microsandbox_agentd::AgentdError::Shutdown) => {}
            Err(e) => {
                eprintln!("agentd: agent loop error: {e}");
                std::process::exit(1);
            }
        }
    });

    std::process::exit(0);
}
