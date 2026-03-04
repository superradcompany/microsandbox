//! Binary entry point for `microsandbox-agentd`.
//!
//! Runs as PID 1 inside the microVM guest. Performs synchronous init
//! (mount filesystems, prepare runtime directories), then enters the async agent loop.

//--------------------------------------------------------------------------------------------------
// Functions: main
//--------------------------------------------------------------------------------------------------

fn main() {
    // Phase 1: Synchronous init (mount filesystems, prepare runtime directories).
    if let Err(e) = microsandbox_agentd::init::init() {
        eprintln!("agentd: init failed: {e}");
        std::process::exit(1);
    }

    // Phase 2: Build a single-threaded tokio runtime and run the agent loop.
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("agentd: failed to build tokio runtime");

    rt.block_on(async {
        if let Err(e) = microsandbox_agentd::agent::run().await {
            eprintln!("agentd: agent loop error: {e}");
            std::process::exit(1);
        }
    });

    std::process::exit(0);
}
