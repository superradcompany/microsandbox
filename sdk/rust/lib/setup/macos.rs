//! macOS host prerequisite checks for local sandbox execution.
//!
//! The local runtime requires Apple silicon; Intel Macs (and x86_64 binaries
//! running under Rosetta) cannot run sandboxes. macOS needs no separate
//! hypervisor feature toggle, so there is nothing to fix automatically.

use super::host::{Check, Problem, Section};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Diagnose macOS host virtualization prerequisites.
pub(super) fn host_section() -> (Section, Vec<Problem>) {
    let arch = std::env::consts::ARCH;
    let mut checks = vec![Check::info("Platform", &format!("macOS {arch}"))];
    let mut problems = Vec::new();

    if arch == "aarch64" {
        checks.push(Check::pass("Architecture", "Apple silicon (arm64)"));
    } else {
        checks.push(Check::fail("Architecture", "unsupported"));
        problems.push(Problem::new(
            "this Mac cannot run local sandboxes",
            vec![
                "local execution requires Apple silicon (arm64)".to_string(),
                format!("this process is running as {arch} (Intel, or x86_64 under Rosetta)"),
                "no automatic fix is available; use an Apple silicon host or a remote runtime"
                    .to_string(),
            ],
        ));
    }

    (
        Section {
            title: "Host".to_string(),
            checks,
        },
        problems,
    )
}
