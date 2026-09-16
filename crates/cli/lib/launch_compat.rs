//! Routing for the old private launcher without shadowing public sandbox commands.

use std::ffi::OsString;

use clap::Parser;

use crate::{log_args::LogArgs, machine_cmd::MachineArgs};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Parser)]
struct LegacyInvocation {
    #[command(flatten)]
    logs: LogArgs,
    #[command(flatten)]
    machine: MachineArgs,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Rewrite only a complete legacy internal invocation, returning whether its boot codec is required.
pub fn route_legacy_launch(args: &mut [OsString]) -> bool {
    if args.get(1).is_none_or(|arg| arg != "sandbox") {
        return false;
    }
    // Validate the whole argv using the internal grammar before routing. Scanning
    // for flags alone would mistake `sandbox --debug exec ... --name` for a launch.
    let Ok(legacy) =
        LegacyInvocation::try_parse_from(args.iter().take(1).chain(args.iter().skip(2)))
    else {
        return false;
    };
    #[cfg(unix)]
    let has_config = legacy.machine.config_fd.is_some() || legacy.machine.config_file.is_some();
    #[cfg(not(unix))]
    let has_config = legacy.machine.config_file.is_some();
    if !has_config {
        return false;
    }
    args[1] = "machine".into();
    true
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_internal_sandbox_invocations_are_routed() {
        for command in [
            vec!["msb", "sandbox", "list"],
            vec!["msb", "sandbox", "exec", "demo", "--", "--name"],
            vec!["msb", "sandbox", "--help"],
            vec!["msb", "sbx", "--name", "demo"],
        ] {
            let mut args: Vec<_> = command.into_iter().map(OsString::from).collect();
            assert!(!route_legacy_launch(&mut args));
        }
        let mut args: Vec<_> = [
            "msb",
            "sandbox",
            "--debug",
            "--name",
            "demo",
            "--sandbox-id",
            "1",
            "--config-file",
            "launch.json",
        ]
        .into_iter()
        .map(OsString::from)
        .collect();
        assert!(route_legacy_launch(&mut args));
        assert_eq!(args[1], "machine");
        let mut args: Vec<_> = ["msb", "sandbox", "--debug", "pause", "demo"]
            .into_iter()
            .map(OsString::from)
            .collect();
        assert!(!route_legacy_launch(&mut args));
    }
}
