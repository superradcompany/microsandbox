//! Public job selectors and aliases must not change ordinary sandbox command parsing.

use std::process::Command;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn job_shortcuts_and_full_forms_have_matching_selectors() {
    for command in [
        "jobs", "attach", "signal", "kill", "eof", "logs", "inspect", "wait",
    ] {
        for prefix in [vec![], vec!["sandbox"]] {
            let output = Command::new(env!("CARGO_BIN_EXE_msb"))
                .args(prefix)
                .args([command, "--help"])
                .output()
                .unwrap();
            assert!(output.status.success(), "{command}: {:?}", output.stderr);
            let help = String::from_utf8(output.stdout).unwrap();
            assert_eq!(
                help.contains("--job "),
                command != "jobs",
                "{command}: {help}"
            );
        }
    }
}

#[test]
fn incompatible_detached_flags_fail_before_sandbox_lookup() {
    for flags in [
        ["--detach", "--stream"],
        ["--tty", "--no-stdin"],
        ["--tty", "--no-tty"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_msb"))
            .arg("exec")
            .args(flags)
            .args(["absent-sandbox", "--", "true"])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(2));
        assert!(String::from_utf8_lossy(&output.stderr).contains("cannot be used with"));
    }
    let output = Command::new(env!("CARGO_BIN_EXE_msb"))
        .args(["jobs", "box", "--job", "anything"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
}
