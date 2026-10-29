//! Net-enabled surface of `proxy_from_env`: the launch-protocol bit, the CLI flag, and
//! strict network-config parsing. No VM is started, so this runs on any host with a
//! virtualization-free CLI build.
#![cfg(feature = "net")]

use std::{
    fs,
    path::{Path, PathBuf},
    process::{Command, Output},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// A local image path that never exists: the CLI stops before any registry or runtime work.
const MISSING_IMAGE: &str = "./proxy-from-env-test-missing.qcow2";

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

fn msb() -> Command {
    Command::new(env!("CARGO_BIN_EXE_msb"))
}

/// Short home inside `/tmp` so runtime-derived socket paths stay valid.
fn home() -> tempfile::TempDir {
    tempfile::Builder::new()
        .prefix("msb-pfe-net-")
        .tempdir_in("/tmp")
        .expect("isolated home")
}

/// Run `msb` with the caller's proxy and `MSB_*` environment kept out of the test.
fn run(home: &Path, arguments: &[&str]) -> Output {
    let mut command = msb();
    for (key, _) in std::env::vars_os() {
        let name = key.to_string_lossy();
        if name.starts_with("MSB_") || name.to_ascii_lowercase().ends_with("_proxy") {
            command.env_remove(key);
        }
    }
    command
        .env("MSB_HOME", home)
        .env("MSB_BACKEND", "local")
        .env("NO_COLOR", "1")
        .args(arguments);
    command.output().expect("spawn the freshly built msb")
}

fn write(path: &Path, contents: &str) -> PathBuf {
    fs::write(path, contents).expect("write fixture");
    path.to_path_buf()
}

#[test]
fn launch_protocol_advertises_ambient_proxy_discovery() {
    let home = home();
    let output = run(home.path(), &["__launch-protocol"]);
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "__launch-protocol failed: {stdout}"
    );
    assert!(
        stdout.contains("\"protocols\":[2,1]"),
        "unexpected protocol list: {stdout}"
    );
    assert!(
        stdout.contains("\"proxy_from_env\":true"),
        "a net-enabled build must advertise proxy_from_env: {stdout}"
    );
}

#[test]
fn create_exposes_the_flag_and_rejects_non_boolean_values() {
    let home = home();
    let help = run(home.path(), &["create", "--help"]);
    assert!(help.status.success(), "create --help failed");
    let help_text = String::from_utf8_lossy(&help.stdout);
    assert!(
        help_text.contains("--proxy-from-env"),
        "create --help must document the flag"
    );
    assert!(
        help_text.contains("possible values: true, false"),
        "the flag must accept only true/false"
    );

    let rejected = run(
        home.path(),
        &[
            "create",
            "-n",
            "surface",
            "--proxy-from-env=maybe",
            MISSING_IMAGE,
        ],
    );
    let stderr = String::from_utf8_lossy(&rejected.stderr);
    assert_eq!(
        rejected.status.code(),
        Some(2),
        "clap must reject the value: {stderr}"
    );
    assert!(
        stderr.contains("--proxy-from-env") && stderr.contains("true, false"),
        "rejection must name the flag and its values: {stderr}"
    );

    // The accepted spellings parse through to the ordinary image error.
    for spelling in [
        "--proxy-from-env",
        "--proxy-from-env=true",
        "--proxy-from-env=false",
    ] {
        let output = run(
            home.path(),
            &["create", "-n", "surface", spelling, MISSING_IMAGE],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{spelling}: expected the image error"
        );
        assert!(
            stderr.contains("disk image does not exist"),
            "{spelling}: expected the deterministic image error, got {stderr}"
        );
    }
}

#[test]
fn network_config_accepts_booleans_only() {
    let home = home();
    let dir = home.path().to_path_buf();

    let good = write(
        &dir.join("good.yaml"),
        "policy: public\nproxy_from_env: true\n",
    );
    let output = run(
        home.path(),
        &[
            "create",
            "-n",
            "surface",
            "--net-conf",
            good.to_str().unwrap(),
            MISSING_IMAGE,
        ],
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(
        output.status.code(),
        Some(1),
        "expected the image error, got {stderr}"
    );
    assert!(
        stderr.contains("disk image does not exist"),
        "a boolean proxy_from_env must be accepted: {stderr}"
    );

    // `null` is not in this list: network config follows the CLI's optional-input
    // convention, where null means "omitted" rather than `false`.
    for invalid in ["\"yes\"", "1", "on"] {
        let path = write(
            &dir.join(format!("bad-{}.yaml", invalid.len())),
            &format!("policy: public\nproxy_from_env: {invalid}\n"),
        );
        let output = run(
            home.path(),
            &[
                "create",
                "-n",
                "surface",
                "--net-conf",
                path.to_str().unwrap(),
                MISSING_IMAGE,
            ],
        );
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(
            output.status.code(),
            Some(1),
            "proxy_from_env: {invalid} must be refused"
        );
        assert!(
            stderr.contains("invalid network config"),
            "proxy_from_env: {invalid} must be a network-config error, got {stderr}"
        );
        assert!(
            !stderr.contains("disk image does not exist"),
            "proxy_from_env: {invalid} must be refused before image resolution: {stderr}"
        );
    }
}
