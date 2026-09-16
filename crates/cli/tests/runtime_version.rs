use std::process::Command;

use microsandbox::setup::{Version, resolve_runtime_version};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn packaged_version_matches_cargo_and_clap() {
    // Release validation can inspect the final stripped/signed artifact.
    let executable = std::env::var_os("MSB_VERSION_TEST_BINARY")
        .unwrap_or_else(|| env!("CARGO_BIN_EXE_msb").into());
    let expected = Version::parse(env!("CARGO_PKG_VERSION")).unwrap();
    assert_eq!(
        resolve_runtime_version(&executable).unwrap(),
        Some(expected.clone())
    );
    let output = Command::new(executable).arg("--version").output().unwrap();
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap().trim(),
        format!("msb {expected}")
    );
}
