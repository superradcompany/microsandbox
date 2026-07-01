//! Staleness check for the generated TypeScript bindings.
//!
//! typeshare is the sole codegen for the `@microsandbox/types` bindings; this
//! test regenerates them into a temp file and fails if the checked-in
//! `typescript/src/index.ts` has drifted. It is skipped when the `typeshare`
//! CLI is not on `PATH` (e.g. a minimal `cargo test` image) — the CI `just gen`
//! check installs the CLI and enforces staleness for both Go and TypeScript.

use std::path::PathBuf;
use std::process::Command;

#[test]
fn checked_in_bindings_match_generated_output() {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let lib_dir = manifest_dir.join("lib");
    let package_root = manifest_dir
        .parent()
        .expect("microsandbox-types rust crate should live under <package>/rust");
    let bindings_path = package_root.join("typescript/src/index.ts");

    let out_file = std::env::temp_dir().join("microsandbox-types-index-check.ts");

    let status = Command::new("typeshare")
        .arg(&lib_dir)
        .arg("--lang=typescript")
        .arg(format!("--output-file={}", out_file.display()))
        .status();

    let status = match status {
        Ok(status) => status,
        Err(err) => {
            eprintln!(
                "skipping bindings staleness check: typeshare CLI not runnable ({err}); \
                 run `cargo install typeshare-cli` to enforce"
            );
            return;
        }
    };
    assert!(
        status.success(),
        "typeshare failed to generate TypeScript bindings"
    );

    let generated = std::fs::read_to_string(&out_file)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", out_file.display()));
    let checked_in = std::fs::read_to_string(&bindings_path)
        .unwrap_or_else(|err| panic!("failed to read {}: {err}", bindings_path.display()));

    assert_eq!(
        checked_in,
        generated,
        "{} is stale; run `just gen` to refresh",
        bindings_path.display()
    );
}
