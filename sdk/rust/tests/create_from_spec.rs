//! Integration tests for [`SandboxBuilder::from_spec_json`] — booting a sandbox
//! from a full `SandboxSpec` JSON, and overriding fields on top of it.
//!
//! These require KVM (or libkrun on macOS). The `#[msb_test]` attribute marks
//! them `#[ignore]`, so plain `cargo test` skips them. Run via:
//!
//!     cargo nextest run -p microsandbox --test create_from_spec --run-ignored=only

use microsandbox::{Sandbox, sandbox::SandboxBuilder};
use test_utils::msb_test;

const IMAGE: &str = "mirror.gcr.io/library/alpine";
const FROM_SPEC_VALUE: &str = "{\"message\":\"hello\",\"nested\":{\"quote\":\"a=b\"}}";

async fn cleanup(name: &str) {
    if let Ok(h) = Sandbox::get(name).await {
        let _ = h.kill().await;
        let _ = h.remove().await;
    }
}

async fn assert_shell_ok(sandbox: &Sandbox, command: &str, expected: &str) {
    let output = sandbox.shell(command).await.expect("shell command");
    let stdout = output.stdout().unwrap_or_default();
    let stderr = output.stderr().unwrap_or_default();
    assert!(
        output.status().success,
        "shell `{command}` failed: stdout=`{stdout}` stderr=`{stderr}`"
    );
    assert_eq!(stdout.trim(), expected);
}

/// A full `SandboxSpec` — image, resources, a guest hostname, and an env var.
/// Everything else falls back to the spec defaults.
fn spec_json(name: &str) -> String {
    serde_json::json!({
        "name": name,
        "image": { "Oci": { "reference": IMAGE } },
        "resources": { "cpus": 1, "memory_mib": 256 },
        "runtime": { "hostname": "spec-host" },
        "env": [{ "key": "FROM_SPEC", "value": FROM_SPEC_VALUE }]
    })
    .to_string()
}

/// A full spec JSON boots and its fields take effect in the guest — the whole
/// spec rides straight to the builder with nothing dropped.
#[msb_test]
async fn from_spec_json_boots_and_applies_spec_fields() {
    let name = "from-spec-json-fields";
    cleanup(name).await;

    let sandbox = SandboxBuilder::from_spec_json(&spec_json(name))
        .expect("from_spec_json")
        .replace()
        .create()
        .await
        .expect("create from spec");

    assert_shell_ok(&sandbox, r#"printf %s "$FROM_SPEC""#, FROM_SPEC_VALUE).await;
    assert_shell_ok(&sandbox, "hostname", "spec-host").await;
    let cmdline = sandbox
        .shell("cat /proc/cmdline")
        .await
        .expect("read kernel command line")
        .stdout()
        .unwrap_or_default();
    assert!(!cmdline.contains("FROM_SPEC"));
    assert!(!cmdline.contains(FROM_SPEC_VALUE));

    let _ = sandbox.stop().await;
    cleanup(name).await;
}

/// Options chained after `from_spec_json` override the spec (last-wins): the
/// builder's hostname wins over the spec's, while the rest of the spec survives.
#[msb_test]
async fn from_spec_json_options_override_spec() {
    let name = "from-spec-json-override";
    cleanup(name).await;

    let sandbox = SandboxBuilder::from_spec_json(&spec_json(name))
        .expect("from_spec_json")
        .hostname("override-host")
        .replace()
        .create()
        .await
        .expect("create from spec with override");

    assert_shell_ok(&sandbox, "hostname", "override-host").await;
    assert_shell_ok(&sandbox, r#"printf %s "$FROM_SPEC""#, FROM_SPEC_VALUE).await;

    let _ = sandbox.stop().await;
    cleanup(name).await;
}
