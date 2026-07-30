//! Integration tests for combined stdout/stderr output (`2>&1` semantics).
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --test combined_output --run-ignored=only --test-threads 1

use microsandbox::{ExecEvent, Sandbox};
use test_utils::msb_test;

async fn stop_and_remove(name: &str) {
    let handle = Sandbox::get(name).await.expect("get");
    handle.stop().await.expect("stop");
    Sandbox::remove(name).await.expect("remove");
}

/// Alternating stdout/stderr writes from one sequential guest process must
/// arrive in emission order when combined, and stderr must stay empty.
#[msb_test]
async fn exec_combined_output_preserves_interleaved_order() {
    let name = "combined-output-order";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let script = r#"i=0; while [ $i -lt 16 ]; do echo "out$i"; echo "err$i" >&2; i=$((i+1)); done"#;
    let output = sandbox
        .exec_with("sh", |e| e.args(["-c", script]).combined_output(true))
        .await
        .expect("exec combined");

    stop_and_remove(name).await;

    assert!(output.status().success, "guest command failed");
    let expected: String = (0..16).map(|i| format!("out{i}\nerr{i}\n")).collect();
    assert_eq!(
        output.stdout().expect("stdout utf8"),
        expected,
        "stderr writes must interleave into stdout in emission order",
    );
    assert_eq!(
        output.stderr().expect("stderr utf8"),
        "",
        "combined mode must leave stderr empty",
    );
}

/// The streaming path must deliver everything as stdout events — no stderr
/// events at all.
#[msb_test]
async fn exec_stream_combined_output_emits_no_stderr_events() {
    let name = "combined-output-stream";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let mut handle = sandbox
        .exec_stream_with("sh", |e| {
            e.args(["-c", "echo s; echo e >&2"]).combined_output(true)
        })
        .await
        .expect("exec_stream combined");

    let mut stdout = Vec::new();
    let mut stderr_events = 0usize;
    while let Some(event) = handle.recv().await {
        match event {
            ExecEvent::Stdout(data) => stdout.extend_from_slice(&data),
            ExecEvent::Stderr(_) => stderr_events += 1,
            ExecEvent::Exited { code } => {
                assert_eq!(code, 0);
                break;
            }
            ExecEvent::Failed(payload) => panic!("exec failed: {payload:?}"),
            _ => {}
        }
    }

    stop_and_remove(name).await;

    assert_eq!(
        stderr_events, 0,
        "combined mode must not emit stderr events"
    );
    assert_eq!(String::from_utf8_lossy(&stdout), "s\ne\n");
}
