//! Integration tests for relay correlation ID handling.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --test correlation_ids --run-ignored=only

use std::time::Duration;

use microsandbox::Sandbox;
use test_utils::msb_test;

/// `core.shutdown` is a process-level control frame sent with correlation ID
/// 0, not a client-owned request/session ID. The relay must allow it even
/// though normal client frames are restricted to the assigned ID range.
#[msb_test]
async fn shutdown_control_id_zero_stops_sandbox() {
    let name = "correlation-shutdown-id-zero";

    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .expect("create sandbox");

    let stop_result = tokio::time::timeout(Duration::from_secs(30), sandbox.stop_and_wait()).await;

    if stop_result.is_err() {
        if let Ok(mut h) = Sandbox::get(name).await {
            let _ = h.kill().await;
            let _ = h.remove().await;
        }
    }
    Sandbox::remove(name).await.ok();

    stop_result
        .expect("stop_and_wait timed out; relay likely rejected core.shutdown id 0")
        .expect("stop_and_wait failed");
}
