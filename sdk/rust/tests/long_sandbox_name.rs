//! Integration tests covering sandbox names that approach the upstream
//! 128-byte limit.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --test long_sandbox_name --run-ignored=only

use microsandbox::{MAX_HOSTNAME_BYTES, MAX_SANDBOX_NAME_BYTES, Sandbox};
use test_utils::msb_test;

/// A 128-byte sandbox name spawns end-to-end. The guest hostname falls
/// back to a derived 64-byte form so `sethostname(2)` does not return
/// EINVAL.
#[msb_test]
async fn sandbox_with_128_byte_name_spawns() {
    let name = format!(
        "longname-{}",
        "x".repeat(MAX_SANDBOX_NAME_BYTES - "longname-".len())
    );
    assert_eq!(name.len(), MAX_SANDBOX_NAME_BYTES);

    let sandbox = Sandbox::builder(&name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .expect("create sandbox with 128-byte name");

    let out = sandbox
        .shell("hostname")
        .await
        .expect("read guest hostname");
    let hostname = out.stdout().expect("utf8").trim().to_owned();

    assert!(
        hostname.len() <= MAX_HOSTNAME_BYTES,
        "guest hostname must fit the UTS limit, got {} bytes: {hostname:?}",
        hostname.len()
    );

    sandbox.stop().await.ok();
    Sandbox::remove(&name).await.ok();
}
