//! Integration tests for `Sandbox::builder(...).replace().create()`.
//!
//! Mirrors the bug pattern from PR #587 review: a second create with
//! the same name and `.replace()` while the first `Sandbox` handle is
//! still alive previously hung for ~30s because libkrun's SIGTERM
//! handler did a slow graceful shutdown of the VM and the loop polled
//! `kill(pid, 0)` against a process that was genuinely still alive.
//! The replace path now SIGTERMs with a configurable grace, then
//! escalates to SIGKILL — bounded by kernel time, not by handler
//! latency — so a second `.replace().create()` returns in the time it
//! takes to boot a VM rather than the 30s timeout.

use std::time::{Duration, Instant};

use microsandbox::{MicrosandboxError, Sandbox};
use test_utils::msb_test;

const IMAGE: &str = "mirror.gcr.io/library/alpine";

async fn cleanup(name: &str) {
    if let Ok(mut h) = Sandbox::get(name).await {
        let _ = h.kill().await;
        let _ = h.remove().await;
    }
}

/// First create succeeds; second create with `.replace()` while sb1 is
/// still alive completes promptly. The session timeout is generous
/// enough to also cover slow boots, but well under the legacy 30s
/// SIGTERM-poll deadline that was the bug's hallmark.
#[msb_test]
async fn replace_with_live_handle_does_not_hang() {
    let name = "replace-live-handle";
    cleanup(name).await;

    let sb1 = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .expect("first create");

    let started = Instant::now();
    let result = tokio::time::timeout(
        Duration::from_secs(120),
        Sandbox::builder(name)
            .image(IMAGE)
            .cpus(1)
            .memory(256)
            .replace()
            .create(),
    )
    .await;
    let elapsed = started.elapsed();

    let sb2 = match result {
        Err(_) => {
            // Best-effort cleanup before failing the assertion.
            drop(sb1);
            cleanup(name).await;
            panic!(
                "second .replace().create() did not return within 120s — bug regressed (was the 30s SIGTERM-poll path)"
            );
        }
        Ok(Err(err)) => {
            drop(sb1);
            cleanup(name).await;
            panic!("second .replace().create() failed: {err}");
        }
        Ok(Ok(sb2)) => sb2,
    };

    assert!(
        elapsed < Duration::from_secs(60),
        "second create took {elapsed:?}; expected sub-30s with SIGKILL escalation"
    );

    drop(sb2);
    drop(sb1);
    cleanup(name).await;
}

/// Without `.replace()`, a second create with the same name while sb1
/// is alive errors immediately with `SandboxAlreadyExists` instead of
/// blocking or surfacing a generic `Custom` error.
#[msb_test]
async fn create_without_replace_returns_typed_already_exists() {
    let name = "replace-typed-error";
    cleanup(name).await;

    let sb1 = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .expect("first create");

    let result = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .memory(256)
        .create()
        .await;
    let err = match result {
        Ok(_) => {
            drop(sb1);
            cleanup(name).await;
            panic!("second create without .replace() should error, got Ok");
        }
        Err(e) => e,
    };

    assert!(
        matches!(err, MicrosandboxError::SandboxAlreadyExists(_)),
        "expected SandboxAlreadyExists, got {err:?}"
    );

    drop(sb1);
    cleanup(name).await;
}

/// `.replace_grace(0)` skips SIGTERM and goes straight to SIGKILL.
/// Should be at least as fast as the default 10-second grace.
#[msb_test]
async fn replace_grace_zero_succeeds() {
    let name = "replace-grace-zero";
    cleanup(name).await;

    let sb1 = Sandbox::builder(name)
        .image(IMAGE)
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .expect("first create");

    let result = tokio::time::timeout(
        Duration::from_secs(120),
        Sandbox::builder(name)
            .image(IMAGE)
            .cpus(1)
            .memory(256)
            .replace_grace(Duration::from_secs(0))
            .create(),
    )
    .await
    .expect("did not hang")
    .expect("create");

    drop(result);
    drop(sb1);
    cleanup(name).await;
}
