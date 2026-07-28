//! End-to-end tests for the shared [`LogRegistry`] against real
//! microVMs.
//!
//! These boot alpine sandboxes, register their loggers with a single
//! host-scoped registry, and validate the registry-backed pipeline:
//! `sandbox.logger()` → `registry.register()` → `RegisteredSandboxLogger`
//! read/stream carries the sandbox's real output through to a consumer,
//! and multiple sandboxes coexist on one registry.
//!
//! Scope: these prove the registry *wiring* end to end. The fine-grained
//! routing, refcount, and ordering guarantees are covered deterministically
//! by the `logs::watch` unit tests; a followed stream also has a fallback
//! poll, so a live-delivery test here can't isolate the watcher from it.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --test log_registry_e2e --run-ignored=only

use std::time::Duration;

use futures::StreamExt;
use microsandbox::Sandbox;
use microsandbox::logs::{
    LogEntry, LogOptions, LogRegistry, LogSource, LogStreamOptions, LogStreamStart,
};
use test_utils::msb_test;

const ALPINE: &str = "mirror.gcr.io/library/alpine";

async fn start_alpine(name: &str) -> Sandbox {
    Sandbox::builder(name)
        .image(ALPINE)
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox")
}

async fn stop_and_remove(name: &str) {
    let handle = Sandbox::get(name).await.expect("get");
    handle.stop().await.expect("stop");
    Sandbox::remove(name).await.expect("remove");
}

fn contains(entry: &LogEntry, needle: &str) -> bool {
    std::str::from_utf8(&entry.data)
        .map(|s| s.contains(needle))
        .unwrap_or(false)
}

/// Snapshot path through the registry: register a running sandbox's
/// logger, exec a command, and `read` back its stdout. The registry
/// should report exactly one watched directory.
#[msb_test]
async fn registry_reads_sandbox_logs() {
    let name = "log-watch-registry-e2e-read";
    let marker = "registry-read-marker-4c1a";

    let registry = LogRegistry::new().expect("registry");
    let sandbox = start_alpine(name).await;

    let logger = sandbox.logger().expect("logger");
    let registered = registry.register(logger).await.expect("register");
    assert_eq!(registry.stats().registered_dirs, 1);

    sandbox
        .exec("sh", ["-c", &format!("echo {marker}")])
        .await
        .expect("exec");

    let entries = registered
        .read(&LogOptions::default())
        .await
        .expect("read logs");

    stop_and_remove(name).await;

    let matched: Vec<_> = entries.iter().filter(|e| contains(e, marker)).collect();
    assert!(
        !matched.is_empty(),
        "expected marker {marker:?} via registered logger; saw {} entries",
        entries.len(),
    );
    assert_eq!(matched[0].source, LogSource::Stdout);
}

/// Follow path through the registry: open a followed stream on the
/// registered logger, then exec. The shared-watcher pipeline must deliver
/// the new write to the subscriber within a short timeout.
#[msb_test]
async fn registry_follow_catches_live_writes() {
    let name = "log-watch-registry-e2e-follow";
    let marker = "registry-follow-marker-9d2f";

    let registry = LogRegistry::new().expect("registry");
    let sandbox = start_alpine(name).await;

    let logger = sandbox.logger().expect("logger");
    let registered = registry.register(logger).await.expect("register");

    // Start at "now" so boot-lifecycle entries are skipped and the only
    // match is the exec below.
    let cutoff = chrono::Utc::now();
    let mut stream = registered
        .stream(&LogStreamOptions {
            sources: Vec::new(),
            start: LogStreamStart::Since(cutoff),
            until: None,
            follow: true,
        })
        .await
        .expect("open registry stream");

    sandbox
        .exec("sh", ["-c", &format!("echo {marker}")])
        .await
        .expect("exec");

    let found = tokio::time::timeout(Duration::from_secs(8), async {
        while let Some(item) = stream.next().await {
            let entry = item.expect("stream item");
            if contains(&entry, marker) {
                return entry;
            }
        }
        panic!("stream ended without ever seeing marker {marker:?}");
    })
    .await
    .expect("marker arrived within timeout");

    stop_and_remove(name).await;

    assert_eq!(found.source, LogSource::Stdout);
}

/// One registry, two sandboxes: register both, confirm the registry
/// tracks two watched directories, and confirm each registered logger
/// reads back its own sandbox's output and not the other's.
#[msb_test]
async fn registry_serves_two_sandboxes() {
    let name_a = "log-watch-registry-e2e-multi-a";
    let name_b = "log-watch-registry-e2e-multi-b";
    let marker_a = "registry-multi-marker-A-6b3c";
    let marker_b = "registry-multi-marker-B-1e8d";

    let registry = LogRegistry::new().expect("registry");
    let sandbox_a = start_alpine(name_a).await;
    let sandbox_b = start_alpine(name_b).await;

    let registered_a = registry
        .register(sandbox_a.logger().expect("logger a"))
        .await
        .expect("register a");
    let registered_b = registry
        .register(sandbox_b.logger().expect("logger b"))
        .await
        .expect("register b");

    // Two distinct directories on the one registry.
    assert_eq!(registry.stats().registered_dirs, 2);

    sandbox_a
        .exec("sh", ["-c", &format!("echo {marker_a}")])
        .await
        .expect("exec a");
    sandbox_b
        .exec("sh", ["-c", &format!("echo {marker_b}")])
        .await
        .expect("exec b");

    let entries_a = registered_a
        .read(&LogOptions::default())
        .await
        .expect("read a");
    let entries_b = registered_b
        .read(&LogOptions::default())
        .await
        .expect("read b");

    stop_and_remove(name_a).await;
    stop_and_remove(name_b).await;

    assert!(
        entries_a.iter().any(|e| contains(e, marker_a)),
        "sandbox A logs missing its own marker",
    );
    assert!(
        !entries_a.iter().any(|e| contains(e, marker_b)),
        "sandbox A logs leaked sandbox B's marker",
    );
    assert!(
        entries_b.iter().any(|e| contains(e, marker_b)),
        "sandbox B logs missing its own marker",
    );
    assert!(
        !entries_b.iter().any(|e| contains(e, marker_a)),
        "sandbox B logs leaked sandbox A's marker",
    );
}
