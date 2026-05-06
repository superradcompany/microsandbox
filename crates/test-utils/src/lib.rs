//! Internal test helpers for microsandbox integration tests.
//!
//! Use the [`msb_test`] attribute on async test functions; it expands to
//! `#[tokio::test] #[ignore]` and injects a call to [`init_isolated_home`]
//! at the start of the body so each test can be run in parallel without
//! sharing `~/.microsandbox` state.
//!
//! ```ignore
//! use test_utils::msb_test;
//!
//! #[msb_test]
//! async fn my_test() {
//!     // body — no manual home-dir setup needed.
//! }
//! ```

use std::path::{Path, PathBuf};

use tempfile::TempDir;

pub use test_macros::msb_test;

/// Env var that gates per-test home isolation.
///
/// When set (any value), [`init_isolated_home`] points microsandbox at a
/// fresh tempdir for state (db, sandboxes, cache, logs). When unset, the
/// helper is a no-op and tests run against the real `~/.microsandbox`
/// (suitable for quick local runs, but unsafe for parallel execution).
pub const ISOLATE_HOME_ENV: &str = "MSB_TEST_ISOLATE_HOME";

/// Env var that, when set, preserves the isolated tempdir on drop so its
/// contents (sqlite db, sandbox logs, etc.) can be inspected post-mortem.
pub const KEEP_HOME_ENV: &str = "MSB_TEST_KEEP_HOME";

/// Set up an isolated microsandbox home for this test if [`ISOLATE_HOME_ENV`]
/// is set, otherwise do nothing.
///
/// Returns a guard that the caller must hold for the full duration of the
/// test. Dropping the guard removes the tempdir on disk (unless
/// [`KEEP_HOME_ENV`] is set).
///
/// Isolation is achieved via the `MSB_HOME` env var, which microsandbox
/// reads in preference to `$HOME/.microsandbox`. The real installed msb
/// binary is reused via `MSB_PATH`; libkrunfw is resolved relative to it.
/// No symlinks, no `$HOME` mutation, no impact on tooling that reads
/// `$HOME` (npm cache, ssh keys, etc.).
///
/// Relies on the test runner using one process per test (e.g. `cargo
/// nextest`) — under plain libtest the env mutation leaks between tests
/// in the same binary.
pub fn init_isolated_home() -> IsolatedHome {
    if std::env::var_os(ISOLATE_HOME_ENV).is_none() {
        return IsolatedHome(None);
    }

    let real_home = PathBuf::from(
        std::env::var_os("HOME").expect("HOME must be set for integration-test setup"),
    );
    let real_msb_path = real_home.join(".microsandbox").join("bin").join("msb");
    if !real_msb_path.exists() {
        panic!(
            "required msb binary missing for isolated home: {}",
            real_msb_path.display()
        );
    }

    // Anchor the tempdir under `/tmp` explicitly. On macOS `TMPDIR` points at
    // `/var/folders/<hash>/T/...` (~49 chars), which combined with
    // `.microsandbox/sandboxes/<name>/<sock>` exceeds the 104-byte `SUN_LEN`
    // limit for Unix domain sockets and breaks sandbox agent relay setup.
    let mut builder = tempfile::Builder::new();
    builder.prefix("msb-");
    if std::env::var_os(KEEP_HOME_ENV).is_some() {
        builder.disable_cleanup(true);
    }
    let tempdir = builder
        .tempdir_in("/tmp")
        .expect("failed to create tempdir under /tmp");

    // SAFETY: each #[msb_test] runs in its own process under cargo-nextest,
    // so mutating env only affects this test and its subprocesses. Must run
    // before the first microsandbox API call.
    unsafe {
        std::env::set_var("MSB_HOME", tempdir.path());
        std::env::set_var("MSB_PATH", &real_msb_path);
    }

    IsolatedHome(Some(tempdir))
}

/// Guard returned by [`init_isolated_home`].
///
/// Holds the tempdir alive (when isolation is active) so it isn't deleted
/// while the test is still running.
pub struct IsolatedHome(Option<TempDir>);

impl IsolatedHome {
    /// Returns the path to the isolated home, if isolation is active.
    pub fn path(&self) -> Option<&Path> {
        self.0.as_ref().map(TempDir::path)
    }
}
