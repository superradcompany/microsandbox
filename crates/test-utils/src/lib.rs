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

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

pub use test_macros::msb_test;

/// Env var that gates per-test home isolation.
///
/// When set (any value), [`init_isolated_home`] redirects `HOME` at the
/// process level to a fresh tempdir-rooted layout. When unset, the helper is
/// a no-op and tests run against the real `~/.microsandbox` (suitable for
/// quick local runs, but unsafe for parallel execution).
pub const ISOLATE_HOME_ENV: &str = "MSB_TEST_ISOLATE_HOME";

/// Env var that, when set, preserves the isolated tempdir on drop so its
/// contents (sqlite db, sandbox logs, etc.) can be inspected post-mortem.
pub const KEEP_HOME_ENV: &str = "MSB_TEST_KEEP_HOME";

/// Set up an isolated `HOME` for this test if [`ISOLATE_HOME_ENV`] is set,
/// otherwise do nothing.
///
/// Returns a guard that the caller must hold for the full duration of the
/// test. Dropping the guard removes the tempdir on disk (unless
/// [`KEEP_HOME_ENV`] is set).
///
/// Layout when isolation is active:
///
/// ```text
/// /tmp/msb-XXXXXX/
///   .microsandbox/
///     bin/msb            -> symlink to $HOME/.microsandbox/bin/msb
///     lib/libkrunfw.*    -> symlinks to $HOME/.microsandbox/lib/*
/// ```
///
/// sandbox state, sqlite db, image cache, and volumes are then created fresh
/// inside `<tempdir>/.microsandbox/` during the test.
///
/// Relies on the test runner using one process per test (e.g. `cargo
/// nextest`) — under plain libtest the `HOME` mutation leaks between tests
/// in the same binary.
pub fn init_isolated_home() -> IsolatedHome {
    if std::env::var_os(ISOLATE_HOME_ENV).is_none() {
        return IsolatedHome(None);
    }

    let real_home = PathBuf::from(
        std::env::var_os("HOME").expect("HOME must be set for integration-test setup"),
    );
    let real_msb_home = real_home.join(".microsandbox");

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

    let msb_home = tempdir.path().join(".microsandbox");
    let bin_dir = msb_home.join("bin");
    let lib_dir = msb_home.join("lib");
    std::fs::create_dir_all(&bin_dir).expect("create bin dir");
    std::fs::create_dir_all(&lib_dir).expect("create lib dir");

    symlink_into(&real_msb_home.join("bin").join("msb"), &bin_dir.join("msb"));
    mirror_dir(&real_msb_home.join("lib"), &lib_dir);

    // SAFETY: each #[msb_test] runs in its own process under cargo-nextest,
    // so mutating HOME only affects this test and its subprocesses. Must run
    // before the first microsandbox API call.
    unsafe {
        std::env::set_var("HOME", tempdir.path());
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

fn symlink_into(src: &Path, dst: &Path) {
    if !src.exists() {
        panic!("required file missing for isolated home: {}", src.display());
    }
    symlink(src, dst)
        .unwrap_or_else(|e| panic!("symlink {} -> {}: {e}", dst.display(), src.display()));
}

fn mirror_dir(src: &Path, dst: &Path) {
    let entries =
        std::fs::read_dir(src).unwrap_or_else(|e| panic!("read_dir {}: {e}", src.display()));
    for entry in entries {
        let entry = entry.expect("read_dir entry");
        let src_path = entry.path();
        let dst_path = dst.join(entry.file_name());
        symlink(&src_path, &dst_path).unwrap_or_else(|e| {
            panic!(
                "symlink {} -> {}: {e}",
                dst_path.display(),
                src_path.display()
            )
        });
    }
}
