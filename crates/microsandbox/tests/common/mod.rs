//! Shared helpers for integration tests.
//!
//! These tests spawn real `msb` subprocesses (which themselves spawn sandbox
//! processes). Subprocesses don't inherit [`microsandbox::config`] overrides
//! set via `set_config`, so to isolate per-test state we redirect `HOME` for
//! the test process (and therefore every child it spawns).
//!
//! Relies on `cargo-nextest` running each `#[test]` in its own process — this
//! keeps the `HOME` mutation from leaking between tests that would otherwise
//! share a process under plain libtest.

use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

/// Build an isolated `HOME` for this test and point the process at it.
///
/// Returns the `TempDir` guard. The caller must bind it (e.g. `let _home =
/// ...;`) so it survives until end of test; dropping removes the directory.
///
/// Layout created under the tempdir:
///
/// ```text
/// <tempdir>/
///   .microsandbox/
///     bin/msb            -> symlink to $REAL_HOME/.microsandbox/bin/msb
///     lib/libkrunfw.*    -> symlinks to $REAL_HOME/.microsandbox/lib/*
/// ```
///
/// sandbox state, sqlite db, image cache, and volumes are then created fresh
/// inside `<tempdir>/.microsandbox/` during the test.
pub fn init_isolated_home() -> TempDir {
    let real_home = PathBuf::from(
        std::env::var_os("HOME").expect("HOME must be set for integration-test setup"),
    );
    let real_msb_home = real_home.join(".microsandbox");

    // Anchor the tempdir under `/tmp` explicitly. On macOS `TMPDIR` points at
    // `/var/folders/<hash>/T/...` (~49 chars), which combined with
    // `.microsandbox/sandboxes/<name>/<sock>` exceeds the 104-byte `SUN_LEN`
    // limit for Unix domain sockets and breaks sandbox agent relay setup.
    // Set `MSB_TEST_KEEP_HOME=1` to preserve the tempdir for post-mortem.
    let mut builder = tempfile::Builder::new();
    builder.prefix("msb-");
    if std::env::var_os("MSB_TEST_KEEP_HOME").is_some() {
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

    // SAFETY: nextest runs each #[test] in its own process, so mutating HOME
    // only affects this test and its subprocesses. Must be called before any
    // crate code reads HOME — specifically before the first microsandbox API
    // call in the test.
    unsafe {
        std::env::set_var("HOME", tempdir.path());
    }

    tempdir
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
