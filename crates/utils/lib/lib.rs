//! Shared constants and utilities for the microsandbox project.

pub mod copy;
pub mod log_text;
pub mod size;
pub mod ttl_reverse_index;
pub mod wake_pipe;

//--------------------------------------------------------------------------------------------------
// Constants: Directory Layout
//--------------------------------------------------------------------------------------------------

/// Name of the microsandbox home directory (relative to user's home).
pub const BASE_DIR_NAME: &str = ".microsandbox";

/// Subdirectory for shared libraries (libkrunfw).
pub const LIB_SUBDIR: &str = "lib";

/// Subdirectory for helper binaries.
pub const BIN_SUBDIR: &str = "bin";

/// Subdirectory for the database.
pub const DB_SUBDIR: &str = "db";

/// Subdirectory for OCI layer cache.
pub const CACHE_SUBDIR: &str = "cache";

/// Subdirectory for per-sandbox state.
pub const SANDBOXES_SUBDIR: &str = "sandboxes";

/// Subdirectory for named volumes.
pub const VOLUMES_SUBDIR: &str = "volumes";

/// Subdirectory for snapshot artifacts.
pub const SNAPSHOTS_SUBDIR: &str = "snapshots";

/// Subdirectory for logs.
pub const LOGS_SUBDIR: &str = "logs";

/// Subdirectory for secrets.
pub const SECRETS_SUBDIR: &str = "secrets";

/// Subdirectory for TLS certificates.
pub const TLS_SUBDIR: &str = "tls";

/// Subdirectory for SSH keys.
pub const SSH_SUBDIR: &str = "ssh";

//--------------------------------------------------------------------------------------------------
// Constants: Binary Names
//--------------------------------------------------------------------------------------------------

/// Guest agent binary name.
pub const AGENTD_BINARY: &str = "agentd";

/// CLI binary name.
pub const MSB_BINARY: &str = "msb";

//--------------------------------------------------------------------------------------------------
// Constants: Versions
//--------------------------------------------------------------------------------------------------

/// Version for downloading prebuilt release artifacts.
///
/// This tracks the published crate/package version so the SDK and the
/// downloaded runtime bundle stay aligned.
pub const PREBUILT_VERSION: &str = env!("CARGO_PKG_VERSION");

/// libkrunfw release version. Keep in sync with justfile.
pub const LIBKRUNFW_VERSION: &str = "5.2.1";

/// libkrunfw ABI version (soname major). Keep in sync with justfile.
pub const LIBKRUNFW_ABI: &str = "5";

//--------------------------------------------------------------------------------------------------
// Constants: Filenames
//--------------------------------------------------------------------------------------------------

/// Database filename.
pub const DB_FILENAME: &str = "msb.db";

/// SQLite PRAGMAs applied to every connection for concurrent-access safety.
///
/// - WAL mode prevents `SQLITE_BUSY` when multiple processes access the DB
/// - 5-second busy timeout retries on transient lock contention
/// - Foreign key enforcement is off by default in SQLite
pub const SQLITE_PRAGMAS: &str =
    "PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000; PRAGMA foreign_keys = ON;";

/// Global configuration filename.
pub const CONFIG_FILENAME: &str = "config.json";

/// Project-local sandbox configuration filename.
pub const SANDBOXFILE_NAME: &str = "Sandboxfile";

//--------------------------------------------------------------------------------------------------
// Constants: GitHub
//--------------------------------------------------------------------------------------------------

/// GitHub organization.
pub const GITHUB_ORG: &str = "superradcompany";

/// Main repository name.
pub const MICROSANDBOX_REPO: &str = "microsandbox";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Returns the platform-specific libkrunfw filename.
pub fn libkrunfw_filename(os: &str) -> String {
    if os == "macos" {
        format!("libkrunfw.{LIBKRUNFW_ABI}.dylib")
    } else {
        format!("libkrunfw.so.{LIBKRUNFW_VERSION}")
    }
}

/// Returns the GitHub release download URL for libkrunfw.
pub fn libkrunfw_download_url(version: &str, arch: &str, os: &str) -> String {
    let (target_os, ext) = if os == "macos" {
        ("darwin", "dylib")
    } else {
        ("linux", "so")
    };

    format!(
        "https://github.com/{GITHUB_ORG}/{MICROSANDBOX_REPO}/releases/download/v{version}/libkrunfw-{target_os}-{arch}.{ext}"
    )
}

/// Returns the GitHub release download URL for the agentd binary.
pub fn agentd_download_url(version: &str, arch: &str) -> String {
    format!(
        "https://github.com/{GITHUB_ORG}/{MICROSANDBOX_REPO}/releases/download/v{version}/{AGENTD_BINARY}-{arch}"
    )
}

/// Returns the GitHub release download URL for the microsandbox bundle tarball.
pub fn bundle_download_url(version: &str, arch: &str, os: &str) -> String {
    let target_os = if os == "macos" { "darwin" } else { "linux" };
    format!(
        "https://github.com/{GITHUB_ORG}/{MICROSANDBOX_REPO}/releases/download/v{version}/{MICROSANDBOX_REPO}-{target_os}-{arch}.tar.gz"
    )
}
