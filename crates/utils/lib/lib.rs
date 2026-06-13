//! Shared constants and utilities for the microsandbox project.

pub mod copy;
pub mod format;
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

/// Subdirectory for ephemeral runtime artifacts that should not be backed up.
pub const RUN_SUBDIR: &str = "run";

/// Subdirectory under `run` for metrics-related diagnostic artifacts.
pub const METRICS_RUN_SUBDIR: &str = "metrics";

/// Prefix used when constructing the POSIX shared-memory object name for the
/// live metrics registry. Combined with a stable hash of `GlobalConfig::home()`
/// so concurrent `MSB_HOME`-isolated environments do not collide.
///
/// Kept short because macOS limits `shm_open` names to ~31 bytes including the
/// leading slash; the final form is `<prefix>-<hex16>-vN` (28 bytes for
/// single-digit ABI versions).
pub const METRICS_SHM_PREFIX: &str = "/msb-met";

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

/// Derive a short, stable identifier from a path.
///
/// Used to build a POSIX shared-memory object name that depends only on the
/// resolved home directory, so two processes pointed at the same `MSB_HOME`
/// agree on a single registry without leaking the absolute path through a
/// public name.
pub fn stable_hash_path(path: &std::path::Path) -> String {
    // Avoid pulling sha2 into the utils crate for one filename; a stable
    // 64-bit FNV-1a over the OS-bytes is plenty for collision-resistance at
    // this scale (one entry per concurrent MSB_HOME on a host).
    let bytes = path.as_os_str().as_encoded_bytes();
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// Filename of the optional registry-name diagnostic file under `run/metrics`.
pub fn metrics_registry_name_filename(registry_abi_version: u32) -> String {
    format!("registry-v{registry_abi_version}.name")
}

/// Derive the POSIX shared-memory object name for a metrics registry.
pub fn metrics_registry_shm_name(home: &std::path::Path, registry_abi_version: u32) -> String {
    format!(
        "{}-{}-v{}",
        METRICS_SHM_PREFIX,
        stable_hash_path(home),
        registry_abi_version
    )
}

/// Resolve the microsandbox home directory.
///
/// Order of resolution:
/// 1. `MSB_HOME` env var (used as-is, no `.microsandbox` suffix appended)
/// 2. `~/.microsandbox/` (i.e. `dirs::home_dir().join(BASE_DIR_NAME)`)
/// 3. `./.microsandbox/` if no home is available
///
/// `MSB_HOME` lets CI and integration tests isolate microsandbox state
/// (db, sandboxes, cache, logs) per process without disturbing other
/// `$HOME`-rooted tooling.
pub fn resolve_home() -> std::path::PathBuf {
    if let Some(path) = std::env::var_os("MSB_HOME") {
        return std::path::PathBuf::from(path);
    }
    dirs::home_dir()
        .unwrap_or_else(|| std::path::PathBuf::from("."))
        .join(BASE_DIR_NAME)
}

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

/// Returns an HTTP client configured for release asset downloads.
#[cfg(feature = "http-client")]
pub fn http_client() -> ureq::Agent {
    ureq::Agent::config_builder()
        .tls_config(
            ureq::tls::TlsConfig::builder()
                .root_certs(ureq::tls::RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .new_agent()
}

/// Returns true when a user-provided text value should be interpreted as a
/// local filesystem path rather than a named resource or OCI reference.
pub fn looks_like_local_path_text(s: &str) -> bool {
    s == "." || s == ".." || s.starts_with('/') || s.starts_with("./") || s.starts_with("../")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// `MSB_HOME` is honoured verbatim (no `.microsandbox` suffix appended)
    /// so callers can isolate state per process without disturbing tooling
    /// that reads `$HOME` (npm cache, ssh keys, etc.).
    ///
    /// Uses a unique env var per test process to avoid clashing with other
    /// parallel tests that read `MSB_HOME`.
    #[test]
    fn test_resolve_home_respects_env_override() {
        // SAFETY: This test sets a process-global env var. Vitest-style
        // single-test isolation isn't available; rely on the test being
        // the sole reader of `MSB_HOME` in this binary.
        let custom = std::path::PathBuf::from("/tmp/msb-home-resolve-test-12345");
        unsafe { std::env::set_var("MSB_HOME", &custom) };
        let resolved = resolve_home();
        unsafe { std::env::remove_var("MSB_HOME") };
        assert_eq!(resolved, custom);
    }

    #[test]
    fn test_metrics_registry_names_include_abi_version() {
        let home = std::path::Path::new("/tmp/msb-home");

        assert_eq!(metrics_registry_name_filename(2), "registry-v2.name");
        assert_eq!(
            metrics_registry_shm_name(home, 2),
            format!("{}-{}-v2", METRICS_SHM_PREFIX, stable_hash_path(home))
        );
    }
}
