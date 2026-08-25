//! Download and installation of microsandbox runtime dependencies.

use std::path::{Path, PathBuf};
use tokio::process::Command;

use flate2::read::GzDecoder;
use futures::StreamExt;
use sha2::{Digest as _, Sha256};
use tar::Archive;

use crate::{MicrosandboxError, MicrosandboxResult};
#[cfg(unix)]
use microsandbox_utils::LIBKRUNFW_ABI;
use microsandbox_utils::{BIN_SUBDIR, LIB_SUBDIR, PREBUILT_VERSION};

use super::verify::verify_installation;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Builder for configuring and running the microsandbox setup process.
#[derive(Debug, typed_builder::TypedBuilder)]
pub struct Setup {
    /// Base directory for microsandbox files. Defaults to `~/.microsandbox`.
    #[builder(default, setter(strip_option, into))]
    base_dir: Option<PathBuf>,

    /// Target version to download. Defaults to `PREBUILT_VERSION` (compile-time).
    #[builder(default, setter(strip_option, into))]
    version: Option<String>,

    /// Skip verification after installation.
    #[builder(default = false)]
    skip_verify: bool,

    /// Force re-download even if binaries already exist.
    #[builder(default = false)]
    force: bool,

    /// Allow CI to install from the workspace `build/` directory.
    #[builder(default = true)]
    allow_ci_local_bundle: bool,

    /// Expected SHA-256 for the downloaded release bundle.
    ///
    /// When set, this digest is used as-is and the release's published
    /// `checksums.sha256` asset is not fetched — self-downgrade supplies the
    /// digest from the GitHub release API this way. When unset, the digest is
    /// fetched from the release's `checksums.sha256` asset before the bundle
    /// download. Either way, verification is fail-closed: the bundle is not
    /// extracted unless its bytes match the expected digest.
    #[builder(default, setter(strip_option, into))]
    expected_bundle_sha256: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Setup {
    /// Run the installation process.
    pub async fn install(&self) -> MicrosandboxResult<()> {
        let base_dir = self.resolve_base_dir()?;
        let bin_dir = base_dir.join(BIN_SUBDIR);
        let lib_dir = base_dir.join(LIB_SUBDIR);
        tokio::fs::create_dir_all(&bin_dir).await?;
        tokio::fs::create_dir_all(&lib_dir).await?;

        self.install_bundle(&bin_dir, &lib_dir).await?;

        if !self.skip_verify {
            verify_installation(&bin_dir, &lib_dir)?;
        }

        Ok(())
    }

    /// Download and extract the microsandbox bundle tarball.
    async fn install_bundle(&self, bin_dir: &Path, lib_dir: &Path) -> MicrosandboxResult<()> {
        let msb_name = microsandbox_utils::msb_binary_filename(std::env::consts::OS);
        let libkrunfw_name = microsandbox_utils::libkrunfw_filename(std::env::consts::OS);
        let version = self.version.as_deref().unwrap_or(PREBUILT_VERSION);

        // Skip if all binaries are already present and the installed msb
        // version matches the target version.
        if !self.force
            && lib_dir.join(&libkrunfw_name).exists()
            && installed_msb_version(&bin_dir.join(&msb_name))
                .await
                .as_deref()
                == Some(version)
        {
            tracing::debug!("setup: binaries already present, skipping download");
            return Ok(());
        }

        if self.allow_ci_local_bundle
            && install_ci_local_bundle(bin_dir, lib_dir, &msb_name, &libkrunfw_name).await?
        {
            tracing::debug!("setup: installed runtime dependencies from local CI build/");
            return Ok(());
        }

        let url = microsandbox_utils::bundle_download_url(
            version,
            std::env::consts::ARCH,
            std::env::consts::OS,
        );

        let expected_digest = match self.expected_bundle_sha256.clone() {
            Some(digest) => digest,
            None => fetch_bundle_digest(version, &url).await?,
        };

        tracing::info!(
            version = version,
            url = %url,
            "downloading microsandbox runtime dependencies"
        );
        let data = download_bytes(&url).await?;
        verify_bundle_digest(&data, &expected_digest)?;
        extract_bundle(&data, bin_dir, lib_dir)?;
        tracing::info!("microsandbox runtime dependencies installed");

        // Create libkrunfw symlinks.
        #[cfg(unix)]
        {
            let symlinks = libkrunfw_symlinks(&libkrunfw_name);
            for (link_name, target) in &symlinks {
                let link_path = lib_dir.join(link_name);
                if link_path.exists() || link_path.is_symlink() {
                    std::fs::remove_file(&link_path)?;
                }
                std::os::unix::fs::symlink(target, &link_path)?;
            }
        }

        Ok(())
    }

    fn resolve_base_dir(&self) -> MicrosandboxResult<PathBuf> {
        match &self.base_dir {
            Some(dir) => Ok(dir.clone()),
            None => default_base_dir().ok_or_else(|| {
                MicrosandboxError::Custom("could not determine home directory".to_string())
            }),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Install microsandbox runtime dependencies with default settings.
///
/// This downloads the microsandbox bundle tarball, verifies it against the
/// SHA-256 digest published in the release's `checksums.sha256` asset, and
/// extracts `msb` and `libkrunfw` to `~/.microsandbox/{bin,lib}/`.
pub async fn install() -> MicrosandboxResult<()> {
    Setup::builder().build().install().await
}

/// Check if microsandbox runtime dependencies are installed.
pub fn is_installed() -> bool {
    let Some(base_dir) = default_base_dir() else {
        return false;
    };
    let bin_dir = base_dir.join(BIN_SUBDIR);
    let lib_dir = base_dir.join(LIB_SUBDIR);
    verify_installation(&bin_dir, &lib_dir).is_ok()
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn default_base_dir() -> Option<PathBuf> {
    Some(microsandbox_utils::resolve_home())
}

#[cfg(unix)]
fn libkrunfw_symlinks(filename: &str) -> Vec<(String, String)> {
    if cfg!(target_os = "macos") {
        vec![("libkrunfw.dylib".to_string(), filename.to_string())]
    } else {
        let soname = format!("libkrunfw.so.{LIBKRUNFW_ABI}");
        vec![
            (soname.clone(), filename.to_string()),
            ("libkrunfw.so".to_string(), soname),
        ]
    }
}

/// Extract the bundle tarball, routing files to bin/ or lib/ based on name.
fn extract_bundle(data: &[u8], bin_dir: &Path, lib_dir: &Path) -> MicrosandboxResult<()> {
    let decoder = GzDecoder::new(std::io::Cursor::new(data));
    let mut archive = Archive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        let Some(filename) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };

        let dest = if filename.starts_with("libkrunfw") {
            lib_dir.join(filename)
        } else {
            bin_dir.join(filename)
        };

        entry.unpack(&dest)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&dest, std::fs::Permissions::from_mode(0o755))?;
        }
    }

    Ok(())
}

async fn download_bytes(url: &str) -> MicrosandboxResult<Vec<u8>> {
    let response = reqwest::get(url).await?.error_for_status()?;
    let mut stream = response.bytes_stream();
    let mut data = Vec::new();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        data.extend_from_slice(&chunk);
    }

    Ok(data)
}

/// Fetch the published SHA-256 digest for the bundle at `bundle_url` from the
/// release's `checksums.sha256` asset.
///
/// The checksums asset is served from the same release-download endpoint as
/// the bundle itself, so this adds no GitHub API calls (and no unauthenticated
/// rate-limit exposure) to the default install path. The fetch is fail-closed:
/// a release without published checksums, an unreachable checksums asset, or a
/// checksums file without an entry for this bundle all abort installation.
/// Callers that cannot rely on published checksums can supply
/// `expected_bundle_sha256` explicitly instead.
async fn fetch_bundle_digest(version: &str, bundle_url: &str) -> MicrosandboxResult<String> {
    let checksums_url = microsandbox_utils::checksums_download_url(version);
    let checksums = download_bytes(&checksums_url).await.map_err(|error| {
        MicrosandboxError::Custom(format!(
            "could not fetch release bundle checksums from {checksums_url}: {error}"
        ))
    })?;
    let checksums = String::from_utf8(checksums).map_err(|_| {
        MicrosandboxError::Custom(format!(
            "release checksums at {checksums_url} are not valid UTF-8"
        ))
    })?;
    let filename = bundle_url.rsplit('/').next().unwrap_or(bundle_url);
    bundle_digest_from_checksums(&checksums, filename)
}

/// Extract the digest for `filename` from `sha256sum`-formatted checksums.
fn bundle_digest_from_checksums(checksums: &str, filename: &str) -> MicrosandboxResult<String> {
    microsandbox_utils::bundle_digest_from_checksums(checksums, filename).ok_or_else(|| {
        MicrosandboxError::Custom(format!(
            "release checksums do not contain an entry for {filename}"
        ))
    })
}

fn verify_bundle_digest(data: &[u8], expected: &str) -> MicrosandboxResult<()> {
    let expected = expected.strip_prefix("sha256:").unwrap_or(expected);
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MicrosandboxError::Custom(
            "release bundle has an invalid published SHA-256 digest".into(),
        ));
    }
    let actual = hex::encode(Sha256::digest(data));
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(MicrosandboxError::Custom(format!(
            "release bundle SHA-256 mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

async fn installed_msb_version(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }

    let output = Command::new(path).arg("--version").output().await.ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout
        .trim()
        .strip_prefix("msb ")
        .map(std::string::ToString::to_string)
}

async fn install_ci_local_bundle(
    bin_dir: &Path,
    lib_dir: &Path,
    msb_name: &str,
    libkrunfw_name: &str,
) -> MicrosandboxResult<bool> {
    if std::env::var_os("CI").is_none() && std::env::var_os("GITHUB_ACTIONS").is_none() {
        return Ok(false);
    }

    let Some(build_dir) = workspace_build_dir() else {
        return Ok(false);
    };

    let msb_src = build_dir.join(msb_name);
    let lib_src = build_dir.join(libkrunfw_name);
    if !msb_src.is_file() || !lib_src.is_file() {
        return Ok(false);
    }

    tokio::fs::copy(&msb_src, bin_dir.join(msb_name)).await?;
    tokio::fs::copy(&lib_src, lib_dir.join(libkrunfw_name)).await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(
            bin_dir.join(msb_name),
            std::fs::Permissions::from_mode(0o755),
        )
        .await?;
        tokio::fs::set_permissions(
            lib_dir.join(libkrunfw_name),
            std::fs::Permissions::from_mode(0o755),
        )
        .await?;
    }

    #[cfg(unix)]
    {
        for (link_name, target) in libkrunfw_symlinks(libkrunfw_name) {
            let link_path = lib_dir.join(&link_name);
            if link_path.exists() || link_path.is_symlink() {
                std::fs::remove_file(&link_path)?;
            }
            std::os::unix::fs::symlink(&target, &link_path)?;
        }
    }

    Ok(true)
}

fn workspace_build_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent()?.parent()?;
    if !workspace_root.join("Cargo.toml").is_file() {
        return None;
    }
    Some(workspace_root.join("build"))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_bundle_digest_must_match_published_sha256() {
        verify_bundle_digest(
            b"hello",
            "sha256:2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824",
        )
        .unwrap();

        let error = verify_bundle_digest(b"changed", &"0".repeat(64)).unwrap_err();
        assert!(error.to_string().contains("SHA-256 mismatch"));
    }

    #[test]
    fn bundle_digest_is_selected_from_release_checksums() {
        let hello = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";
        let checksums = format!(
            "{}  agentd-aarch64\n\
             {hello}  microsandbox-darwin-aarch64.tar.gz\n\
             {} *microsandbox-linux-x86_64.tar.gz\n",
            "a".repeat(64),
            "b".repeat(64),
        );

        let digest =
            bundle_digest_from_checksums(&checksums, "microsandbox-darwin-aarch64.tar.gz").unwrap();
        assert_eq!(digest, hello);
        verify_bundle_digest(b"hello", &digest).unwrap();

        // Binary-mode `*` markers are stripped before matching.
        let digest =
            bundle_digest_from_checksums(&checksums, "microsandbox-linux-x86_64.tar.gz").unwrap();
        assert_eq!(digest, "b".repeat(64));
    }

    #[test]
    fn missing_checksums_entry_fails_closed() {
        let checksums = format!("{}  agentd-aarch64\n", "a".repeat(64));

        let error = bundle_digest_from_checksums(&checksums, "microsandbox-linux-aarch64.tar.gz")
            .unwrap_err();
        assert!(
            error
                .to_string()
                .contains("microsandbox-linux-aarch64.tar.gz")
        );
    }

    #[test]
    fn malformed_checksums_digest_fails_closed() {
        // A matching entry whose digest is not 64 hex chars must still fail
        // verification rather than being accepted.
        let checksums = "not-a-digest  microsandbox-linux-aarch64.tar.gz\n";

        let digest =
            bundle_digest_from_checksums(checksums, "microsandbox-linux-aarch64.tar.gz").unwrap();
        let error = verify_bundle_digest(b"hello", &digest).unwrap_err();
        assert!(error.to_string().contains("invalid published SHA-256"));
    }
}
