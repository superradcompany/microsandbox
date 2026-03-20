//! Download and installation of microsandbox runtime dependencies.

use std::path::{Path, PathBuf};

use flate2::read::GzDecoder;
use futures::StreamExt;
use tar::Archive;

use crate::{MicrosandboxError, MicrosandboxResult};
use microsandbox_utils::{
    BASE_DIR_NAME, BIN_SUBDIR, LIB_SUBDIR, LIBKRUNFW_ABI, MSB_BINARY, MSBNET_BINARY,
};

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

    /// Skip verification after installation.
    #[builder(default = false)]
    skip_verify: bool,

    /// Force re-download even if binaries already exist.
    #[builder(default = false)]
    force: bool,
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
        let libkrunfw_name = microsandbox_utils::libkrunfw_filename(std::env::consts::OS);

        // Skip if all binaries are already present.
        if !self.force
            && bin_dir.join(MSB_BINARY).exists()
            && bin_dir.join(MSBNET_BINARY).exists()
            && lib_dir.join(&libkrunfw_name).exists()
        {
            return Ok(());
        }

        let version = env!("CARGO_PKG_VERSION");
        let url = microsandbox_utils::bundle_download_url(
            version,
            std::env::consts::ARCH,
            std::env::consts::OS,
        );

        tracing::info!(version, "downloading microsandbox runtime dependencies");
        let data = download_bytes(&url).await?;
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
/// This downloads the microsandbox bundle tarball and extracts `msb`, `msbnet`,
/// and `libkrunfw` to `~/.microsandbox/{bin,lib}/`.
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
    dirs::home_dir().map(|home| home.join(BASE_DIR_NAME))
}

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
