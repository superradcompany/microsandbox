//! Download and installation of microsandbox runtime dependencies.

use std::path::{Path, PathBuf};

use futures::StreamExt;
use tokio::io::AsyncWriteExt;

use crate::{MicrosandboxError, MicrosandboxResult};
use microsandbox_utils::{BASE_DIR_NAME, LIB_SUBDIR, LIBKRUNFW_ABI};

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
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Setup {
    /// Run the installation process.
    pub async fn install(&self) -> MicrosandboxResult<()> {
        let base_dir = self.resolve_base_dir()?;
        let lib_dir = base_dir.join(LIB_SUBDIR);
        tokio::fs::create_dir_all(&lib_dir).await?;

        self.install_libkrunfw(&lib_dir).await?;

        if !self.skip_verify {
            verify_installation(&lib_dir)?;
        }

        Ok(())
    }

    /// Install libkrunfw to the target directory.
    async fn install_libkrunfw(&self, lib_dir: &Path) -> MicrosandboxResult<()> {
        let filename = microsandbox_utils::libkrunfw_filename(std::env::consts::OS);
        let symlinks = libkrunfw_symlinks(&filename);

        let dest = lib_dir.join(&filename);
        if dest.exists() {
            return Ok(());
        }

        let url = microsandbox_utils::libkrunfw_download_url(
            std::env::consts::ARCH,
            std::env::consts::OS,
        );
        download_file(&url, &dest).await?;

        // Create symlinks.
        #[cfg(unix)]
        for (link_name, target) in &symlinks {
            let link_path = lib_dir.join(link_name);
            if link_path.exists() {
                tokio::fs::remove_file(&link_path).await?;
            }
            tokio::fs::symlink(target, &link_path).await?;
        }

        // Suppress unused variable warning on non-unix platforms.
        #[cfg(not(unix))]
        let _ = symlinks;

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
/// This creates `~/.microsandbox/lib/` and downloads libkrunfw if not already present.
pub async fn install() -> MicrosandboxResult<()> {
    Setup::builder().build().install().await
}

/// Check if microsandbox runtime dependencies are installed.
pub fn is_installed() -> bool {
    let Some(base_dir) = default_base_dir() else {
        return false;
    };
    let lib_dir = base_dir.join(LIB_SUBDIR);
    verify_installation(&lib_dir).is_ok()
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

async fn download_file(url: &str, dest: &Path) -> MicrosandboxResult<()> {
    let response = reqwest::get(url).await?.error_for_status()?;

    // Download to a temporary file first for atomic write.
    let part_path = {
        let mut s = dest.as_os_str().to_os_string();
        s.push(".part");
        PathBuf::from(s)
    };

    let result = write_part_file(&part_path, response).await;
    if result.is_err() {
        // Clean up partial .part file on error.
        let _ = tokio::fs::remove_file(&part_path).await;
    }
    result?;

    // Atomically move to final destination.
    tokio::fs::rename(&part_path, dest).await?;

    Ok(())
}

async fn write_part_file(part_path: &Path, response: reqwest::Response) -> MicrosandboxResult<()> {
    let mut stream = response.bytes_stream();
    let file = tokio::fs::File::create(part_path).await?;
    let mut writer = tokio::io::BufWriter::new(file);

    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        writer.write_all(&chunk).await?;
    }
    writer.flush().await?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        tokio::fs::set_permissions(part_path, std::fs::Permissions::from_mode(0o755)).await?;
    }

    Ok(())
}
