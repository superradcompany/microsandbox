//! Private scratch space for resolving archive inputs before sandbox creation.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use microsandbox_utils::{private_file, process_lock};

use super::migration::{io as private_io, namespace};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// No sandbox or snapshot catalog entry is needed for a prepared launch. A live
/// process owns its directory through an OS lock, even while a builder is idle.
pub struct LaunchStaging {
    path: PathBuf,
    owner: Option<File>,
    _home_authority: namespace::ConfigurationHome,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LaunchStaging {
    /// Reap abandoned preparations before allocating a private operation directory.
    pub fn reserve(home: &Path) -> io::Result<Self> {
        fs::create_dir_all(home)?;
        let authority = namespace::configuration_home(home);
        #[cfg(windows)]
        let (authority, name) = match authority {
            Ok(guard) => (Ok(guard), "snapshot-launch-staging"),
            Err(home_error) => {
                // Archives can contain private guest data. Unpack under the
                // user's profile when the configured data drive is shared.
                let profile = dirs::data_local_dir().ok_or_else(|| io::Error::other(home_error))?;
                (
                    namespace::configuration_home(&profile),
                    "microsandbox-archive-staging",
                )
            }
        };
        #[cfg(not(windows))]
        let name = "snapshot-launch-staging";
        let authority = authority.map_err(io::Error::other)?;
        let root = authority.path.join(name);
        // Two first-time builders may both attempt to publish the private root.
        // In that case, authenticate the winning directory before opening any files.
        if let Err(error) = private_io::private_directory(&root) {
            private_io::verify_private_directory(&root).map_err(|_| io::Error::other(error))?;
        }
        let _admission = admission(&root)?;
        for item in fs::read_dir(&root)? {
            let item = item?;
            let name = item.file_name();
            let Some(id) = name.to_str().and_then(|s| s.strip_prefix("op-")) else {
                continue;
            };
            if id.len() != 32 || !id.bytes().all(|c| c.is_ascii_hexdigit()) {
                continue;
            }
            let path = item.path();
            private_io::verify_private_directory(&path).map_err(io::Error::other)?;
            match process_lock::open_existing_lock_file(&path.join("owner.lock")) {
                Ok(owner) if !process_lock::try_lock_exclusive(&owner)? => continue,
                Ok(_) => {}
                // A crash can leave the directory before its owner file exists.
                // Admission excludes all active creators during that interval.
                Err(e) if e.kind() == io::ErrorKind::NotFound => {}
                Err(e) => return Err(e),
            }
            fs::remove_dir_all(path)?;
        }

        let path = root.join(format!("op-{:032x}", rand::random::<u128>()));
        private_file::create_private_directory(&path)?;
        let owner = process_lock::create_new_lock_file(&path.join("owner.lock"))?;
        process_lock::lock_exclusive(&owner)?;
        Ok(Self {
            path,
            owner: Some(owner),
            _home_authority: authority,
        })
    }

    /// Parent for this operation's archive extraction and cache scratch directories.
    pub fn path(&self) -> &Path {
        &self.path
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for LaunchStaging {
    fn drop(&mut self) {
        let root = self.path.parent().expect("staging has a parent");
        // On Windows the owner file must be closed before unlink. Admission covers
        // that interval so a concurrent recovery cannot race normal cleanup.
        if let Ok(_admission) = admission(root) {
            drop(self.owner.take());
            if let Err(error) = fs::remove_dir_all(&self.path) {
                tracing::warn!(%error, "archive launch staging cleanup will retry at the next preparation");
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn admission(root: &Path) -> io::Result<File> {
    let lock = process_lock::open_lock_file(&root.join("admission.lock"))?;
    process_lock::lock_exclusive(&lock)?;
    Ok(lock)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abandoned_preparation_is_recovered_and_live_preparations_are_preserved() {
        const CHILD_HOME: &str = "MSB_TEST_ABANDONED_LAUNCH_STAGING_HOME";
        if let Some(home) = std::env::var_os(CHILD_HOME) {
            let home = PathBuf::from(home);
            let stage = LaunchStaging::reserve(&home).unwrap();
            fs::write(stage.path().join("private-guest-data"), b"staged").unwrap();
            fs::write(
                home.join("abandoned-name"),
                stage.path().file_name().unwrap().to_str().unwrap(),
            )
            .unwrap();
            // Abrupt process exit closes kernel handles without running Rust destructors.
            std::process::exit(37);
        }
        let home = tempfile::tempdir().unwrap();
        let live = LaunchStaging::reserve(home.path()).unwrap();
        let checkpoint = live.path().join("contents");
        fs::write(&checkpoint, b"still prepared").unwrap();
        let name = std::thread::current().name().unwrap().to_owned();
        let child = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", &name])
            .env(CHILD_HOME, home.path())
            .status()
            .unwrap();
        assert_eq!(child.code(), Some(37));
        let name = fs::read_to_string(home.path().join("abandoned-name")).unwrap();
        let path = live.path().parent().unwrap().join(name);
        assert!(path.join("private-guest-data").is_file());
        let replacement = LaunchStaging::reserve(home.path()).unwrap();
        assert!(!path.exists());
        assert_eq!(fs::read(&checkpoint).unwrap(), b"still prepared");
        let remaining = replacement.path().to_owned();
        drop(replacement);
        assert!(!remaining.exists());
        drop(live);
        assert!(!checkpoint.exists());
    }
}
