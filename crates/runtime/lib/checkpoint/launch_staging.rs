//! Private scratch space for resolving archive inputs before sandbox creation.

use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use microsandbox_utils::{private_file, process_lock};

use super::migration::{io as private_io, namespace};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(windows)]
const PROFILE_STAGING: &str = "microsandbox-archive-staging";

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
            Ok(guard) => {
                // An earlier launch may have used the profile before this home was protected.
                // Failure to clean an old root should not prevent using the current one.
                if let Some(profile) = dirs::data_local_dir()
                    && let Err(error) = reap_profile_staging(&profile)
                {
                    tracing::warn!(%error, "could not clean up old profile archive staging");
                }
                (Ok(guard), "snapshot-launch-staging")
            }
            Err(home_error) => {
                // Archives can contain private guest data. Unpack under the
                // user's profile when the configured data drive is shared.
                let profile = dirs::data_local_dir().ok_or_else(|| io::Error::other(home_error))?;
                (namespace::configuration_home(&profile), PROFILE_STAGING)
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
        let _admission = lock_and_reap(&root)?;

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

#[cfg(windows)]
fn reap_profile_staging(profile: &Path) -> io::Result<()> {
    if !profile.join(PROFILE_STAGING).try_exists()? {
        return Ok(());
    }
    let authority = namespace::configuration_home(profile).map_err(io::Error::other)?;
    let root = authority.path.join(PROFILE_STAGING);
    private_io::verify_private_directory(&root).map_err(io::Error::other)?;
    lock_and_reap(&root).map(drop)
}

/// Return the admission lock so a creator can publish its new owner lock before
/// another process checks this root for abandoned extractions.
fn lock_and_reap(root: &Path) -> io::Result<File> {
    let lock = admission(root)?;
    for item in fs::read_dir(root)? {
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
    Ok(lock)
}

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

    #[cfg(windows)]
    #[test]
    fn protecting_home_reaps_abandoned_profile_staging_and_preserves_live_work() {
        use std::process::Command;

        let profile = dirs::data_local_dir().unwrap();
        let fixture = tempfile::tempdir_in(&profile).unwrap();
        let home = fixture.path().join("home");
        fs::create_dir(&home).unwrap();
        let acl = |args: &[&str]| {
            let output = Command::new("icacls")
                .arg(&home)
                .args(args)
                .output()
                .unwrap();
            assert!(output.status.success(), "{output:?}");
        };
        acl(&["/grant", "*S-1-5-11:(OI)(CI)(M)"]);
        let live = LaunchStaging::reserve(&home).unwrap();
        let profile_root = fs::canonicalize(profile)
            .unwrap()
            .join("microsandbox-archive-staging");
        assert_eq!(live.path().parent(), Some(profile_root.as_path()));
        let live_payload = live.path().join("contents");
        fs::write(&live_payload, b"still prepared").unwrap();

        // Leave the same on-disk state as a process that exited mid-extraction.
        // Admission keeps concurrent preparations out until the fixture is complete.
        let abandoned = profile_root.join(format!("op-{:032x}", rand::random::<u128>()));
        {
            let _admission = admission(&profile_root).unwrap();
            private_file::create_private_directory(&abandoned).unwrap();
            process_lock::create_new_lock_file(&abandoned.join("owner.lock")).unwrap();
            fs::write(abandoned.join("extracted"), b"unfinished").unwrap();
            acl(&["/remove:g", "*S-1-5-11"]);
        }

        let replacement = LaunchStaging::reserve(&home).unwrap();
        let home_root = fs::canonicalize(&home)
            .unwrap()
            .join("snapshot-launch-staging");
        assert_eq!(replacement.path().parent(), Some(home_root.as_path()));
        assert!(
            !abandoned.exists(),
            "left an abandoned extraction in the profile"
        );
        assert_eq!(fs::read(live_payload).unwrap(), b"still prepared");
    }

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
