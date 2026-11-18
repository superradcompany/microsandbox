//! Stage bounded host-copy inputs before patch application.
//! Retain the staging owner until every consumer has stopped using the files.

mod files;
use std::collections::HashMap;
#[cfg(unix)]
use std::fs::Permissions;
use std::fs::{self, File};
use std::io::{self, Read, Write};
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf, absolute};
use std::sync::{Arc, LazyLock};

#[cfg(not(target_os = "linux"))]
use cap_primitives::fs::FollowSymlinks;
use cap_std::fs::Dir;
#[cfg(not(target_os = "linux"))]
use cap_std::fs::{OpenOptions, OpenOptionsExt};
use microsandbox_types::Patch;
use tempfile::{Builder, TempDir};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_BYTES: u64 = 64 * 1024 * 1024;
const MAX_ENTRIES: usize = 4096;
const MAX_DEPTH: usize = 32;
static CAPACITY: LazyLock<Arc<Semaphore>> = LazyLock::new(|| Arc::new(Semaphore::new(2)));

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
pub(crate) struct Prepared {
    modes: HashMap<PathBuf, u32>,
    patches: Option<Vec<Patch>>,
    _stage: Option<TempDir>,
    _capacity: Option<OwnedSemaphorePermit>,
}

struct Budget {
    modes: HashMap<PathBuf, u32>,
    bytes: u64,
    entries: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Prepared {
    pub(crate) fn mode(&self, path: &Path) -> Option<u32> {
        self.modes.get(path).copied()
    }

    pub(crate) fn patches<'a>(&'a self, original: &'a [Patch]) -> &'a [Patch] {
        self.patches.as_deref().unwrap_or(original)
    }
}

impl Budget {
    fn add(&mut self, bytes: u64) -> io::Result<()> {
        self.bytes = self
            .bytes
            .checked_add(bytes)
            .ok_or_else(|| io::Error::other("copy byte budget overflow"))?;
        if self.bytes > MAX_BYTES {
            return Err(io::Error::other("copy sources exceed 64 MiB"));
        }
        Ok(())
    }
    fn entry(&mut self, depth: usize) -> io::Result<()> {
        self.entries += 1;
        if self.entries > MAX_ENTRIES || depth > MAX_DEPTH {
            return Err(io::Error::other("copy entry or depth budget exceeded"));
        }
        Ok(())
    }
    fn file(&mut self, file: File, destination: &Path) -> io::Result<()> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::other("copy source is not regular"));
        }
        if metadata.len() > MAX_BYTES - self.bytes {
            return Err(io::Error::other(
                "copy source exceeds remaining byte budget",
            ));
        }
        let mut output = File::options()
            .write(true)
            .create_new(true)
            .open(destination)?;
        // A concurrent writer may grow the file after fstat. Bound the actual read too.
        let count = io::copy(&mut file.take(MAX_BYTES - self.bytes + 1), &mut output)?;
        self.add(count)?;
        output.flush()?;
        #[cfg(unix)]
        output.set_permissions(Permissions::from_mode(0o600))?;
        #[cfg(unix)]
        self.modes.insert(
            destination.to_path_buf(),
            metadata.permissions().mode() & 0o7777,
        );
        // Staging belongs to this process, regardless of who owned the input.
        // Leave owner access intact; consumers apply the separately retained mode.
        Ok(())
    }
    fn directory(&mut self, file: File, destination: &Path, depth: usize) -> io::Result<()> {
        let source_device = device(&file)?;
        #[cfg(unix)]
        let permissions = file.metadata()?.permissions();
        let directory = Dir::from_std_file(file.try_clone()?);
        fs::create_dir(destination)?;
        #[cfg(unix)]
        fs::set_permissions(destination, Permissions::from_mode(0o700))?;
        for entry in directory.entries()? {
            let entry = entry?;
            self.entry(depth + 1)?;
            let name = PathBuf::from(entry.file_name());
            #[cfg(target_os = "linux")]
            let child = files::open_child(&file, &name)?;
            #[cfg(not(target_os = "linux"))]
            let child = {
                let mut options = OpenOptions::new();
                options.read(true);
                options._cap_fs_ext_follow(FollowSymlinks::No);
                #[cfg(unix)]
                options.custom_flags(libc::O_NONBLOCK);
                directory.open_with(&name, &options)?.into_std()
            };
            if device(&child)? != source_device {
                return Err(io::Error::other("copy source crosses a filesystem"));
            }
            let output = destination.join(name);
            if child.metadata()?.is_dir() {
                self.directory(child, &output, depth + 1)?;
            } else {
                self.file(child, &output)?;
            }
        }
        #[cfg(unix)]
        self.modes
            .insert(destination.to_path_buf(), permissions.mode() & 0o7777);
        Ok(())
    }
}
//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn prepare(patches: &[Patch], enabled: bool) -> MicrosandboxResult<Prepared> {
    if !enabled {
        return Ok(Prepared::default());
    }
    let mut budget = Budget {
        bytes: 0,
        entries: 0,
        modes: HashMap::new(),
    };
    let mut sources = Vec::with_capacity(patches.len().min(MAX_ENTRIES));
    for patch in patches {
        budget.entry(0)?;
        let source = match patch {
            Patch::CopyFile { src, .. } | Patch::CopyDir { src, .. } => Some(absolute(src)?),
            Patch::Text { content, .. } | Patch::Append { content, .. } => {
                budget.add(content.len() as u64)?;
                None
            }
            Patch::File { content, .. } => {
                budget.add(content.len() as u64)?;
                None
            }
            _ => None,
        };
        sources.push(source);
    }
    let permit = CAPACITY
        .clone()
        .acquire_owned()
        .await
        .map_err(|error| MicrosandboxError::PatchFailed(error.to_string()))?;
    // Bound inline payloads and acquire capacity before cloning their bytes.
    // Resolve host paths before the wait without canonicalizing away symlinks.
    let mut patches = patches.to_vec();
    for (patch, source) in patches.iter_mut().zip(sources) {
        if let Patch::CopyFile { src, .. } | Patch::CopyDir { src, .. } = patch {
            *src = source.expect("copy source was resolved");
        }
    }
    tokio::task::spawn_blocking(move || {
        let stage = Builder::new().prefix("msb-copy-").tempdir()?;
        let mut prepared = Vec::new();
        for (index, mut patch) in patches.into_iter().enumerate() {
            match &mut patch {
                Patch::CopyFile { src, .. } => {
                    let output = stage.path().join(index.to_string());
                    let source = files::open_regular(src, false)?;
                    budget.file(source, &output)?;
                    *src = output;
                }
                Patch::CopyDir { src, .. } => {
                    let output = stage.path().join(index.to_string());
                    budget.directory(files::open_directory(src)?, &output, 0)?;
                    *src = output;
                }
                _ => {}
            }
            prepared.push(patch);
        }
        Ok::<_, io::Error>(Prepared {
            modes: budget.modes,
            patches: Some(prepared),
            _stage: Some(stage),
            _capacity: Some(permit),
        })
    })
    .await
    .map_err(|error| MicrosandboxError::PatchFailed(error.to_string()))?
    .map_err(|error| {
        MicrosandboxError::PatchFailed(format!("unsafe or oversized copy source: {error}"))
    })
}

fn device(file: &File) -> io::Result<u64> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        Ok(file.metadata()?.dev())
    }
    #[cfg(not(unix))]
    {
        let _ = file;
        Ok(0)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::MetadataExt;

    #[test]
    fn staged_file_keeps_owner_access_without_changing_its_destination_mode() {
        let source = tempfile::tempdir().unwrap();
        let source_path = source.path().join("source");
        fs::write(&source_path, b"group readable").unwrap();
        let file = File::open(&source_path).unwrap();
        // Metadata can become group-readable-only after admission. The held
        // descriptor still reads it, but applying its mode to staging would
        // make the newly owned file unreadable to this process.
        fs::set_permissions(&source_path, Permissions::from_mode(0o040)).unwrap();
        let destination = source.path().join("staged");
        let mut budget = Budget {
            modes: HashMap::new(),
            bytes: 0,
            entries: 0,
        };
        budget.file(file, &destination).unwrap();
        assert_eq!(fs::read(&destination).unwrap(), b"group readable");
        assert_eq!(budget.modes[&destination], 0o040);
        assert_eq!(fs::metadata(&destination).unwrap().mode() & 0o777, 0o600);
    }

    #[tokio::test]
    async fn copy_source_paths_preserve_parent_steps_through_search_only_directories() {
        let fixture = tempfile::tempdir().unwrap();
        let root = fixture.path().canonicalize().unwrap();
        fs::create_dir(root.join("search-only")).unwrap();
        fs::create_dir(root.join("step")).unwrap();
        fs::write(root.join("search-only/data"), b"payload").unwrap();
        fs::set_permissions(root.join("search-only"), Permissions::from_mode(0o111)).unwrap();
        let patches = [Patch::CopyFile {
            src: root.join("step/../search-only/data"),
            dst: "/data".into(),
            mode: None,
            replace: false,
        }];
        let result = prepare(&patches, true).await;
        fs::set_permissions(root.join("search-only"), Permissions::from_mode(0o700)).unwrap();
        let prepared = result.unwrap();
        let [Patch::CopyFile { src, .. }] = prepared.patches(&patches) else {
            panic!("copy patch missing")
        };
        assert_eq!(fs::read(src).unwrap(), b"payload");
    }

    #[tokio::test]
    async fn staged_copy_is_independent_of_later_source_writes() {
        let source = tempfile::tempdir().unwrap();
        let file = source.path().canonicalize().unwrap().join("data");
        fs::write(&file, b"original").unwrap();
        let patches = [Patch::CopyFile {
            src: file.clone(),
            dst: "/data".into(),
            mode: None,
            replace: false,
        }];
        let prepared = prepare(&patches, true).await.unwrap();
        fs::write(&file, b"replacement").unwrap();
        let [Patch::CopyFile { src, .. }] = prepared.patches(&patches) else {
            panic!("copy patch missing")
        };
        assert_eq!(fs::read(src).unwrap(), b"original");
        assert_eq!(fs::read(file).unwrap(), b"replacement");
    }
}
