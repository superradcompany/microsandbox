//! Stage bounded host-copy inputs before patch application.
//! Retain the staging owner until every consumer has stopped using the files.

mod files;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, LazyLock};

use microsandbox_types::Patch;
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

pub(crate) struct Prepared {
    patches: Option<Vec<Patch>>,
    _stage: Option<tempfile::TempDir>,
    _capacity: Option<OwnedSemaphorePermit>,
}

struct Budget {
    bytes: u64,
    entries: usize,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Prepared {
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
        fs::set_permissions(destination, metadata.permissions())
    }
    fn directory(&mut self, file: File, destination: &Path, depth: usize) -> io::Result<()> {
        let source_device = device(&file)?;
        let permissions = file.metadata()?.permissions();
        let directory = cap_std::fs::Dir::from_std_file(file.try_clone()?);
        fs::create_dir(destination)?;
        for entry in directory.entries()? {
            let entry = entry?;
            self.entry(depth + 1)?;
            let name = PathBuf::from(entry.file_name());
            #[cfg(target_os = "linux")]
            let child = files::open_child(&file, &name)?;
            #[cfg(not(target_os = "linux"))]
            let child = {
                let mut options = cap_std::fs::OpenOptions::new();
                options.read(true);
                use cap_std::fs::OpenOptionsExt;
                options._cap_fs_ext_follow(cap_primitives::fs::FollowSymlinks::No);
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
        // Set modes last so a read-only input directory can still be materialized.
        fs::set_permissions(destination, permissions)
    }
}
//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn prepare(patches: &[Patch], enabled: bool) -> MicrosandboxResult<Prepared> {
    if !enabled {
        return Ok(Prepared {
            patches: None,
            _stage: None,
            _capacity: None,
        });
    }
    let mut patches = patches.to_vec();
    for patch in &mut patches {
        if let Patch::CopyFile { src, .. } | Patch::CopyDir { src, .. } = patch {
            *src = std::path::absolute(&*src)?;
        }
    }
    let permit = CAPACITY
        .clone()
        .acquire_owned()
        .await
        .map_err(|error| MicrosandboxError::PatchFailed(error.to_string()))?;
    tokio::task::spawn_blocking(move || {
        let stage = tempfile::Builder::new().prefix("msb-copy-").tempdir()?;
        let mut budget = Budget {
            bytes: 0,
            entries: 0,
        };
        let mut prepared = Vec::new();
        for (index, mut patch) in patches.into_iter().enumerate() {
            budget.entry(0)?;
            match &mut patch {
                Patch::CopyFile { src, .. } => {
                    let output = stage.path().join(index.to_string());
                    budget.file(files::open_regular(src, false)?, &output)?;
                    *src = output;
                }
                Patch::CopyDir { src, .. } => {
                    let output = stage.path().join(index.to_string());
                    budget.directory(files::open_directory(src)?, &output, 0)?;
                    *src = output;
                }
                Patch::Text { content, .. } | Patch::Append { content, .. } => {
                    budget.add(content.len() as u64)?
                }
                Patch::File { content, .. } => budget.add(content.len() as u64)?,
                _ => {}
            }
            prepared.push(patch);
        }
        Ok::<_, io::Error>(Prepared {
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

    #[tokio::test]
    async fn staged_copy_is_independent_of_later_source_writes() {
        let source = tempfile::tempdir().unwrap();
        let file = source.path().join("data");
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
