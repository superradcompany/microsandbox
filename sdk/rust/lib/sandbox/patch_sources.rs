//! Stage bounded host-copy inputs before patch application.
//! Retain the staging owner until every consumer has stopped using the files.

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
use cap_std::fs::OpenOptions;
#[cfg(all(unix, not(target_os = "linux")))]
use cap_std::fs::OpenOptionsExt;
use microsandbox_types::Patch;
use tempfile::{Builder, TempDir};
use tokio::runtime::Handle;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::{MicrosandboxError, MicrosandboxResult};

mod files;

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
    stage: Option<TempDir>,
    capacity: Option<OwnedSemaphorePermit>,
}

/// Retains the process-wide patch staging capacity permit after staged files are consumed.
#[derive(Debug)]
pub(crate) struct CapacityGuard {
    _permit: Option<OwnedSemaphorePermit>,
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

    /// Remove the staged source directory on the current thread and keep only the
    /// capacity permit until the caller's downstream payload is also removed.
    pub(crate) fn into_capacity_guard(mut self) -> CapacityGuard {
        drop(self.stage.take());
        CapacityGuard {
            _permit: self.capacity.take(),
        }
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
    /// Stage the host directory `source`; read errors name the host path involved.
    fn directory(
        &mut self,
        file: File,
        source: &Path,
        destination: &Path,
        depth: usize,
    ) -> io::Result<()> {
        let source_device = device(&file).map_err(with_path(source))?;
        #[cfg(unix)]
        let permissions = file.metadata().map_err(with_path(source))?.permissions();
        let directory = Dir::from_std_file(file.try_clone().map_err(with_path(source))?);
        fs::create_dir(destination)?;
        #[cfg(unix)]
        fs::set_permissions(destination, Permissions::from_mode(0o700))?;
        for entry in directory.entries().map_err(with_path(source))? {
            let entry = entry.map_err(with_path(source))?;
            let name = PathBuf::from(entry.file_name());
            let source_child = source.join(&name);
            self.entry(depth + 1).map_err(with_path(&source_child))?;

            // Opening a device can have side effects, so reject special entries first.
            let file_type = entry.file_type().map_err(with_path(&source_child))?;
            if !file_type.is_file() && !file_type.is_dir() {
                return Err(with_path(&source_child)(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "copy source is not a regular file or directory",
                )));
            }
            #[cfg(target_os = "linux")]
            let child = files::open_child(&file, &name, file_type.is_dir())
                .map_err(with_path(&source_child))?;
            #[cfg(not(target_os = "linux"))]
            let child = {
                let mut options = OpenOptions::new();
                options.read(true);
                options._cap_fs_ext_follow(FollowSymlinks::No);
                #[cfg(unix)]
                options.custom_flags(
                    libc::O_NONBLOCK
                        | if file_type.is_dir() {
                            libc::O_DIRECTORY
                        } else {
                            0
                        },
                );
                directory
                    .open_with(&name, &options)
                    .map_err(with_path(&source_child))?
                    .into_std()
            };
            if device(&child).map_err(with_path(&source_child))? != source_device {
                return Err(with_path(&source_child)(io::Error::other(
                    "copy source crosses a filesystem",
                )));
            }

            let output = destination.join(name);
            if child.metadata().map_err(with_path(&source_child))?.is_dir() {
                self.directory(child, &source_child, &output, depth + 1)?;
            } else {
                self.file(child, &output)
                    .map_err(with_path(&source_child))?;
            }
        }
        #[cfg(unix)]
        self.modes
            .insert(destination.to_path_buf(), permissions.mode() & 0o7777);
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Prepared {
    /// Remove staged files on a blocking thread, then release staging capacity.
    fn drop(&mut self) {
        let Some(stage) = self.stage.take() else {
            return;
        };
        let capacity = self.capacity.take();
        let cleanup = move || {
            drop(stage);
            drop(capacity);
        };
        match Handle::try_current() {
            Ok(runtime) => {
                runtime.spawn_blocking(cleanup);
            }
            Err(_) => cleanup(),
        }
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
        budget.entry(0).map_err(source_failure)?;
        let source = match patch {
            Patch::CopyFile { src, .. } | Patch::CopyDir { src, .. } => Some(
                absolute(src)
                    .map_err(with_path(src))
                    .map_err(source_failure)?,
            ),
            Patch::Text { content, .. } | Patch::Append { content, .. } => {
                budget.add(content.len() as u64).map_err(source_failure)?;
                None
            }
            Patch::File { content, .. } => {
                budget.add(content.len() as u64).map_err(source_failure)?;
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
                    let source = files::open_regular(src, false).map_err(with_path(src))?;
                    budget.file(source, &output).map_err(with_path(src))?;
                    *src = output;
                }
                Patch::CopyDir { src, .. } => {
                    let output = stage.path().join(index.to_string());
                    let source = files::open_directory(src).map_err(with_path(src))?;
                    budget.directory(source, src, &output, 0)?;
                    *src = output;
                }
                _ => {}
            }
            prepared.push(patch);
        }
        Ok::<_, io::Error>(Prepared {
            modes: budget.modes,
            patches: Some(prepared),
            stage: Some(stage),
            capacity: Some(permit),
        })
    })
    .await
    .map_err(|error| MicrosandboxError::PatchFailed(error.to_string()))?
    .map_err(source_failure)
}

fn source_failure(error: io::Error) -> MicrosandboxError {
    MicrosandboxError::PatchFailed(format!("unsafe or oversized copy source: {error}"))
}

/// Prefix an error with the host source path it concerns.
fn with_path(path: &Path) -> impl FnOnce(io::Error) -> io::Error + '_ {
    move |error| io::Error::new(error.kind(), format!("{}: {error}", path.display()))
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
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    use std::os::unix::net::UnixListener;
    use std::sync::mpsc;
    use std::time::Duration;

    use tokio::runtime::Builder as RuntimeBuilder;

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

    #[tokio::test]
    async fn special_sources_are_refused_before_opening_them() {
        let fixture = tempfile::tempdir().unwrap();
        let source = fixture.path().canonicalize().unwrap().join("source");
        fs::create_dir(&source).unwrap();
        let fifo = source.join("fifo");
        let fifo_name = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo_name.as_ptr(), 0o600) }, 0);
        let socket = source.join("socket");
        let _listener = UnixListener::bind(&socket).unwrap();
        let copy_file = |src: &Path| Patch::CopyFile {
            src: src.to_path_buf(),
            dst: "/copied".into(),
            mode: None,
            replace: false,
        };
        let copy_dir = Patch::CopyDir {
            src: source.clone(),
            dst: "/copied".into(),
            replace: false,
        };

        for patch in [copy_file(&fifo), copy_dir.clone()] {
            // A blocking writer finishes opening only once some reader opens the FIFO.
            let (opened, wait) = mpsc::channel();
            let writer_path = fifo.clone();
            let writer = std::thread::spawn(move || {
                let _writer = File::options().write(true).open(writer_path).unwrap();
                opened.send(()).unwrap();
            });
            std::thread::sleep(Duration::from_millis(100));

            let result = prepare(std::slice::from_ref(&patch), true).await;
            let opened_by_staging = wait.recv_timeout(Duration::from_millis(200)).is_ok();
            let _reader = File::options()
                .read(true)
                .custom_flags(libc::O_NONBLOCK)
                .open(&fifo)
                .unwrap();
            writer.join().unwrap();

            let Err(error) = result else {
                panic!("FIFO was staged");
            };
            let message = error.to_string();
            assert!(!opened_by_staging, "staging opened the FIFO: {message}");
            assert!(message.contains("not a regular file"), "{message}");
        }

        let Err(error) = prepare(&[copy_file(&socket)], true).await else {
            panic!("socket was staged");
        };
        let message = error.to_string();
        assert!(message.contains(&socket.display().to_string()), "{message}");
        assert!(message.contains("not a regular file"), "{message}");

        fs::remove_file(&socket).unwrap();
        let Err(error) = prepare(&[copy_dir], true).await else {
            panic!("FIFO entry was staged");
        };
        let message = error.to_string();
        assert!(message.contains(&fifo.display().to_string()), "{message}");
        assert!(
            message.contains("not a regular file or directory"),
            "{message}"
        );
    }

    #[test]
    fn dropping_a_staged_batch_removes_it_on_the_blocking_pool() {
        let runtime = RuntimeBuilder::new_current_thread()
            .max_blocking_threads(1)
            .enable_time()
            .build()
            .unwrap();
        let source = tempfile::tempdir().unwrap();
        let file = source.path().canonicalize().unwrap().join("data");
        fs::write(&file, b"payload").unwrap();
        let patches = [Patch::CopyFile {
            src: file,
            dst: "/data".into(),
            mode: None,
            replace: false,
        }];
        let prepared = runtime.block_on(prepare(&patches, true)).unwrap();
        let [Patch::CopyFile { src, .. }] = prepared.patches(&patches) else {
            panic!("copy patch missing")
        };
        let stage = src.parent().unwrap().to_path_buf();

        runtime.block_on(async {
            // Occupy the only blocking thread so removal must wait behind it.
            let (release, released) = mpsc::channel::<()>();
            let busy = tokio::task::spawn_blocking(move || released.recv());
            drop(prepared);
            assert!(
                stage.exists(),
                "staged batch was removed on the async thread"
            );

            release.send(()).unwrap();
            busy.await.unwrap().unwrap();
            for _ in 0..500 {
                if !stage.exists() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            panic!("staged batch was not removed");
        });
    }
}
