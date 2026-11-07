//! Per-source exclusion of existing and newly arriving writers during one capture epoch.

use std::fs::File;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct WriterGuard {
    #[cfg(target_os = "linux")]
    worker: Option<linux::LeaseWorker>,
    #[cfg(windows)]
    _pins: Vec<File>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WriterGuard {
    pub(super) fn acquire(files: &[Vec<File>]) -> Result<Self, String> {
        #[cfg(target_os = "linux")]
        {
            let pins = files
                .iter()
                .flatten()
                .map(|file| file.try_clone())
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| "cannot retain source writer protection")?;
            let worker = if pins.is_empty() {
                None
            } else {
                Some(linux::LeaseWorker::acquire(pins)?)
            };
            Ok(Self { worker })
        }
        #[cfg(windows)]
        {
            use std::os::windows::io::{AsRawHandle, FromRawHandle};
            use windows_sys::Win32::Foundation::INVALID_HANDLE_VALUE;
            use windows_sys::Win32::Storage::FileSystem::{
                FILE_FLAG_OPEN_REPARSE_POINT, FILE_GENERIC_READ, FILE_SHARE_READ, ReOpenFile,
            };
            let mut pins = Vec::new();
            for file in files.iter().flatten() {
                // ReOpenFile addresses the already-pinned object, never its mutable pathname.
                // The new share mode rejects existing write handles/mappings and prevents new
                // writers until every guard is dropped; metadata-only discovery shares freely.
                let handle = unsafe {
                    ReOpenFile(
                        file.as_raw_handle() as _,
                        FILE_GENERIC_READ,
                        FILE_SHARE_READ,
                        FILE_FLAG_OPEN_REPARSE_POINT,
                    )
                };
                if handle == INVALID_HANDLE_VALUE {
                    return Err("source has an open writer or writable mapping, or cannot enforce read sharing; stop its writer before retrying".into());
                }
                let pin = unsafe { File::from_raw_handle(handle as _) };
                if super::io::identity(&pin)?.object != super::io::identity(file)?.object {
                    return Err("source identity changed while protecting writers".into());
                }
                pins.push(pin);
            }
            Ok(Self { _pins: pins })
        }
        #[cfg(target_os = "macos")]
        {
            // macOS execution requires the caller's separately enforced legacy-runtime
            // quiescence gate. Its kernel file leases require a private Apple entitlement.
            let _ = files;
            Ok(Self {})
        }
        #[cfg(not(any(target_os = "linux", target_os = "macos", windows)))]
        {
            let _ = files;
            Err("legacy storage migration has no writer protection on this platform".into())
        }
    }

    /// A forced or requested lease break invalidates the entire epoch permanently. Never try
    /// to reacquire a broken lease and silently certify a mixture of capture epochs.
    pub(super) fn audit(&self) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        if let Some(worker) = &self.worker {
            worker.audit()?;
        }
        Ok(())
    }
}

#[cfg(target_os = "linux")]
mod linux {
    use std::fs::File;
    use std::os::fd::AsRawFd;
    use std::sync::mpsc::{self, SyncSender};
    use std::thread::JoinHandle;

    //--------------------------------------------------------------------------------------------------
    // Constants
    //--------------------------------------------------------------------------------------------------

    // Linux UAPI fcntl.h: libc does not expose F_SETOWN_EX on every supported Linux target.
    const F_SETOWN_EX: libc::c_int = 15;
    const F_OWNER_TID: libc::c_int = 0;

    //--------------------------------------------------------------------------------------------------
    // Types
    //--------------------------------------------------------------------------------------------------

    #[repr(C)]
    struct Owner {
        kind: libc::c_int,
        id: libc::pid_t,
    }

    enum Command {
        Audit(SyncSender<Result<(), String>>),
        Release,
    }

    pub(super) struct LeaseWorker {
        commands: SyncSender<Command>,
        thread: Option<JoinHandle<()>>,
    }

    struct Leases(Vec<File>);

    //--------------------------------------------------------------------------------------------------
    // Methods
    //--------------------------------------------------------------------------------------------------

    impl LeaseWorker {
        pub(super) fn acquire(files: Vec<File>) -> Result<Self, String> {
            let (commands, receiver) = mpsc::sync_channel(1);
            let (ready, result) = mpsc::sync_channel(1);
            let thread = std::thread::Builder::new()
                .name("msb-storage-leases".into())
                .spawn(move || {
                    // SIGIO defaults to process termination. Block it only in this dedicated
                    // worker and direct every lease notification specifically to its Linux TID.
                    // Never restore its mask: queued thread-directed notifications disappear when
                    // this worker exits, without changing the SDK application's signal policy.
                    let leases = match acquire_leases(files) {
                        Ok(leases) => leases,
                        Err(error) => {
                            let _ = ready.send(Err(error));
                            return;
                        }
                    };
                    if ready.send(Ok(())).is_err() {
                        return;
                    }

                    let mut intact = true;
                    while let Ok(command) = receiver.recv() {
                        match command {
                            Command::Audit(reply) => {
                                intact &= leases.0.iter().all(|file| unsafe {
                                    libc::fcntl(file.as_raw_fd(), libc::F_GETLEASE) == libc::F_RDLCK
                                });
                                let result = if intact {
                                    Ok(())
                                } else {
                                    Err("source writer protection was broken; \
                                     no captured group was published"
                                        .into())
                                };
                                let _ = reply.send(result);
                            }
                            Command::Release => break,
                        }
                    }
                    drop(leases);
                })
                .map_err(|_| "cannot create source writer protection worker")?;

            match result.recv() {
                Ok(Ok(())) => Ok(Self {
                    commands,
                    thread: Some(thread),
                }),
                other => {
                    let _ = thread.join();
                    Err(other
                        .ok()
                        .and_then(Result::err)
                        .unwrap_or_else(|| "source writer protection worker failed".into()))
                }
            }
        }

        pub(super) fn audit(&self) -> Result<(), String> {
            let (reply, result) = mpsc::sync_channel(1);
            self.commands
                .send(Command::Audit(reply))
                .map_err(|_| "source writer protection worker stopped")?;
            result
                .recv()
                .map_err(|_| "source writer protection audit failed")?
        }
    }

    //--------------------------------------------------------------------------------------------------
    // Trait Implementations
    //--------------------------------------------------------------------------------------------------

    impl Drop for LeaseWorker {
        fn drop(&mut self) {
            let _ = self.commands.send(Command::Release);
            if let Some(thread) = self.thread.take() {
                let _ = thread.join();
            }
        }
    }

    impl Drop for Leases {
        fn drop(&mut self) {
            // Leases belong to an open file description shared with the reader pins. Unlock
            // explicitly before dropping worker clones, including partial acquisition failures.
            for file in &self.0 {
                unsafe {
                    libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_UNLCK);
                }
            }
        }
    }

    //--------------------------------------------------------------------------------------------------
    // Functions
    //--------------------------------------------------------------------------------------------------

    fn acquire_leases(files: Vec<File>) -> Result<Leases, String> {
        let mut blocked: libc::sigset_t = unsafe { std::mem::zeroed() };
        if unsafe { libc::sigemptyset(&mut blocked) } != 0
            || unsafe { libc::sigaddset(&mut blocked, libc::SIGIO) } != 0
            || unsafe { libc::pthread_sigmask(libc::SIG_BLOCK, &blocked, std::ptr::null_mut()) }
                != 0
        {
            return Err("cannot safely isolate storage lease notifications".into());
        }
        let owner = Owner {
            kind: F_OWNER_TID,
            id: unsafe { libc::syscall(libc::SYS_gettid) as libc::pid_t },
        };
        let mut leases = Leases(Vec::new());
        for file in files {
            if unsafe { libc::fcntl(file.as_raw_fd(), F_SETOWN_EX, &owner) } != 0 {
                return Err("filesystem does not support safe source lease ownership".into());
            }
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLEASE, libc::F_RDLCK) } != 0 {
                return Err("source has an open writer or writable mapping, or its filesystem cannot enforce read leases; stop its writer or use supported storage".into());
            }
            leases.0.push(file);
        }
        Ok(leases)
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;
    use std::os::unix::fs::OpenOptionsExt;

    #[test]
    fn linux_existing_writer_and_unlinked_writable_mapping_are_refused() {
        for mapping in [false, true] {
            let directory = tempfile::tempdir().unwrap();
            let path = directory.path().join("source.raw");
            std::fs::write(&path, vec![0; 4096]).unwrap();
            let writer = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .open(&path)
                .unwrap();
            let reader = File::open(&path).unwrap();
            if mapping {
                let address = unsafe {
                    libc::mmap(
                        std::ptr::null_mut(),
                        4096,
                        libc::PROT_READ | libc::PROT_WRITE,
                        libc::MAP_SHARED,
                        writer.as_raw_fd(),
                        0,
                    )
                };
                assert_ne!(address, libc::MAP_FAILED);
                drop(writer);
                std::fs::remove_file(&path).unwrap();
                assert!(WriterGuard::acquire(&[vec![reader]]).is_err());
                assert_eq!(unsafe { libc::munmap(address, 4096) }, 0);
            } else {
                assert!(WriterGuard::acquire(&[vec![reader]]).is_err());
            }
        }
    }

    #[test]
    fn linux_new_writer_break_is_detected_without_delivering_sigio_to_application() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.raw");
        std::fs::write(&path, vec![0; 4096]).unwrap();
        let files = vec![vec![File::open(&path).unwrap()]];
        let guard = WriterGuard::acquire(&files).unwrap();
        guard.audit().unwrap();
        let error = std::fs::OpenOptions::new()
            .write(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(&path)
            .unwrap_err();
        assert_eq!(error.raw_os_error(), Some(libc::EWOULDBLOCK));
        assert!(guard.audit().is_err());
        assert!(guard.audit().is_err());
        drop(guard);
        assert!(std::fs::OpenOptions::new().write(true).open(path).is_ok());
    }
}

#[cfg(all(test, windows))]
mod windows_tests {
    use std::fs::{self, OpenOptions};
    use std::os::windows::io::AsRawHandle;

    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Memory::{
        CreateFileMappingW, FILE_MAP_WRITE, MapViewOfFile, PAGE_READWRITE, UnmapViewOfFile,
    };

    #[test]
    fn windows_source_pin_excludes_existing_and_new_writer_handles() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.raw");
        fs::write(&path, vec![0; 4096]).unwrap();
        let writer = OpenOptions::new().write(true).open(&path).unwrap();
        let files = vec![vec![super::super::io::exact(&path).unwrap()]];
        assert!(super::WriterGuard::acquire(&files).is_err());
        drop(writer);
        let guard = super::WriterGuard::acquire(&files).unwrap();
        assert!(OpenOptions::new().write(true).open(&path).is_err());
        drop(guard);
        assert!(OpenOptions::new().write(true).open(path).is_ok());
    }

    #[test]
    fn windows_source_pin_excludes_writable_mapping_after_original_handle_closes() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.raw");
        fs::write(&path, vec![0; 4096]).unwrap();
        let writer = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        let mapping = unsafe {
            CreateFileMappingW(
                writer.as_raw_handle() as _,
                std::ptr::null(),
                PAGE_READWRITE,
                0,
                0,
                std::ptr::null(),
            )
        };
        assert!(!mapping.is_null());
        let view = unsafe { MapViewOfFile(mapping, FILE_MAP_WRITE, 0, 0, 4096) };
        assert!(!view.Value.is_null());
        drop(writer);
        let files = vec![vec![super::super::io::exact(&path).unwrap()]];
        let denied = super::WriterGuard::acquire(&files).is_err();
        unsafe {
            UnmapViewOfFile(view);
            CloseHandle(mapping);
        }
        assert!(denied, "writable mappings must prevent source admission");
        assert!(super::WriterGuard::acquire(&files).is_ok());
    }

    #[test]
    fn windows_metadata_inspection_does_not_exclude_new_writers() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("source.raw");
        fs::write(&path, vec![0; 4096]).unwrap();
        let _inspection = super::super::io::exact(&path).unwrap();
        assert!(OpenOptions::new().write(true).open(path).is_ok());
    }
}
