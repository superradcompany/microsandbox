//! Translate user-selected host inputs into a private, ordered edit stream.

use std::fs::{File, OpenOptions};
use std::io::{self, BufWriter, Write};
use std::path::Path;
use std::process::Stdio;

use cap_std::fs::Dir;
use microsandbox_protocol::snapshot_patch::{Action, Edit, RECEIPT};
use microsandbox_types::Patch;

use super::restore::RestoreStaging;
use crate::sandbox::patch_sources::{CapacityGuard, PatchStaging, Prepared};
use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct EditStream {
    manifest: BufWriter<File>,
    payload: BufWriter<File>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl EditStream {
    fn record(&mut self, path: &[u8], action: Action) -> MicrosandboxResult<()> {
        serde_json::to_writer(
            &mut self.manifest,
            &Edit {
                path: path.to_owned(),
                action,
            },
        )?;
        self.manifest.write_all(b"\n")?;
        Ok(())
    }

    fn directory(
        &mut self,
        dir: &Dir,
        source_path: &Path,
        path: &[u8],
        replace: bool,
        sources: &Prepared,
    ) -> MicrosandboxResult<()> {
        let handle = dir.try_clone()?.into_std_file();
        let dir_mode = match sources.mode(source_path) {
            Some(0) => 0o755,
            Some(mode) => mode,
            None => mode(&handle, 0o755)?,
        };
        self.record(
            path,
            Action::CopyDirectory {
                mode: dir_mode,
                replace,
            },
        )?;
        for entry in dir.entries()? {
            let entry = entry?;
            let name = entry.file_name();
            let source_child = source_path.join(&name);
            let mut child = path.to_vec();
            child.push(b'/');
            child.extend_from_slice(name.as_encoded_bytes());
            let kind = entry.file_type()?;
            if kind.is_symlink() {
                let target = dir.read_link_contents(&name)?;
                self.record(
                    &child,
                    Action::Symlink {
                        target: target.as_os_str().as_encoded_bytes().to_vec(),
                        replace: true,
                    },
                )?;
            } else if kind.is_dir() {
                let fd = cap_primitives::fs::open_dir_nofollow(&handle, Path::new(&name))?;
                self.directory(
                    &Dir::from_std_file(fd),
                    &source_child,
                    &child,
                    true,
                    sources,
                )?;
            } else if kind.is_file() {
                let mut options = cap_std::fs::OpenOptions::new();
                options
                    .read(true)
                    ._cap_fs_ext_follow(cap_primitives::fs::FollowSymlinks::No);
                #[cfg(unix)]
                {
                    use cap_std::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NONBLOCK);
                }
                self.copy_file(
                    dir.open_with(&name, &options)?.into_std(),
                    &child,
                    None,
                    sources.mode(&source_child),
                    true,
                )?;
            } else {
                return Err(MicrosandboxError::PatchFailed(format!(
                    "unsupported CopyDir entry {name:?}"
                )));
            }
        }
        Ok(())
    }

    fn copy_file(
        &mut self,
        mut file: File,
        path: &[u8],
        requested: Option<u32>,
        staged_mode: Option<u32>,
        replace: bool,
    ) -> MicrosandboxResult<()> {
        if !file.metadata()?.is_file() {
            return Err(MicrosandboxError::PatchFailed(
                "copy source must be a regular file".into(),
            ));
        }
        let file_mode = match requested {
            Some(mode) => mode,
            None => match staged_mode {
                Some(0) => 0o644,
                Some(mode) => mode,
                None => mode(&file, 0o644)?,
            },
        };
        let len = io::copy(&mut file, &mut self.payload)?;
        self.record(
            path,
            Action::Write {
                mode: file_mode,
                replace,
                len,
            },
        )
    }

    fn push(&mut self, patch: &Patch, sources: &Prepared) -> MicrosandboxResult<()> {
        match patch {
            Patch::Text {
                path,
                content,
                mode,
                replace,
            } => self.write(path, content.as_bytes(), *mode, *replace),
            Patch::File {
                path,
                content,
                mode,
                replace,
            } => self.write(path, content, *mode, *replace),
            Patch::Append { path, content } => {
                self.payload.write_all(content.as_bytes())?;
                self.record(
                    path.as_bytes(),
                    Action::Append {
                        len: content.len() as u64,
                    },
                )
            }
            Patch::CopyDir { src, dst, replace } => self.directory(
                &Dir::open_ambient_dir(src, cap_std::ambient_authority())?,
                src,
                dst.as_bytes(),
                *replace,
                sources,
            ),
            Patch::CopyFile {
                src,
                dst,
                mode,
                replace,
            } => {
                let mut options = OpenOptions::new();
                options.read(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.custom_flags(libc::O_NONBLOCK);
                }
                self.copy_file(
                    options.open(src)?,
                    dst.as_bytes(),
                    *mode,
                    sources.mode(src),
                    *replace,
                )
            }
            Patch::Symlink {
                target,
                link,
                replace,
            } => self.record(
                link.as_bytes(),
                Action::Symlink {
                    target: target.as_bytes().to_vec(),
                    replace: *replace,
                },
            ),
            Patch::Remove { path } => self.record(path.as_bytes(), Action::Remove),
            Patch::Mkdir { path, mode } => self.record(
                path.as_bytes(),
                Action::Directory {
                    mode: mode.unwrap_or(0o755),
                },
            ),
        }
    }

    fn write(
        &mut self,
        path: &str,
        bytes: &[u8],
        mode: Option<u32>,
        replace: bool,
    ) -> MicrosandboxResult<()> {
        self.payload.write_all(bytes)?;
        self.record(
            path.as_bytes(),
            Action::Write {
                mode: mode.unwrap_or(0o644),
                replace,
                len: bytes.len() as u64,
            },
        )
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn mode(file: &File, fallback: u32) -> io::Result<u32> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let permissions = file.metadata()?.permissions().mode() & 0o7777;
        if permissions != 0 {
            return Ok(permissions);
        }
    }
    #[cfg(not(unix))]
    let _ = file;
    Ok(fallback)
}

async fn write_edit_stream(
    scratch: std::path::PathBuf,
    patches: Vec<Patch>,
    patch_staging: &PatchStaging,
) -> MicrosandboxResult<CapacityGuard> {
    let prepared = patch_staging.prepare(&patches).await?;
    tokio::task::spawn_blocking(move || -> MicrosandboxResult<CapacityGuard> {
        microsandbox_utils::private_file::create_private_directory(&scratch)?;
        let mut stream = EditStream {
            manifest: BufWriter::new(File::create_new(scratch.join("edits"))?),
            payload: BufWriter::new(File::create_new(scratch.join("payload"))?),
        };
        for patch in prepared.patches(&patches) {
            stream.push(patch, &prepared)?;
        }
        stream.manifest.flush()?;
        stream.payload.flush()?;
        // Release the staged source copy now, but retain the batch staging
        // permit until the caller removes `scratch/payload`.
        Ok(prepared.into_capacity_guard())
    })
    .await
    .map_err(|e| MicrosandboxError::PatchFailed(e.to_string()))?
}

pub(super) async fn apply(
    mut config: SandboxConfig,
    stage: RestoreStaging,
    msb: std::path::PathBuf,
    firmware: std::path::PathBuf,
    image: super::ResolvedOciImage,
    patch_staging: PatchStaging,
) -> MicrosandboxResult<(SandboxConfig, RestoreStaging, super::ResolvedOciImage)> {
    // Keep the reservation and its disk leases until the VMM has really exited, even
    // if the original create future is dropped. Scratch is never published with the child.
    tokio::spawn(async move {
        let patches = std::mem::take(&mut config.spec.patches);
        // Declare the capacity guard before `temp` so `temp` is always removed before
        // releasing the staging permit, including on early error or cancellation.
        #[allow(unused_assignments)]
        let mut _capacity: Option<CapacityGuard> = None;
        let temp = tempfile::Builder::new()
            .prefix(".editor-")
            .tempdir_in(stage.path())?;
        let scratch = temp.path().join("guest");
        _capacity = Some(write_edit_stream(scratch.clone(), patches, &patch_staging).await?);
        serde_json::to_writer(
            File::create_new(temp.path().join("chain"))?,
            &config.snapshot_upper_layers,
        )?;
        let scratch = std::fs::canonicalize(scratch)?;
        let mut command = tokio::process::Command::new(msb);
        command
            .arg("__snapshot-editor")
            .arg(firmware)
            .arg(&scratch)
            .arg(temp.path().join("chain"));
        if matches!(
            config.spec.image.oci_root_disk(),
            Some(crate::sandbox::RootDisk::Managed { .. })
        ) {
            let lower = image
                .cache_operation
                .vmdk_path(&image.pull_result.manifest_digest);
            File::create_new(scratch.join("layered"))?;
            command.arg(lower);
        }
        let stderr = temp.path().join("stderr");
        let mut vm = command
            .env_remove("MSB_KRUN_KERNEL_CMDLINE")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(File::create_new(&stderr)?)
            .kill_on_drop(true)
            .spawn()?;
        // Child::wait closes any attached stdin. Hold the pipe separately so EOF really
        // means the SDK died, including an abrupt process exit.
        let _owner = vm.stdin.take();
        let status = vm.wait().await?;
        let receipt = std::fs::read_to_string(scratch.join("result")).unwrap_or_default();
        if status.success() && !receipt.is_empty() && receipt != RECEIPT {
            return Err(MicrosandboxError::PatchFailed(receipt));
        }
        if !status.success() || receipt != RECEIPT {
            let detail = if receipt.is_empty() {
                std::fs::read_to_string(stderr)?
            } else {
                receipt
            };
            return Err(MicrosandboxError::PatchFailed(format!(
                "snapshot editor exited {status}: {detail}"
            )));
        }
        temp.close()?;
        Ok((config, stage, image))
    })
    .await
    .map_err(|e| MicrosandboxError::PatchFailed(e.to_string()))?
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{PermissionsExt, symlink};

    use super::*;

    #[tokio::test]
    async fn snapshot_edit_stream_enforces_bounded_patch_sources() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().canonicalize().unwrap();
        let source = root.join("source");
        std::fs::create_dir(&source).unwrap();
        let file = source.join("data");
        std::fs::write(&file, b"payload").unwrap();
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o640)).unwrap();
        symlink(&file, source.join("alias")).unwrap();

        let patches = vec![Patch::CopyDir {
            src: source.clone(),
            dst: "/copied".into(),
            replace: false,
        }];

        let bounded_scratch = root.join("bounded-symlink");
        let enabled = PatchStaging::enabled_default();
        assert!(
            write_edit_stream(bounded_scratch.clone(), patches.clone(), &enabled)
                .await
                .is_err()
        );
        assert!(!bounded_scratch.exists());

        let unbounded_scratch = root.join("unbounded-symlink");
        let disabled = PatchStaging::disabled();
        write_edit_stream(unbounded_scratch, patches.clone(), &disabled)
            .await
            .unwrap();

        std::fs::remove_file(source.join("alias")).unwrap();
        let clean_scratch = root.join("bounded-clean");
        write_edit_stream(clean_scratch.clone(), patches.clone(), &enabled)
            .await
            .unwrap();
        let manifest = std::fs::read_to_string(clean_scratch.join("edits")).unwrap();
        let edits: Vec<Edit> = manifest
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert!(edits.iter().any(|edit| matches!(
            &edit.action,
            Action::Write { mode, len: 7, .. } if *mode == 0o640
        )));

        std::fs::File::options()
            .write(true)
            .open(&file)
            .unwrap()
            .set_len(65 * 1024 * 1024)
            .unwrap();
        let oversized_scratch = root.join("bounded-oversized");
        let error = write_edit_stream(oversized_scratch.clone(), patches, &enabled)
            .await
            .unwrap_err();
        assert!(error.to_string().contains("byte budget"), "{error}");
        assert!(!oversized_scratch.exists());
    }
}
