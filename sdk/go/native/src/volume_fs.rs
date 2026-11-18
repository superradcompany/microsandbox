//! Go volume adapters share the Rust directory capability and retain Go filesystem semantics.

use std::{io::Write, path::Path};

use base64::Engine;
#[cfg(windows)]
use cap_std::fs::MetadataExt;
use cap_std::fs::{DirBuilder, OpenOptions};
#[cfg(unix)]
use cap_std::fs::{DirBuilderExt, OpenOptionsExt};
use microsandbox::{
    MicrosandboxError, MicrosandboxResult, default_backend,
    volume::{VolumeFs, fs::RootedVolumeFs},
};
use serde_json::{Value, json};

use crate::FfiError;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(windows)]
const ERROR_PATH_NOT_FOUND: i32 = 3;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn dispatch(target: &str, op: &str, args: &Value) -> Result<String, FfiError> {
    let path = args["path"]
        .as_str()
        .ok_or_else(|| FfiError::invalid_argument("missing volume fs path"))?;
    if let Some(op) = op.strip_prefix("local_") {
        // The explicit root is retained by the Go handle. Never resolve it through
        // the process's current default backend or volume name.
        if !Path::new(target).is_absolute() {
            return Err(FfiError::invalid_argument(
                "local volume root must be absolute",
            ));
        }
        let target = target.to_owned();
        let op = op.to_owned();
        let args = args.clone();
        return tokio::task::spawn_blocking(move || local_dispatch(&target, &op, &args))
            .await
            .map_err(|error| {
                FfiError::internal(format!("volume filesystem task failed: {error}"))
            })?;
    }

    // Keep the existing cloud request shape and immutable cloud-id target intact.
    let fs = VolumeFs::with_backend(default_backend(), target);
    match op {
        "read" => Ok(
            json!({"data_b64": base64::engine::general_purpose::STANDARD.encode(
                fs.read(path).await.map_err(FfiError::from)?
            )})
            .to_string(),
        ),
        "write" => {
            fs.write(path, decode_data(args)?)
                .await
                .map_err(FfiError::from)?;
            Ok(json!({"ok": true}).to_string())
        }
        "mkdir" => {
            fs.mkdir(path).await.map_err(FfiError::from)?;
            Ok(json!({"ok": true}).to_string())
        }
        "remove" => {
            if args["recursive"].as_bool().unwrap_or(false) {
                fs.remove_dir(path).await.map_err(FfiError::from)?;
            } else {
                fs.remove(path).await.map_err(FfiError::from)?;
            }
            Ok(json!({"ok": true}).to_string())
        }
        "exists" => {
            Ok(json!({"exists": fs.exists(path).await.map_err(FfiError::from)?}).to_string())
        }
        _ => Err(FfiError::invalid_argument("unknown volume fs operation")),
    }
}

fn local_dispatch(target: &str, op: &str, args: &Value) -> Result<String, FfiError> {
    let path = args["path"].as_str().expect("dispatch validates path");
    let data = if op == "write" {
        Some(decode_data(args)?)
    } else {
        None
    };
    let operation = || -> MicrosandboxResult<Value> {
        let opened = if op == "mkdir" {
            RootedVolumeFs::open_or_create(Path::new(target))
        } else {
            RootedVolumeFs::open(Path::new(target))
        };
        let root = match opened {
            Ok(root) => root,
            Err(MicrosandboxError::Io(error))
                if op == "exists" && error.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(json!({"exists": false}));
            }
            Err(MicrosandboxError::Io(error))
                if op == "remove"
                    && args["recursive"].as_bool().unwrap_or(false)
                    && error.kind() == std::io::ErrorKind::NotFound =>
            {
                return Ok(json!({"ok": true}));
            }
            Err(error) => return Err(error),
        };
        let clean = args["clean_path"].as_str().unwrap_or(path);
        let resolve = |path: &str| {
            if op == "remove" {
                root.resolve_entry(path)
            } else {
                root.resolve(path)
            }
        };
        // Go previously used filepath.Clean before entering the filesystem.
        // Never silently switch an ambiguous symlink/.. operation to another file.
        let path = resolve(path)?;
        let cleaned = resolve(clean)?;
        if lexical_destination(&path) != lexical_destination(&cleaned)
            && Path::new(args["path"].as_str().unwrap())
                .components()
                .any(|part| part == std::path::Component::ParentDir)
        {
            return Err(MicrosandboxError::InvalidConfig(
                "ambiguous symlink/.. volume path; use an explicit destination".into(),
            ));
        }
        if op == "remove" {
            if clean == "." {
                if args["recursive"].as_bool().unwrap_or(false) {
                    root.remove_root()?;
                } else {
                    root.remove_empty_root()?;
                }
                return Ok(json!({"ok": true}));
            }
            return remove(&root, clean, args["recursive"].as_bool().unwrap_or(false));
        }
        let path = cleaned;
        match op {
            "read" => Ok(
                json!({"data_b64": base64::engine::general_purpose::STANDARD.encode(
                    root.dir.read(&path).map_err(|error| go_io_error(&root, &path, error, false))?
                )}),
            ),
            "write" => {
                // Go WriteFile creates the file, but does not create missing parents
                // or change permissions on an existing file.
                let mut options = OpenOptions::new();
                options.write(true).create(true).truncate(true);
                #[cfg(unix)]
                options.mode(0o644);
                root.dir
                    .open_with(&path, &options)
                    .map_err(|error| go_io_error(&root, &path, error, true))?
                    .write_all(data.as_ref().expect("decoded write data"))?;
                Ok(json!({"ok": true}))
            }
            "mkdir" => {
                // Go MkdirAll reports ENOTDIR when the final entry exists as a
                // file; create_dir_all would otherwise report EEXIST instead.
                if root
                    .dir
                    .metadata(&path)
                    .is_ok_and(|metadata| !metadata.is_dir())
                {
                    return Err(std::io::Error::from(std::io::ErrorKind::NotADirectory).into());
                }
                let mut options = DirBuilder::new();
                options.recursive(true);
                #[cfg(unix)]
                options.mode(0o755);
                root.dir.create_dir_with(path, &options)?;
                Ok(json!({"ok": true}))
            }
            "exists" => Ok(json!({"exists": root.dir.try_exists(path)?})),
            _ => Err(MicrosandboxError::InvalidConfig(
                "unknown local volume fs operation".into(),
            )),
        }
    };
    operation()
        .map(|value| value.to_string())
        .map_err(local_error)
}

// Compare destinations after resolution; missing/.. without a symlink is still
// the old, unambiguous Go lexical path and must remain supported.
fn lexical_destination(path: &Path) -> std::path::PathBuf {
    let mut result = std::path::PathBuf::new();
    for part in path.components() {
        match part {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {}
            _ => result.push(part),
        }
    }
    result
}

/// Match Go's Windows error interpretation without reopening an ambient path.
fn go_io_error(
    _root: &RootedVolumeFs,
    _path: &Path,
    error: std::io::Error,
    _writing: bool,
) -> std::io::Error {
    #[cfg(windows)]
    {
        // Capability traversal can report FILE_NOT_FOUND for a missing parent;
        // Go's full-path open/remove reports PATH_NOT_FOUND in that case.
        if error.kind() == std::io::ErrorKind::NotFound
            && let Some(parent) = _path
                .parent()
                .filter(|parent| !parent.as_os_str().is_empty())
            && _root
                .dir
                .metadata(parent)
                .is_err_and(|error| error.kind() == std::io::ErrorKind::NotFound)
        {
            return std::io::Error::from_raw_os_error(ERROR_PATH_NOT_FOUND);
        }
        // Go translates a denied write-open of a directory to its synthetic
        // EISDIR errno. Inspect through the same capability only after failure,
        // so this diagnostic check never authorizes or redirects an operation.
        if _writing
            && error.kind() == std::io::ErrorKind::PermissionDenied
            && _root.dir.metadata(_path).is_ok_and(|entry| entry.is_dir())
        {
            return std::io::ErrorKind::IsADirectory.into();
        }
    }
    error
}

fn remove(root: &RootedVolumeFs, path: &str, recursive: bool) -> MicrosandboxResult<Value> {
    let path = Path::new(path);
    let name = path.file_name().ok_or_else(|| {
        MicrosandboxError::SandboxFsOps("remove cannot target the volume root".into())
    })?;
    // Resolve only the parent: Go Remove/RemoveAll unlink a final symlink instead
    // of deleting its target. Capability operations still constrain the parent.
    let parent = path.parent().unwrap_or_else(|| Path::new(""));
    let parent = root.resolve(
        parent
            .to_str()
            .ok_or_else(|| MicrosandboxError::SandboxFsOps("invalid volume path".into()))?,
    )?;
    let path = parent.join(name);
    let metadata = match root
        .dir
        .symlink_metadata(&path)
        .map_err(|error| go_io_error(root, &path, error, false))
    {
        Ok(metadata) => metadata,
        Err(error) if recursive && error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(json!({"ok": true}));
        }
        Err(error) => return Err(error.into()),
    };
    #[cfg(windows)]
    // FILE_ATTRIBUTE_DIRECTORY remains set on a directory reparse point even
    // when its target is missing; querying the target would break dangling links.
    let directory_link = metadata.is_symlink() && metadata.file_attributes() & 0x10 != 0;
    #[cfg(not(windows))]
    let directory_link = false;
    let result = if directory_link {
        // Windows removes directory symlinks with RemoveDirectory, even when
        // their targets are missing. Unlink only: never recurse into the target.
        root.dir.remove_dir(path).map_err(MicrosandboxError::from)
    } else if metadata.is_dir() {
        if recursive {
            root.remove_dir_all(&path).map_err(MicrosandboxError::from)
        } else {
            root.dir.remove_dir(path).map_err(MicrosandboxError::from)
        }
    } else {
        root.dir.remove_file(path).map_err(MicrosandboxError::from)
    };
    match result {
        Ok(()) => Ok(json!({"ok": true})),
        Err(MicrosandboxError::Io(error))
            if recursive && error.kind() == std::io::ErrorKind::NotFound =>
        {
            Ok(json!({"ok": true}))
        }
        Err(error) => Err(error),
    }
}

fn decode_data(args: &Value) -> Result<Vec<u8>, FfiError> {
    let encoded = args["data_b64"]
        .as_str()
        .ok_or_else(|| FfiError::invalid_argument("missing volume fs data"))?;
    base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|error| FfiError::invalid_argument(format!("invalid base64 data: {error}")))
}

fn local_error(error: MicrosandboxError) -> FfiError {
    let escape = match &error {
        MicrosandboxError::SandboxFsOps(message) => message == "path traversal outside volume root",
        MicrosandboxError::Io(error) => {
            error.kind() == std::io::ErrorKind::PermissionDenied
                && error.to_string() == "a path led outside of the filesystem"
        }
        _ => false,
    };
    if let MicrosandboxError::Io(io) = &error {
        let kind = match io.kind() {
            std::io::ErrorKind::NotFound => Some("volume_path_not_found"),
            std::io::ErrorKind::AlreadyExists => Some("volume_path_exists"),
            std::io::ErrorKind::PermissionDenied if !escape => Some("volume_path_permission"),
            std::io::ErrorKind::NotADirectory => Some("volume_path_not_directory"),
            std::io::ErrorKind::IsADirectory => Some("volume_path_is_directory"),
            _ => None,
        };
        if !escape {
            let mut native = FfiError::new(kind.unwrap_or("io"), error.to_string());
            // This library runs in the Go process on the same OS. Preserve the
            // numeric error so syscall.Errno and errors.Is retain their identity.
            native.os_error = io.raw_os_error();
            return native;
        }
    }
    if escape {
        FfiError::new("volume_path_escape", error.to_string())
    } else {
        FfiError::from(error)
    }
}
