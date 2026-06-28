//! Server-side RPC dispatch: turn wire requests into [`PathFs`] calls.
//!
//! [`dispatch`] and [`dispatch_with_state`] are the reference server the Go SDK
//! mirrors. Per-connection [`DispatchState`] holds a [`ReadDirCache`](super::readdir_cache::ReadDirCache).

use std::{ffi::OsStr, io, os::unix::ffi::OsStrExt, path::Path, sync::Mutex};

use serde_bytes::ByteBuf;

use super::super::PathFs;
use super::super::path_fs::NodeKind;
use super::limits::{clamp_io_size, clamp_readdir_limit, clamp_write_len};
use super::protocol::{MAX_BATCH_PATHS, VAttrResult, VfsRequest, VfsResponse};
use super::readdir_cache::ReadDirCache;
use crate::SetattrValid;
use crate::backends::shared::{name_validation, platform};

/// Per-connection state for the reference RPC server (mirrors Go `readDirCache`).
///
/// The embedded ReadDirCache is mutex-protected so concurrent `serve` worker
/// threads can share one connection safely. The cache is invalidated after each
/// successful mutating op; a generation counter forces a refetch when paginated
/// reads continue after an overlapping mutation.
///
/// Mutating RPCs also take the `mutation` mutex so directory removal
/// (emptiness check + delete) cannot race with concurrent creates on the same
/// connection, and so ReadDir cache invalidation cannot race with concurrent
/// ReadDir on the same connection.
pub struct DispatchState {
    read_dir: ReadDirCache,
    mutation: Mutex<()>,
}

impl Default for DispatchState {
    fn default() -> Self {
        Self {
            read_dir: ReadDirCache::default(),
            mutation: Mutex::new(()),
        }
    }
}

fn invalidates_read_dir_cache(req: &VfsRequest) -> bool {
    matches!(
        req,
        VfsRequest::Write { .. }
            | VfsRequest::Create { .. }
            | VfsRequest::Mkdir { .. }
            | VfsRequest::Remove { .. }
            | VfsRequest::Rename { .. }
            | VfsRequest::SetAttr { .. }
            | VfsRequest::Symlink { .. }
            | VfsRequest::SetXattr { .. }
            | VfsRequest::RemoveXattr { .. }
            | VfsRequest::FsyncDir { .. }
    )
}

fn as_path(bytes: &[u8]) -> &Path {
    Path::new(OsStr::from_bytes(bytes))
}

/// Reject absolute guest paths the provider must not be asked to serve.
fn validate_provider_path(bytes: &[u8]) -> io::Result<()> {
    name_validation::validate_provider_path_bytes(bytes)
}

/// Reject symlink targets that could confuse path resolution if mishandled.
fn validate_symlink_target(bytes: &[u8]) -> io::Result<()> {
    name_validation::validate_symlink_target_bytes(bytes)
}

pub(crate) fn validate_request_paths(req: &VfsRequest) -> io::Result<()> {
    match req {
        VfsRequest::GetAttr { path }
        | VfsRequest::ReadDir { path, .. }
        | VfsRequest::ReadLink { path }
        | VfsRequest::Read { path, .. }
        | VfsRequest::Write { path, .. }
        | VfsRequest::Create { path, .. }
        | VfsRequest::Mkdir { path, .. }
        | VfsRequest::Remove { path }
        | VfsRequest::SetAttr { path, .. }
        | VfsRequest::ListXattr { path } => validate_provider_path(path),
        VfsRequest::SetXattr { path, name, .. }
        | VfsRequest::GetXattr { path, name }
        | VfsRequest::RemoveXattr { path, name, .. } => {
            validate_provider_path(path)?;
            name_validation::validate_xattr_name_bytes(name)
        }
        VfsRequest::Flush { path }
        | VfsRequest::Fsync { path, .. }
        | VfsRequest::FsyncDir { path } => validate_provider_path(path),
        VfsRequest::GetAttrMany { paths } => {
            for path in paths {
                validate_provider_path(path)?;
            }
            Ok(())
        }
        VfsRequest::Rename { from, to, .. } => {
            validate_provider_path(from)?;
            validate_provider_path(to)
        }
        VfsRequest::Symlink { path, target } => {
            validate_provider_path(path)?;
            validate_symlink_target(target)?;
            Ok(())
        }
        VfsRequest::StatFs => Ok(()),
    }
}

/// Answer a [`VfsRequest`] from a concrete [`PathFs`], turning any error into
/// [`VfsResponse::Err`] with its Linux errno. This is the reference server the
/// Go side mirrors.
pub fn dispatch(provider: &dyn PathFs, req: VfsRequest) -> VfsResponse {
    dispatch_with_state(provider, req, &DispatchState::default())
}

/// Like [`dispatch`] with per-connection state (e.g. a ReadDir listing cache).
pub fn dispatch_with_state(
    provider: &dyn PathFs,
    req: VfsRequest,
    state: &DispatchState,
) -> VfsResponse {
    let invalidate_on_ok = invalidates_read_dir_cache(&req);
    let lock_cache = matches!(req, VfsRequest::ReadDir { .. }) || invalidate_on_ok;
    let result = if lock_cache {
        let _guard = state.mutation.lock().unwrap_or_else(|e| e.into_inner());
        let result = dispatch_inner(provider, req, state);
        if let Ok(ref resp) = result
            && invalidate_on_ok
            && !matches!(resp, VfsResponse::Err(_))
        {
            state.read_dir.invalidate();
        }
        result
    } else {
        dispatch_inner(provider, req, state)
    };
    match result {
        Ok(resp) => resp,
        // A `PathFs` provider reports errors in *host* errno (macOS uses BSD
        // values), but the wire — like the FUSE guest — always speaks Linux
        // errno. Translate so this reference server stays wire-compatible with
        // the Go server on every host.
        Err(e) => VfsResponse::Err(platform::provider_errno_to_wire(e)),
    }
}

fn dispatch_inner(
    provider: &dyn PathFs,
    req: VfsRequest,
    state: &DispatchState,
) -> io::Result<VfsResponse> {
    validate_request_paths(&req)?;
    Ok(match req {
        VfsRequest::GetAttr { path } => {
            VfsResponse::Attr((&provider.getattr(as_path(&path))?).into())
        }
        VfsRequest::GetAttrMany { paths } => {
            if paths.len() > MAX_BATCH_PATHS {
                return Err(platform::einval());
            }
            VfsResponse::AttrMany(
                paths
                    .iter()
                    .map(|p| match provider.getattr(as_path(p)) {
                        Ok(a) => VAttrResult::Ok((&a).into()),
                        // Per-path errors are reported in-band (they must not fail
                        // the whole batch); translate host errno to Linux like the
                        // top-level dispatch does.
                        Err(e) => VAttrResult::Err(platform::provider_errno_to_wire(e)),
                    })
                    .collect(),
            )
        }
        VfsRequest::ReadDir {
            path,
            offset,
            limit,
        } => {
            let limit = clamp_readdir_limit(limit)?;
            let entries = state.read_dir.page(provider, &path, offset, limit)?;
            let dir = entries.iter().map(Into::into).collect();
            VfsResponse::Dir(dir)
        }
        VfsRequest::ReadLink { path } => {
            let target = provider.readlink(as_path(&path))?;
            validate_symlink_target(&target)?;
            VfsResponse::Bytes(ByteBuf::from(target))
        }
        VfsRequest::Read { path, offset, size } => {
            let size = clamp_io_size(size)?;
            let data = provider.read(as_path(&path), offset, size)?;
            if data.len() > size as usize {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vfs: read returned more bytes than requested",
                ));
            }
            VfsResponse::Bytes(ByteBuf::from(data))
        }
        VfsRequest::Write { path, offset, data } => {
            clamp_write_len(data.len())?;
            let count = provider.write(as_path(&path), offset, &data)?;
            if count > data.len() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vfs: write returned more bytes than sent",
                ));
            }
            VfsResponse::Count(count as u64)
        }
        VfsRequest::Create { path, attr } => {
            VfsResponse::Attr((&provider.create(as_path(&path), &attr.into_vattr()?)?).into())
        }
        VfsRequest::Mkdir { path, mode } => {
            VfsResponse::Attr((&provider.mkdir(as_path(&path), mode)?).into())
        }
        VfsRequest::Remove { path } => {
            let guest_path = as_path(&path);
            match provider.getattr(guest_path) {
                Ok(attr) if attr.kind == NodeKind::Dir => {
                    provider.rmdir(guest_path)?;
                }
                Err(e) if e.raw_os_error() != platform::enoent().raw_os_error() => return Err(e),
                _ => provider.remove(guest_path)?,
            }
            VfsResponse::Ok
        }
        VfsRequest::Rename { from, to, flags } => {
            const RENAME_NOREPLACE: u32 = 1;
            const RENAME_EXCHANGE: u32 = 2;
            const KNOWN_RENAME_FLAGS: u32 = RENAME_NOREPLACE | RENAME_EXCHANGE;
            if flags & !KNOWN_RENAME_FLAGS != 0 {
                return Err(platform::einval());
            }
            if flags & RENAME_NOREPLACE != 0 && flags & RENAME_EXCHANGE != 0 {
                return Err(platform::einval());
            }
            if flags & RENAME_EXCHANGE != 0 {
                return Err(platform::enosys());
            }
            provider.rename_with_flags(as_path(&from), as_path(&to), flags)?;
            VfsResponse::Ok
        }
        VfsRequest::SetAttr { path, attr, valid } => VfsResponse::Attr(
            (&provider.setattr(
                as_path(&path),
                &attr.into_vattr()?,
                SetattrValid::from_bits_truncate(valid as _),
            )?)
                .into(),
        ),
        VfsRequest::Symlink { path, target } => {
            VfsResponse::Attr((&provider.symlink(as_path(&path), &target)?).into())
        }
        VfsRequest::SetXattr {
            path,
            name,
            value,
            flags,
        } => {
            provider.setxattr(as_path(&path), &name, &value, flags)?;
            VfsResponse::Ok
        }
        VfsRequest::GetXattr { path, name } => {
            VfsResponse::Bytes(ByteBuf::from(provider.getxattr(as_path(&path), &name)?))
        }
        VfsRequest::ListXattr { path } => {
            let names = provider.listxattr(as_path(&path))?;
            for name in &names {
                name_validation::validate_xattr_name_bytes(name)?;
            }
            VfsResponse::Names(names.into_iter().map(ByteBuf::from).collect())
        }
        VfsRequest::RemoveXattr { path, name } => {
            provider.removexattr(as_path(&path), &name)?;
            VfsResponse::Ok
        }
        VfsRequest::Flush { path } => {
            provider.flush(as_path(&path))?;
            VfsResponse::Ok
        }
        VfsRequest::Fsync { path, datasync } => {
            provider.fsync(as_path(&path), datasync)?;
            VfsResponse::Ok
        }
        VfsRequest::FsyncDir { .. } => VfsResponse::Ok,
        VfsRequest::StatFs => VfsResponse::StatFs((&provider.statfs()?).into()),
    })
}

#[cfg(test)]
mod dispatch_mutation_tests {
    use std::path::Path;
    use std::sync::Arc;
    use std::thread;

    use serde_bytes::ByteBuf;

    use super::super::super::test_backend::InMemoryFs;
    use super::super::super::{PathFs, VAttr};
    use super::super::protocol::{VfsRequest, VfsResponse};
    use super::{DispatchState, dispatch_with_state};
    use crate::backends::shared::platform;

    #[test]
    fn remove_empty_dir_races_create_on_same_connection() {
        let provider = Arc::new(InMemoryFs::new());
        provider.mkdir(Path::new("/d"), 0o755).expect("mkdir /d");
        let state = Arc::new(DispatchState::default());

        for _ in 0..32 {
            let provider_remove = Arc::clone(&provider);
            let state_remove = Arc::clone(&state);
            let remove = thread::spawn(move || {
                dispatch_with_state(
                    provider_remove.as_ref(),
                    VfsRequest::Remove {
                        path: ByteBuf::from(b"/d".to_vec()),
                    },
                    state_remove.as_ref(),
                )
            });
            let provider_create = Arc::clone(&provider);
            let state_create = Arc::clone(&state);
            let create = thread::spawn(move || {
                dispatch_with_state(
                    provider_create.as_ref(),
                    VfsRequest::Create {
                        path: ByteBuf::from(b"/d/f".to_vec()),
                        attr: (&VAttr::file(0o644, 0)).into(),
                    },
                    state_create.as_ref(),
                )
            });
            let remove_resp = remove.join().expect("remove thread panicked");
            let create_resp = create.join().expect("create thread panicked");

            let dir_exists = provider.getattr(Path::new("/d")).is_ok();
            let child_exists = provider.getattr(Path::new("/d/f")).is_ok();
            match (dir_exists, child_exists) {
                (false, false) => {
                    assert!(
                        matches!(remove_resp, VfsResponse::Ok),
                        "removed dir should win: remove={remove_resp:?} create={create_resp:?}"
                    );
                }
                (true, true) => {
                    assert!(
                        matches!(create_resp, VfsResponse::Attr(_)),
                        "create should win when dir remains: remove={remove_resp:?} create={create_resp:?}"
                    );
                    let wire_enotempty = crate::backends::shared::platform::provider_errno_to_wire(
                        platform::enotempty(),
                    );
                    assert!(
                        matches!(remove_resp, VfsResponse::Err(errno) if errno == wire_enotempty),
                        "non-empty dir remove should fail: {remove_resp:?}"
                    );
                }
                (true, false) => {
                    assert!(
                        matches!(remove_resp, VfsResponse::Ok),
                        "empty dir remove should succeed: {remove_resp:?}"
                    );
                }
                (false, true) => {
                    panic!(
                        "orphan child without parent: remove={remove_resp:?} create={create_resp:?}"
                    );
                }
            }

            if !dir_exists {
                provider
                    .mkdir(Path::new("/d"), 0o755)
                    .expect("reset /d for next iteration");
            } else if child_exists {
                dispatch_with_state(
                    provider.as_ref(),
                    VfsRequest::Remove {
                        path: ByteBuf::from(b"/d/f".to_vec()),
                    },
                    state.as_ref(),
                );
            }
        }
    }
}
