//! Durable single-file admission state without widening its synthetic namespace.

use std::{collections::BTreeMap, ffi::CString, io, sync::atomic::Ordering};

use serde::{Deserialize, Serialize};

use super::{OpenHandleAdmission, ROOT_INODE, SingleFileFs};
use crate::backends::passthroughfs::ExternalSingleFileIndex;
use crate::{DynFileSystem, PassthroughFs, backends::mobility};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const KIND: &[u8; 8] = b"MSBSFILE";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize, Serialize)]
struct SingleFileState {
    inner_name: Vec<u8>,
    guest_name: Vec<u8>,
    current_inode: u64,
    lookup_refs: BTreeMap<u64, u64>,
    open_handles: BTreeMap<u64, OpenHandleAdmission>,
    inner: Vec<u8>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn capture(fs: &SingleFileFs) -> io::Result<Vec<u8>> {
    let state = SingleFileState {
        inner_name: fs.inner_name.to_bytes().to_vec(),
        guest_name: fs.guest_name.to_vec(),
        current_inode: fs.current_inode.load(Ordering::Acquire),
        lookup_refs: fs
            .lookup_refs
            .read()
            .unwrap()
            .iter()
            .map(|(id, count)| (*id, *count))
            .collect(),
        open_handles: fs
            .open_handles
            .read()
            .unwrap()
            .iter()
            .map(|(id, admission)| (*id, *admission))
            .collect(),
        inner: fs.inner.capture_state()?,
    };
    let (_, index) =
        PassthroughFs::prepare_single_file_state(&state.inner, &fs.inner_name, &fs.inner_name)?;
    validate_admission(&state, &index)?;
    mobility::encode(KIND, &state)
}

pub(super) fn validate(fs: &SingleFileFs, bytes: &[u8]) -> io::Result<()> {
    let state = prepare(fs, bytes)?;
    fs.inner.validate_state(&state.inner)
}

pub(super) fn restore(fs: &SingleFileFs, bytes: &[u8]) -> io::Result<()> {
    let state = prepare(fs, bytes)?;
    // Inner restore validates/reopens everything before installing its state. Only
    // infallible admission-table replacement follows a successful inner commit.
    fs.inner.restore_state(&state.inner)?;
    *fs.lookup_refs.write().unwrap() = state.lookup_refs.into_iter().collect();
    *fs.open_handles.write().unwrap() = state.open_handles.into_iter().collect();
    fs.current_inode
        .store(state.current_inode, Ordering::Release);
    Ok(())
}

pub(super) fn validate_unavailable(bytes: &[u8]) -> io::Result<()> {
    let state: SingleFileState = mobility::decode(KIND, bytes)?;
    let source = checked_name(&state.inner_name)?;
    checked_name(&state.guest_name)?;
    let (_, index) = PassthroughFs::prepare_single_file_state(&state.inner, &source, &source)?;
    validate_admission(&state, &index)
}

fn prepare(fs: &SingleFileFs, bytes: &[u8]) -> io::Result<SingleFileState> {
    let mut state: SingleFileState = mobility::decode(KIND, bytes)?;
    let source = checked_name(&state.inner_name)?;
    if state.guest_name != fs.guest_name || (!fs.checkpoint_remapped && source != fs.inner_name) {
        return Err(invalid(
            "single-file checkpoint namespace differs from the requested mount",
        ));
    }
    // The inner backend confirms every saved path is either its root or precisely
    // the admitted source basename. Translation can never expose a sibling path.
    let (inner, index) =
        PassthroughFs::prepare_single_file_state(&state.inner, &source, &fs.inner_name)?;
    validate_admission(&state, &index)?;
    state.inner = inner;
    Ok(state)
}

fn validate_admission(state: &SingleFileState, index: &ExternalSingleFileIndex) -> io::Result<()> {
    let known = |inode: &u64| {
        *inode > 2 && (index.inodes.contains(inode) || index.invalid_inodes.contains(inode))
    };
    if (state.current_inode != 0 && !known(&state.current_inode))
        || state
            .lookup_refs
            .iter()
            .any(|(inode, count)| !known(inode) || (*count == 0 && *inode != state.current_inode))
        || index.files.iter().any(|(handle, inode)| {
            state
                .open_handles
                .get(handle)
                .is_none_or(|admission| admission.inner_inode != *inode)
        })
        || state.open_handles.iter().any(|(handle, admission)| {
            *handle == 0
                || admission.guest_inode <= 2
                || (index.files.get(handle) != Some(&admission.inner_inode)
                    && !index.invalid_inodes.contains(&admission.inner_inode))
        })
        || (state.current_inode == 0
            && (!state.lookup_refs.is_empty() || !state.open_handles.is_empty()))
        || (state.current_inode == ROOT_INODE)
    {
        return Err(invalid(
            "invalid single-file inode or handle admission table",
        ));
    }
    Ok(())
}

fn checked_name(bytes: &[u8]) -> io::Result<CString> {
    if bytes.is_empty() || bytes == b"." || bytes == b".." || bytes.contains(&b'/') {
        return Err(invalid("single-file checkpoint contains an invalid name"));
    }
    CString::new(bytes).map_err(|_| invalid("single-file checkpoint name contains NUL"))
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::{Context, ExternalCheckpointOptions, FsOptions, PassthroughConfig};

    fn context() -> Context {
        Context {
            uid: 0,
            gid: 0,
            pid: 1,
        }
    }

    fn mount(path: &Path, relaxed: bool, remapped: bool) -> SingleFileFs {
        let fs = SingleFileFs::new(
            path.to_path_buf(),
            "guest-file".into(),
            PassthroughConfig {
                external_checkpoint: Some(ExternalCheckpointOptions {
                    relaxed,
                    remapped,
                    ..Default::default()
                }),
                ..Default::default()
            },
        )
        .unwrap();
        fs.init(FsOptions::empty()).unwrap();
        fs
    }

    #[test]
    fn single_file_restore_preserves_fd_admission_and_hides_siblings() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        std::fs::write(&path, b"selected").unwrap();
        std::fs::write(temp.path().join("sibling"), b"private").unwrap();
        let source = mount(&path, false, false);
        let entry = source.lookup(context(), ROOT_INODE, c"guest-file").unwrap();
        let handle = source
            .open(context(), entry.inode, false, 0)
            .unwrap()
            .0
            .unwrap();
        let bytes = source.capture_state().unwrap();
        let destination = mount(&path, false, false);
        destination.restore_state(&bytes).unwrap();
        assert!(
            destination
                .lookup(context(), ROOT_INODE, c"sibling")
                .is_err()
        );
        assert!(
            destination
                .lookup(context(), ROOT_INODE, c"source")
                .is_err()
        );
        assert_eq!(
            destination.current_inode.load(Ordering::Acquire),
            entry.inode
        );
        assert_eq!(
            destination
                .inner_inode_for_handle(entry.inode, handle)
                .unwrap(),
            entry.inode
        );
        assert!(
            destination
                .getattr(context(), entry.inode, Some(handle))
                .is_ok()
        );
        assert!(
            destination
                .inner_inode_for_handle(entry.inode, handle + 1)
                .is_err()
        );
    }

    #[test]
    fn single_file_remap_translates_only_selected_basename() {
        let source_dir = tempfile::tempdir().unwrap();
        let destination_dir = tempfile::tempdir().unwrap();
        let source_path = source_dir.path().join("source-name");
        let destination_path = destination_dir.path().join("different-name");
        std::fs::write(&source_path, b"identical").unwrap();
        std::fs::write(&destination_path, b"identical").unwrap();
        let source = mount(&source_path, false, false);
        let entry = source.lookup(context(), ROOT_INODE, c"guest-file").unwrap();
        let bytes = source.capture_state().unwrap();
        assert!(
            mount(&destination_path, false, false)
                .restore_state(&bytes)
                .is_err()
        );
        let destination = mount(&destination_path, false, true);
        destination.restore_state(&bytes).unwrap();
        assert_eq!(
            destination
                .lookup(context(), ROOT_INODE, c"guest-file")
                .unwrap()
                .inode,
            entry.inode
        );
        assert!(
            destination
                .lookup(context(), ROOT_INODE, c"different-name")
                .is_err()
        );
        std::fs::write(&destination_path, b"different").unwrap();
        assert!(destination.restore_state(&bytes).is_err());
    }

    #[test]
    fn single_file_relaxed_restore_retains_stale_handles_across_recapture() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        std::fs::write(&path, b"before").unwrap();
        let source = mount(&path, false, false);
        let entry = source.lookup(context(), ROOT_INODE, c"guest-file").unwrap();
        source.open(context(), entry.inode, false, 0).unwrap();
        let bytes = source.capture_state().unwrap();
        std::fs::write(&path, b"after!").unwrap();
        assert!(mount(&path, false, false).restore_state(&bytes).is_err());
        let destination = mount(&path, true, false);
        destination.restore_state(&bytes).unwrap();
        assert_eq!(destination.request_error(entry.inode), Some(116));
        let fresh = destination
            .lookup(context(), ROOT_INODE, c"guest-file")
            .unwrap();
        assert_ne!(fresh.inode, entry.inode);
        let next = mount(&path, true, false);
        next.restore_state(&destination.capture_state().unwrap())
            .unwrap();
        assert_eq!(next.request_error(entry.inode), Some(116));
        assert_eq!(next.request_error(fresh.inode), None);
    }

    #[test]
    fn single_file_rejects_malformed_admission_and_forged_sibling_name() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("source");
        std::fs::write(&path, b"selected").unwrap();
        let source = mount(&path, false, false);
        let entry = source.lookup(context(), ROOT_INODE, c"guest-file").unwrap();
        let bytes = source.capture_state().unwrap();
        let destination = mount(&path, true, true);
        let mut state: SingleFileState = mobility::decode(KIND, &bytes).unwrap();
        state.lookup_refs.insert(ROOT_INODE, 1);
        assert!(
            destination
                .restore_state(&mobility::encode(KIND, &state).unwrap())
                .is_err()
        );
        state.lookup_refs.remove(&ROOT_INODE);
        state.inner_name = b"sibling".to_vec();
        assert!(
            destination
                .restore_state(&mobility::encode(KIND, &state).unwrap())
                .is_err()
        );
        assert_eq!(destination.current_inode.load(Ordering::Acquire), 0);
        assert!(entry.inode > 2);
        let unavailable = crate::UnavailableFs::default();
        unavailable.restore_state(&bytes).unwrap();
        assert_eq!(unavailable.request_error(entry.inode), Some(5));
        assert!(
            unavailable
                .restore_state(&bytes[..bytes.len() - 1])
                .is_err()
        );
    }
}
