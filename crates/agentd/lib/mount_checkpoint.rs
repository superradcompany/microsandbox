//! Guest-side writeback boundary for external and sandbox-owned filesystem checkpoints.

use std::{
    collections::BTreeSet,
    ffi::CString,
    fs::File,
    io,
    os::{fd::AsRawFd, unix::ffi::OsStrExt},
    sync::atomic::{AtomicBool, Ordering},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

static SYNC_ACTIVE: AtomicBool = AtomicBool::new(false);

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Pins an in-flight flush even after the async caller times out.
pub(crate) struct ExternalSyncPermit;

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for ExternalSyncPermit {
    fn drop(&mut self) {
        SYNC_ACTIVE.store(false, Ordering::Release);
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Reserve before scheduling, so queued and timed-out blocking work both stay visible.
pub(crate) fn try_start_sync() -> Option<ExternalSyncPermit> {
    SYNC_ACTIVE
        .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
        .ok()
        .map(|_| ExternalSyncPermit)
}

/// Flush selected superblocks while application tasks and external input are frozen.
///
/// `syncfs` reports writeback errors, unlike `sync`. This never unmounts a filesystem or
/// discards dirty pages. The caller must exclude independently running agent write streams.
/// Existing selectors are virtiofs tags; `path:/...` selects an exact guest mountpoint
/// for root and owned disk writeback. Older guests reject those unfamiliar tags, so
/// callers cannot mistake an old guest's acknowledgement for owned-disk sync support.
pub(crate) fn sync_external_mounts(expected_tags: Vec<String>) -> io::Result<()> {
    if expected_tags.is_empty() {
        return Ok(());
    }
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    for mountpoint in resolve_mountpoints(expected_tags, &mounts)? {
        let path =
            CString::new(mountpoint).map_err(|_| io::Error::other("NUL in guest mountpoint"))?;
        // O_PATH is not accepted by syncfs. Opening the mount root read-only does not
        // alter host data and also keeps the exact superblock pinned through the flush.
        let file = File::open(std::path::Path::new(std::ffi::OsStr::from_bytes(
            path.as_bytes(),
        )))?;
        if unsafe { libc::syncfs(file.as_raw_fd()) } < 0 {
            return Err(io::Error::last_os_error());
        }
    }
    Ok(())
}

/// Resolve the complete request before opening anything. A path selector is never
/// an arbitrary file to sync: it must name a decoded mountpoint in this namespace.
fn resolve_mountpoints(expected: Vec<String>, mounts: &str) -> io::Result<Vec<Vec<u8>>> {
    let mut tags = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for selector in expected {
        if let Some(path) = selector.strip_prefix("path:") {
            if !path.starts_with('/')
                || path.as_bytes().contains(&0)
                || path.split('/').any(|part| matches!(part, "." | ".."))
            {
                return Err(io::Error::other("invalid guest mountpoint selector"));
            }
            paths.insert(path.as_bytes().to_vec());
        } else {
            tags.insert(selector);
        }
    }
    let mut selected = BTreeSet::new();
    for line in mounts.lines() {
        let Some((fields, filesystem)) = line.split_once(" - ") else {
            return Err(io::Error::other("malformed guest mount inventory"));
        };
        let mut filesystem = filesystem.split_whitespace();
        let kind = filesystem
            .next()
            .ok_or_else(|| io::Error::other("missing guest filesystem type"))?;
        let tag = if kind == "virtiofs" {
            Some(
                filesystem
                    .next()
                    .ok_or_else(|| io::Error::other("missing virtiofs tag"))?,
            )
        } else {
            None
        };
        let selected_tag = tag.filter(|tag| tags.contains(*tag));
        if selected_tag.is_none() && paths.is_empty() {
            continue;
        }
        let mountpoint = fields
            .split_whitespace()
            .nth(4)
            .ok_or_else(|| io::Error::other("missing guest mountpoint"))?;
        let mountpoint = decode_mountpoint(mountpoint)?;
        let selected_path = paths.remove(&mountpoint);
        if let Some(tag) = selected_tag {
            tags.remove(tag);
        }
        if selected_tag.is_some() || selected_path {
            selected.insert(mountpoint);
        }
    }
    if tags.is_empty() && paths.is_empty() {
        Ok(selected.into_iter().collect())
    } else {
        let missing = tags
            .into_iter()
            .chain(
                paths
                    .into_iter()
                    .map(|path| format!("path:{}", String::from_utf8_lossy(&path))),
            )
            .collect::<Vec<_>>()
            .join(", ");
        Err(io::Error::other(format!(
            "checkpoint mounts are absent from the agent mount namespace: {missing}",
        )))
    }
}

fn decode_mountpoint(encoded: &str) -> io::Result<Vec<u8>> {
    let input = encoded.as_bytes();
    let mut output = Vec::with_capacity(input.len());
    let mut index = 0;
    while index < input.len() {
        if input[index] == b'\\' {
            let escape = input
                .get(index + 1..index + 4)
                .ok_or_else(|| io::Error::other("truncated mountpoint escape"))?;
            if !escape.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
                return Err(io::Error::other("invalid mountpoint escape"));
            }
            let value = u16::from(escape[0] - b'0') * 64
                + u16::from(escape[1] - b'0') * 8
                + u16::from(escape[2] - b'0');
            output.push(
                u8::try_from(value).map_err(|_| io::Error::other("invalid mountpoint octet"))?,
            );
            index += 4;
        } else {
            output.push(input[index]);
            index += 1;
        }
    }
    Ok(output)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::{decode_mountpoint, resolve_mountpoints, try_start_sync};

    const INVENTORY: &str = "1 0 0:1 / / rw - overlay overlay rw\n\
2 1 8:1 / /var/lib/docker rw - ext4 /dev/vdb rw\n\
3 1 0:2 / /cache\\040dir rw - virtiofs owned_cache rw\n\
4 1 0:3 / /external rw - virtiofs external_data rw\n";

    #[test]
    fn selects_root_owned_disk_and_existing_virtiofs_tags_together() {
        let mountpoints = resolve_mountpoints(
            vec![
                "path:/".into(),
                "path:/var/lib/docker".into(),
                "external_data".into(),
            ],
            INVENTORY,
        )
        .unwrap();
        assert_eq!(
            mountpoints,
            vec![
                b"/".to_vec(),
                b"/external".to_vec(),
                b"/var/lib/docker".to_vec()
            ]
        );
    }

    #[test]
    fn paths_match_decoded_mountpoints_and_deduplicate_tag_selection() {
        assert_eq!(
            resolve_mountpoints(
                vec![
                    "path:/cache dir".into(),
                    "owned_cache".into(),
                    "path:/cache dir".into()
                ],
                INVENTORY,
            )
            .unwrap(),
            vec![b"/cache dir".to_vec()]
        );
        assert!(resolve_mountpoints(vec![r"path:/cache\040dir".into()], INVENTORY).is_err());
    }

    #[test]
    fn path_selection_refuses_non_mount_files_and_invalid_paths() {
        for path in [
            "/var/lib/docker/file",
            "/var/lib",
            "relative",
            "/cache/../external",
            "/external/.",
            "/bad\0",
        ] {
            assert!(
                resolve_mountpoints(vec![format!("path:{path}")], INVENTORY).is_err(),
                "{path}"
            );
        }
        // Only virtiofs tags retain the original bare selector syntax.
        assert!(resolve_mountpoints(vec!["/var/lib/docker".into()], INVENTORY).is_err());
        assert!(resolve_mountpoints(vec!["/dev/vdb".into()], INVENTORY).is_err());
        assert!(resolve_mountpoints(vec!["unknown_tag".into()], INVENTORY).is_err());
    }

    #[test]
    fn incomplete_inventory_cannot_certify_a_partial_request() {
        assert!(
            resolve_mountpoints(vec!["path:/".into(), "path:/missing".into()], INVENTORY).is_err()
        );
        assert!(resolve_mountpoints(vec!["path:/".into()], "malformed").is_err());
        assert!(
            resolve_mountpoints(
                vec!["path:/".into()],
                r"1 0 0:1 / /bad\x rw - ext4 /dev/vdb rw"
            )
            .is_err()
        );
    }

    #[tokio::test]
    async fn timed_out_worker_keeps_later_capture_from_certifying_clean() {
        let permit = try_start_sync().unwrap();
        let (release, waiting) = std::sync::mpsc::channel();
        let worker = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            waiting.recv().unwrap();
        });
        // Timeout drops only the wait future, not the blocking worker's permit.
        let mut worker = worker;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(1), &mut worker)
                .await
                .is_err()
        );
        assert!(try_start_sync().is_none());
        release.send(()).unwrap();
        worker.await.unwrap();
        assert!(try_start_sync().is_some());
    }

    #[test]
    fn mount_inventory_escapes_are_decoded_without_path_substitution() {
        assert_eq!(
            decode_mountpoint(r"/work\040dir\134name").unwrap(),
            b"/work dir\\name"
        );
        assert!(decode_mountpoint(r"/bad\0").is_err());
        assert!(decode_mountpoint(r"/bad\xyz").is_err());
    }
}
