//! Recover per-sandbox private writeback leases before removing a stopped sandbox.

use std::fs::File;
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use microsandbox_db::{
    DbReadConnection, DbWriteConnection,
    entity::{run, writeback_allocation},
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter};

use crate::{
    MicrosandboxError, MicrosandboxResult,
    context::LocalContext,
    host_file::{self, HostFileAccess, HostFileKind, HostFilePolicy},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Recover and clear any remaining `writeback_allocation` rows backed by a
/// sandbox's private `sandboxes/<name>/runtime-leases/writeback` directory.
pub(super) async fn recover(
    local: &LocalContext,
    read: &DbReadConnection,
    write: &DbWriteConnection,
    name: &str,
    sandbox_id: i32,
) -> MicrosandboxResult<()> {
    // The caller holds transition and lifecycle ownership. No new runtime for
    // this sandbox can start until removal or recovery completes.
    let runs = run::Entity::find()
        .filter(run::Column::SandboxId.eq(sandbox_id))
        .all(read)
        .await?
        .into_iter()
        .map(|run| run.id)
        .collect::<Vec<_>>();
    if runs.is_empty() {
        return Ok(());
    }

    let allocations = writeback_allocation::Entity::find()
        .filter(writeback_allocation::Column::RunId.is_in(runs))
        .all(read)
        .await?;
    if allocations.is_empty() {
        return Ok(());
    }

    let directory = local
        .sandboxes_dir()
        .join(name)
        .join("runtime-leases/writeback");
    let policy = HostFilePolicy::strict_beneath(local.config().home());

    let leases = tokio::task::spawn_blocking(move || -> std::io::Result<_> {
        let boot = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")?;
        let mut leases = Vec::with_capacity(allocations.len());
        for allocation in allocations {
            if allocation.id.len() != 32
                || !allocation.id.bytes().all(|byte| byte.is_ascii_hexdigit())
                || allocation.lease_name != format!("{}.lock", allocation.id)
            {
                return Err(std::io::Error::other(
                    "invalid private writeback lease identity",
                ));
            }
            let lease = host_file::open(
                &directory.join(&allocation.lease_name),
                HostFileKind::Regular,
                HostFileAccess::ReadWrite,
                &policy,
            )?;
            if unsafe { libc::flock(lease.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if allocation.boot_id.trim() == boot.trim() {
                sync_devices(&allocation.backing_devices)?;
            } else if allocation.boot_id.len() != 36
                || !allocation.boot_id.bytes().enumerate().all(|(index, byte)| {
                    if matches!(index, 8 | 13 | 18 | 23) {
                        byte == b'-'
                    } else {
                        byte.is_ascii_hexdigit()
                    }
                })
            {
                return Err(std::io::Error::other("invalid writeback boot identity"));
            }
            leases.push((allocation, lease));
        }
        Ok(leases)
    })
    .await
    .map_err(|error| MicrosandboxError::Runtime(error.to_string()))??;

    for (allocation, _lease) in leases {
        // Keep each exact lease locked through deletion. An unavailable device,
        // live lock, or failed sync leaves reservation and recovery files intact.
        let removed = writeback_allocation::Entity::delete_many()
            .filter(writeback_allocation::Column::Id.eq(allocation.id))
            .filter(writeback_allocation::Column::RunId.eq(allocation.run_id))
            .filter(writeback_allocation::Column::LeaseName.eq(allocation.lease_name))
            .filter(writeback_allocation::Column::BootId.eq(allocation.boot_id))
            .filter(writeback_allocation::Column::BackingDevices.eq(allocation.backing_devices))
            .exec(write)
            .await?;
        if removed.rows_affected != 1 {
            return Err(MicrosandboxError::Runtime(
                "writeback reservation changed during removal; retaining recovery state".into(),
            ));
        }
    }

    Ok(())
}

fn sync_devices(encoded: &str) -> std::io::Result<()> {
    if encoded.is_empty() || encoded.len() > 32768 {
        return Err(std::io::Error::other("invalid writeback device identity"));
    }
    let mounts = std::fs::read_to_string("/proc/self/mountinfo")?;
    for device in encoded.split(',') {
        let mut synced = false;
        for line in mounts.lines() {
            let fields = line.split_whitespace().collect::<Vec<_>>();
            if fields.len() < 5 || fields[2] != device {
                continue;
            }
            let path = mount_path(fields[4])?;
            let file = match File::options()
                .read(true)
                .custom_flags(
                    libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK | libc::O_CLOEXEC,
                )
                .open(path)
            {
                Ok(file) => file,
                Err(_) => continue,
            };
            let dev = file.metadata()?.dev();
            if format!("{}:{}", libc::major(dev), libc::minor(dev)) != device {
                continue;
            }
            if unsafe { libc::syncfs(file.as_raw_fd()) } != 0 {
                return Err(std::io::Error::last_os_error());
            }
            synced = true;
            break;
        }
        if !synced {
            return Err(std::io::Error::other(
                "writeback backing filesystem is unavailable; retaining recovery state",
            ));
        }
    }
    Ok(())
}

fn mount_path(encoded: &str) -> std::io::Result<PathBuf> {
    let mut bytes = Vec::new();
    let mut input = encoded.bytes();
    while let Some(byte) = input.next() {
        if byte != b'\\' {
            bytes.push(byte);
            continue;
        }
        let digits = input.by_ref().take(3).collect::<Vec<_>>();
        if digits.len() != 3 || !digits.iter().all(|byte| (b'0'..=b'7').contains(byte)) {
            return Err(std::io::Error::other("invalid mount path escape"));
        }
        let value = digits
            .iter()
            .fold(0u16, |value, byte| value * 8 + u16::from(byte - b'0'));
        bytes.push(u8::try_from(value).map_err(std::io::Error::other)?);
    }
    let path = PathBuf::from(std::ffi::OsString::from_vec(bytes));
    if !path.is_absolute() {
        return Err(std::io::Error::other("relative mount path"));
    }
    Ok(path)
}
