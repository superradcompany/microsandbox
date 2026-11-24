//! Shared crash-recovery helpers for bounded block-writeback allocations.
//!
//! Both the VM runner and host-side sandbox removal use these helpers to
//! validate lease identities, check whether an allocation belongs to the
//! current Linux boot, and flush backing filesystems before releasing quota.

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::io;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
#[cfg(target_os = "linux")]
use std::path::PathBuf;

use microsandbox_db::entity::writeback_allocation;

#[cfg(any(target_os = "linux", not(test)))]
use crate::RuntimeError;
use crate::RuntimeResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Linux `(major, minor)` filesystem device identifier from `stat` / `mountinfo`.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct DeviceId {
    /// Device major number.
    pub major: u64,
    /// Device minor number.
    pub minor: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Verify that a persisted writeback allocation ID and lease filename match the
/// canonical 32-hex-character `<id>.lock` format.
pub fn is_valid_lease_name(allocation_id: &str, lease_name: &str) -> bool {
    allocation_id.len() == 32
        && allocation_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        && lease_name == format!("{allocation_id}.lock")
}

/// Read and normalize the current Linux kernel boot UUID.
#[cfg(target_os = "linux")]
pub fn current_boot_id() -> RuntimeResult<String> {
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| RuntimeError::Custom(format!("read Linux boot ID: {error}")))?;
    normalize_boot_id(boot_id.trim())
}

/// Validate a Linux boot UUID and normalize it to lowercase.
#[cfg(target_os = "linux")]
pub fn normalize_boot_id(boot_id: &str) -> RuntimeResult<String> {
    if boot_id.len() != 36
        || !boot_id
            .bytes()
            .enumerate()
            .all(|(index, byte)| match index {
                8 | 13 | 18 | 23 => byte == b'-',
                _ => byte.is_ascii_hexdigit(),
            })
    {
        return Err(RuntimeError::Custom(
            "Linux boot ID has an invalid format".into(),
        ));
    }
    Ok(boot_id.to_ascii_lowercase())
}

/// Extract a `(major, minor)` [`DeviceId`] from a Linux `st_dev` value.
#[cfg(target_os = "linux")]
pub fn device_id(raw: u64) -> DeviceId {
    DeviceId {
        major: libc::major(raw) as u64,
        minor: libc::minor(raw) as u64,
    }
}

/// Parse, sort, and deduplicate a comma-separated list of `major:minor` device IDs.
#[cfg(target_os = "linux")]
pub fn parse_backing_devices(encoded: &str) -> RuntimeResult<Vec<DeviceId>> {
    if encoded.is_empty() || encoded.len() > 32 * 1024 {
        return Err(RuntimeError::Custom(
            "writeback backing-device identity length is invalid".into(),
        ));
    }
    let mut devices = encoded
        .split(',')
        .map(|field| {
            let (major, minor) = field.split_once(':').ok_or_else(|| {
                RuntimeError::Custom("invalid writeback backing-device identity".into())
            })?;
            let major = major.parse::<u64>().map_err(|_| {
                RuntimeError::Custom("invalid writeback backing-device major number".into())
            })?;
            let minor = minor.parse::<u64>().map_err(|_| {
                RuntimeError::Custom("invalid writeback backing-device minor number".into())
            })?;
            Ok(DeviceId { major, minor })
        })
        .collect::<RuntimeResult<Vec<_>>>()?;
    devices.sort_unstable();
    devices.dedup();
    if devices.is_empty() || devices.len() > 1024 {
        return Err(RuntimeError::Custom(
            "writeback backing-device identity count is invalid".into(),
        ));
    }
    Ok(devices)
}

/// Flush all backing filesystems for an abandoned writeback allocation if it
/// belongs to the current Linux boot. Allocations from an earlier boot have no
/// surviving page-cache dirty data and succeed immediately.
pub fn recover_stale_allocation(allocation: &writeback_allocation::Model) -> RuntimeResult<()> {
    #[cfg(target_os = "linux")]
    {
        let current_boot_id = current_boot_id()?;
        let recorded_boot_id = normalize_boot_id(&allocation.boot_id)?;
        if recorded_boot_id != current_boot_id {
            // The page cache and all process locks disappeared at reboot, so no abandoned dirty
            // data from the recorded boot can still affect this boot's pressure membership.
            return Ok(());
        }
        let devices = parse_backing_devices(&allocation.backing_devices)?;
        sync_backing_devices(&devices)
    }

    #[cfg(all(not(target_os = "linux"), test))]
    {
        let _ = allocation;
        Ok(())
    }

    #[cfg(all(not(target_os = "linux"), not(test)))]
    {
        let _ = allocation;
        Err(RuntimeError::Custom(
            "writeback crash recovery is only supported on Linux".into(),
        ))
    }
}

/// Call `syncfs` on each recorded Linux backing filesystem device.
#[cfg(target_os = "linux")]
pub fn sync_backing_devices(devices: &[DeviceId]) -> RuntimeResult<()> {
    for device in devices {
        sync_backing_device(*device)?;
    }
    Ok(())
}

/// Decode an octal-escaped mount path field from `/proc/self/mountinfo`.
#[cfg(target_os = "linux")]
pub fn decode_mountinfo_path(value: &str) -> RuntimeResult<PathBuf> {
    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' {
            if index + 3 >= bytes.len()
                || !bytes[index + 1..=index + 3]
                    .iter()
                    .all(|byte| matches!(byte, b'0'..=b'7'))
            {
                return Err(RuntimeError::Custom(
                    "invalid escape in Linux mount table".into(),
                ));
            }
            let escaped = u16::from(bytes[index + 1] - b'0') * 64
                + u16::from(bytes[index + 2] - b'0') * 8
                + u16::from(bytes[index + 3] - b'0');
            let escaped = u8::try_from(escaped).map_err(|_| {
                RuntimeError::Custom("out-of-range escape in Linux mount table".into())
            })?;
            decoded.push(escaped);
            index += 4;
        } else {
            decoded.push(bytes[index]);
            index += 1;
        }
    }
    let decoded = String::from_utf8(decoded)
        .map_err(|_| RuntimeError::Custom("non-UTF-8 Linux mount point is unsupported".into()))?;
    let path = PathBuf::from(decoded);
    if !path.is_absolute() {
        return Err(RuntimeError::Custom(
            "Linux mount table contained a relative mount point".into(),
        ));
    }
    Ok(path)
}

#[cfg(target_os = "linux")]
fn sync_backing_device(expected: DeviceId) -> RuntimeResult<()> {
    let mountinfo = std::fs::read_to_string("/proc/self/mountinfo")
        .map_err(|error| RuntimeError::Custom(format!("read Linux mount table: {error}")))?;
    let mut matching_mount_seen = false;
    let mut last_error = None;

    for line in mountinfo.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 5 || parse_device_id(fields[2]) != Some(expected) {
            continue;
        }
        matching_mount_seen = true;
        let mount_path = match decode_mountinfo_path(fields[4]) {
            Ok(path) => path,
            Err(error) => {
                last_error = Some(error);
                continue;
            }
        };
        let file = match File::options()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&mount_path)
        {
            Ok(file) => file,
            Err(error) => {
                last_error = Some(RuntimeError::Custom(format!(
                    "open writeback backing mount {}: {error}",
                    mount_path.display()
                )));
                continue;
            }
        };
        let metadata = match file.metadata() {
            Ok(metadata) => metadata,
            Err(error) => {
                last_error = Some(RuntimeError::Custom(format!(
                    "verify writeback backing mount {}: {error}",
                    mount_path.display()
                )));
                continue;
            }
        };
        // Mount namespaces can change between reading mountinfo and opening the path. Verify the
        // opened descriptor still belongs to the recorded device before using it as a syncfs key.
        if device_id(metadata.dev()) != expected {
            continue;
        }
        if unsafe { libc::syncfs(file.as_raw_fd()) } == 0 {
            return Ok(());
        }
        last_error = Some(RuntimeError::Io(io::Error::last_os_error()));
    }

    Err(last_error.unwrap_or_else(|| {
        let reason = if matching_mount_seen {
            "no matching mount could be opened and verified"
        } else {
            "the backing filesystem is not mounted in this runtime namespace"
        };
        RuntimeError::Custom(format!(
            "cannot safely recycle writeback credit for device {}:{}: {reason}",
            expected.major, expected.minor
        ))
    }))
}

#[cfg(target_os = "linux")]
fn parse_device_id(value: &str) -> Option<DeviceId> {
    let (major, minor) = value.split_once(':')?;
    Some(DeviceId {
        major: major.parse().ok()?,
        minor: minor.parse().ok()?,
    })
}
