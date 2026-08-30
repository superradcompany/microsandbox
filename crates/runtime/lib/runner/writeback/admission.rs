//! Crash-safe membership and fair-share coordination for bounded block writeback.

use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

#[cfg(target_os = "linux")]
use std::fs::OpenOptions;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;

use microsandbox_db::DbWriteConnection;
use microsandbox_db::entity::writeback_allocation;
use microsandbox_utils::process_lock;
use msb_krun::WritebackLimit;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set};

use crate::{RuntimeError, RuntimeResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Process-held membership in the host-global buffered-writeback pool.
pub(crate) struct WritebackPressureGuard {
    lease: Option<AllocationLease>,
    limit: Option<WritebackLimit>,
}

struct AllocationLease {
    allocation_id: String,
    lease_path: PathBuf,
    file: File,
    backing_files: Vec<File>,
    released: AtomicBool,
}

struct StaleAllocation {
    id: String,
    lease_name: String,
    lease_path: PathBuf,
    file: File,
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DeviceId {
    major: u64,
    minor: u64,
}

struct RecoveryIdentity {
    boot_id: String,
    backing_devices: String,
    files: Vec<File>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl WritebackPressureGuard {
    pub(crate) fn is_managed(&self) -> bool {
        self.lease.is_some()
    }

    /// Returns the live limit shared by every eligible disk in this VM.
    pub(crate) fn limit(&self) -> Option<WritebackLimit> {
        self.limit.clone()
    }

    /// Refreshes this VM's per-disk target from the current host-wide fair share.
    pub(crate) async fn refresh(&self, db: &DbWriteConnection) -> RuntimeResult<()> {
        let (Some(lease), Some(limit)) = (&self.lease, &self.limit) else {
            return Ok(());
        };
        let allocations = writeback_allocation::Entity::find().all(db).await?;
        let target_bytes = fair_target_bytes(&lease.allocation_id, &allocations)?;
        let previous_target_bytes = limit.target_bytes();
        limit.set_target_bytes(target_bytes).map_err(|error| {
            RuntimeError::Custom(format!("update live writeback pressure target: {error}"))
        })?;
        if target_bytes != previous_target_bytes {
            // Target transitions are infrequent and useful when diagnosing host-wide pressure.
            tracing::debug!(
                allocation_id = %lease.allocation_id,
                previous_target_bytes,
                target_bytes,
                "writeback pressure target changed"
            );
        }
        Ok(())
    }

    /// Moves this VM to its smallest forward-progress target after coordination fails.
    pub(crate) fn fail_closed(&self) {
        if let Some(limit) = &self.limit {
            let _ = limit.set_target_bytes(1);
        }
    }

    /// Removes catalog state and releases the process-held pressure lease.
    pub(crate) async fn release(&self, db: &DbWriteConnection) -> RuntimeResult<()> {
        if let Some(lease) = &self.lease {
            lease.release(db).await?;
        }
        Ok(())
    }
}

impl AllocationLease {
    async fn release(&self, db: &DbWriteConnection) -> RuntimeResult<()> {
        if self.released.load(Ordering::Acquire) {
            return Ok(());
        }

        // Do not recycle aggregate credit merely because the VMM process exited. A guest can stop
        // without issuing FLUSH, and the kernel may still own dirty pages after libkrun closes the
        // image. Retained descriptors verify the exact backing inodes after libkrun's own teardown
        // sync; crash recovery falls back to syncfs because process-held descriptors are gone.
        sync_backing_files(&self.backing_files)?;
        writeback_allocation::Entity::delete_many()
            .filter(writeback_allocation::Column::Id.eq(self.allocation_id.clone()))
            .exec(db)
            .await?;
        process_lock::unlock(&self.file)?;
        self.released.store(true, Ordering::Release);
        if let Err(error) = std::fs::remove_file(&self.lease_path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::debug!(path = %self.lease_path.display(), %error, "remove writeback lease file");
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Registers every eligible disk and initializes this VM's live fair-share target.
pub(crate) async fn acquire(
    db: &DbWriteConnection,
    run_id: i32,
    lease_dir: &Path,
    pool_bytes: Option<u64>,
    per_disk_limit_bytes: Option<u64>,
    disk_paths: &[PathBuf],
) -> RuntimeResult<WritebackPressureGuard> {
    let Some(per_disk_limit_bytes) = per_disk_limit_bytes else {
        return Ok(WritebackPressureGuard {
            lease: None,
            limit: None,
        });
    };
    let limit = WritebackLimit::new(per_disk_limit_bytes);
    let Some(pool_bytes) = pool_bytes else {
        return Ok(WritebackPressureGuard {
            lease: None,
            limit: Some(limit),
        });
    };
    if disk_paths.is_empty() {
        return Ok(WritebackPressureGuard {
            lease: None,
            limit: None,
        });
    }

    let disk_count = disk_paths.len();
    let recovery_identity = recovery_identity(disk_paths)?;
    let requested_bytes = requested_max_bytes(per_disk_limit_bytes, disk_count)?;
    prepare_lease_dir(lease_dir)?;
    let allocation_id = format!("{:032x}", rand::random::<u128>());
    let lease_name = format!("{allocation_id}.lock");
    let lease_path = lease_dir.join(&lease_name);
    let file = process_lock::create_new_lock_file(&lease_path)?;
    process_lock::lock_exclusive(&file)?;

    let started = Instant::now();
    let allocations = match writeback_allocation::Entity::find().all(db).await {
        Ok(allocations) => allocations,
        Err(error) => {
            clean_unpublished_lease(&file, &lease_path);
            return Err(error.into());
        }
    };
    let stale = probe_stale_allocations(lease_dir, &allocations);
    let recovery_boot_id = recovery_identity.boot_id.clone();
    let recovery_backing_devices = recovery_identity.backing_devices.clone();

    let transaction_result = db
        .transaction(|transaction| {
            let stale = stale
                .iter()
                .map(|entry| (entry.id.clone(), entry.lease_name.clone()))
                .collect::<Vec<_>>();
            let allocation_id = allocation_id.clone();
            let lease_name = lease_name.clone();
            let recovery_boot_id = recovery_boot_id.clone();
            let recovery_backing_devices = recovery_backing_devices.clone();
            async move {
                for (id, expected_lease_name) in stale {
                    writeback_allocation::Entity::delete_many()
                        .filter(writeback_allocation::Column::Id.eq(id))
                        .filter(writeback_allocation::Column::LeaseName.eq(expected_lease_name))
                        .exec(&transaction)
                        .await?;
                }

                // The insert remains serialized with stale cleanup. Capacity is intentionally not
                // an admission gate: every live runtime converges to a weighted fair share instead.
                let active = writeback_allocation::Entity::find()
                    .all(&transaction)
                    .await?;
                let existing_requested_bytes = total_requested_bytes(&active)?;

                writeback_allocation::Entity::insert(writeback_allocation::ActiveModel {
                    id: Set(allocation_id.clone()),
                    run_id: Set(run_id),
                    lease_name: Set(lease_name.clone()),
                    per_disk_limit_bytes: Set(to_i64(
                        per_disk_limit_bytes,
                        "per-disk writeback limit",
                    )?),
                    disk_count: Set(i32::try_from(disk_count).map_err(|_| {
                        RuntimeError::Custom("writeback disk count exceeds i32".into())
                    })?),
                    reserved_bytes: Set(to_i64(requested_bytes, "writeback requested maximum")?),
                    pool_bytes: Set(to_i64(pool_bytes, "writeback pool")?),
                    boot_id: Set(recovery_boot_id),
                    backing_devices: Set(recovery_backing_devices),
                    created_at: Set(chrono::Utc::now().naive_utc()),
                })
                .exec(&transaction)
                .await?;

                let active = writeback_allocation::Entity::find()
                    .all(&transaction)
                    .await?;
                let target_bytes = fair_target_bytes(&allocation_id, &active)?;

                Ok::<_, RuntimeError>((transaction, (existing_requested_bytes, target_bytes)))
            }
        })
        .await;

    match transaction_result {
        Ok((existing_requested_bytes, target_bytes)) => {
            clean_stale_files(stale);
            limit.set_target_bytes(target_bytes).map_err(|error| {
                RuntimeError::Custom(format!("set initial writeback pressure target: {error}"))
            })?;
            tracing::debug!(
                pool_bytes,
                existing_requested_bytes,
                requested_bytes,
                per_disk_limit_bytes,
                target_bytes,
                disk_count,
                elapsed_us = started.elapsed().as_micros(),
                "writeback pressure lease acquired"
            );
            Ok(WritebackPressureGuard {
                lease: Some(AllocationLease {
                    allocation_id,
                    lease_path,
                    file,
                    backing_files: recovery_identity.files,
                    released: AtomicBool::new(false),
                }),
                limit: Some(limit),
            })
        }
        Err(error) => {
            clean_unpublished_lease(&file, &lease_path);
            Err(error)
        }
    }
}

fn requested_max_bytes(per_disk_limit_bytes: u64, disk_count: usize) -> RuntimeResult<u64> {
    let disk_count = u64::try_from(disk_count)
        .map_err(|_| RuntimeError::Custom("writeback disk count exceeds u64".into()))?;
    per_disk_limit_bytes
        .checked_mul(disk_count)
        .ok_or_else(|| RuntimeError::Custom("writeback requested maximum overflowed u64".into()))
}

fn total_requested_bytes(allocations: &[writeback_allocation::Model]) -> RuntimeResult<u64> {
    allocations.iter().try_fold(0_u64, |total, allocation| {
        let reserved = u64::try_from(allocation.reserved_bytes).map_err(|_| {
            RuntimeError::Custom(format!(
                "writeback allocation {} contains a negative requested maximum",
                allocation.id
            ))
        })?;
        total
            .checked_add(reserved)
            .ok_or_else(|| RuntimeError::Custom("writeback requested total overflowed u64".into()))
    })
}

fn most_restrictive_pool_bytes(
    requested_pool_bytes: u64,
    allocations: &[writeback_allocation::Model],
) -> RuntimeResult<u64> {
    allocations
        .iter()
        .try_fold(requested_pool_bytes, |minimum, allocation| {
            let pool_bytes = u64::try_from(allocation.pool_bytes).map_err(|_| {
                RuntimeError::Custom(format!(
                    "writeback allocation {} contains a negative pool limit",
                    allocation.id
                ))
            })?;
            Ok(minimum.min(pool_bytes))
        })
}

/// Computes the weighted max-min fair target for one allocation.
///
/// Every disk receives the same waterline unless its configured maximum is lower. An allocation
/// with multiple writable disks therefore consumes one share per disk rather than one share per
/// sandbox. Integer division may leave a few bytes unused but never exceeds the active pool.
fn fair_target_bytes(
    allocation_id: &str,
    allocations: &[writeback_allocation::Model],
) -> RuntimeResult<u64> {
    let allocation = allocations
        .iter()
        .find(|allocation| allocation.id == allocation_id)
        .ok_or_else(|| {
            RuntimeError::Custom(format!(
                "writeback pressure allocation {allocation_id} disappeared"
            ))
        })?;
    let requested_limit = allocation_limit_bytes(allocation)?;
    let pool_bytes = most_restrictive_pool_bytes(u64::MAX, allocations)?;
    let mut limits = allocations
        .iter()
        .map(|allocation| {
            Ok((
                allocation_limit_bytes(allocation)?,
                allocation_disk_count(allocation)?,
            ))
        })
        .collect::<RuntimeResult<Vec<_>>>()?;
    limits.sort_unstable_by_key(|(limit, _)| *limit);

    let mut remaining_pool = pool_bytes;
    let mut remaining_disks = limits.iter().try_fold(0_u64, |total, (_, count)| {
        total
            .checked_add(*count)
            .ok_or_else(|| RuntimeError::Custom("writeback disk total overflowed u64".into()))
    })?;
    if remaining_disks == 0 {
        return Err(RuntimeError::Custom(
            "writeback pressure allocation has no disks".into(),
        ));
    }

    for (configured_limit, disk_count) in limits {
        let waterline = remaining_pool / remaining_disks;
        if configured_limit >= waterline {
            return Ok(requested_limit.min(waterline.max(1)));
        }
        let allocation_bytes = configured_limit.checked_mul(disk_count).ok_or_else(|| {
            RuntimeError::Custom("writeback fair-share total overflowed u64".into())
        })?;
        remaining_pool = remaining_pool.saturating_sub(allocation_bytes);
        remaining_disks -= disk_count;
        if remaining_disks == 0 {
            return Ok(requested_limit);
        }
    }

    Ok(requested_limit)
}

fn allocation_limit_bytes(allocation: &writeback_allocation::Model) -> RuntimeResult<u64> {
    u64::try_from(allocation.per_disk_limit_bytes).map_err(|_| {
        RuntimeError::Custom(format!(
            "writeback allocation {} contains a negative per-disk limit",
            allocation.id
        ))
    })
}

fn allocation_disk_count(allocation: &writeback_allocation::Model) -> RuntimeResult<u64> {
    let disk_count = u64::try_from(allocation.disk_count).map_err(|_| {
        RuntimeError::Custom(format!(
            "writeback allocation {} contains a negative disk count",
            allocation.id
        ))
    })?;
    if disk_count == 0 {
        return Err(RuntimeError::Custom(format!(
            "writeback allocation {} contains no disks",
            allocation.id
        )));
    }
    Ok(disk_count)
}

fn to_i64(value: u64, label: &str) -> RuntimeResult<i64> {
    i64::try_from(value).map_err(|_| RuntimeError::Custom(format!("{label} exceeds i64")))
}

fn recovery_identity(disk_paths: &[PathBuf]) -> RuntimeResult<RecoveryIdentity> {
    #[cfg(target_os = "linux")]
    {
        let files = disk_paths
            .iter()
            .map(|path| {
                OpenOptions::new().read(true).open(path).map_err(|error| {
                    RuntimeError::Custom(format!(
                        "open writeback backing file {} for recovery: {error}",
                        path.display()
                    ))
                })
            })
            .collect::<RuntimeResult<Vec<_>>>()?;
        let mut devices = files
            .iter()
            .map(|file| file.metadata().map(|metadata| device_id(metadata.dev())))
            .collect::<io::Result<Vec<_>>>()?;
        devices.sort_unstable();
        devices.dedup();
        if devices.is_empty() {
            return Err(RuntimeError::Custom(
                "active writeback pressure policy has no backing filesystem identity".into(),
            ));
        }
        let backing_devices = devices
            .iter()
            .map(|device| format!("{}:{}", device.major, device.minor))
            .collect::<Vec<_>>()
            .join(",");
        Ok(RecoveryIdentity {
            boot_id: current_boot_id()?,
            backing_devices,
            files,
        })
    }

    #[cfg(all(not(target_os = "linux"), test))]
    {
        let _ = disk_paths;
        Ok(RecoveryIdentity {
            boot_id: "unit-test-boot".into(),
            backing_devices: "0:0".into(),
            files: Vec::new(),
        })
    }

    #[cfg(all(not(target_os = "linux"), not(test)))]
    {
        let _ = disk_paths;
        Err(RuntimeError::Custom(
            "bounded buffered block writeback is only supported on Linux".into(),
        ))
    }
}

#[cfg(target_os = "linux")]
fn current_boot_id() -> RuntimeResult<String> {
    let boot_id = std::fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .map_err(|error| RuntimeError::Custom(format!("read Linux boot ID: {error}")))?;
    normalize_boot_id(boot_id.trim())
}

#[cfg(target_os = "linux")]
fn normalize_boot_id(boot_id: &str) -> RuntimeResult<String> {
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

#[cfg(target_os = "linux")]
fn device_id(raw: u64) -> DeviceId {
    DeviceId {
        major: libc::major(raw) as u64,
        minor: libc::minor(raw) as u64,
    }
}

#[cfg(target_os = "linux")]
fn parse_backing_devices(encoded: &str) -> RuntimeResult<Vec<DeviceId>> {
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

fn recover_stale_allocation(allocation: &writeback_allocation::Model) -> RuntimeResult<()> {
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

#[cfg(target_os = "linux")]
fn sync_backing_devices(devices: &[DeviceId]) -> RuntimeResult<()> {
    for device in devices {
        sync_backing_device(*device)?;
    }
    Ok(())
}

fn sync_backing_files(files: &[File]) -> RuntimeResult<()> {
    for (index, file) in files.iter().enumerate() {
        file.sync_all().map_err(|error| {
            RuntimeError::Custom(format!(
                "synchronize writeback backing file {index} before recycling credit: {error}"
            ))
        })?;
    }
    Ok(())
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
        let file = match File::open(&mount_path) {
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

#[cfg(target_os = "linux")]
fn decode_mountinfo_path(value: &str) -> RuntimeResult<PathBuf> {
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

fn probe_stale_allocations(
    lease_dir: &Path,
    allocations: &[writeback_allocation::Model],
) -> Vec<StaleAllocation> {
    let mut stale = Vec::new();
    for allocation in allocations {
        if !is_valid_lease_name(&allocation.id, &allocation.lease_name) {
            // Catalog contents are not trusted as paths. An invalid or unverifiable entry remains
            // charged, which fails closed instead of escaping the private lease directory.
            tracing::warn!(
                allocation_id = %allocation.id,
                lease_name = %allocation.lease_name,
                "writeback allocation has an invalid lease name; preserving reservation"
            );
            continue;
        }
        let lease_path = lease_dir.join(&allocation.lease_name);
        let Ok(file) = process_lock::open_existing_lock_file(&lease_path) else {
            // Missing lease files remain conservatively occupied. This avoids freeing credit when
            // the lease directory is unreadable or has been tampered with.
            continue;
        };
        match process_lock::try_lock_exclusive(&file) {
            Ok(true) => match recover_stale_allocation(allocation) {
                Ok(()) => stale.push(StaleAllocation {
                    id: allocation.id.clone(),
                    lease_name: allocation.lease_name.clone(),
                    lease_path,
                    file,
                }),
                Err(error) => tracing::warn!(
                    allocation_id = %allocation.id,
                    %error,
                    "could not synchronize abandoned writeback credit; preserving reservation"
                ),
            },
            Ok(false) => {}
            Err(error) => tracing::warn!(
                allocation_id = %allocation.id,
                %error,
                "could not verify writeback allocation lease; preserving reservation"
            ),
        }
    }
    stale
}

fn clean_stale_files(stale: Vec<StaleAllocation>) {
    for entry in stale {
        let _ = process_lock::unlock(&entry.file);
        if let Err(error) = std::fs::remove_file(&entry.lease_path)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::debug!(path = %entry.lease_path.display(), %error, "remove stale writeback lease");
        }
    }
}

fn clean_unpublished_lease(file: &File, lease_path: &Path) {
    let _ = process_lock::unlock(file);
    if let Err(error) = std::fs::remove_file(lease_path)
        && error.kind() != io::ErrorKind::NotFound
    {
        tracing::debug!(path = %lease_path.display(), %error, "remove unpublished writeback lease");
    }
}

fn prepare_lease_dir(path: &Path) -> RuntimeResult<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn is_valid_lease_name(allocation_id: &str, lease_name: &str) -> bool {
    allocation_id.len() == 32
        && allocation_id.bytes().all(|byte| byte.is_ascii_hexdigit())
        && lease_name == format!("{allocation_id}.lock")
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::Duration;

    use microsandbox_db::DbWriteConnection;
    use microsandbox_db::entity::{run, sandbox, writeback_allocation};
    use microsandbox_migration::{Migrator, MigratorTrait};
    use sea_orm::{ActiveModelTrait, EntityTrait, Set};
    use tempfile::TempDir;

    #[cfg(target_os = "linux")]
    use super::{DeviceId, decode_mountinfo_path, normalize_boot_id, parse_backing_devices};
    use super::{acquire, is_valid_lease_name, requested_max_bytes};

    fn test_disks(dir: &TempDir, count: usize) -> Vec<PathBuf> {
        (0..count)
            .map(|index| {
                let path = dir.path().join(format!("disk-{index}.raw"));
                std::fs::File::create(&path).unwrap();
                path
            })
            .collect()
    }

    async fn test_db() -> (TempDir, DbWriteConnection, Vec<i32>) {
        let dir = tempfile::tempdir().unwrap();
        let db = DbWriteConnection::open(
            &dir.path().join("catalog.db"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        Migrator::up(db.inner(), None).await.unwrap();

        let sandbox_id = sandbox::ActiveModel {
            name: Set("writeback-pressure-test".into()),
            config: Set("{}".into()),
            status: Set(sandbox::SandboxStatus::Running),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(&db)
        .await
        .unwrap()
        .id;
        let mut run_ids = Vec::new();
        for _ in 0..3 {
            run_ids.push(
                run::ActiveModel {
                    sandbox_id: Set(sandbox_id),
                    status: Set(run::RunStatus::Running),
                    ..Default::default()
                }
                .insert(&db)
                .await
                .unwrap()
                .id,
            );
        }
        (dir, db, run_ids)
    }

    #[test]
    fn reservation_multiplies_the_per_disk_limit() {
        assert_eq!(requested_max_bytes(1280, 3).unwrap(), 3840);
        assert!(requested_max_bytes(u64::MAX, 2).is_err());
    }

    #[test]
    fn lease_names_are_derived_from_canonical_allocation_ids() {
        let id = "0123456789abcdef0123456789abcdef";
        assert!(is_valid_lease_name(id, &format!("{id}.lock")));
        assert!(!is_valid_lease_name(id, "../outside.lock"));
        assert!(!is_valid_lease_name("short", "short.lock"));
        assert!(!is_valid_lease_name(
            "0123456789abcdef0123456789abcdeg",
            "0123456789abcdef0123456789abcdeg.lock"
        ));
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn recovery_metadata_is_strict_and_mount_paths_are_decoded() {
        assert_eq!(
            normalize_boot_id("550E8400-E29B-41D4-A716-446655440000").unwrap(),
            "550e8400-e29b-41d4-a716-446655440000"
        );
        assert!(normalize_boot_id("not-a-boot-id").is_err());
        assert_eq!(
            parse_backing_devices("8:2,8:1,8:2").unwrap(),
            vec![
                DeviceId { major: 8, minor: 1 },
                DeviceId { major: 8, minor: 2 }
            ]
        );
        assert!(parse_backing_devices("").is_err());
        assert!(parse_backing_devices("8:1:2").is_err());
        assert_eq!(
            decode_mountinfo_path("/srv/msb\\040data").unwrap(),
            PathBuf::from("/srv/msb data")
        );
        assert!(decode_mountinfo_path("relative").is_err());
        assert!(decode_mountinfo_path("/bad\\999").is_err());
    }

    #[tokio::test]
    async fn pressure_admits_overcommit_and_rebalances_live_limits() {
        let (dir, db, run_ids) = test_db().await;
        let lease_dir = dir.path().join("leases");
        let per_disk = 512 * 1024 * 1024;
        let pool = 2 * per_disk;
        let disks = test_disks(&dir, 1);

        let first = acquire(
            &db,
            run_ids[0],
            &lease_dir,
            Some(pool),
            Some(per_disk),
            &disks,
        )
        .await
        .unwrap();
        let second = acquire(
            &db,
            run_ids[1],
            &lease_dir,
            Some(pool),
            Some(per_disk),
            &disks,
        )
        .await
        .unwrap();
        let third = acquire(
            &db,
            run_ids[2],
            &lease_dir,
            Some(pool),
            Some(per_disk),
            &disks,
        )
        .await
        .unwrap();

        assert_eq!(
            writeback_allocation::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .len(),
            3
        );
        first.refresh(&db).await.unwrap();
        second.refresh(&db).await.unwrap();
        assert_eq!(first.limit().unwrap().target_bytes(), pool / 3);
        assert_eq!(second.limit().unwrap().target_bytes(), pool / 3);
        assert_eq!(third.limit().unwrap().target_bytes(), pool / 3);

        third.release(&db).await.unwrap();
        first.refresh(&db).await.unwrap();
        assert_eq!(first.limit().unwrap().target_bytes(), per_disk);

        first.release(&db).await.unwrap();
        second.release(&db).await.unwrap();
    }

    #[tokio::test]
    async fn pressure_preserves_the_most_restrictive_live_pool() {
        let (dir, db, run_ids) = test_db().await;
        let lease_dir = dir.path().join("leases");
        let limit = 512 * 1024 * 1024;
        let disks = test_disks(&dir, 1);

        let first = acquire(
            &db,
            run_ids[0],
            &lease_dir,
            Some(limit),
            Some(limit),
            &disks,
        )
        .await
        .unwrap();
        let second = acquire(
            &db,
            run_ids[1],
            &lease_dir,
            Some(2 * limit),
            Some(limit),
            &disks,
        )
        .await
        .unwrap();
        first.refresh(&db).await.unwrap();
        assert_eq!(first.limit().unwrap().target_bytes(), limit / 2);
        assert_eq!(second.limit().unwrap().target_bytes(), limit / 2);

        first.release(&db).await.unwrap();
        second.refresh(&db).await.unwrap();
        assert_eq!(second.limit().unwrap().target_bytes(), limit);
        second.release(&db).await.unwrap();
    }

    #[tokio::test]
    async fn disabled_pressure_pool_does_not_create_a_lease_or_catalog_row() {
        let (dir, db, run_ids) = test_db().await;
        let lease_dir = dir.path().join("leases");
        let disks = test_disks(&dir, 1);

        let guard = acquire(
            &db,
            run_ids[0],
            &lease_dir,
            None,
            Some(512 * 1024 * 1024),
            &disks,
        )
        .await
        .unwrap();

        assert!(!lease_dir.exists());
        assert!(
            writeback_allocation::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(guard.limit().unwrap().target_bytes(), 512 * 1024 * 1024);
        guard.release(&db).await.unwrap();
    }

    #[tokio::test]
    async fn pressure_pool_recovers_membership_after_owner_crash() {
        let (dir, db, run_ids) = test_db().await;
        let lease_dir = dir.path().join("leases");
        let limit = 512 * 1024 * 1024;
        let disks = test_disks(&dir, 1);

        let abandoned = acquire(
            &db,
            run_ids[0],
            &lease_dir,
            Some(limit),
            Some(limit),
            &disks,
        )
        .await
        .unwrap();
        drop(abandoned);

        let replacement = acquire(
            &db,
            run_ids[1],
            &lease_dir,
            Some(limit),
            Some(limit),
            &disks,
        )
        .await
        .unwrap();
        let rows = writeback_allocation::Entity::find().all(&db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].run_id, run_ids[1]);

        replacement.release(&db).await.unwrap();
    }

    #[tokio::test]
    async fn pressure_membership_survives_run_cleanup_until_safely_released() {
        let (dir, db, run_ids) = test_db().await;
        let lease_dir = dir.path().join("leases");
        let limit = 512 * 1024 * 1024;
        let disks = test_disks(&dir, 1);

        let guard = acquire(
            &db,
            run_ids[0],
            &lease_dir,
            Some(limit),
            Some(limit),
            &disks,
        )
        .await
        .unwrap();
        run::Entity::delete_by_id(run_ids[0])
            .exec(&db)
            .await
            .unwrap();

        let rows = writeback_allocation::Entity::find().all(&db).await.unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].run_id, run_ids[0]);

        guard.release(&db).await.unwrap();
        assert!(
            writeback_allocation::Entity::find()
                .all(&db)
                .await
                .unwrap()
                .is_empty()
        );
    }

    #[tokio::test]
    async fn concurrent_pressure_membership_keeps_both_creators() {
        let (dir, first_db, run_ids) = test_db().await;
        let second_db = DbWriteConnection::open(
            &dir.path().join("catalog.db"),
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await
        .unwrap();
        let lease_dir = dir.path().join("leases");
        let limit = 512 * 1024 * 1024;
        let disks = test_disks(&dir, 1);

        let (first, second) = tokio::join!(
            acquire(
                &first_db,
                run_ids[0],
                &lease_dir,
                Some(limit),
                Some(limit),
                &disks,
            ),
            acquire(
                &second_db,
                run_ids[1],
                &lease_dir,
                Some(limit),
                Some(limit),
                &disks,
            ),
        );

        assert!(first.is_ok());
        assert!(second.is_ok());
        assert_eq!(
            writeback_allocation::Entity::find()
                .all(&first_db)
                .await
                .unwrap()
                .len(),
            2
        );

        let first = first.unwrap();
        let second = second.unwrap();
        first.refresh(&first_db).await.unwrap();
        second.refresh(&second_db).await.unwrap();
        assert_eq!(first.limit().unwrap().target_bytes(), limit / 2);
        assert_eq!(second.limit().unwrap().target_bytes(), limit / 2);
        first.release(&first_db).await.unwrap();
        second.release(&second_db).await.unwrap();
    }

    #[tokio::test]
    async fn pressure_counts_every_writable_disk_in_the_fair_share() {
        let (dir, db, run_ids) = test_db().await;
        let lease_dir = dir.path().join("leases");
        let limit = 512 * 1024 * 1024;
        let pool = 3 * 256 * 1024 * 1024;
        let two_disks = test_disks(&dir, 2);
        let one_disk = vec![two_disks[0].clone()];

        let first = acquire(
            &db,
            run_ids[0],
            &lease_dir,
            Some(pool),
            Some(limit),
            &two_disks,
        )
        .await
        .unwrap();
        let second = acquire(
            &db,
            run_ids[1],
            &lease_dir,
            Some(pool),
            Some(limit),
            &one_disk,
        )
        .await
        .unwrap();

        first.refresh(&db).await.unwrap();
        assert_eq!(first.limit().unwrap().target_bytes(), pool / 3);
        assert_eq!(second.limit().unwrap().target_bytes(), pool / 3);

        second.release(&db).await.unwrap();
        first.refresh(&db).await.unwrap();
        assert_eq!(first.limit().unwrap().target_bytes(), pool / 2);
        first.release(&db).await.unwrap();
    }
}
