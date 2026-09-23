//! Online ext4 growth using pinned init-time descriptors, never a caller-supplied path.

use std::fs::File;
use std::io;
use std::os::fd::AsRawFd;
use std::os::unix::fs::FileExt;
use std::sync::OnceLock;
use std::time::{Duration, Instant};

use microsandbox_protocol::core::RootDiskState;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const EXT4_IOC_RESIZE_FS: libc::c_ulong = 0x4008_6610;
const BLKGETSIZE64: libc::c_ulong = 0x8008_1272;
static ROOT: OnceLock<io::Result<RootFiles>> = OnceLock::new();

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct RootFiles {
    mount: File,
    device: File,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn register(mount: &str, device: &str) {
    // The managed ext4 mount becomes unreachable by path after pivot. Pin it now, just as
    // teardown does. An unavailable capability must not prevent ordinary sandbox startup.
    let _ = ROOT.set((|| {
        Ok(RootFiles {
            mount: File::open(mount)?,
            device: File::open(device)?,
        })
    })());
}

pub(crate) fn resize(target: u64, apply: bool) -> Result<RootDiskState, String> {
    let files = ROOT
        .get()
        .ok_or("root has no pinned block filesystem")?
        .as_ref()
        .map_err(|e| format!("root disk unavailable: {e}"))?;
    let caps = std::fs::read_to_string("/proc/self/status").map_err(|e| e.to_string())?;
    let admin = caps
        .lines()
        .find_map(|line| line.strip_prefix("CapEff:\t"))
        .and_then(|value| u64::from_str_radix(value.trim(), 16).ok())
        .is_some_and(|value| value & (1 << 24) != 0);
    if !admin {
        return Err("online ext4 growth requires agent CAP_SYS_RESOURCE".into());
    }
    let mut sb = [0u8; 1024];
    files
        .device
        .read_exact_at(&mut sb, 1024)
        .map_err(|e| e.to_string())?;
    let current = validate_superblock(&sb, target)?;
    let mut device_bytes = device_size(&files.device)?;
    if apply && target > current {
        // Virtio config change is asynchronous in the guest. Never issue the filesystem ioctl
        // until the block driver's own capacity reflects the host target.
        let deadline = Instant::now() + Duration::from_secs(10);
        while device_bytes < target {
            if Instant::now() >= deadline {
                return Err("guest block capacity did not converge".into());
            }
            std::thread::sleep(Duration::from_millis(2));
            device_bytes = device_size(&files.device)?;
        }
        let blocks = target / 4096;
        // SAFETY: ioctl reads one u64 from a valid reference; mount is a pinned open directory.
        if unsafe { libc::ioctl(files.mount.as_raw_fd(), EXT4_IOC_RESIZE_FS as _, &blocks) } < 0 {
            return Err(format!(
                "online ext4 expansion: {}",
                io::Error::last_os_error()
            ));
        }
        // Flush the committed superblock before observing it through the block descriptor.
        if unsafe { libc::syncfs(files.mount.as_raw_fd()) } < 0 {
            return Err(format!("sync grown ext4: {}", io::Error::last_os_error()));
        }
        files
            .device
            .read_exact_at(&mut sb, 1024)
            .map_err(|e| e.to_string())?;
    }
    let actual = validate_superblock(&sb, target)?;
    if apply && actual != target {
        return Err(format!(
            "filesystem capacity is {actual}, expected {target}"
        ));
    }
    Ok(RootDiskState {
        filesystem_bytes: actual,
        device_bytes,
    })
}

fn device_size(file: &File) -> Result<u64, String> {
    let mut size = 0u64;
    // SAFETY: BLKGETSIZE64 writes exactly one u64 into the supplied live storage.
    if unsafe { libc::ioctl(file.as_raw_fd(), BLKGETSIZE64 as _, &mut size) } < 0 {
        return Err(format!(
            "read guest block capacity: {}",
            io::Error::last_os_error()
        ));
    }
    Ok(size)
}

fn validate_superblock(sb: &[u8; 1024], target: u64) -> Result<u64, String> {
    let u16_at = |i| u16::from_le_bytes([sb[i], sb[i + 1]]);
    let u32_at = |i| u32::from_le_bytes(sb[i..i + 4].try_into().unwrap());
    if u16_at(56) != 0xef53 || u32_at(24) != 2 || u32_at(32) != 32768 {
        return Err("online growth requires a supported 4 KiB ext4 root".into());
    }
    let current_blocks = u64::from(u32_at(4)) | (u64::from(u32_at(0x150)) << 32);
    let current = current_blocks
        .checked_mul(4096)
        .ok_or("ext4 size overflow")?;
    if target < current || !target.is_multiple_of(4096) || target == 0 {
        return Err("root growth requires a nondecreasing size aligned to 4 KiB".into());
    }
    if target == current {
        return Ok(current);
    }
    if u32_at(92) & 0x10 == 0 || u32_at(96) & 0x10 != 0 {
        return Err(
            "root ext4 lacks supported resize-inode metadata; offline preparation is required"
                .into(),
        );
    }
    let descriptor_size = u64::from(u16_at(254)).max(32);
    let groups = current_blocks.div_ceil(32768);
    let gdt_blocks = (groups * descriptor_size).div_ceil(4096);
    let max_groups = (gdt_blocks + u64::from(u16_at(206))) * 4096 / descriptor_size;
    if target / 4096 > max_groups * 32768 {
        return Err("target exceeds ext4 reserved group-descriptor capacity".into());
    }
    let target_blocks = target / 4096;
    let last_group = (target_blocks - 1) / 32768;
    if last_group >= groups && !target_blocks.is_multiple_of(32768) {
        let sparse = last_group <= 1
            || [3u64, 5, 7].iter().any(|base| {
                let mut group = last_group;
                while group > 1 && group.is_multiple_of(*base) {
                    group /= base;
                }
                group == 1
            });
        let inode_blocks = (u64::from(u32_at(40)) * u64::from(u16_at(88))).div_ceil(4096);
        let metadata = inode_blocks
            + 2
            + if sparse {
                1 + gdt_blocks + u64::from(u16_at(206))
            } else {
                0
            };
        if target_blocks % 32768 < metadata {
            return Err("target leaves a final block group too small for ext4 metadata".into());
        }
    }
    Ok(current)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_unknown_filesystems_before_mutation() {
        assert!(validate_superblock(&[0; 1024], 1024 * 1024 * 1024).is_err());
    }
}
