//! Offline ext4 growth over a caller-resolved chain with a private staging head.

use std::io::{self, Read, Seek, SeekFrom, Write};
use std::sync::Arc;

use imago::{DynStorage, FormatAccess};

use super::formatter::Ext4Error;
use super::resizer::{GrowOutcome, grow_storage};
use super::storage::Ext4Storage;
use crate::checkpoint::{CompactLayer, open_writable_chain};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct LogicalDisk {
    image: Arc<FormatAccess<Box<dyn DynStorage>>>,
    runtime: tokio::runtime::Runtime,
    position: u64,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Read for LogicalDisk {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let count =
            (self.image.size().saturating_sub(self.position)).min(buffer.len() as u64) as usize;
        self.runtime
            .block_on(self.image.read(&mut buffer[..count], self.position))?;
        self.position += count as u64;
        Ok(count)
    }
}

impl Write for LogicalDisk {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        self.runtime
            .block_on(self.image.write(buffer, self.position))?;
        self.position += buffer.len() as u64;
        Ok(buffer.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.runtime.block_on(self.image.flush())
    }
}

impl Seek for LogicalDisk {
    fn seek(&mut self, position: SeekFrom) -> io::Result<u64> {
        let target = match position {
            SeekFrom::Start(value) => i128::from(value),
            SeekFrom::Current(delta) => i128::from(self.position) + i128::from(delta),
            SeekFrom::End(delta) => i128::from(self.image.size()) + i128::from(delta),
        };
        self.position = u64::try_from(target).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "invalid logical disk seek")
        })?;
        Ok(self.position)
    }
}

impl Ext4Storage for LogicalDisk {
    fn length(&self) -> io::Result<u64> {
        Ok(self.image.size())
    }

    fn grow(&mut self, size: u64) -> io::Result<()> {
        self.runtime.block_on(
            self.image
                .resize_grow(size, imago::format::PreallocateMode::None),
        )
    }

    fn sync_all(&self) -> io::Result<()> {
        self.runtime.block_on(async {
            self.image.flush().await?;
            self.image.sync().await
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Grow ext4 in a private staging head without flattening or modifying its sealed ancestors.
///
/// Call outside an async executor with the complete oldest-to-newest chain. The last file must
/// be an unpublished private copy: the offline filesystem rewrite is not rollback-safe on error.
/// The caller publishes the head only after success and excludes all concurrent writers.
pub fn grow_chain(layers: &[CompactLayer], size: u64) -> Result<GrowOutcome, Ext4Error> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let image = runtime.block_on(open_writable_chain(layers))?;
    let mut disk = LogicalDisk {
        image,
        runtime,
        position: 0,
    };
    grow_storage(&mut disk, size, true)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::{create_qcow2_overlay, layer_capacities, sparse_file_integrity};
    use crate::ext4::{Ext4FormatOptions, format_ext4};

    #[test]
    fn qcow2_growth_keeps_ancestors_and_reconciles_completed_target() {
        let dir = tempfile::tempdir().unwrap();
        let base = dir.path().join("base.raw");
        let head = dir.path().join("head.qcow2");
        let mib = 1024 * 1024;
        format_ext4(
            &base,
            &Ext4FormatOptions {
                size_bytes: 256 * mib,
                journal_blocks: 4096,
            },
        )
        .unwrap();
        let before = sparse_file_integrity(&base).unwrap().root;
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(create_qcow2_overlay(&head, 256 * mib, &base, "raw"))
            .unwrap();
        let layers = vec![
            CompactLayer {
                path: base.clone(),
                qcow2: false,
            },
            CompactLayer {
                path: head,
                qcow2: true,
            },
        ];
        let grown = grow_chain(&layers, 512 * mib).unwrap();
        assert_eq!(grown.old_blocks * 4096, 256 * mib);
        assert_eq!(grown.new_blocks * 4096, 512 * mib);
        assert_eq!(
            layer_capacities(layers.clone()).unwrap(),
            vec![256 * mib, 512 * mib]
        );
        assert_eq!(sparse_file_integrity(&base).unwrap().root, before);
        let replay = grow_chain(&layers, 512 * mib).unwrap();
        assert_eq!(replay.old_blocks, replay.new_blocks);
        assert!(grow_chain(&layers, 128 * mib).is_err());
        assert_eq!(sparse_file_integrity(&base).unwrap().root, before);
    }
}
