//! Materialize a pinned immutable disk prefix without following ambient backing paths.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use imago::file::File as ImagoFile;
use imago::qcow2::Qcow2;
use imago::raw::Raw;
use imago::{
    DenyImplicitOpenGate, DynStorage, FormatAccess, FormatCreateBuilder, FormatDriverBuilder,
    Mapping,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type SharedImage = Arc<FormatAccess<Box<dyn DynStorage>>>;

/// One caller-resolved immutable member of a compaction prefix.
#[derive(Clone, Debug)]
pub struct CompactLayer {
    /// File pinned by the caller's disk mutation lease.
    pub path: PathBuf,
    /// Whether this file is qcow2; otherwise it is raw.
    pub qcow2: bool,
}

/// Work performed while materializing a consolidated base.
#[derive(Clone, Debug)]
pub struct CompactMaterialization {
    /// Guest-visible capacity, not the qcow2 container length.
    pub virtual_size: u64,
    /// Guest bytes written into materialized runs, including zeros within those runs.
    pub materialized_bytes: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Open a complete, explicitly supplied immutable chain read-only.
async fn open_chain(layers: &[CompactLayer]) -> io::Result<SharedImage> {
    if layers.is_empty() || layers.iter().skip(1).any(|layer| !layer.qcow2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid raw/qcow2 compaction prefix",
        ));
    }
    let mut backing: Option<SharedImage> = None;
    for layer in layers {
        let storage: Box<dyn DynStorage> =
            Box::new(ImagoFile::try_from(std::fs::File::open(&layer.path)?)?);
        backing = Some(if layer.qcow2 {
            let image = Qcow2::<Box<dyn DynStorage>, SharedImage>::builder(storage)
                .write(false)
                .backing(backing)
                .data_file(None)
                .open(DenyImplicitOpenGate::default())
                .await?;
            if image.requires_external_data_file() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "external qcow2 data files are not supported",
                ));
            }
            Arc::new(FormatAccess::new(image))
        } else {
            Arc::new(FormatAccess::new(
                Raw::<Box<dyn DynStorage>>::builder(storage)
                    .write(false)
                    .open(DenyImplicitOpenGate::default())
                    .await?,
            ))
        });
    }
    Ok(backing.expect("nonempty chain checked above"))
}

/// Copy the resolved guest bytes into a new standalone sparse qcow2 image.
///
/// The caller owns staging and removes it on cancellation/error. The destination must not exist.
/// All source layers must remain immutable for the duration. Neither header paths nor guest paths
/// can open additional files; only the supplied chain is used. Run outside the VM pause window.
pub async fn materialize_compact_prefix(
    layers: &[CompactLayer],
    destination: &Path,
) -> io::Result<CompactMaterialization> {
    let source = open_chain(layers).await?;
    let virtual_size = source.size();
    if virtual_size == 0 || !virtual_size.is_multiple_of(512) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid compaction disk capacity",
        ));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(destination)?;
    Qcow2::<ImagoFile>::create_builder(ImagoFile::try_from(file)?)
        .size(virtual_size)
        .cluster_size(65536)
        .create()
        .await?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(destination)?;
    let target = FormatAccess::new(
        Qcow2::<ImagoFile>::builder(ImagoFile::try_from(file)?)
            .write(true)
            .backing(None)
            .data_file(None)
            .open(DenyImplicitOpenGate::default())
            .await?,
    );
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut offset = 0;
    let mut materialized_bytes = 0;
    while offset < virtual_size {
        let (mapping, length) = source.get_mapping(offset, virtual_size - offset).await?;
        if length == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "compaction mapping made no progress",
            ));
        }
        if matches!(mapping, Mapping::Zero { .. }) {
            offset += length;
            continue;
        }
        let count = length.min(buffer.len() as u64) as usize;
        source.read(&mut buffer[..count], offset).await?;
        // Raw sources may represent sparse holes as data mappings. Preserve sparseness even
        // there, without depending on platform-specific host extent reporting.
        if buffer[..count].iter().any(|byte| *byte != 0) {
            target.write(&buffer[..count], offset).await?;
            materialized_bytes += count as u64;
        }
        offset += count as u64;
    }
    target.flush().await?;
    target.sync().await?;
    Ok(CompactMaterialization {
        virtual_size,
        materialized_bytes,
    })
}

/// Read a raw or qcow2 file's declared capacity without opening its backing filename.
pub async fn compact_layer_capacity(layer: CompactLayer) -> io::Result<u64> {
    Ok(open_chain(&[layer]).await?.size())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::checkpoint::create_qcow2_overlay;

    #[tokio::test]
    async fn compacted_prefix_preserves_overwrites_zeroes_and_grown_tail() {
        let dir = tempfile::tempdir().unwrap();
        let raw = dir.path().join("base.raw");
        std::fs::write(&raw, vec![17u8; 131072]).unwrap();
        let overlay = dir.path().join("layer.qcow2");
        create_qcow2_overlay(&overlay, 262144, &raw, "raw")
            .await
            .unwrap();
        let image = FormatAccess::new(
            Qcow2::<ImagoFile>::builder(
                ImagoFile::try_from(
                    std::fs::OpenOptions::new()
                        .read(true)
                        .write(true)
                        .open(&overlay)
                        .unwrap(),
                )
                .unwrap(),
            )
            .write(true)
            .backing(None)
            .data_file(None)
            .open(DenyImplicitOpenGate::default())
            .await
            .unwrap(),
        );
        image.write(&vec![29u8; 65536][..], 0).await.unwrap();
        image.write_zeroes(65536, 65536).await.unwrap();
        image.flush().await.unwrap();
        image.sync().await.unwrap();
        drop(image);
        let layers = vec![
            CompactLayer {
                path: raw.clone(),
                qcow2: false,
            },
            CompactLayer {
                path: overlay.clone(),
                qcow2: true,
            },
        ];
        let original = std::fs::read(&overlay).unwrap();
        let destination = dir.path().join("compact.qcow2");
        let result = materialize_compact_prefix(&layers, &destination)
            .await
            .unwrap();
        assert_eq!(result.virtual_size, 262144);
        let input = open_chain(&layers).await.unwrap();
        let output = open_chain(&[CompactLayer {
            path: destination.clone(),
            qcow2: true,
        }])
        .await
        .unwrap();
        let mut before = vec![0; 262144];
        let mut after = before.clone();
        input.read(&mut before[..], 0).await.unwrap();
        output.read(&mut after[..], 0).await.unwrap();
        assert!(before == after, "compaction changed guest bytes");
        assert!(after[..65536].iter().all(|byte| *byte == 29));
        assert!(after[65536..].iter().all(|byte| *byte == 0));
        assert_eq!(std::fs::read(overlay).unwrap(), original);
        assert!(
            materialize_compact_prefix(&layers, &destination)
                .await
                .is_err()
        );
    }
}
