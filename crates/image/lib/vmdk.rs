use std::io::{self, Write};
use std::path::Path;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum sectors per VMDK extent line (2 GiB / 512 bytes).
const MAX_EXTENT_SECTORS: u64 = 4_194_304;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Write a VMDK flat descriptor that concatenates the given extent files into a
/// single virtual disk.
///
/// Each extent file must be 512-byte aligned. Files larger than 2 GiB are split
/// into multiple extent lines with increasing offsets.
pub fn write_vmdk_descriptor(output: &Path, extents: &[&Path]) -> io::Result<()> {
    let mut total_sectors: u64 = 0;
    let mut extent_lines = Vec::new();

    for path in extents {
        let meta = std::fs::metadata(path).map_err(|e| {
            io::Error::new(
                e.kind(),
                format!("failed to stat extent {}: {e}", path.display()),
            )
        })?;
        let size = meta.len();

        if size % 512 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "extent {} size ({size}) is not 512-byte aligned",
                    path.display()
                ),
            ));
        }

        let sectors = size / 512;
        let abs_path = std::fs::canonicalize(path)?;
        let abs_str = abs_path.to_string_lossy();

        // Split into <= 2 GiB extent lines.
        let mut offset: u64 = 0;
        let mut remaining = sectors;
        while remaining > 0 {
            let chunk = remaining.min(MAX_EXTENT_SECTORS);
            extent_lines.push(format!("RW {chunk} FLAT \"{abs_str}\" {offset}"));
            offset += chunk;
            remaining -= chunk;
        }

        total_sectors += sectors;
    }

    let heads: u64 = 16;
    let sectors_per_track: u64 = 63;
    let cylinders = total_sectors.div_ceil(heads * sectors_per_track);

    let mut file = std::fs::File::create(output)?;

    writeln!(file, "# Disk DescriptorFile")?;
    writeln!(file, "version=1")?;
    writeln!(file, "CID=fffffffe")?;
    writeln!(file, "parentCID=ffffffff")?;
    writeln!(file, "createType=\"twoGbMaxExtentFlat\"")?;
    writeln!(file)?;
    writeln!(file, "# Extent description")?;
    for line in &extent_lines {
        writeln!(file, "{line}")?;
    }
    writeln!(file)?;
    writeln!(file, "# The Disk Data Base")?;
    writeln!(file, "#DDB")?;
    writeln!(file, "ddb.virtualHWVersion = \"4\"")?;
    writeln!(file, "ddb.geometry.cylinders = \"{cylinders}\"")?;
    writeln!(file, "ddb.geometry.heads = \"{heads}\"")?;
    writeln!(file, "ddb.geometry.sectors = \"{sectors_per_track}\"")?;
    writeln!(file, "ddb.adapterType = \"ide\"")?;

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn test_vmdk_basic() {
        let dir = tempfile::tempdir().unwrap();

        // Create 3 small extent files (each 4096 bytes = 8 sectors).
        let mut paths = Vec::new();
        for i in 0..3 {
            let p = dir.path().join(format!("extent{i}.bin"));
            std::fs::write(&p, vec![0u8; 4096]).unwrap();
            paths.push(p);
        }

        let vmdk_path = dir.path().join("test.vmdk");
        let refs: Vec<&Path> = paths.iter().map(|p| p.as_path()).collect();
        write_vmdk_descriptor(&vmdk_path, &refs).unwrap();

        let mut content = String::new();
        std::fs::File::open(&vmdk_path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();

        assert!(content.contains("version=1"));
        assert!(content.contains("createType=\"twoGbMaxExtentFlat\""));
        // 3 files * 4096 bytes / 512 = 24 sectors total, 8 per file
        assert!(content.contains("RW 8 FLAT"));
        assert_eq!(content.matches("RW 8 FLAT").count(), 3);
        assert!(content.contains("ddb.virtualHWVersion = \"4\""));
    }

    #[test]
    fn test_vmdk_rejects_unaligned() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("bad.bin");
        std::fs::write(&p, vec![0u8; 1000]).unwrap();

        let vmdk_path = dir.path().join("test.vmdk");
        let err = write_vmdk_descriptor(&vmdk_path, &[p.as_path()]).unwrap_err();
        assert!(err.to_string().contains("not 512-byte aligned"));
    }
}
