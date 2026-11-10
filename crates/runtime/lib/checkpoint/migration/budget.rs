//! Conservative admission cost for legacy metadata retained by the runtime image parser.

use std::fs::File;
use std::io::{BufReader, Read, Seek, SeekFrom};

use super::io;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LIMIT: u64 = 256 * 1024 * 1024;
const FIXED_LAYER_COST: u64 = 64 * 1024;
const EXTENSION_RECORD_COST: u64 = 256;
const EXTENSION_PAYLOAD_FACTOR: u64 = 16;
const LIMIT_ERROR: &str = "legacy storage exceeds the supported 256 MiB parser-metadata budget; preserve the original disks and any recorded migration state for recovery";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Shared by all selected disk roles, rather than reset for each individually valid chain.
#[derive(Default)]
pub(super) struct ParserBudget {
    used: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ParserBudget {
    /// Inspect only bounded headers on an already authorized handle. No image parser or
    /// dependency opener is involved; read-only diagnosis uses this same calculation.
    pub(super) fn layer(&mut self, file: &File, qcow: bool, writable: bool) -> Result<(), String> {
        self.charge(FIXED_LAYER_COST, 1)?;
        if !qcow {
            return Ok(());
        }
        // Keep format/feature and table-container policy identical on admission and replay.
        io::header(file, true)?;
        let mut reader = BufReader::with_capacity(
            4096,
            file.try_clone()
                .map_err(|_| "cannot retain metadata budget source")?,
        );
        reader
            .seek(SeekFrom::Start(0))
            .map_err(|_| "cannot seek metadata budget header")?;
        let mut header = [0u8; 104];
        reader
            .read_exact(&mut header)
            .map_err(|_| "truncated metadata budget header")?;
        let version = u32::from_be_bytes(header[4..8].try_into().unwrap());
        let cluster_bits = u32::from_be_bytes(header[20..24].try_into().unwrap());
        let cluster = 1u64
            .checked_shl(cluster_bits)
            .ok_or("invalid metadata budget cluster")?;
        let l1_entries = u64::from(u32::from_be_bytes(header[36..40].try_into().unwrap()));
        self.charge(l1_entries, 16)?; // Input buffer plus retained eight-byte L1 entries.
        if writable {
            let clusters = u64::from(u32::from_be_bytes(header[56..60].try_into().unwrap()));
            self.charge(clusters.checked_mul(cluster).ok_or(LIMIT_ERROR)?, 2)?;
        }
        let backing = u64::from(u32::from_be_bytes(header[16..20].try_into().unwrap()));
        // Private capture rewrites only the backing basename. Reserve its generated name
        // before intent so normalization cannot push an otherwise admitted group over budget.
        self.charge(if backing == 0 { 0 } else { backing.max(64) }, 2)?;
        if version == 2 {
            return Ok(());
        }
        let mut offset = u64::from(u32::from_be_bytes(header[100..104].try_into().unwrap()));
        self.charge(
            offset
                .checked_sub(104)
                .ok_or("invalid metadata budget header length")?,
            4,
        )?;
        let container = file
            .metadata()
            .map_err(|_| "cannot inspect metadata budget source")?
            .len();
        reader
            .seek(SeekFrom::Start(offset))
            .map_err(|_| "cannot seek metadata extensions")?;
        loop {
            let payload_offset = offset.checked_add(8).ok_or("metadata extension overflow")?;
            if payload_offset > cluster || payload_offset > container {
                return Err("metadata extensions have no bounded terminator".into());
            }
            let mut extension = [0u8; 8];
            reader
                .read_exact(&mut extension)
                .map_err(|_| "truncated metadata extension")?;
            let kind = u32::from_be_bytes(extension[..4].try_into().unwrap());
            let length = u64::from(u32::from_be_bytes(extension[4..].try_into().unwrap()));
            let end = payload_offset
                .checked_add(length)
                .ok_or("metadata extension overflow")?;
            if end > cluster || end > container {
                return Err("metadata extension exceeds its bounded container".into());
            }
            // msb-imago 0.1.7 retains extension enums and feature-name hash maps. Count even
            // zero-length records, and End payloads (allocated before the parser sees End).
            self.charge(1, EXTENSION_RECORD_COST)?;
            self.charge(length, EXTENSION_PAYLOAD_FACTOR)?;
            if kind == 0 {
                return Ok(());
            }
            let padded = length.checked_add(7).ok_or("metadata extension overflow")? & !7;
            offset = payload_offset
                .checked_add(padded)
                .ok_or("metadata extension overflow")?;
            // Buffer-local seeking keeps a flood of empty records from causing one syscall
            // per record. Payload bytes are skipped; only private execution parses contents.
            reader
                .seek_relative(padded as i64)
                .map_err(|_| "cannot seek metadata extension")?;
        }
    }

    fn charge(&mut self, count: u64, factor: u64) -> Result<(), String> {
        let next = count
            .checked_mul(factor)
            .and_then(|cost| self.used.checked_add(cost))
            .filter(|cost| *cost <= LIMIT)
            .ok_or(LIMIT_ERROR)?;
        self.used = next;
        Ok(())
    }
}

// This is an admission allowance for the pinned parser, not an RSS/whole-VM limit. The
// doubled tables, 4x unknown header fields, 256 bytes/extension and 16x payloads cover
// retained allocations and transient growth, including lossy feature-name decoding and
// writable autoclear-header serialization. Lazy runtime caches and guest RAM are separate.
// At 64 KiB producer geometry, 1,024 ordinary <=4 TiB layers plus 65 ordinary writable
// refcount tables fit this budget. Revisit the accounting when the image parser changes.

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn image(l1: u32, unknown: u32, extensions: &[(u32, u32)]) -> tempfile::NamedTempFile {
        let mut file = tempfile::NamedTempFile::new().unwrap();
        let cluster = 65536u64;
        let refcount = cluster + u64::from(l1).next_multiple_of(cluster);
        file.as_file().set_len(refcount + cluster).unwrap();
        let mut header = [0u8; 104];
        header[..4].copy_from_slice(b"QFI\xfb");
        header[4..8].copy_from_slice(&3u32.to_be_bytes());
        header[20..24].copy_from_slice(&16u32.to_be_bytes());
        header[24..32].copy_from_slice(&131072u64.to_be_bytes());
        header[36..40].copy_from_slice(&(l1 / 8).to_be_bytes());
        header[40..48].copy_from_slice(&cluster.to_be_bytes());
        header[48..56].copy_from_slice(&refcount.to_be_bytes());
        header[56..60].copy_from_slice(&1u32.to_be_bytes());
        header[96..100].copy_from_slice(&4u32.to_be_bytes());
        header[100..104].copy_from_slice(&(104 + unknown).to_be_bytes());
        file.write_all(&header).unwrap();
        file.seek(SeekFrom::Start(u64::from(104 + unknown)))
            .unwrap();
        for (kind, length) in extensions {
            file.write_all(&kind.to_be_bytes()).unwrap();
            file.write_all(&length.to_be_bytes()).unwrap();
            file.seek(SeekFrom::Current(
                u64::from(*length).next_multiple_of(8) as i64
            ))
            .unwrap();
        }
        file.write_all(&[0u8; 8]).unwrap();
        file
    }

    #[test]
    fn exact_limit_and_overflow_fail_without_wrapping() {
        let mut budget = ParserBudget::default();
        budget.charge(LIMIT, 1).unwrap();
        assert!(budget.charge(1, 1).unwrap_err().contains("256 MiB"));
        assert!(ParserBudget::default().charge(u64::MAX, 2).is_err());
        assert!(budget.charge(u64::MAX, 1).is_err());
        assert_eq!(budget.used, LIMIT);
    }

    #[test]
    fn table_charges_include_only_writable_refcounts() {
        let file = image(65536, 0, &[]);
        let mut readonly = ParserBudget::default();
        readonly.layer(file.as_file(), true, false).unwrap();
        assert_eq!(
            readonly.used,
            FIXED_LAYER_COST + 2 * 65536 + EXTENSION_RECORD_COST
        );
        let mut writable = ParserBudget::default();
        writable.layer(file.as_file(), true, true).unwrap();
        assert_eq!(writable.used - readonly.used, 2 * 65536);
        let mut raw = ParserBudget::default();
        raw.layer(file.as_file(), false, true).unwrap();
        assert_eq!(raw.used, FIXED_LAYER_COST);
    }

    #[test]
    fn ordinary_producer_source_ceiling_fits_without_parsing_disk_data() {
        // Eight ordinary feature-name records and a backing-format extension; the bytes
        // need not be semantically parsed to calculate the same conservative charge.
        let file = image(65536, 0, &[(0x6803f857, 384), (0xe2792aca, 5)]);
        let mut budget = ParserBudget::default();
        for index in 0..1024 {
            budget.layer(file.as_file(), true, index < 65).unwrap();
        }
        assert!(budget.used < 220 * 1024 * 1024);
    }

    #[test]
    fn backing_normalization_is_reserved_and_v2_has_no_extension_walk() {
        let mut file = image(65536, 0, &[]);
        file.seek(SeekFrom::Start(8)).unwrap();
        file.write_all(&512u64.to_be_bytes()).unwrap();
        file.write_all(&1u32.to_be_bytes()).unwrap();
        file.seek(SeekFrom::Start(512)).unwrap();
        file.write_all(b"b").unwrap();
        let mut original = ParserBudget::default();
        original.layer(file.as_file(), true, false).unwrap();
        file.seek(SeekFrom::Start(16)).unwrap();
        file.write_all(&15u32.to_be_bytes()).unwrap();
        file.seek(SeekFrom::Start(512)).unwrap();
        file.write_all(b"layer-000.qcow2").unwrap();
        let mut normalized = ParserBudget::default();
        normalized.layer(file.as_file(), true, false).unwrap();
        assert_eq!(original.used, normalized.used);
        file.seek(SeekFrom::Start(4)).unwrap();
        file.write_all(&2u32.to_be_bytes()).unwrap();
        let mut v2 = ParserBudget::default();
        v2.layer(file.as_file(), true, false).unwrap();
        assert_eq!(v2.used + EXTENSION_RECORD_COST, original.used);
    }

    #[test]
    fn individually_bounded_sparse_tables_exceed_the_aggregate_limit() {
        let file = image(8 * 1024 * 1024, 0, &[]);
        let mut budget = ParserBudget::default();
        for _ in 0..15 {
            budget.layer(file.as_file(), true, false).unwrap();
        }
        assert!(
            budget
                .layer(file.as_file(), true, false)
                .unwrap_err()
                .contains("256 MiB")
        );
    }

    #[test]
    fn unknown_fields_empty_extensions_and_end_payload_are_all_charged() {
        let file = image(0, 8, &vec![(0x12345678, 0); 600]);
        let mut budget = ParserBudget::default();
        budget.layer(file.as_file(), true, false).unwrap();
        assert_eq!(
            budget.used,
            FIXED_LAYER_COST + 4 * 8 + 601 * EXTENSION_RECORD_COST
        );
        let end = image(0, 0, &[(0, 4096)]);
        let mut budget = ParserBudget::default();
        budget.layer(end.as_file(), true, false).unwrap();
        assert_eq!(
            budget.used,
            FIXED_LAYER_COST + EXTENSION_RECORD_COST + 16 * 4096
        );
    }

    #[test]
    fn extension_payload_and_unterminated_or_truncated_headers_are_bounded() {
        let file = image(0, 0, &[(0x12345678, 32768)]);
        let mut budget = ParserBudget::default();
        budget.layer(file.as_file(), true, false).unwrap();
        assert_eq!(
            budget.used,
            FIXED_LAYER_COST + 2 * EXTENSION_RECORD_COST + 16 * 32768
        );
        let mut malformed = image(0, 0, &[]);
        malformed.seek(SeekFrom::Start(104)).unwrap();
        malformed.write_all(&0x12345678u32.to_be_bytes()).unwrap();
        malformed.write_all(&u32::MAX.to_be_bytes()).unwrap();
        assert!(
            ParserBudget::default()
                .layer(malformed.as_file(), true, false)
                .is_err()
        );
        let truncated = image(0, 0, &[]);
        truncated.as_file().set_len(104).unwrap();
        assert!(
            ParserBudget::default()
                .layer(truncated.as_file(), true, false)
                .is_err()
        );
        let mut unterminated = image(0, 0, &[]);
        unterminated.seek(SeekFrom::Start(104)).unwrap();
        for _ in 0..(65536 - 104) / 8 {
            unterminated
                .write_all(&0x12345678u32.to_be_bytes())
                .unwrap();
            unterminated.write_all(&0u32.to_be_bytes()).unwrap();
        }
        assert!(
            ParserBudget::default()
                .layer(unterminated.as_file(), true, false)
                .is_err()
        );
    }
}
