use std::io::Write;

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn u16_at(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn u32_at(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn u64_at(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

// Minimal executable-header fixtures exercise all readers on every host. They
// intentionally cannot boot; actual linked/stripped artifacts are checked too.
fn elf(version: &[u8], present: bool) -> Vec<u8> {
    let mut bytes = vec![0; 384 + version.len()];
    bytes[..7].copy_from_slice(b"\x7fELF\x02\x01\x01");
    u16_at(&mut bytes, 16, 2);
    u16_at(&mut bytes, 18, 62);
    u32_at(&mut bytes, 20, 1);
    u64_at(&mut bytes, 40, 128);
    u16_at(&mut bytes, 52, 64);
    u16_at(&mut bytes, 58, 64);
    u16_at(&mut bytes, 60, 3);
    u16_at(&mut bytes, 62, 1);
    let names = b"\0.shstrtab\0.msbver\0.other\0";
    bytes[64..64 + names.len()].copy_from_slice(names);
    u32_at(&mut bytes, 192, 1);
    u32_at(&mut bytes, 196, 3);
    u64_at(&mut bytes, 216, 64);
    u64_at(&mut bytes, 224, names.len() as u64);
    u32_at(&mut bytes, 256, if present { 11 } else { 19 });
    u32_at(&mut bytes, 260, 1);
    u64_at(&mut bytes, 280, 384);
    u64_at(&mut bytes, 288, version.len() as u64);
    bytes[384..].copy_from_slice(version);
    bytes
}

fn macho(version: &[u8], present: bool) -> Vec<u8> {
    let mut bytes = vec![0; 184 + version.len()];
    u32_at(&mut bytes, 0, 0xfeedfacf);
    u32_at(&mut bytes, 4, 0x0100000c);
    u32_at(&mut bytes, 12, 2);
    u32_at(&mut bytes, 16, 1);
    u32_at(&mut bytes, 20, 152);
    u32_at(&mut bytes, 32, 0x19);
    u32_at(&mut bytes, 36, 152);
    bytes[40..46].copy_from_slice(b"__TEXT");
    u32_at(&mut bytes, 96, 1);
    let name: &[u8] = if present { b"__msbver" } else { b"__other" };
    bytes[104..104 + name.len()].copy_from_slice(name);
    bytes[120..126].copy_from_slice(b"__TEXT");
    u64_at(&mut bytes, 144, version.len() as u64);
    u32_at(&mut bytes, 152, 184);
    bytes[184..].copy_from_slice(version);
    bytes
}

fn pe(version: &[u8], present: bool) -> Vec<u8> {
    let mut bytes = vec![0; 1024];
    bytes[..2].copy_from_slice(b"MZ");
    u32_at(&mut bytes, 60, 128);
    bytes[128..132].copy_from_slice(b"PE\0\0");
    u16_at(&mut bytes, 132, 0x8664);
    u16_at(&mut bytes, 134, 1);
    u16_at(&mut bytes, 148, 240);
    u16_at(&mut bytes, 150, 2);
    u16_at(&mut bytes, 152, 0x20b);
    u32_at(&mut bytes, 184, 4096);
    u32_at(&mut bytes, 188, 512);
    u32_at(&mut bytes, 260, 16);
    bytes[392..400].copy_from_slice(if present { b".msbver\0" } else { b".other\0\0" });
    u32_at(&mut bytes, 400, version.len() as u32);
    u32_at(&mut bytes, 404, 4096);
    u32_at(&mut bytes, 408, 512);
    u32_at(&mut bytes, 412, 512);
    bytes[512..512 + version.len()].copy_from_slice(version);
    bytes
}

fn fat(slices: &[Vec<u8>], wide: bool) -> Vec<u8> {
    let mut bytes = vec![0; 4096 * (slices.len() + 1)];
    let magic: u32 = if wide { 0xcafebabf } else { 0xcafebabe };
    bytes[..4].copy_from_slice(&magic.to_be_bytes());
    bytes[4..8].copy_from_slice(&(slices.len() as u32).to_be_bytes());
    for (index, slice) in slices.iter().enumerate() {
        let entry = 8 + index * if wide { 32 } else { 20 };
        let offset = 4096 * (index + 1);
        bytes[entry..entry + 4].copy_from_slice(&0x0100000cu32.to_be_bytes());
        if wide {
            bytes[entry + 8..entry + 16].copy_from_slice(&(offset as u64).to_be_bytes());
            bytes[entry + 16..entry + 24].copy_from_slice(&(slice.len() as u64).to_be_bytes());
        } else {
            bytes[entry + 8..entry + 12].copy_from_slice(&(offset as u32).to_be_bytes());
            bytes[entry + 12..entry + 16].copy_from_slice(&(slice.len() as u32).to_be_bytes());
        }
        bytes[offset..offset + slice.len()].copy_from_slice(slice);
    }
    bytes
}

fn inspect(bytes: &[u8]) -> MicrosandboxResult<Option<Version>> {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(bytes).unwrap();
    resolve_runtime_version(file.path())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn versions_and_missing_sections_across_platforms() {
    for fixture in [elf, macho, pe] {
        assert_eq!(
            inspect(&fixture(b"1.2.3-rc.1+build.42", true)).unwrap(),
            Some(Version::parse("1.2.3-rc.1+build.42").unwrap())
        );
        // Version-shaped bytes elsewhere must not be mistaken for the section.
        assert_eq!(inspect(&fixture(b"1.2.3", false)).unwrap(), None);
    }
}

#[test]
fn rejects_invalid_versions_without_normalizing_them() {
    for fixture in [elf, macho, pe] {
        for version in [
            b"".as_slice(),
            b"1.2",
            b"1.2.3\n",
            b"1.2.3\0",
            b"01.2.3",
            b"\xff",
            &[b'a'; 257],
        ] {
            assert!(
                inspect(&fixture(version, true)).is_err(),
                "accepted {version:?}"
            );
        }
    }
}

#[test]
fn universal_slices_must_agree_even_on_absence() {
    for wide in [false, true] {
        let version = macho(b"1.2.3", true);
        let missing = macho(b"", false);
        assert_eq!(
            inspect(&fat(&[version.clone(), version.clone()], wide)).unwrap(),
            Some(Version::new(1, 2, 3))
        );
        assert_eq!(
            inspect(&fat(&[missing.clone(), missing.clone()], wide)).unwrap(),
            None
        );
        assert!(inspect(&fat(&[version.clone(), missing.clone()], wide)).is_err());
        assert!(inspect(&fat(&[missing, version.clone()], wide)).is_err());
        assert!(inspect(&fat(&[version, macho(b"2.0.0", true)], wide)).is_err());
    }
}

#[test]
fn rejects_truncation_and_out_of_bounds_version_sections() {
    for fixture in [elf, macho, pe] {
        let bytes = fixture(b"1.2.3", true);
        assert!(inspect(&bytes[..bytes.len().min(160)]).is_err());
    }
    let mut bytes = elf(b"1.2.3", true);
    u64_at(&mut bytes, 280, u64::MAX);
    assert!(inspect(&bytes).is_err());
    let mut bytes = pe(b"1.2.3", true);
    u32_at(&mut bytes, 408, 1);
    assert!(inspect(&bytes).is_err());
}

#[test]
fn rejects_duplicate_version_sections() {
    let mut bytes = macho(b"1.2.3", true);
    let section = bytes[104..184].to_vec();
    bytes.splice(184..184, section);
    u32_at(&mut bytes, 20, 232);
    u32_at(&mut bytes, 36, 232);
    u32_at(&mut bytes, 96, 2);
    u32_at(&mut bytes, 152, 264);
    u32_at(&mut bytes, 232, 264);
    assert!(inspect(&bytes).is_err());
}

#[test]
fn missing_files_and_non_executables_are_errors() {
    let dir = tempfile::tempdir().unwrap();
    assert!(resolve_runtime_version(dir.path().join("missing")).is_err());
    assert!(resolve_runtime_version(dir.path()).is_err());
    assert!(inspect(b"#!/bin/sh\necho 1.2.3\n").is_err());
    let mut bytes = elf(b"1.2.3", true);
    u16_at(&mut bytes, 16, 1); // ET_REL is not an executable.
    assert!(inspect(&bytes).is_err());
    let mut bytes = pe(b"1.2.3", true);
    u16_at(&mut bytes, 150, 0x20); // Large-address-aware alone is not executable.
    assert!(inspect(&bytes).is_err());
    u16_at(&mut bytes, 150, 0x22); // Unrelated flags may accompany the executable bit.
    assert_eq!(inspect(&bytes).unwrap(), Some(Version::new(1, 2, 3)));
}

#[test]
fn metadata_budget_precedes_allocation() {
    let mut file = tempfile::NamedTempFile::new().unwrap();
    file.write_all(&elf(b"1.2.3", true)).unwrap();
    let cache = ReadCache::new(file.reopen().unwrap());
    let budget = Cell::new(32);
    let reader = MetadataReader {
        cache: &cache,
        budget: &budget,
        base: 0,
        size: 389,
    };
    assert!(reader.read_bytes_at(0, 33).is_err());
    assert_eq!(budget.get(), 32);
    assert!(reader.read_bytes_at(0, 16).is_ok());
    assert!(reader.read_bytes_at(16, 17).is_err());
    assert!(reader.read_bytes_at(u64::MAX, 1).is_err());
}
