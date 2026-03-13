//! Tests for the sidecar index (MmapIndex) and index-accelerated overlay operations.

use std::{
    ffi::CString,
    path::{Path, PathBuf},
};

use microsandbox_utils::index::{
    DIR_FLAG_OPAQUE, DIR_RECORD_IDX_NONE, ENTRY_FLAG_WHITEOUT, INDEX_MAGIC, INDEX_VERSION,
    IndexBuilder, MmapIndex,
};

use super::*;
use crate::backends::overlayfs::inode;

//--------------------------------------------------------------------------------------------------
// Functions: Test Helpers
//--------------------------------------------------------------------------------------------------

/// Write index bytes to a temp file and return the temp dir + path.
fn write_index(data: &[u8]) -> (tempfile::TempDir, PathBuf) {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("test.index");
    std::fs::write(&path, data).unwrap();
    (tmp, path)
}

/// Build a minimal valid index (just root dir, no entries).
fn minimal_index() -> Vec<u8> {
    IndexBuilder::new().dir("").build()
}

/// Corrupt the magic bytes of a valid index.
fn corrupt_magic(data: Vec<u8>) -> Vec<u8> {
    let mut data = data;
    data[0] = 0xFF;
    data
}

/// Set version to 99 in a valid index.
fn corrupt_version(data: Vec<u8>) -> Vec<u8> {
    let mut data = data;
    data[4..8].copy_from_slice(&99u32.to_le_bytes());
    data
}

/// Flip a bit in the checksum field.
fn corrupt_checksum(data: Vec<u8>) -> Vec<u8> {
    let mut data = data;
    data[28] ^= 0xFF;
    data
}

/// Truncate the file to lose some data.
fn truncate(data: Vec<u8>) -> Vec<u8> {
    let new_len = data.len().saturating_sub(10).max(32);
    data[..new_len].to_vec()
}

/// Inflate dir_count to make expected size > actual file size.
fn wrong_size(data: Vec<u8>) -> Vec<u8> {
    let mut data = data;
    data[12..16].copy_from_slice(&9999u32.to_le_bytes());
    data
}

fn ctx() -> Context {
    Context {
        uid: 0,
        gid: 0,
        pid: 1,
    }
}

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

/// Create standard temp dirs for a single indexed lower layer test.
fn setup_dirs(tmp: &tempfile::TempDir) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
    let lower = tmp.path().join("lower");
    let upper = tmp.path().join("upper");
    let staging = tmp.path().join("staging");
    let index_path = tmp.path().join("lower.index");
    std::fs::create_dir_all(&lower).unwrap();
    std::fs::create_dir(&upper).unwrap();
    std::fs::create_dir(&staging).unwrap();
    (lower, upper, staging, index_path)
}

/// Mount an overlay with a single indexed lower layer.
fn mount_indexed(lower: &Path, index: &Path, upper: &Path, staging: &Path) -> OverlayFs {
    let fs = OverlayFs::builder()
        .layer_with_index(lower, index)
        .writable(upper)
        .staging(staging)
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs
}

/// Mount an overlay with a single non-indexed lower layer.
fn mount_plain(lower: &Path, upper: &Path, staging: &Path) -> OverlayFs {
    let fs = OverlayFs::builder()
        .layer(lower)
        .writable(upper)
        .staging(staging)
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();
    fs
}

/// Collect readdir entry names from a directory inode.
fn readdir_names(fs: &OverlayFs, ino: u64) -> Vec<Vec<u8>> {
    let (handle, _) = fs.opendir(ctx(), ino, 0).unwrap();
    let handle = handle.unwrap();
    let entries = fs.readdir(ctx(), ino, handle, 65536, 0).unwrap();
    let names: Vec<Vec<u8>> = entries.iter().map(|e| e.name.to_vec()).collect();
    fs.releasedir(ctx(), ino, 0, handle).unwrap();
    names
}

/// Collect readdir entries with their d_type values.
fn readdir_entries(fs: &OverlayFs, ino: u64) -> Vec<(Vec<u8>, u32)> {
    let (handle, _) = fs.opendir(ctx(), ino, 0).unwrap();
    let handle = handle.unwrap();
    let entries = fs.readdir(ctx(), ino, handle, 65536, 0).unwrap();
    let result: Vec<(Vec<u8>, u32)> = entries.iter().map(|e| (e.name.to_vec(), e.type_)).collect();
    fs.releasedir(ctx(), ino, 0, handle).unwrap();
    result
}

//--------------------------------------------------------------------------------------------------
// Tests: MmapIndex Unit Tests — Validation
//--------------------------------------------------------------------------------------------------

#[test]
fn test_open_valid_index() {
    let data = IndexBuilder::new()
        .dir("")
        .file("", "hello.txt", 0o644)
        .build();
    let (_tmp, path) = write_index(&data);
    assert!(MmapIndex::open(&path).is_some());
}

#[test]
fn test_open_nonexistent_file() {
    assert!(MmapIndex::open(Path::new("/nonexistent/path/to/index")).is_none());
}

#[test]
fn test_open_empty_file() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("empty.index");
    std::fs::write(&path, b"").unwrap();
    assert!(MmapIndex::open(&path).is_none());
}

#[test]
fn test_open_too_small() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("small.index");
    std::fs::write(&path, &[0u8; 16]).unwrap(); // Less than 32-byte header.
    assert!(MmapIndex::open(&path).is_none());
}

#[test]
fn test_open_corrupt_magic() {
    let data = corrupt_magic(minimal_index());
    let (_tmp, path) = write_index(&data);
    assert!(MmapIndex::open(&path).is_none());
}

#[test]
fn test_open_corrupt_version() {
    let data = corrupt_version(minimal_index());
    let (_tmp, path) = write_index(&data);
    assert!(MmapIndex::open(&path).is_none());
}

#[test]
fn test_open_corrupt_checksum() {
    let data = corrupt_checksum(minimal_index());
    let (_tmp, path) = write_index(&data);
    assert!(MmapIndex::open(&path).is_none());
}

#[test]
fn test_open_truncated() {
    let data = IndexBuilder::new()
        .dir("")
        .dir("etc")
        .file("", "a", 0o644)
        .file("", "b", 0o644)
        .file("etc", "passwd", 0o644)
        .build();
    let data = truncate(data);
    let (_tmp, path) = write_index(&data);
    assert!(MmapIndex::open(&path).is_none());
}

#[test]
fn test_open_wrong_size() {
    let data = wrong_size(minimal_index());
    let (_tmp, path) = write_index(&data);
    assert!(MmapIndex::open(&path).is_none());
}

//--------------------------------------------------------------------------------------------------
// Tests: MmapIndex Unit Tests — Directory Lookup
//--------------------------------------------------------------------------------------------------

#[test]
fn test_find_dir_root() {
    let data = IndexBuilder::new().dir("").build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (pos, _rec) = idx.find_dir(b"").unwrap();
    assert_eq!(pos, 0);
}

#[test]
fn test_find_dir_nested() {
    let data = IndexBuilder::new()
        .dir("")
        .dir("etc")
        .dir("usr")
        .dir("usr/bin")
        .build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();

    let (pos, _) = idx.find_dir(b"").unwrap();
    assert_eq!(pos, 0);
    let (pos, _) = idx.find_dir(b"etc").unwrap();
    assert_eq!(pos, 1);
    let (pos, _) = idx.find_dir(b"usr").unwrap();
    assert_eq!(pos, 2);
    let (pos, _) = idx.find_dir(b"usr/bin").unwrap();
    assert_eq!(pos, 3);
}

#[test]
fn test_find_dir_missing() {
    let data = IndexBuilder::new().dir("").dir("etc").build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    assert!(idx.find_dir(b"nonexistent").is_none());
    assert!(idx.find_dir(b"usr").is_none());
}

//--------------------------------------------------------------------------------------------------
// Tests: MmapIndex Unit Tests — Entry Lookup
//--------------------------------------------------------------------------------------------------

#[test]
fn test_find_entry_exists() {
    let data = IndexBuilder::new()
        .dir("")
        .file("", "bar", 0o644)
        .file("", "foo", 0o644)
        .file("", "qux", 0o644)
        .build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();
    let entry = idx.find_entry(dir, b"foo").unwrap();
    assert_eq!(idx.get_str(entry.name_off, entry.name_len), b"foo");
}

#[test]
fn test_find_entry_missing() {
    let data = IndexBuilder::new().dir("").file("", "bar", 0o644).build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();
    assert!(idx.find_entry(dir, b"nope").is_none());
}

#[test]
fn test_find_entry_binary_search_boundaries() {
    // 7 entries — test first, last, and middle.
    let data = IndexBuilder::new()
        .dir("")
        .file("", "aaa", 0o644)
        .file("", "bbb", 0o644)
        .file("", "ccc", 0o644)
        .file("", "ddd", 0o644)
        .file("", "eee", 0o644)
        .file("", "fff", 0o644)
        .file("", "ggg", 0o644)
        .build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();

    // First.
    let e = idx.find_entry(dir, b"aaa").unwrap();
    assert_eq!(idx.get_str(e.name_off, e.name_len), b"aaa");
    // Last.
    let e = idx.find_entry(dir, b"ggg").unwrap();
    assert_eq!(idx.get_str(e.name_off, e.name_len), b"ggg");
    // Middle.
    let e = idx.find_entry(dir, b"ddd").unwrap();
    assert_eq!(idx.get_str(e.name_off, e.name_len), b"ddd");
    // Miss between entries.
    assert!(idx.find_entry(dir, b"aab").is_none());
}

#[test]
fn test_find_entry_single_entry_dir() {
    let data = IndexBuilder::new().dir("").file("", "only", 0o644).build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();
    assert!(idx.find_entry(dir, b"only").is_some());
    assert!(idx.find_entry(dir, b"other").is_none());
}

#[test]
fn test_find_entry_empty_dir() {
    let data = IndexBuilder::new().dir("").dir("empty").build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"empty").unwrap();
    assert!(idx.find_entry(dir, b"anything").is_none());
}

//--------------------------------------------------------------------------------------------------
// Tests: MmapIndex Unit Tests — dir_entries, opaque, whiteout
//--------------------------------------------------------------------------------------------------

#[test]
fn test_dir_entries_slice() {
    let data = IndexBuilder::new()
        .dir("")
        .file("", "alpha", 0o644)
        .file("", "beta", 0o644)
        .file("", "gamma", 0o644)
        .build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();
    let entries = idx.dir_entries(dir);
    assert_eq!(entries.len(), 3);
    let names: Vec<&[u8]> = entries
        .iter()
        .map(|e| idx.get_str(e.name_off, e.name_len))
        .collect();
    assert_eq!(names, vec![b"alpha" as &[u8], b"beta", b"gamma"]);
}

#[test]
fn test_dir_entries_empty_dir() {
    let data = IndexBuilder::new().dir("").build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();
    assert!(idx.dir_entries(dir).is_empty());
}

#[test]
fn test_is_opaque_true() {
    let data = IndexBuilder::new().dir("").opaque_dir("mydir").build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"mydir").unwrap();
    assert!(idx.is_opaque(dir));
}

#[test]
fn test_is_opaque_false() {
    let data = IndexBuilder::new().dir("").dir("mydir").build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"mydir").unwrap();
    assert!(!idx.is_opaque(dir));
}

#[test]
fn test_has_whiteout_true() {
    let data = IndexBuilder::new().dir("").whiteout("", "deleted").build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();
    assert!(idx.has_whiteout(dir, b"deleted"));
}

#[test]
fn test_has_whiteout_false() {
    let data = IndexBuilder::new()
        .dir("")
        .file("", "exists", 0o644)
        .build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();
    assert!(!idx.has_whiteout(dir, b"exists"));
}

#[test]
fn test_has_whiteout_missing_name() {
    let data = IndexBuilder::new().dir("").build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();
    // Name not in index at all — should return false, not panic.
    assert!(!idx.has_whiteout(dir, b"ghost"));
}

//--------------------------------------------------------------------------------------------------
// Tests: MmapIndex Unit Tests — Tombstones
//--------------------------------------------------------------------------------------------------

#[test]
fn test_tombstone_names_empty() {
    let data = IndexBuilder::new().dir("").build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();
    assert_eq!(idx.tombstone_names(dir).count(), 0);
}

#[test]
fn test_tombstone_names_multiple() {
    let data = IndexBuilder::new()
        .dir("")
        .tombstone("", "long_deleted_name_1")
        .tombstone("", "long_deleted_name_2")
        .tombstone("", "long_deleted_name_3")
        .build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();
    let names: Vec<&[u8]> = idx.tombstone_names(dir).collect();
    assert_eq!(names.len(), 3);
    assert_eq!(names[0], b"long_deleted_name_1");
    assert_eq!(names[1], b"long_deleted_name_2");
    assert_eq!(names[2], b"long_deleted_name_3");
}

#[test]
fn test_tombstone_names_long_names() {
    let long_name = "x".repeat(250); // Near NAME_MAX.
    let data = IndexBuilder::new()
        .dir("")
        .tombstone("", &long_name)
        .build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();
    let names: Vec<&[u8]> = idx.tombstone_names(dir).collect();
    assert_eq!(names.len(), 1);
    assert_eq!(names[0], long_name.as_bytes());
}

//--------------------------------------------------------------------------------------------------
// Tests: MmapIndex Unit Tests — String Pool & Hardlinks
//--------------------------------------------------------------------------------------------------

#[test]
fn test_get_str_valid() {
    let data = IndexBuilder::new()
        .dir("")
        .file("", "test_file", 0o644)
        .build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, dir) = idx.find_dir(b"").unwrap();
    let entry = idx.find_entry(dir, b"test_file").unwrap();
    assert_eq!(idx.get_str(entry.name_off, entry.name_len), b"test_file");
}

#[test]
fn test_get_str_out_of_bounds() {
    let data = IndexBuilder::new().dir("").build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    // Offset way past the string pool.
    let result = idx.get_str(999999, 10);
    assert_eq!(result, b"");
}

#[test]
fn test_hardlink_refs() {
    let data = IndexBuilder::new()
        .dir("")
        .file("", "link1", 0o644)
        .hardlink(42, "usr/bin/tool")
        .hardlink(42, "bin/tool")
        .build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let aliases = idx.find_aliases(42);
    assert_eq!(aliases.len(), 2);
    // Sorted by path: "bin/tool" before "usr/bin/tool".
    assert_eq!(idx.hardlink_path(&aliases[0]), b"bin/tool");
    assert_eq!(idx.hardlink_path(&aliases[1]), b"usr/bin/tool");
}

#[test]
fn test_hardlink_refs_no_match() {
    let data = IndexBuilder::new()
        .dir("")
        .hardlink(42, "some/path")
        .build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    assert!(idx.find_aliases(999).is_empty());
}

#[test]
fn test_dir_record_idx_links() {
    let data = IndexBuilder::new()
        .dir("")
        .dir("etc")
        .subdir("", "etc", 0o755)
        .build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, root) = idx.find_dir(b"").unwrap();
    let entry = idx.find_entry(root, b"etc").unwrap();
    // "etc" is dir at sorted index 1.
    assert_eq!(entry.dir_record_idx, 1);
    // Verify it points to the correct dir.
    let dirs = idx.dir_records();
    let linked = &dirs[entry.dir_record_idx as usize];
    assert_eq!(idx.get_str(linked.path_off, linked.path_len), b"etc");
}

#[test]
fn test_dir_record_idx_non_dir() {
    let data = IndexBuilder::new()
        .dir("")
        .file("", "regular.txt", 0o644)
        .build();
    let (_tmp, path) = write_index(&data);
    let idx = MmapIndex::open(&path).unwrap();
    let (_, root) = idx.find_dir(b"").unwrap();
    let entry = idx.find_entry(root, b"regular.txt").unwrap();
    assert_eq!(entry.dir_record_idx, DIR_RECORD_IDX_NONE);
}

//--------------------------------------------------------------------------------------------------
// Tests: Builder Integration
//--------------------------------------------------------------------------------------------------

#[test]
fn test_builder_layer_no_index() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, _index_path) = setup_dirs(&tmp);
    let fs = OverlayFs::builder()
        .layer(&lower)
        .writable(&upper)
        .staging(&staging)
        .build()
        .unwrap();
    assert!(fs.lowers[0].lower_index.is_none());
}

#[test]
fn test_builder_layer_with_valid_index() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    IndexBuilder::new()
        .dir("")
        .build_to_file(&index_path)
        .unwrap();
    let fs = OverlayFs::builder()
        .layer_with_index(&lower, &index_path)
        .writable(&upper)
        .staging(&staging)
        .build()
        .unwrap();
    assert!(fs.lowers[0].lower_index.is_some());
}

#[test]
fn test_builder_layer_with_missing_index() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, _) = setup_dirs(&tmp);
    let bad_path = tmp.path().join("nonexistent.index");
    let fs = OverlayFs::builder()
        .layer_with_index(&lower, &bad_path)
        .writable(&upper)
        .staging(&staging)
        .build()
        .unwrap();
    // Graceful: no panic, just falls back to None.
    assert!(fs.lowers[0].lower_index.is_none());
}

#[test]
fn test_builder_layer_with_corrupt_index() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    let data = corrupt_checksum(minimal_index());
    std::fs::write(&index_path, data).unwrap();
    let fs = OverlayFs::builder()
        .layer_with_index(&lower, &index_path)
        .writable(&upper)
        .staging(&staging)
        .build()
        .unwrap();
    assert!(fs.lowers[0].lower_index.is_none());
}

#[test]
fn test_builder_layers_no_index() {
    let tmp = tempfile::tempdir().unwrap();
    let lower0 = tmp.path().join("lower0");
    let lower1 = tmp.path().join("lower1");
    let upper = tmp.path().join("upper");
    let staging = tmp.path().join("staging");
    for d in [&lower0, &lower1, &upper, &staging] {
        std::fs::create_dir(d).unwrap();
    }
    let fs = OverlayFs::builder()
        .layers([&lower0, &lower1])
        .writable(&upper)
        .staging(&staging)
        .build()
        .unwrap();
    assert!(fs.lowers[0].lower_index.is_none());
    assert!(fs.lowers[1].lower_index.is_none());
}

#[test]
fn test_builder_mixed_layers() {
    let tmp = tempfile::tempdir().unwrap();
    let lower0 = tmp.path().join("lower0");
    let lower1 = tmp.path().join("lower1");
    let upper = tmp.path().join("upper");
    let staging = tmp.path().join("staging");
    let index0 = tmp.path().join("lower0.index");
    for d in [&lower0, &lower1, &upper, &staging] {
        std::fs::create_dir(d).unwrap();
    }
    IndexBuilder::new().dir("").build_to_file(&index0).unwrap();
    let fs = OverlayFs::builder()
        .layer_with_index(&lower0, &index0)
        .layer(&lower1) // no index
        .writable(&upper)
        .staging(&staging)
        .build()
        .unwrap();
    assert!(fs.lowers[0].lower_index.is_some());
    assert!(fs.lowers[1].lower_index.is_none());
}

//--------------------------------------------------------------------------------------------------
// Tests: Index-Accelerated Lookup
//--------------------------------------------------------------------------------------------------

#[test]
fn test_index_lookup_hit() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::write(lower.join("hello.txt"), b"hello world").unwrap();

    IndexBuilder::new()
        .dir("")
        .file("", "hello.txt", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let entry = fs.lookup(ctx(), ROOT_INODE, &cstr("hello.txt")).unwrap();
    assert_ne!(entry.inode, 0);
    let mode = entry.attr.st_mode as u32;
    assert_eq!(mode & libc::S_IFMT as u32, libc::S_IFREG as u32);
}

#[test]
fn test_index_lookup_miss() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);

    // Index lists no entries — lookup should fail.
    IndexBuilder::new()
        .dir("")
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let result = fs.lookup(ctx(), ROOT_INODE, &cstr("nonexistent.txt"));
    assert!(result.is_err());
    assert_eq!(result.err().unwrap().raw_os_error(), Some(LINUX_ENOENT));
}

#[test]
fn test_index_lookup_whiteout() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    // File exists on disk but is whited out in the index.
    std::fs::write(lower.join("deleted.txt"), b"data").unwrap();

    IndexBuilder::new()
        .dir("")
        .whiteout("", "deleted.txt")
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let result = fs.lookup(ctx(), ROOT_INODE, &cstr("deleted.txt"));
    assert!(result.is_err());
    assert_eq!(result.err().unwrap().raw_os_error(), Some(LINUX_ENOENT));
}

#[test]
fn test_index_lookup_opaque_stops_search() {
    let tmp = tempfile::tempdir().unwrap();
    let lower0 = tmp.path().join("lower0");
    let lower1 = tmp.path().join("lower1");
    let upper = tmp.path().join("upper");
    let staging = tmp.path().join("staging");
    let index0 = tmp.path().join("lower0.index");
    let index1 = tmp.path().join("lower1.index");
    for d in [&lower0, &lower1, &upper, &staging] {
        std::fs::create_dir(d).unwrap();
    }

    // Layer 0 (bottom) has the file.
    std::fs::write(lower0.join("hidden.txt"), b"data").unwrap();
    IndexBuilder::new()
        .dir("")
        .file("", "hidden.txt", 0o644)
        .build_to_file(&index0)
        .unwrap();

    // Layer 1 (top) is opaque — should block search into layer 0.
    IndexBuilder::new()
        .opaque_dir("")
        .build_to_file(&index1)
        .unwrap();

    let fs = OverlayFs::builder()
        .layer_with_index(&lower0, &index0)
        .layer_with_index(&lower1, &index1)
        .writable(&upper)
        .staging(&staging)
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let result = fs.lookup(ctx(), ROOT_INODE, &cstr("hidden.txt"));
    assert!(result.is_err());
    assert_eq!(result.err().unwrap().raw_os_error(), Some(LINUX_ENOENT));
}

#[test]
fn test_index_lookup_nested_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::create_dir_all(lower.join("a/b/c")).unwrap();
    std::fs::write(lower.join("a/b/c/deep.txt"), b"deep").unwrap();

    IndexBuilder::new()
        .dir("")
        .dir("a")
        .dir("a/b")
        .dir("a/b/c")
        .subdir("", "a", 0o755)
        .subdir("a", "b", 0o755)
        .subdir("a/b", "c", 0o755)
        .file("a/b/c", "deep.txt", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let a = fs.lookup(ctx(), ROOT_INODE, &cstr("a")).unwrap();
    let b = fs.lookup(ctx(), a.inode, &cstr("b")).unwrap();
    let c = fs.lookup(ctx(), b.inode, &cstr("c")).unwrap();
    let deep = fs.lookup(ctx(), c.inode, &cstr("deep.txt")).unwrap();
    assert_ne!(deep.inode, 0);
}

#[test]
fn test_index_lookup_dir_record_idx_caching() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::create_dir_all(lower.join("mydir")).unwrap();
    std::fs::write(lower.join("mydir/file_a"), b"a").unwrap();
    std::fs::write(lower.join("mydir/file_b"), b"b").unwrap();

    IndexBuilder::new()
        .dir("")
        .dir("mydir")
        .subdir("", "mydir", 0o755)
        .file("mydir", "file_a", 0o644)
        .file("mydir", "file_b", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let dir = fs.lookup(ctx(), ROOT_INODE, &cstr("mydir")).unwrap();

    // First lookup populates the cache.
    let _a = fs.lookup(ctx(), dir.inode, &cstr("file_a")).unwrap();

    // Verify cache was set on the mydir node.
    {
        let nodes = fs.nodes.read().unwrap();
        let node = nodes.get(&dir.inode).unwrap();
        let cache = node.dir_record_cache.read().unwrap();
        assert!(
            cache.is_some(),
            "dir_record_cache should be populated after first lookup"
        );
    }

    // Second lookup should use the cached DirRecord (still succeeds).
    let _b = fs.lookup(ctx(), dir.inode, &cstr("file_b")).unwrap();
}

#[test]
fn test_index_lookup_cross_layer() {
    let tmp = tempfile::tempdir().unwrap();
    let lower0 = tmp.path().join("lower0");
    let lower1 = tmp.path().join("lower1");
    let upper = tmp.path().join("upper");
    let staging = tmp.path().join("staging");
    let index0 = tmp.path().join("lower0.index");
    let index1 = tmp.path().join("lower1.index");
    for d in [&lower0, &lower1, &upper, &staging] {
        std::fs::create_dir(d).unwrap();
    }

    // File only in layer 0 (bottom).
    std::fs::write(lower0.join("bottom.txt"), b"bottom").unwrap();
    IndexBuilder::new()
        .dir("")
        .file("", "bottom.txt", 0o644)
        .build_to_file(&index0)
        .unwrap();

    // Layer 1 (top) has no entries — index should skip it.
    IndexBuilder::new().dir("").build_to_file(&index1).unwrap();

    let fs = OverlayFs::builder()
        .layer_with_index(&lower0, &index0)
        .layer_with_index(&lower1, &index1)
        .writable(&upper)
        .staging(&staging)
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let entry = fs.lookup(ctx(), ROOT_INODE, &cstr("bottom.txt")).unwrap();
    assert_ne!(entry.inode, 0);
}

#[test]
fn test_index_lookup_shadowed_by_upper() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::write(lower.join("file.txt"), b"lower data").unwrap();
    std::fs::write(upper.join("file.txt"), b"upper data").unwrap();

    IndexBuilder::new()
        .dir("")
        .file("", "file.txt", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let entry = fs.lookup(ctx(), ROOT_INODE, &cstr("file.txt")).unwrap();

    // Read the file — should get upper data.
    let (handle, _) = fs
        .open(ctx(), entry.inode, false, libc::O_RDONLY as u32)
        .unwrap();
    let handle = handle.unwrap();
    let mut writer = MockZeroCopyWriter::new();
    let n = fs
        .read(ctx(), entry.inode, handle, &mut writer, 4096, 0, None, 0)
        .unwrap();
    let mut data = writer.into_data();
    data.truncate(n);
    assert_eq!(&data, b"upper data");
}

#[test]
fn test_index_lookup_upper_whiteout_over_indexed_lower() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::write(lower.join("victim.txt"), b"data").unwrap();
    // Create whiteout in upper.
    std::fs::write(upper.join(".wh.victim.txt"), b"").unwrap();

    IndexBuilder::new()
        .dir("")
        .file("", "victim.txt", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let result = fs.lookup(ctx(), ROOT_INODE, &cstr("victim.txt"));
    assert!(result.is_err());
    assert_eq!(result.err().unwrap().raw_os_error(), Some(LINUX_ENOENT));
}

#[test]
fn test_index_lookup_absent_dir_not_indexed() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::create_dir_all(lower.join("known")).unwrap();
    std::fs::write(lower.join("known/file.txt"), b"data").unwrap();

    // Index describes root but has no entry for "known". The index is authoritative,
    // so the overlay won't fall back to syscalls — "known" returns ENOENT even though
    // it exists on disk.
    IndexBuilder::new()
        .dir("")
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let result = fs.lookup(ctx(), ROOT_INODE, &cstr("known"));
    assert!(result.is_err());
}

#[test]
fn test_index_lookup_matches_syscall_path() {
    let tmp = tempfile::tempdir().unwrap();
    let lower = tmp.path().join("lower");
    let upper1 = tmp.path().join("upper1");
    let upper2 = tmp.path().join("upper2");
    let staging1 = tmp.path().join("staging1");
    let staging2 = tmp.path().join("staging2");
    let index_path = tmp.path().join("lower.index");
    std::fs::create_dir_all(lower.join("etc")).unwrap();
    std::fs::write(lower.join("etc/passwd"), b"root:x:0:0").unwrap();
    std::fs::write(lower.join("hello.txt"), b"hello").unwrap();
    for d in [&upper1, &upper2, &staging1, &staging2] {
        std::fs::create_dir(d).unwrap();
    }

    IndexBuilder::new()
        .dir("")
        .dir("etc")
        .subdir("", "etc", 0o755)
        .file("", "hello.txt", 0o644)
        .file("etc", "passwd", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    // With index.
    let fs_idx = mount_indexed(&lower, &index_path, &upper1, &staging1);
    // Without index.
    let fs_plain = mount_plain(&lower, &upper2, &staging2);

    // Compare root-level lookups.
    for name in ["etc", "hello.txt", "nonexistent"] {
        let r1 = fs_idx.lookup(ctx(), ROOT_INODE, &cstr(name));
        let r2 = fs_plain.lookup(ctx(), ROOT_INODE, &cstr(name));
        match (&r1, &r2) {
            (Ok(e1), Ok(e2)) => {
                assert_eq!(
                    e1.attr.st_mode, e2.attr.st_mode,
                    "mode mismatch for '{name}'"
                );
            }
            (Err(e1), Err(e2)) => {
                assert_eq!(
                    e1.raw_os_error(),
                    e2.raw_os_error(),
                    "error mismatch for '{name}'"
                );
            }
            (Ok(_), Err(e)) => panic!("result type mismatch for '{name}': Ok vs Err({e})"),
            (Err(e), Ok(_)) => panic!("result type mismatch for '{name}': Err({e}) vs Ok"),
        }
    }

    // Compare nested lookup.
    let etc_idx = fs_idx.lookup(ctx(), ROOT_INODE, &cstr("etc")).unwrap();
    let etc_plain = fs_plain.lookup(ctx(), ROOT_INODE, &cstr("etc")).unwrap();

    let pw_idx = fs_idx.lookup(ctx(), etc_idx.inode, &cstr("passwd"));
    let pw_plain = fs_plain.lookup(ctx(), etc_plain.inode, &cstr("passwd"));
    assert!(pw_idx.is_ok());
    assert!(pw_plain.is_ok());
}

//--------------------------------------------------------------------------------------------------
// Tests: Index-Accelerated Readdir
//--------------------------------------------------------------------------------------------------

#[test]
fn test_index_readdir_basic() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    for name in ["alpha", "beta", "gamma", "delta", "epsilon"] {
        std::fs::write(lower.join(name), b"data").unwrap();
    }

    IndexBuilder::new()
        .dir("")
        .file("", "alpha", 0o644)
        .file("", "beta", 0o644)
        .file("", "delta", 0o644)
        .file("", "epsilon", 0o644)
        .file("", "gamma", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let names = readdir_names(&fs, ROOT_INODE);
    for expected in [&b"alpha"[..], b"beta", b"gamma", b"delta", b"epsilon"] {
        assert!(
            names.iter().any(|n| n == expected),
            "missing entry: {}",
            std::str::from_utf8(expected).unwrap()
        );
    }
}

#[test]
fn test_index_readdir_skips_whiteouts() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::write(lower.join("visible"), b"data").unwrap();
    std::fs::write(lower.join("also_visible"), b"data").unwrap();

    IndexBuilder::new()
        .dir("")
        .file("", "also_visible", 0o644)
        .whiteout("", "hidden")
        .file("", "visible", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let names = readdir_names(&fs, ROOT_INODE);
    assert!(names.iter().any(|n| n == b"visible"));
    assert!(names.iter().any(|n| n == b"also_visible"));
    assert!(!names.iter().any(|n| n == b"hidden"));
}

#[test]
fn test_index_readdir_dedup_with_upper() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::write(lower.join("shared.txt"), b"lower").unwrap();
    std::fs::write(upper.join("shared.txt"), b"upper").unwrap();

    IndexBuilder::new()
        .dir("")
        .file("", "shared.txt", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let names = readdir_names(&fs, ROOT_INODE);
    let count = names
        .iter()
        .filter(|n| n.as_slice() == b"shared.txt")
        .count();
    assert_eq!(count, 1, "shared.txt should appear exactly once");
}

#[test]
fn test_index_readdir_whiteout_masks_indexed_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::write(lower.join("victim.txt"), b"data").unwrap();
    std::fs::write(upper.join(".wh.victim.txt"), b"").unwrap();

    IndexBuilder::new()
        .dir("")
        .file("", "victim.txt", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let names = readdir_names(&fs, ROOT_INODE);
    assert!(!names.iter().any(|n| n == b"victim.txt"));
}

#[test]
fn test_index_readdir_opaque_stops_lower() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::write(lower.join("lower_only.txt"), b"data").unwrap();
    // Make upper root opaque.
    std::fs::write(upper.join(".wh..wh..opq"), b"").unwrap();
    std::fs::write(upper.join("upper_file.txt"), b"data").unwrap();

    IndexBuilder::new()
        .dir("")
        .file("", "lower_only.txt", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let names = readdir_names(&fs, ROOT_INODE);
    assert!(!names.iter().any(|n| n == b"lower_only.txt"));
    assert!(names.iter().any(|n| n == b"upper_file.txt"));
}

#[test]
fn test_index_readdir_multi_layer() {
    let tmp = tempfile::tempdir().unwrap();
    let lower0 = tmp.path().join("lower0");
    let lower1 = tmp.path().join("lower1");
    let upper = tmp.path().join("upper");
    let staging = tmp.path().join("staging");
    let index0 = tmp.path().join("lower0.index");
    let index1 = tmp.path().join("lower1.index");
    for d in [&lower0, &lower1, &upper, &staging] {
        std::fs::create_dir(d).unwrap();
    }

    std::fs::write(lower0.join("base.txt"), b"base").unwrap();
    std::fs::write(lower0.join("shared.txt"), b"base_shared").unwrap();
    std::fs::write(lower1.join("shared.txt"), b"top_shared").unwrap();
    std::fs::write(lower1.join("top.txt"), b"top").unwrap();

    IndexBuilder::new()
        .dir("")
        .file("", "base.txt", 0o644)
        .file("", "shared.txt", 0o644)
        .build_to_file(&index0)
        .unwrap();
    IndexBuilder::new()
        .dir("")
        .file("", "shared.txt", 0o644)
        .file("", "top.txt", 0o644)
        .build_to_file(&index1)
        .unwrap();

    let fs = OverlayFs::builder()
        .layer_with_index(&lower0, &index0)
        .layer_with_index(&lower1, &index1)
        .writable(&upper)
        .staging(&staging)
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let names = readdir_names(&fs, ROOT_INODE);
    assert!(names.iter().any(|n| n == b"base.txt"));
    assert!(names.iter().any(|n| n == b"top.txt"));
    // shared.txt should appear only once (top layer wins).
    let count = names
        .iter()
        .filter(|n| n.as_slice() == b"shared.txt")
        .count();
    assert_eq!(count, 1);
}

#[test]
fn test_index_readdir_tombstones() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::write(lower.join("visible"), b"data").unwrap();
    std::fs::write(lower.join("tombstoned"), b"data").unwrap();

    // The tombstoned name should be masked from readdir.
    IndexBuilder::new()
        .dir("")
        .file("", "tombstoned", 0o644)
        .tombstone("", "tombstoned")
        .file("", "visible", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let names = readdir_names(&fs, ROOT_INODE);
    assert!(names.iter().any(|n| n == b"visible"));
    // Tombstone masks the entry — "tombstoned" should not appear in readdir output.
    assert!(!names.iter().any(|n| n == b"tombstoned"));
}

#[test]
fn test_index_readdir_empty_dir() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::create_dir(lower.join("emptydir")).unwrap();

    IndexBuilder::new()
        .dir("")
        .dir("emptydir")
        .subdir("", "emptydir", 0o755)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let dir = fs.lookup(ctx(), ROOT_INODE, &cstr("emptydir")).unwrap();
    let names = readdir_names(&fs, dir.inode);
    // No real entries beyond . and ..
    let real_names: Vec<_> = names
        .iter()
        .filter(|n| n.as_slice() != b"." && n.as_slice() != b"..")
        .collect();
    assert!(real_names.is_empty());
}

#[test]
fn test_index_readdir_matches_syscall_path() {
    let tmp = tempfile::tempdir().unwrap();
    let lower = tmp.path().join("lower");
    let upper1 = tmp.path().join("upper1");
    let upper2 = tmp.path().join("upper2");
    let staging1 = tmp.path().join("staging1");
    let staging2 = tmp.path().join("staging2");
    let index_path = tmp.path().join("lower.index");
    std::fs::create_dir_all(&lower).unwrap();
    for d in [&upper1, &upper2, &staging1, &staging2] {
        std::fs::create_dir(d).unwrap();
    }

    for name in ["aaa", "bbb", "ccc"] {
        std::fs::write(lower.join(name), b"data").unwrap();
    }

    IndexBuilder::new()
        .dir("")
        .file("", "aaa", 0o644)
        .file("", "bbb", 0o644)
        .file("", "ccc", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs_idx = mount_indexed(&lower, &index_path, &upper1, &staging1);
    let fs_plain = mount_plain(&lower, &upper2, &staging2);

    let mut names_idx = readdir_names(&fs_idx, ROOT_INODE);
    let mut names_plain = readdir_names(&fs_plain, ROOT_INODE);
    names_idx.sort();
    names_plain.sort();
    assert_eq!(names_idx, names_plain);
}

#[test]
fn test_index_readdir_d_type_from_mode() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);

    std::fs::write(lower.join("regular"), b"data").unwrap();
    std::fs::create_dir(lower.join("subdir")).unwrap();
    #[cfg(unix)]
    std::os::unix::fs::symlink("regular", lower.join("link")).unwrap();

    let mut builder = IndexBuilder::new()
        .dir("")
        .dir("subdir")
        .file("", "regular", 0o644)
        .subdir("", "subdir", 0o755);
    #[cfg(unix)]
    {
        builder = builder.symlink("", "link");
    }
    builder.build_to_file(&index_path).unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let entries = readdir_entries(&fs, ROOT_INODE);

    // Check d_type values.
    let find = |name: &[u8]| entries.iter().find(|(n, _)| n == name).map(|(_, t)| *t);
    assert_eq!(find(b"regular"), Some(libc::DT_REG as u32));
    assert_eq!(find(b"subdir"), Some(libc::DT_DIR as u32));
    #[cfg(unix)]
    assert_eq!(find(b"link"), Some(libc::DT_LNK as u32));
}

//--------------------------------------------------------------------------------------------------
// Tests: Fallback & Graceful Degradation
//--------------------------------------------------------------------------------------------------

#[test]
fn test_index_fallback_corrupt_file() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::write(lower.join("file.txt"), b"data").unwrap();

    // Write corrupt index.
    let data = corrupt_checksum(
        IndexBuilder::new()
            .dir("")
            .file("", "file.txt", 0o644)
            .build(),
    );
    std::fs::write(&index_path, data).unwrap();

    // Should still work via syscall fallback.
    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let entry = fs.lookup(ctx(), ROOT_INODE, &cstr("file.txt")).unwrap();
    assert_ne!(entry.inode, 0);
}

#[test]
fn test_index_fallback_missing_file() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, _) = setup_dirs(&tmp);
    std::fs::write(lower.join("file.txt"), b"data").unwrap();
    let bad_path = tmp.path().join("nonexistent.index");

    let fs = OverlayFs::builder()
        .layer_with_index(&lower, &bad_path)
        .writable(&upper)
        .staging(&staging)
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    let entry = fs.lookup(ctx(), ROOT_INODE, &cstr("file.txt")).unwrap();
    assert_ne!(entry.inode, 0);
}

#[test]
fn test_index_mixed_indexed_unindexed() {
    let tmp = tempfile::tempdir().unwrap();
    let lower0 = tmp.path().join("lower0");
    let lower1 = tmp.path().join("lower1");
    let upper = tmp.path().join("upper");
    let staging = tmp.path().join("staging");
    let index0 = tmp.path().join("lower0.index");
    for d in [&lower0, &lower1, &upper, &staging] {
        std::fs::create_dir(d).unwrap();
    }

    std::fs::write(lower0.join("from_indexed.txt"), b"indexed").unwrap();
    std::fs::write(lower1.join("from_plain.txt"), b"plain").unwrap();

    IndexBuilder::new()
        .dir("")
        .file("", "from_indexed.txt", 0o644)
        .build_to_file(&index0)
        .unwrap();

    let fs = OverlayFs::builder()
        .layer_with_index(&lower0, &index0) // indexed
        .layer(&lower1) // unindexed
        .writable(&upper)
        .staging(&staging)
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    // Both files should be findable.
    let e1 = fs
        .lookup(ctx(), ROOT_INODE, &cstr("from_indexed.txt"))
        .unwrap();
    let e2 = fs
        .lookup(ctx(), ROOT_INODE, &cstr("from_plain.txt"))
        .unwrap();
    assert_ne!(e1.inode, 0);
    assert_ne!(e2.inode, 0);
}

#[test]
fn test_index_does_not_affect_upper_ops() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    IndexBuilder::new()
        .dir("")
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);

    // Create a file on upper.
    let (entry, handle, _opts) = fs
        .create(
            ctx(),
            ROOT_INODE,
            &cstr("new_file.txt"),
            0o644,
            false,
            libc::O_RDWR as u32,
            0,
            Extensions::default(),
        )
        .unwrap();
    let handle = handle.unwrap();

    // Write to it.
    let mut reader = MockZeroCopyReader::new(b"hello".to_vec());
    fs.write(
        ctx(),
        entry.inode,
        handle,
        &mut reader,
        5,
        0,
        None,
        false,
        false,
        0,
    )
    .unwrap();

    // Release and re-lookup.
    fs.release(ctx(), entry.inode, 0, handle, false, false, None)
        .unwrap();
    let e2 = fs.lookup(ctx(), ROOT_INODE, &cstr("new_file.txt")).unwrap();
    assert_eq!(e2.inode, entry.inode);
}

#[test]
fn test_index_copy_up_from_indexed_lower() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::write(lower.join("file.txt"), b"original").unwrap();

    IndexBuilder::new()
        .dir("")
        .file("", "file.txt", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);

    // Look up the lower file.
    let entry = fs.lookup(ctx(), ROOT_INODE, &cstr("file.txt")).unwrap();

    // Open for writing — triggers copy-up.
    let (handle, _) = fs
        .open(ctx(), entry.inode, false, libc::O_RDWR as u32)
        .unwrap();
    let handle = handle.unwrap();

    // Write new data.
    let mut reader = MockZeroCopyReader::new(b"modified".to_vec());
    fs.write(
        ctx(),
        entry.inode,
        handle,
        &mut reader,
        8,
        0,
        None,
        false,
        false,
        0,
    )
    .unwrap();

    // Read back.
    let mut writer = MockZeroCopyWriter::new();
    let n = fs
        .read(ctx(), entry.inode, handle, &mut writer, 4096, 0, None, 0)
        .unwrap();
    let mut data = writer.into_data();
    data.truncate(n);
    assert_eq!(&data, b"modified");

    // Verify copy-up happened on upper.
    assert!(upper.join("file.txt").exists());
}

//--------------------------------------------------------------------------------------------------
// Tests: is_merged_dir_empty with Index
//--------------------------------------------------------------------------------------------------

#[test]
fn test_index_empty_check_truly_empty() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::create_dir(lower.join("emptydir")).unwrap();

    IndexBuilder::new()
        .dir("")
        .dir("emptydir")
        .subdir("", "emptydir", 0o755)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let dir = fs.lookup(ctx(), ROOT_INODE, &cstr("emptydir")).unwrap();

    use crate::backends::overlayfs::dir_ops;
    assert!(dir_ops::is_merged_dir_empty(&fs, dir.inode).unwrap());
}

#[test]
fn test_index_empty_check_has_entry() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::create_dir(lower.join("notempty")).unwrap();
    std::fs::write(lower.join("notempty/file.txt"), b"data").unwrap();

    IndexBuilder::new()
        .dir("")
        .dir("notempty")
        .subdir("", "notempty", 0o755)
        .file("notempty", "file.txt", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let dir = fs.lookup(ctx(), ROOT_INODE, &cstr("notempty")).unwrap();

    use crate::backends::overlayfs::dir_ops;
    assert!(!dir_ops::is_merged_dir_empty(&fs, dir.inode).unwrap());
}

#[test]
fn test_index_empty_check_only_whiteouts() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::create_dir(lower.join("wh_only")).unwrap();

    IndexBuilder::new()
        .dir("")
        .dir("wh_only")
        .subdir("", "wh_only", 0o755)
        .whiteout("wh_only", "deleted")
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let dir = fs.lookup(ctx(), ROOT_INODE, &cstr("wh_only")).unwrap();

    use crate::backends::overlayfs::dir_ops;
    // Only whiteout entries → no visible entries → empty.
    assert!(dir_ops::is_merged_dir_empty(&fs, dir.inode).unwrap());
}

#[test]
fn test_index_empty_check_entry_masked() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::create_dir(lower.join("masked")).unwrap();
    std::fs::write(lower.join("masked/file.txt"), b"data").unwrap();
    // Upper whiteout masks the lower entry.
    std::fs::create_dir(upper.join("masked")).unwrap();
    std::fs::write(upper.join("masked/.wh.file.txt"), b"").unwrap();

    IndexBuilder::new()
        .dir("")
        .dir("masked")
        .subdir("", "masked", 0o755)
        .file("masked", "file.txt", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let dir = fs.lookup(ctx(), ROOT_INODE, &cstr("masked")).unwrap();

    use crate::backends::overlayfs::dir_ops;
    assert!(dir_ops::is_merged_dir_empty(&fs, dir.inode).unwrap());
}

#[test]
fn test_index_empty_check_opaque_upper() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::create_dir(lower.join("opq")).unwrap();
    std::fs::write(lower.join("opq/lower_file.txt"), b"data").unwrap();
    // Upper makes it opaque.
    std::fs::create_dir(upper.join("opq")).unwrap();
    std::fs::write(upper.join("opq/.wh..wh..opq"), b"").unwrap();

    IndexBuilder::new()
        .dir("")
        .dir("opq")
        .subdir("", "opq", 0o755)
        .file("opq", "lower_file.txt", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let dir = fs.lookup(ctx(), ROOT_INODE, &cstr("opq")).unwrap();

    use crate::backends::overlayfs::dir_ops;
    // Opaque upper hides lower entries → empty.
    assert!(dir_ops::is_merged_dir_empty(&fs, dir.inode).unwrap());
}

//--------------------------------------------------------------------------------------------------
// Tests: build_overlay_path
//--------------------------------------------------------------------------------------------------

#[test]
fn test_overlay_path_root() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    IndexBuilder::new()
        .dir("")
        .build_to_file(&index_path)
        .unwrap();
    let fs = mount_indexed(&lower, &index_path, &upper, &staging);

    let nodes = fs.nodes.read().unwrap();
    let root = nodes.get(&ROOT_INODE).unwrap();
    let path = inode::build_overlay_path(&fs, root).unwrap();
    assert_eq!(path, b"");
}

#[test]
fn test_overlay_path_one_level() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::create_dir(lower.join("etc")).unwrap();

    IndexBuilder::new()
        .dir("")
        .dir("etc")
        .subdir("", "etc", 0o755)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let entry = fs.lookup(ctx(), ROOT_INODE, &cstr("etc")).unwrap();

    let nodes = fs.nodes.read().unwrap();
    let node = nodes.get(&entry.inode).unwrap();
    let path = inode::build_overlay_path(&fs, node).unwrap();
    assert_eq!(path, b"etc");
}

#[test]
fn test_overlay_path_nested() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::create_dir_all(lower.join("usr/bin")).unwrap();

    IndexBuilder::new()
        .dir("")
        .dir("usr")
        .dir("usr/bin")
        .subdir("", "usr", 0o755)
        .subdir("usr", "bin", 0o755)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let usr = fs.lookup(ctx(), ROOT_INODE, &cstr("usr")).unwrap();
    let bin = fs.lookup(ctx(), usr.inode, &cstr("bin")).unwrap();

    let nodes = fs.nodes.read().unwrap();
    let node = nodes.get(&bin.inode).unwrap();
    let path = inode::build_overlay_path(&fs, node).unwrap();
    assert_eq!(path, b"usr/bin");
}

//--------------------------------------------------------------------------------------------------
// Tests: Stale Index & Index Proof
//--------------------------------------------------------------------------------------------------

/// Index says file exists, but it's not on disk. Proves the index path is exercised:
/// the index hits, but the subsequent fstatat fails, returning ENOENT.
#[test]
fn test_index_stale_single_layer() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    // Do NOT create "ghost.txt" on disk — only in the index.
    IndexBuilder::new()
        .dir("")
        .file("", "ghost.txt", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);
    let result = fs.lookup(ctx(), ROOT_INODE, &cstr("ghost.txt"));
    assert!(result.is_err());
    assert_eq!(result.err().unwrap().raw_os_error(), Some(LINUX_ENOENT));
}

/// Index says file exists on layer 1 (stale), but it really exists on layer 0 (unindexed).
/// Proves the index hit + fstatat fail triggers fallthrough to next layer.
#[test]
fn test_index_stale_fallthrough_to_next_layer() {
    let tmp = tempfile::tempdir().unwrap();
    let lower0 = tmp.path().join("lower0");
    let lower1 = tmp.path().join("lower1");
    let upper = tmp.path().join("upper");
    let staging = tmp.path().join("staging");
    let index1 = tmp.path().join("lower1.index");

    for d in [&lower0, &lower1, &upper, &staging] {
        std::fs::create_dir(d).unwrap();
    }

    // Layer 0 (bottom, unindexed): has the real file.
    std::fs::write(lower0.join("real.txt"), b"from layer 0").unwrap();

    // Layer 1 (top, indexed): index claims "real.txt" exists, but it's NOT on disk.
    IndexBuilder::new()
        .dir("")
        .file("", "real.txt", 0o644)
        .build_to_file(&index1)
        .unwrap();

    let fs = OverlayFs::builder()
        .layer(&lower0) // bottom, no index
        .layer_with_index(&lower1, &index1) // top, stale index
        .writable(&upper)
        .staging(&staging)
        .build()
        .unwrap();
    fs.init(FsOptions::empty()).unwrap();

    // The index on layer 1 hits for "real.txt", but fstatat fails (file not on disk).
    // The overlay falls through to layer 0 (syscall path) and finds the real file.
    let entry = fs.lookup(ctx(), ROOT_INODE, &cstr("real.txt")).unwrap();
    assert_ne!(entry.inode, 0);
}

/// Index has directory records but no root (""). Verifies:
///   1. Root's dir_record_cache stays None (not poisoned with another dir's record).
///   2. No panic from the missing root record.
///   3. Root lookups return ENOENT — the index is authoritative and the overlay
///      skips the layer when it can't describe the queried directory.
#[test]
fn test_index_without_root_dir_record() {
    let tmp = tempfile::tempdir().unwrap();
    let (lower, upper, staging, index_path) = setup_dirs(&tmp);
    std::fs::create_dir_all(lower.join("etc")).unwrap();
    std::fs::write(lower.join("etc/hosts"), b"127.0.0.1").unwrap();
    std::fs::write(lower.join("top.txt"), b"top").unwrap();

    // Index describes "etc/hosts" but has no root dir record ("").
    IndexBuilder::new()
        .dir("etc")
        .file("etc", "hosts", 0o644)
        .build_to_file(&index_path)
        .unwrap();

    let fs = mount_indexed(&lower, &index_path, &upper, &staging);

    // Root's cache must be None — not poisoned with "etc"'s record.
    {
        let nodes = fs.nodes.read().unwrap();
        let root_node = nodes.get(&ROOT_INODE).unwrap();
        let cache = root_node.dir_record_cache.read().unwrap();
        assert!(
            cache.is_none(),
            "root cache should be None when index has no root dir"
        );
    }

    // "top.txt" exists on disk but the index has no root dir, so the index
    // fast path can't search this layer's root and skips it. With no other
    // layers to fall through to, the result is ENOENT.
    let result = fs.lookup(ctx(), ROOT_INODE, &cstr("top.txt"));
    assert!(result.is_err());
}
