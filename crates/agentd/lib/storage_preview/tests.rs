//! Hostile guest files must never become reader commands or special-device opens.

use std::fs::{self, File};
use std::io;
use std::os::unix::fs::symlink;
use std::path::Path;

use microsandbox_protocol::storage_preview::{MAX_ENTRIES, MAX_FILE, StoragePreviewEntry};
use nix::sys::stat::Mode;
use nix::unistd::mkfifo;
use tempfile::tempdir;

use super::{open_guest_path, write_reply};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn query(directory: &Path, command: &str, path: &str) -> io::Result<Vec<u8>> {
    let root = File::open(directory)?;
    let pinned = open_guest_path(&root, path)?;
    let mut output = Vec::new();
    write_reply(&pinned, command, &mut output)?;
    Ok(output)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn missing_links_special_files_and_regular_contents_are_distinguishable() {
    let fixture = tempdir().unwrap();
    fs::write(fixture.path().join("record"), b"recognizable\0data").unwrap();
    symlink("/proc/self", fixture.path().join("outside")).unwrap();
    mkfifo(&fixture.path().join("queue"), Mode::S_IRUSR | Mode::S_IWUSR).unwrap();

    assert_eq!(
        query(fixture.path(), "read", "/record").unwrap(),
        b"recognizable\0data"
    );
    assert_eq!(
        query(fixture.path(), "read", "/absent").unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    for unsafe_path in ["/outside", "/outside/environ", "/../etc/passwd", "/queue"] {
        let error = query(fixture.path(), "read", unsafe_path).unwrap_err();
        assert_ne!(
            error.kind(),
            io::ErrorKind::NotFound,
            "{unsafe_path}: {error}"
        );
    }

    let entries: Vec<StoragePreviewEntry> =
        serde_json::from_slice(&query(fixture.path(), "list", "/").unwrap()).unwrap();
    assert!(
        entries
            .iter()
            .any(|e| e.name == "outside" && e.kind == "symlink")
    );
    assert!(
        entries
            .iter()
            .any(|e| e.name == "queue" && e.kind == "other")
    );
}

#[test]
fn oversized_file_or_directory_yields_no_partial_success() {
    let fixture = tempdir().unwrap();
    let data = vec![0x61; MAX_FILE];
    fs::write(fixture.path().join("data"), &data).unwrap();
    assert_eq!(query(fixture.path(), "read", "/data").unwrap(), data);
    File::options()
        .write(true)
        .open(fixture.path().join("data"))
        .unwrap()
        .set_len(MAX_FILE as u64 + 1)
        .unwrap();
    assert!(query(fixture.path(), "read", "/data").is_err());

    for index in 0..MAX_ENTRIES {
        File::create_new(fixture.path().join(index.to_string())).unwrap();
    }
    assert!(query(fixture.path(), "list", "/").is_err());
}
