//! Integration tests for programmable virtual-filesystem mounts.
//!
//! Requires a working microsandbox install (`msb`, `libkrunfw`). Tests are
//! `#[ignore]`-gated via `#[msb_test]` — run with:
//!
//! ```sh
//! cargo test -p microsandbox --test virtual_mount -- --ignored
//! ```

use std::collections::{BTreeMap, HashSet};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::{Arc, Mutex};

use microsandbox::Sandbox;
use microsandbox::sandbox::SandboxBuilder;
use microsandbox_filesystem::{NodeKind, PathFs, VAttr, VDirEntry};
use test_utils::msb_test;

const ALPINE: &str = "mirror.gcr.io/library/alpine";

//--------------------------------------------------------------------------------------------------
// In-memory provider
//--------------------------------------------------------------------------------------------------

#[derive(Clone)]
struct MemVfs {
    inner: Arc<MemVfsInner>,
}

struct MemVfsInner {
    files: Mutex<BTreeMap<Vec<u8>, Vec<u8>>>,
    dirs: Mutex<HashSet<Vec<u8>>>,
}

impl MemVfs {
    fn with_seed(seed: impl IntoIterator<Item = (&'static str, Vec<u8>)>) -> Self {
        let mut files = BTreeMap::new();
        for (path, content) in seed {
            files.insert(path.as_bytes().to_vec(), content);
        }
        let mut dirs = HashSet::new();
        dirs.insert(b"/".to_vec());
        Self {
            inner: Arc::new(MemVfsInner {
                files: Mutex::new(files),
                dirs: Mutex::new(dirs),
            }),
        }
    }

    fn file(&self, path: &str) -> Option<Vec<u8>> {
        self.inner
            .files
            .lock()
            .expect("memvfs files poisoned")
            .get(path.as_bytes())
            .cloned()
    }

    fn add_file_out_of_band(&self, path: &str, content: &[u8]) {
        self.inner
            .files
            .lock()
            .expect("memvfs files poisoned")
            .insert(path.as_bytes().to_vec(), content.to_vec());
    }
}

fn path_key(path: &Path) -> Vec<u8> {
    path.as_os_str().as_bytes().to_vec()
}

impl PathFs for MemVfs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        let key = path_key(path);
        let dirs = self.inner.dirs.lock().expect("memvfs dirs poisoned");
        if dirs.contains(&key) {
            return Ok(VAttr::dir(0o755));
        }
        let files = self.inner.files.lock().expect("memvfs files poisoned");
        let data = files
            .get(&key)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        Ok(VAttr::file(0o644, data.len() as u64))
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        let key = path_key(path);
        let dirs = self.inner.dirs.lock().expect("memvfs dirs poisoned");
        if !dirs.contains(&key) {
            let files = self.inner.files.lock().expect("memvfs files poisoned");
            if files.contains_key(&key) {
                return Err(io::Error::from_raw_os_error(libc::ENOTDIR));
            }
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }

        let prefix = if key == b"/" {
            b"/".to_vec()
        } else {
            let mut p = key.clone();
            if !p.ends_with(b"/") {
                p.push(b'/');
            }
            p
        };

        let files = self.inner.files.lock().expect("memvfs files poisoned");
        let mut out = Vec::new();
        for (file_path, _) in files.iter() {
            if !file_path.starts_with(&prefix) {
                continue;
            }
            let rest = &file_path[prefix.len()..];
            if rest.is_empty() || rest.contains(&b'/') {
                continue;
            }
            out.push(VDirEntry::new(rest.to_vec(), NodeKind::File));
        }

        for dir_path in dirs.iter() {
            if dir_path == &key {
                continue;
            }
            if !dir_path.starts_with(&prefix) {
                continue;
            }
            let rest = &dir_path[prefix.len()..];
            if rest.is_empty() || rest.contains(&b'/') {
                continue;
            }
            out.push(VDirEntry::new(rest.to_vec(), NodeKind::Dir));
        }
        Ok(out)
    }

    fn read(&self, path: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
        let key = path_key(path);
        let files = self.inner.files.lock().expect("memvfs files poisoned");
        let data = files
            .get(&key)
            .ok_or_else(|| io::Error::from_raw_os_error(libc::ENOENT))?;
        let off = offset as usize;
        if off >= data.len() {
            return Ok(Vec::new());
        }
        let end = off.saturating_add(size as usize).min(data.len());
        Ok(data[off..end].to_vec())
    }

    fn write(&self, path: &Path, offset: u64, data: &[u8]) -> io::Result<usize> {
        let key = path_key(path);
        let mut files = self.inner.files.lock().expect("memvfs files poisoned");
        let mut cur = files.remove(&key).unwrap_or_default();
        let off = offset as usize;
        if off > cur.len() {
            cur.resize(off, 0);
        }
        let end = off.saturating_add(data.len());
        if end > cur.len() {
            cur.resize(end, 0);
        }
        cur[off..off + data.len()].copy_from_slice(data);
        files.insert(key, cur);
        Ok(data.len())
    }

    fn create(&self, path: &Path, attr: &VAttr) -> io::Result<VAttr> {
        let key = path_key(path);
        let mut files = self.inner.files.lock().expect("memvfs files poisoned");
        let mut dirs = self.inner.dirs.lock().expect("memvfs dirs poisoned");
        if files.contains_key(&key) || dirs.contains(&key) {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        match attr.kind {
            NodeKind::Dir => {
                dirs.insert(key);
                Ok(VAttr::dir(attr.mode))
            }
            _ => {
                files.insert(key, Vec::new());
                Ok(VAttr::file(attr.mode, 0))
            }
        }
    }

    fn mkdir(&self, path: &Path, mode: u32) -> io::Result<VAttr> {
        self.create(path, &VAttr::dir(mode))
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        let key = path_key(path);
        let mut files = self.inner.files.lock().expect("memvfs files poisoned");
        let mut dirs = self.inner.dirs.lock().expect("memvfs dirs poisoned");
        if dirs.remove(&key) {
            return Ok(());
        }
        if files.remove(&key).is_some() {
            return Ok(());
        }
        Err(io::Error::from_raw_os_error(libc::ENOENT))
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.rename_with_flags(from, to, 0)
    }

    fn rename_with_flags(&self, from: &Path, to: &Path, flags: u32) -> io::Result<()> {
        const RENAME_NOREPLACE: u32 = 1;
        let from_key = path_key(from);
        let to_key = path_key(to);
        let mut files = self.inner.files.lock().expect("memvfs files poisoned");
        let mut dirs = self.inner.dirs.lock().expect("memvfs dirs poisoned");
        let from_is_dir = dirs.contains(&from_key);
        let from_is_file = files.contains_key(&from_key);
        if !from_is_dir && !from_is_file {
            return Err(io::Error::from_raw_os_error(libc::ENOENT));
        }
        if flags & RENAME_NOREPLACE != 0 && from_key != to_key {
            if files.contains_key(&to_key) || dirs.contains(&to_key) {
                return Err(io::Error::from_raw_os_error(libc::EEXIST));
            }
        }
        if files.contains_key(&to_key) || dirs.contains(&to_key) {
            return Err(io::Error::from_raw_os_error(libc::EEXIST));
        }
        if from_is_file {
            let data = files.remove(&from_key).expect("file present");
            files.insert(to_key, data);
        } else {
            dirs.remove(&from_key);
            dirs.insert(to_key);
        }
        Ok(())
    }
}

async fn stop_and_remove(name: &str) {
    let handle = Sandbox::get(name).await.expect("get sandbox");
    handle.stop().await.expect("stop sandbox");
    let _ = Sandbox::remove(name).await;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn virtual_mount_read_write_round_trip() {
    let provider = MemVfs::with_seed([("/hello.txt", b"from-rust-provider".to_vec())]);
    let name = "rust-sdk-virtualfs-readwrite";
    let sb = SandboxBuilder::new(name)
        .image(ALPINE)
        .replace()
        .virtual_mount_with_provider("/inbox", provider.clone())
        .create()
        .await
        .expect("create sandbox with virtual mount");

    let out = sb
        .shell("cat /inbox/hello.txt")
        .await
        .expect("read virtual file");
    assert_eq!(out.stdout().expect("utf8").trim(), "from-rust-provider");

    let write = sb
        .shell("sh -c 'echo guest-write > /inbox/written.txt'")
        .await
        .expect("write virtual file");
    assert!(
        write.status().success,
        "write failed: {}",
        write.stderr().unwrap_or_default()
    );

    let got = provider
        .file("/written.txt")
        .expect("provider should have written file");
    assert_eq!(
        String::from_utf8_lossy(&got).trim(),
        "guest-write",
        "provider did not observe guest write"
    );

    let list = sb.shell("ls /inbox").await.expect("list virtual dir");
    let listing = list.stdout().expect("utf8");
    assert!(
        listing.contains("hello.txt"),
        "missing hello.txt in {listing}"
    );
    assert!(
        listing.contains("written.txt"),
        "missing written.txt in {listing}"
    );

    sb.stop().await.expect("stop sandbox");
    stop_and_remove(name).await;
}

#[msb_test]
async fn virtual_mount_fsyncdir_refreshes_out_of_band_listing() {
    let provider = MemVfs::with_seed([("/hello.txt", b"seed".to_vec())]);
    let name = "rust-sdk-virtualfs-fsyncdir";
    let sb = SandboxBuilder::new(name)
        .image(ALPINE)
        .replace()
        .virtual_mount_with_provider("/inbox", provider.clone())
        .create()
        .await
        .expect("create sandbox with virtual mount");

    sb.shell("apk add --quiet --no-progress util-linux >/dev/null 2>&1")
        .await
        .expect("install util-linux sync shell")
        .status()
        .success
        .then_some(())
        .expect("install util-linux sync");

    let initial = sb.shell("ls /inbox").await.expect("initial list");
    assert!(
        initial.status().success,
        "initial ls failed: {}",
        initial.stderr().unwrap_or_default()
    );
    let initial_listing = initial.stdout().expect("utf8");
    assert!(
        initial_listing.contains("hello.txt"),
        "missing hello.txt in {initial_listing}"
    );
    assert!(
        !initial_listing.contains("fresh.txt"),
        "fresh.txt should not exist yet: {initial_listing}"
    );

    provider.add_file_out_of_band("/fresh.txt", b"out-of-band");

    let stale = sb.shell("ls /inbox").await.expect("stale list");
    assert!(
        stale.status().success,
        "stale ls failed: {}",
        stale.stderr().unwrap_or_default()
    );
    let stale_listing = stale.stdout().expect("utf8");
    assert!(
        !stale_listing.contains("fresh.txt"),
        "listing should stay stale before fsyncdir: {stale_listing}"
    );

    let sync = sb
        .shell("sync -f /inbox")
        .await
        .expect("fsyncdir via util-linux sync shell");
    assert!(
        sync.status().success,
        "sync -f /inbox failed: {}",
        sync.stderr().unwrap_or_default()
    );

    let refreshed = sb.shell("ls /inbox").await.expect("refreshed list");
    assert!(
        refreshed.status().success,
        "refreshed ls failed: {}",
        refreshed.stderr().unwrap_or_default()
    );
    let refreshed_listing = refreshed.stdout().expect("utf8");
    assert!(
        refreshed_listing.contains("hello.txt"),
        "missing hello.txt in {refreshed_listing}"
    );
    assert!(
        refreshed_listing.contains("fresh.txt"),
        "fsyncdir should expose out-of-band listing change: {refreshed_listing}"
    );

    sb.stop().await.expect("stop sandbox");
    stop_and_remove(name).await;
}
