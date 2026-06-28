//! Shared in-memory [`PathFs`] reference backend for the `vfs` tests.
//!
//! Both the scaffold tests ([`super::tests`]) and the RPC-provider tests
//! ([`super::rpc::tests`]) drive this same backend, so the RPC path is proven
//! to behave identically to a direct in-process provider.

#![cfg(test)]

use std::{collections::BTreeMap, fs::File, io, os::fd::AsRawFd, path::Path, sync::RwLock};

use super::{NodeKind, PathFs, VAttr, VDirEntry, parent_path};
use crate::{SetattrValid, ZeroCopyReader, ZeroCopyWriter};

pub(crate) const LINUX_ENOENT: i32 = 2;
pub(crate) const LINUX_EISDIR: i32 = 21;
pub(crate) const LINUX_ENODATA: i32 = 61;

#[derive(Clone)]
pub(crate) struct Node {
    pub(crate) kind: NodeKind,
    pub(crate) mode: u32,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) rdev: u32,
    pub(crate) data: Vec<u8>,
    pub(crate) target: Vec<u8>,
    pub(crate) xattrs: BTreeMap<Vec<u8>, Vec<u8>>,
}

impl Node {
    pub(crate) fn new(kind: NodeKind, mode: u32) -> Self {
        Node {
            kind,
            mode,
            uid: 0,
            gid: 0,
            rdev: 0,
            data: Vec::new(),
            target: Vec::new(),
            xattrs: BTreeMap::new(),
        }
    }

    fn attr(&self) -> VAttr {
        let size = match self.kind {
            NodeKind::File => self.data.len() as u64,
            NodeKind::Symlink => self.target.len() as u64,
            _ => 0,
        };
        let mut a = VAttr::new(self.kind, self.mode, size);
        a.uid = self.uid;
        a.gid = self.gid;
        a.rdev = self.rdev;
        a
    }
}

/// A complete in-memory `PathFs` implementation (the reference backend).
pub(crate) struct InMemoryFs {
    pub(crate) map: RwLock<BTreeMap<Vec<u8>, Node>>,
}

impl InMemoryFs {
    pub(crate) fn new() -> Self {
        let mut map = BTreeMap::new();
        map.insert(b"/".to_vec(), Node::new(NodeKind::Dir, 0o755));
        InMemoryFs {
            map: RwLock::new(map),
        }
    }
}

fn key(path: &Path) -> Vec<u8> {
    use std::os::unix::ffi::OsStrExt;
    path.as_os_str().as_bytes().to_vec()
}

fn err(e: i32) -> io::Error {
    io::Error::from_raw_os_error(e)
}

impl PathFs for InMemoryFs {
    fn getattr(&self, path: &Path) -> io::Result<VAttr> {
        self.map
            .read()
            .unwrap()
            .get(&key(path))
            .map(Node::attr)
            .ok_or_else(|| err(LINUX_ENOENT))
    }

    fn readdir(&self, path: &Path) -> io::Result<Vec<VDirEntry>> {
        let k = key(path);
        let map = self.map.read().unwrap();
        match map.get(&k) {
            Some(n) if n.kind == NodeKind::Dir => {}
            Some(_) => return Err(err(libc::ENOTDIR)),
            None => return Err(err(LINUX_ENOENT)),
        }
        let mut out = Vec::new();
        for (child, node) in map.iter() {
            if child.as_slice() == k.as_slice() {
                continue;
            }
            if parent_path(child) == k {
                let name = match child.iter().rposition(|&b| b == b'/') {
                    Some(idx) => child[idx + 1..].to_vec(),
                    None => child.clone(),
                };
                out.push(VDirEntry::new(name, node.kind));
            }
        }
        Ok(out)
    }

    fn read(&self, path: &Path, offset: u64, size: u32) -> io::Result<Vec<u8>> {
        let map = self.map.read().unwrap();
        let node = map.get(&key(path)).ok_or_else(|| err(LINUX_ENOENT))?;
        if node.kind != NodeKind::File {
            return Err(err(LINUX_EISDIR));
        }
        let off = offset as usize;
        if off >= node.data.len() {
            return Ok(Vec::new());
        }
        let end = (off + size as usize).min(node.data.len());
        Ok(node.data[off..end].to_vec())
    }

    fn write(&self, path: &Path, offset: u64, data: &[u8]) -> io::Result<usize> {
        let mut map = self.map.write().unwrap();
        let node = map.get_mut(&key(path)).ok_or_else(|| err(LINUX_ENOENT))?;
        let off = offset as usize;
        let end = off + data.len();
        if end > node.data.len() {
            node.data.resize(end, 0);
        }
        node.data[off..end].copy_from_slice(data);
        Ok(data.len())
    }

    fn create(&self, path: &Path, attr: &VAttr) -> io::Result<VAttr> {
        let k = key(path);
        let mut map = self.map.write().unwrap();
        match map.get(&parent_path(&k)) {
            Some(p) if p.kind == NodeKind::Dir => {}
            Some(_) => return Err(err(libc::ENOTDIR)),
            None => return Err(err(LINUX_ENOENT)),
        }
        if map.contains_key(&k) {
            return Err(err(libc::EEXIST));
        }
        let mut node = Node::new(attr.kind, attr.mode);
        node.rdev = attr.rdev;
        let result = node.attr();
        map.insert(k, node);
        Ok(result)
    }

    fn mkdir(&self, path: &Path, mode: u32) -> io::Result<VAttr> {
        self.create(path, &VAttr::dir(mode))
    }

    fn remove(&self, path: &Path) -> io::Result<()> {
        self.map
            .write()
            .unwrap()
            .remove(&key(path))
            .map(|_| ())
            .ok_or_else(|| err(LINUX_ENOENT))
    }

    fn rename(&self, from: &Path, to: &Path) -> io::Result<()> {
        self.rename_with_flags(from, to, 0)
    }

    fn rename_with_flags(&self, from: &Path, to: &Path, flags: u32) -> io::Result<()> {
        const RENAME_NOREPLACE: u32 = 1;
        let (from, to) = (key(from), key(to));
        let mut map = self.map.write().unwrap();
        if !map.contains_key(&from) {
            return Err(err(LINUX_ENOENT));
        }
        if flags & RENAME_NOREPLACE != 0 && from != to {
            let dest_exists = map.keys().any(|k| {
                k.as_slice() == to.as_slice()
                    || (k.len() > to.len() && k.starts_with(&to) && k[to.len()] == b'/')
            });
            if dest_exists {
                return Err(err(libc::EEXIST));
            }
        }
        let moved: Vec<Vec<u8>> = map
            .keys()
            .filter(|k| {
                k.as_slice() == from.as_slice()
                    || (k.len() > from.len() && k.starts_with(&from) && k[from.len()] == b'/')
            })
            .cloned()
            .collect();
        for old in moved {
            let node = map.remove(&old).unwrap();
            let mut new = to.clone();
            new.extend_from_slice(&old[from.len()..]);
            map.insert(new, node);
        }
        Ok(())
    }

    fn setattr(&self, path: &Path, attr: &VAttr, valid: SetattrValid) -> io::Result<VAttr> {
        let mut map = self.map.write().unwrap();
        let node = map.get_mut(&key(path)).ok_or_else(|| err(LINUX_ENOENT))?;
        if valid.contains(SetattrValid::SIZE) && node.kind == NodeKind::File {
            node.data.resize(attr.size as usize, 0);
        }
        if valid.contains(SetattrValid::MODE) {
            node.mode = attr.mode;
        }
        if valid.contains(SetattrValid::UID) {
            node.uid = attr.uid;
        }
        if valid.contains(SetattrValid::GID) {
            node.gid = attr.gid;
        }
        Ok(node.attr())
    }

    fn symlink(&self, path: &Path, target: &[u8]) -> io::Result<VAttr> {
        let k = key(path);
        let mut map = self.map.write().unwrap();
        if map.contains_key(&k) {
            return Err(err(libc::EEXIST));
        }
        let mut node = Node::new(NodeKind::Symlink, 0o777);
        node.target = target.to_vec();
        let result = node.attr();
        map.insert(k, node);
        Ok(result)
    }

    fn readlink(&self, path: &Path) -> io::Result<Vec<u8>> {
        let map = self.map.read().unwrap();
        let node = map.get(&key(path)).ok_or_else(|| err(LINUX_ENOENT))?;
        if node.kind != NodeKind::Symlink {
            return Err(err(libc::EINVAL));
        }
        Ok(node.target.clone())
    }

    fn setxattr(&self, path: &Path, name: &[u8], value: &[u8], _flags: u32) -> io::Result<()> {
        let mut map = self.map.write().unwrap();
        let node = map.get_mut(&key(path)).ok_or_else(|| err(LINUX_ENOENT))?;
        node.xattrs.insert(name.to_vec(), value.to_vec());
        Ok(())
    }

    fn getxattr(&self, path: &Path, name: &[u8]) -> io::Result<Vec<u8>> {
        let map = self.map.read().unwrap();
        let node = map.get(&key(path)).ok_or_else(|| err(LINUX_ENOENT))?;
        node.xattrs
            .get(name)
            .cloned()
            .ok_or_else(|| err(LINUX_ENODATA))
    }

    fn listxattr(&self, path: &Path) -> io::Result<Vec<Vec<u8>>> {
        let map = self.map.read().unwrap();
        let node = map.get(&key(path)).ok_or_else(|| err(LINUX_ENOENT))?;
        Ok(node.xattrs.keys().cloned().collect())
    }

    fn removexattr(&self, path: &Path, name: &[u8]) -> io::Result<()> {
        let mut map = self.map.write().unwrap();
        let node = map.get_mut(&key(path)).ok_or_else(|| err(LINUX_ENOENT))?;
        node.xattrs
            .remove(name)
            .map(|_| ())
            .ok_or_else(|| err(LINUX_ENODATA))
    }
}

//--------------------------------------------------------------------------------------------------
// Zero-copy mock reader/writer
//--------------------------------------------------------------------------------------------------

/// Collects bytes the scaffold writes out of its staging file.
pub(crate) struct MockWriter {
    pub(crate) buf: Vec<u8>,
}
impl MockWriter {
    pub(crate) fn new() -> Self {
        MockWriter { buf: Vec::new() }
    }
}
impl ZeroCopyWriter for MockWriter {
    fn write_from(&mut self, f: &File, count: usize, off: u64) -> io::Result<usize> {
        let mut tmp = vec![0u8; count];
        let n = unsafe {
            libc::pread(
                f.as_raw_fd(),
                tmp.as_mut_ptr() as *mut libc::c_void,
                count,
                off as i64,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        self.buf.extend_from_slice(&tmp[..n as usize]);
        Ok(n as usize)
    }
}

/// Feeds bytes into the scaffold's staging file on write.
pub(crate) struct MockReader {
    data: Vec<u8>,
    pos: usize,
}
impl MockReader {
    pub(crate) fn new(data: Vec<u8>) -> Self {
        MockReader { data, pos: 0 }
    }
}
impl ZeroCopyReader for MockReader {
    fn read_to(&mut self, f: &File, count: usize, off: u64) -> io::Result<usize> {
        let remaining = &self.data[self.pos..];
        let to_write = count.min(remaining.len());
        if to_write == 0 {
            return Ok(0);
        }
        let n = unsafe {
            libc::pwrite(
                f.as_raw_fd(),
                remaining.as_ptr() as *const libc::c_void,
                to_write,
                off as i64,
            )
        };
        if n < 0 {
            return Err(io::Error::last_os_error());
        }
        self.pos += n as usize;
        Ok(n as usize)
    }
}
