//! Extended attribute operations: setxattr, getxattr, listxattr, removexattr.
//!
//! Xattrs are stored entirely in memory as raw byte key-value pairs.
//! No internal xattrs are used — MemFs stores metadata directly.

use std::{ffi::CStr, io};

use super::{MemFs, inode};
use crate::{
    Context, GetxattrReply, ListxattrReply,
    backends::shared::{init_binary, platform},
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// XATTR_CREATE flag (Linux value).
const XATTR_CREATE: u32 = 1;

/// XATTR_REPLACE flag (Linux value).
const XATTR_REPLACE: u32 = 2;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Set an extended attribute.
pub(crate) fn do_setxattr(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    name: &CStr,
    value: &[u8],
    flags: u32,
) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    let node = inode::get_node(fs, ino)?;
    let mut xattrs = node.xattrs.write().unwrap();
    let key = name.to_bytes().to_vec();

    if flags & XATTR_CREATE != 0 && xattrs.contains_key(&key) {
        return Err(platform::eexist());
    }
    if flags & XATTR_REPLACE != 0 && !xattrs.contains_key(&key) {
        return Err(platform::enodata());
    }

    xattrs.insert(key, value.to_vec());
    Ok(())
}

/// Get an extended attribute.
pub(crate) fn do_getxattr(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    name: &CStr,
    size: u32,
) -> io::Result<GetxattrReply> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::enodata());
    }

    let node = inode::get_node(fs, ino)?;
    let xattrs = node.xattrs.read().unwrap();
    let key = name.to_bytes();

    match xattrs.get(key) {
        Some(value) => {
            if size == 0 {
                Ok(GetxattrReply::Count(value.len() as u32))
            } else if value.len() > size as usize {
                Err(platform::erange())
            } else {
                Ok(GetxattrReply::Value(value.clone()))
            }
        }
        None => Err(platform::enodata()),
    }
}

/// List extended attribute names.
pub(crate) fn do_listxattr(
    fs: &MemFs,
    _ctx: Context,
    ino: u64,
    size: u32,
) -> io::Result<ListxattrReply> {
    if ino == init_binary::INIT_INODE {
        if size == 0 {
            return Ok(ListxattrReply::Count(0));
        }
        return Ok(ListxattrReply::Names(Vec::new()));
    }

    let node = inode::get_node(fs, ino)?;
    let xattrs = node.xattrs.read().unwrap();

    // Build NUL-separated list of xattr names.
    let mut buf = Vec::new();
    for key in xattrs.keys() {
        buf.extend_from_slice(key);
        buf.push(0);
    }

    if size == 0 {
        Ok(ListxattrReply::Count(buf.len() as u32))
    } else if buf.len() > size as usize {
        Err(platform::erange())
    } else {
        Ok(ListxattrReply::Names(buf))
    }
}

/// Remove an extended attribute.
pub(crate) fn do_removexattr(fs: &MemFs, _ctx: Context, ino: u64, name: &CStr) -> io::Result<()> {
    if ino == init_binary::INIT_INODE {
        return Err(platform::eacces());
    }

    let node = inode::get_node(fs, ino)?;
    let mut xattrs = node.xattrs.write().unwrap();
    let key = name.to_bytes();

    if xattrs.remove(key).is_none() {
        return Err(platform::enodata());
    }

    Ok(())
}
