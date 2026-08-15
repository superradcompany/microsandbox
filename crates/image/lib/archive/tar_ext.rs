//! Extensions for writing tar archive entries.

use std::io::{self, Read, Write};
use std::path::Path;

use crate::{ImageError, ImageResult, path_bytes::path_bytes};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const TAR_LINK_NAME_MAX_BYTES: usize = 100;
const GNU_LONG_LINK_PATH: &str = "././@LongLink";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Additional operations for writing tar archives.
pub(crate) trait TarBuilderExt {
    /// Append a link while preserving its target as literal bytes.
    fn append_link_literal(
        &mut self,
        header: &mut tar::Header,
        path: &Path,
        target: &[u8],
    ) -> ImageResult<()>;
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<W: Write> TarBuilderExt for tar::Builder<W> {
    fn append_link_literal(
        &mut self,
        header: &mut tar::Header,
        path: &Path,
        target: &[u8],
    ) -> ImageResult<()> {
        let path = normalized_link_path(path_bytes(path))?;
        validate_link_bytes(target, "link target")?;

        if path.len() > TAR_LINK_NAME_MAX_BYTES {
            append_gnu_long_value(self, &path, tar::EntryType::GNULongName)?;
        }
        set_gnu_header_field(
            &mut header
                .as_gnu_mut()
                .ok_or_else(|| invalid_link_data("link header is not GNU format"))?
                .name,
            &path[..path.len().min(TAR_LINK_NAME_MAX_BYTES)],
        )?;

        if target.len() > TAR_LINK_NAME_MAX_BYTES {
            append_gnu_long_value(self, target, tar::EntryType::GNULongLink)?;
        }
        set_gnu_header_field(
            &mut header
                .as_gnu_mut()
                .ok_or_else(|| invalid_link_data("link header is not GNU format"))?
                .linkname,
            &target[..target.len().min(TAR_LINK_NAME_MAX_BYTES)],
        )?;

        header.set_cksum();
        self.append(header, io::empty()).map_err(ImageError::Io)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn append_gnu_long_value<W: Write>(
    builder: &mut tar::Builder<W>,
    value: &[u8],
    entry_type: tar::EntryType,
) -> ImageResult<()> {
    let mut header = tar::Header::new_gnu();
    set_gnu_header_field(
        &mut header
            .as_gnu_mut()
            .ok_or_else(|| invalid_link_data("long-link header is not GNU format"))?
            .name,
        GNU_LONG_LINK_PATH.as_bytes(),
    )?;
    header.set_entry_type(entry_type);
    header.set_mode(0o644);
    header.set_uid(0);
    header.set_gid(0);
    header.set_mtime(0);
    header.set_size(value.len() as u64 + 1);
    header.set_cksum();

    let mut data = value.chain(io::repeat(0).take(1));
    builder.append(&header, &mut data).map_err(ImageError::Io)
}

fn set_gnu_header_field(field: &mut [u8], value: &[u8]) -> ImageResult<()> {
    if value.len() > field.len() {
        return Err(invalid_link_data("GNU header field is too short"));
    }
    field.fill(0);
    field[..value.len()].copy_from_slice(value);
    Ok(())
}

fn validate_link_bytes(value: &[u8], field: &str) -> ImageResult<()> {
    if value.is_empty() {
        return Err(invalid_link_data(&format!("{field} is empty")));
    }
    if value.contains(&0) {
        return Err(invalid_link_data(&format!("{field} contains a NUL byte")));
    }
    Ok(())
}

fn normalized_link_path(path: &[u8]) -> ImageResult<Vec<u8>> {
    validate_link_bytes(path, "link path")?;
    if path.starts_with(b"/") {
        return Err(invalid_link_data("link path must be relative without `..`"));
    }

    let mut normalized = Vec::with_capacity(path.len());
    for component in path.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            return Err(invalid_link_data("link path must be relative without `..`"));
        }
        if !normalized.is_empty() {
            normalized.push(b'/');
        }
        normalized.extend_from_slice(component);
    }

    validate_link_bytes(&normalized, "link path")?;
    Ok(normalized)
}

fn invalid_link_data(message: &str) -> ImageError {
    ImageError::Io(io::Error::new(io::ErrorKind::InvalidInput, message))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Cursor;

    use super::*;

    #[test]
    fn append_link_literal_preserves_non_utf8_target() {
        let target = vec![0xff; TAR_LINK_NAME_MAX_BYTES + 1];
        let mut archive_bytes = Vec::new();
        {
            let mut archive = tar::Builder::new(&mut archive_bytes);
            let mut header = tar::Header::new_gnu();
            header.set_entry_type(tar::EntryType::Symlink);
            header.set_size(0);
            archive
                .append_link_literal(&mut header, Path::new("link"), &target)
                .unwrap();
            archive.finish().unwrap();
        }

        let mut archive = tar::Archive::new(Cursor::new(archive_bytes));
        let entry = archive.entries().unwrap().next().unwrap().unwrap();
        assert_eq!(entry.link_name_bytes().unwrap().as_ref(), target);
    }

    #[test]
    fn append_link_literal_rejects_nul_before_writing() {
        let mut target = vec![b'a'; TAR_LINK_NAME_MAX_BYTES + 1];
        target[TAR_LINK_NAME_MAX_BYTES / 2] = 0;
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);

        let err = archive
            .append_link_literal(&mut header, Path::new("link"), &target)
            .unwrap_err();

        assert!(err.to_string().contains("NUL byte"));
        let archive_bytes = archive.into_inner().unwrap();
        let mut archive = tar::Archive::new(Cursor::new(archive_bytes));
        assert!(archive.entries().unwrap().next().is_none());
    }

    #[test]
    fn append_link_literal_rejects_invalid_entry_path_before_writing() {
        let target = vec![b'a'; TAR_LINK_NAME_MAX_BYTES + 1];
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_gnu();
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_size(0);

        let err = archive
            .append_link_literal(&mut header, Path::new("../link"), &target)
            .unwrap_err();

        assert!(err.to_string().contains("must be relative"));
        let archive_bytes = archive.into_inner().unwrap();
        let mut archive = tar::Archive::new(Cursor::new(archive_bytes));
        assert!(archive.entries().unwrap().next().is_none());
    }
}
