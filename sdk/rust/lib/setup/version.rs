//! Read the runtime's embedded Cargo version without executing the binary.

use std::{cell::Cell, fs::File, io, ops::Range, path::Path};

use object::{
    FileKind, LittleEndian as LE,
    read::{
        ReadCache, ReadRef,
        elf::{FileHeader, SectionHeader},
        macho::{FatArch, MachHeader, Section, Segment},
        pe::ImageNtHeaders,
    },
};

use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

// Bound allocations even when untrusted headers advertise enormous tables. The
// reader intentionally skips symbols, relocations, executable code and debug data.
const MAX_METADATA_BYTES: u64 = 4 * 1024 * 1024;
const MAX_VERSION_BYTES: u64 = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct MetadataReader<'a> {
    cache: &'a ReadCache<File>,
    budget: &'a Cell<u64>,
    base: u64,
    size: u64,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'a> ReadRef<'a> for MetadataReader<'a> {
    fn len(self) -> Result<u64, ()> {
        Ok(self.size)
    }

    fn read_bytes_at(self, offset: u64, size: u64) -> Result<&'a [u8], ()> {
        if offset.checked_add(size).ok_or(())? > self.size {
            return Err(());
        }
        let remaining = self.budget.get().checked_sub(size).ok_or(())?;
        self.budget.set(remaining);
        self.cache
            .read_bytes_at(self.base.checked_add(offset).ok_or(())?, size)
    }

    fn read_bytes_at_until(self, range: Range<u64>, delimiter: u8) -> Result<&'a [u8], ()> {
        if range.end > self.size {
            return Err(());
        }
        // Only section names use this operation; never read an entire symbol
        // string table just to locate a short, NUL-terminated name.
        let size = range.end.checked_sub(range.start).ok_or(())?.min(4096);
        let bytes = self.read_bytes_at(range.start, size)?;
        let end = bytes.iter().position(|&byte| byte == delimiter).ok_or(())?;
        Ok(&bytes[..end])
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read the Cargo package version embedded in an `msb` executable.
///
/// Supports ELF, PE and thin or universal Mach-O files on any host. Returns
/// `None` when the executable has no version section, as with older releases.
/// Invalid executable headers, malformed version sections and I/O failures are
/// errors. Universal Mach-O slices must agree, including section absence.
///
/// This function never executes the file, downloads a runtime, or requires
/// firmware. It reads bounded metadata only and does not fall back to `--version`.
/// The version identifies the build; it does not authenticate the executable or
/// establish its supported launch capabilities.
pub fn resolve_runtime_version(
    executable: impl AsRef<Path>,
) -> MicrosandboxResult<Option<Version>> {
    let path = executable.as_ref();
    let inspect = || -> io::Result<Option<Version>> {
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(invalid("expected a regular executable file"));
        }
        let cache = ReadCache::new(file);
        let budget = Cell::new(MAX_METADATA_BYTES);
        let reader = MetadataReader {
            cache: &cache,
            budget: &budget,
            base: 0,
            size: metadata.len(),
        };
        match FileKind::parse(reader).map_err(invalid)? {
            FileKind::MachOFat32 => {
                let fat = object::read::macho::MachOFatFile32::parse(reader).map_err(invalid)?;
                read_fat(reader, fat.arches())
            }
            FileKind::MachOFat64 => {
                let fat = object::read::macho::MachOFatFile64::parse(reader).map_err(invalid)?;
                read_fat(reader, fat.arches())
            }
            _ => read_thin(reader),
        }
    };
    inspect().map_err(|error| {
        io::Error::new(
            error.kind(),
            format!(
                "cannot read runtime version from {}: {error}",
                path.display()
            ),
        )
        .into()
    })
}

fn read_fat<A: FatArch>(reader: MetadataReader<'_>, arches: &[A]) -> io::Result<Option<Version>> {
    if arches.is_empty() || arches.len() > 16 {
        return Err(invalid("invalid number of universal executable slices"));
    }
    let mut result = None;
    for arch in arches {
        let (base, size) = arch.file_range();
        if base.checked_add(size).is_none_or(|end| end > reader.size) {
            return Err(invalid("universal executable slice is outside the file"));
        }
        let version = read_thin(MetadataReader {
            base,
            size,
            ..reader
        })?;
        if let Some(previous) = &result {
            if previous != &version {
                return Err(invalid(
                    "universal executable slices disagree on runtime version",
                ));
            }
        } else {
            result = Some(version);
        }
    }
    Ok(result.flatten())
}

fn read_thin(reader: MetadataReader<'_>) -> io::Result<Option<Version>> {
    match FileKind::parse(reader).map_err(invalid)? {
        FileKind::Elf32 => read_elf::<object::elf::FileHeader32<object::Endianness>>(reader),
        FileKind::Elf64 => read_elf::<object::elf::FileHeader64<object::Endianness>>(reader),
        FileKind::MachO32 => read_macho::<object::macho::MachHeader32<object::Endianness>>(reader),
        FileKind::MachO64 => read_macho::<object::macho::MachHeader64<object::Endianness>>(reader),
        FileKind::Pe32 => read_pe::<object::pe::ImageNtHeaders32>(reader),
        FileKind::Pe64 => read_pe::<object::pe::ImageNtHeaders64>(reader),
        _ => Err(invalid("expected an ELF, Mach-O or PE executable")),
    }
}

fn read_elf<E: FileHeader>(reader: MetadataReader<'_>) -> io::Result<Option<Version>> {
    let header = E::parse(reader).map_err(invalid)?;
    let endian = header.endian().map_err(invalid)?;
    if !matches!(
        header.e_type(endian),
        object::elf::ET_EXEC | object::elf::ET_DYN
    ) {
        return Err(invalid("ELF file is not an executable image"));
    }
    let sections = header.sections(endian, reader).map_err(invalid)?;
    let mut version = None;
    for section in sections.iter().skip(1) {
        if sections.section_name(endian, section).map_err(invalid)? == b".msbver" {
            let (offset, size) = section
                .file_range(endian)
                .ok_or_else(|| invalid("version section has no file data"))?;
            collect_version(reader, offset, size, &mut version)?;
        }
    }
    Ok(version)
}

fn read_macho<M: MachHeader>(reader: MetadataReader<'_>) -> io::Result<Option<Version>> {
    let header = M::parse(reader, 0).map_err(invalid)?;
    let endian = header.endian().map_err(invalid)?;
    if header.filetype(endian) != object::macho::MH_EXECUTE {
        return Err(invalid("Mach-O file is not an executable image"));
    }
    let mut commands = header.load_commands(endian, reader, 0).map_err(invalid)?;
    let mut version = None;
    while let Some(command) = commands.next().map_err(invalid)? {
        if let Some((segment, data)) = M::Segment::from_command(command).map_err(invalid)? {
            for section in segment.sections(endian, data).map_err(invalid)? {
                if section.name() == b"__msbver" && section.segment_name() == b"__TEXT" {
                    let (offset, size) = section
                        .file_range(endian, u64::from(section.offset(endian)))
                        .ok_or_else(|| invalid("version section has no file data"))?;
                    collect_version(reader, offset, size, &mut version)?;
                }
            }
        }
    }
    Ok(version)
}

fn read_pe<P: ImageNtHeaders>(reader: MetadataReader<'_>) -> io::Result<Option<Version>> {
    let dos = object::pe::ImageDosHeader::parse(reader).map_err(invalid)?;
    let mut offset = u64::from(dos.nt_headers_offset());
    let (header, _) = P::parse(reader, &mut offset).map_err(invalid)?;
    if !header
        .file_header()
        .characteristics
        .get(LE)
        .contains(object::pe::IMAGE_FILE_EXECUTABLE_IMAGE)
    {
        return Err(invalid("PE file is not an executable image"));
    }
    let sections = header.sections(reader, offset).map_err(invalid)?;
    let mut version = None;
    for section in sections.iter() {
        if &section.name == b".msbver\0" {
            let (offset, size) = section.pe_file_range();
            if size != section.virtual_size.get(LE) {
                return Err(invalid("truncated PE version section"));
            }
            collect_version(reader, u64::from(offset), u64::from(size), &mut version)?;
        }
    }
    Ok(version)
}

fn collect_version(
    reader: MetadataReader<'_>,
    offset: u64,
    size: u64,
    version: &mut Option<Version>,
) -> io::Result<()> {
    if version.is_some() {
        return Err(invalid("duplicate runtime version sections"));
    }
    if size == 0 || size > MAX_VERSION_BYTES {
        return Err(invalid(
            "runtime version section must contain 1..=256 bytes",
        ));
    }
    let bytes = reader
        .read_bytes_at(offset, size)
        .map_err(|()| invalid("version section is unreadable or outside the file"))?;
    let text = std::str::from_utf8(bytes).map_err(invalid)?;
    *version = Some(Version::parse(text).map_err(invalid)?);
    Ok(())
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
#[path = "version_tests.rs"]
mod tests;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use semver::Version;
