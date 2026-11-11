//! Logical OCI tar records over a Tokio reader. The header codec handles tar
//! fields; this reader owns the extension ordering and physical body boundaries.

use std::borrow::Cow;
use std::io::{self, ErrorKind};
use std::str;

use tar::{GnuExtSparseHeader, GnuSparseHeader, Header};
use tokio::io::{AsyncRead, AsyncReadExt, Take, copy, sink};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const BLOCK_SIZE: u64 = 512;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct Records<R> {
    body: Take<R>,
    padding: usize,
    next_offset: u64,
}

pub(super) struct Member {
    pub(super) header: Header,
    pub(super) size: u64,
    pub(super) uid: Option<u64>,
    pub(super) gid: Option<u64>,
    path: Option<Vec<u8>>,
    link: Option<Vec<u8>>,
}

#[derive(Default)]
struct LocalExtensions {
    gnu_path: Option<Vec<u8>>,
    gnu_link: Option<Vec<u8>>,
    pax: Option<Pax>,
}

struct Pax {
    path: Option<Vec<u8>>,
    link: Option<Vec<u8>>,
    numbers: io::Result<PaxNumbers>,
}

#[derive(Default)]
struct PaxNumbers {
    size: Option<u64>,
    uid: Option<u64>,
    gid: Option<u64>,
    sparse: bool,
    recognized_sparse: bool,
    sparse_major_1: bool,
    sparse_minor_0: bool,
}

struct SparseLayout {
    end: u64,
    stored: u64,
    remaining: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<R: AsyncRead + Unpin> Records<R> {
    pub(super) fn new(reader: R) -> Self {
        Self {
            body: reader.take(0),
            padding: 0,
            next_offset: 0,
        }
    }

    pub(super) fn body(&mut self) -> &mut Take<R> {
        &mut self.body
    }

    pub(super) async fn next(&mut self) -> io::Result<Option<Member>> {
        let mut extensions = LocalExtensions::default();

        loop {
            self.finish_body().await?;
            let Some(header) = self.read_header().await? else {
                if extensions.gnu_path.is_some()
                    || extensions.gnu_link.is_some()
                    || extensions.pax.is_some()
                {
                    return Err(invalid("extension entry was not followed by a member"));
                }
                return Ok(None);
            };
            let size = header.entry_size()?;
            let kind = header.entry_type().as_byte();
            let ustar = header.as_ustar().is_some();
            // Solaris uses uppercase X for local PAX only on a USTAR carrier.
            match kind {
                b'x' | b'X' if ustar => {
                    self.begin_body(size)?;
                    if extensions.pax.is_some() {
                        return Err(invalid("two pax extensions describe the same member"));
                    }
                    let pax = Pax::parse(&self.read_extension().await?)?;
                    if extensions.gnu_path.is_some() && pax.path.is_some() {
                        return Err(invalid("ambiguous path: pax path and GNU longname"));
                    }
                    if extensions.gnu_link.is_some() && pax.link.is_some() {
                        return Err(invalid(
                            "ambiguous link target: pax linkpath and GNU longlink",
                        ));
                    }
                    extensions.pax = Some(pax);
                }
                b'L' | b'K' if ustar || header.as_gnu().is_some() => {
                    self.begin_body(size)?;
                    let (gnu, pax, field) = if kind == b'L' {
                        (
                            &mut extensions.gnu_path,
                            extensions.pax.as_ref().and_then(|pax| pax.path.as_ref()),
                            "path",
                        )
                    } else {
                        (
                            &mut extensions.gnu_link,
                            extensions.pax.as_ref().and_then(|pax| pax.link.as_ref()),
                            "link target",
                        )
                    };
                    if pax.is_some() {
                        return Err(invalid(format!(
                            "ambiguous {field}: PAX and GNU extensions"
                        )));
                    }
                    if gnu.is_some() {
                        return Err(invalid(format!("duplicate GNU {field} extension")));
                    }
                    let mut name = self.read_extension().await?;
                    if let Some(nul) = name.iter().position(|&byte| byte == 0) {
                        name.truncate(nul);
                    }
                    *gnu = Some(name);
                }
                b'x' | b'L' | b'K' => {
                    return Err(invalid(
                        "extension typeflag is not permitted on an unrecognized header",
                    ));
                }
                _ => {
                    let (path, link, numbers) = if let Some(pax) = extensions.pax {
                        // Global headers are ignored by OCI ingestion. As before,
                        // they consume pending names but retain their physical size.
                        let numbers = if kind == b'g' {
                            PaxNumbers::default()
                        } else {
                            pax.numbers?
                        };
                        (pax.path, pax.link, numbers)
                    } else {
                        (None, None, PaxNumbers::default())
                    };
                    let size = numbers.size.unwrap_or(size);
                    self.begin_body(size)?;
                    if kind == b'S' {
                        self.read_sparse_layout(&header, size).await?;
                    }
                    return Ok(Some(Member {
                        header,
                        size,
                        uid: numbers.uid,
                        gid: numbers.gid,
                        path: extensions.gnu_path.or(path),
                        link: extensions.gnu_link.or(link),
                    }));
                }
            }
        }
    }

    async fn read_header(&mut self) -> io::Result<Option<Header>> {
        let mut header = Header::new_old();
        let reader = self.body.get_mut();
        let bytes = header.as_mut_bytes();
        let n = reader.read(bytes).await?;
        if n == 0 {
            return Ok(None);
        }
        reader.read_exact(&mut bytes[n..]).await?;
        if bytes.iter().all(|&byte| byte == 0) {
            return Ok(None);
        }

        self.advance(BLOCK_SIZE)?;
        let bytes = header.as_bytes();
        let checksum = bytes[..148]
            .iter()
            .chain(&bytes[156..])
            .map(|&byte| u32::from(byte))
            .sum::<u32>()
            + 8 * u32::from(b' ');
        if header.cksum()? != checksum {
            return Err(invalid("archive header checksum mismatch"));
        }
        if &bytes[257..265] == b"ustar\0\0\0" {
            return Err(invalid(
                "NUL-version USTAR header is ambiguous and not supported",
            ));
        }
        Ok(Some(header))
    }

    fn begin_body(&mut self, size: u64) -> io::Result<()> {
        let padded = size
            .checked_next_multiple_of(BLOCK_SIZE)
            .ok_or_else(|| invalid("tar size overflow"))?;
        self.advance(padded)?;
        self.padding = (padded - size) as usize;
        self.body.set_limit(size);
        Ok(())
    }

    fn advance(&mut self, amount: u64) -> io::Result<()> {
        self.next_offset = self
            .next_offset
            .checked_add(amount)
            .ok_or_else(|| invalid("tar position overflow"))?;
        Ok(())
    }

    async fn finish_body(&mut self) -> io::Result<()> {
        if self.body.limit() != 0 {
            copy(&mut self.body, &mut sink()).await?;
            if self.body.limit() != 0 {
                return Err(io::Error::new(
                    ErrorKind::UnexpectedEof,
                    "truncated tar body",
                ));
            }
        }
        if self.padding != 0 {
            let mut padding = [0; BLOCK_SIZE as usize];
            self.body
                .get_mut()
                .read_exact(&mut padding[..self.padding])
                .await?;
            self.padding = 0;
        }
        Ok(())
    }

    async fn read_extension(&mut self) -> io::Result<Vec<u8>> {
        // Reserve only a small prefix from the header size. Grow with actual
        // input, as OCI has no separate local extension size limit.
        let mut body = Vec::with_capacity(self.body.limit().min(128 * 1024) as usize);
        self.body.read_to_end(&mut body).await?;
        if self.body.limit() != 0 {
            return Err(io::Error::new(
                ErrorKind::UnexpectedEof,
                "truncated tar extension",
            ));
        }
        Ok(body)
    }

    async fn read_sparse_layout(&mut self, header: &Header, stored: u64) -> io::Result<()> {
        // OCI does not materialize GNU S entries. Check the descriptors
        // without expanding holes; the body is still the stored bytes only.
        let gnu = header
            .as_gnu()
            .ok_or_else(|| invalid("sparse entry type listed but not GNU header"))?;
        let real_size = gnu.real_size()?;
        let mut layout = SparseLayout {
            end: 0,
            stored,
            remaining: stored,
        };
        layout.add(&gnu.sparse)?;
        let mut more = gnu.is_extended();
        while more {
            let mut ext = GnuExtSparseHeader::new();
            self.body.get_mut().read_exact(ext.as_mut_bytes()).await?;
            self.advance(BLOCK_SIZE)?;
            layout.add(ext.sparse())?;
            more = ext.is_extended();
        }
        if layout.end != real_size || layout.remaining != 0 {
            return Err(invalid(
                "GNU sparse layout does not match the declared size",
            ));
        }
        Ok(())
    }
}

impl Member {
    pub(super) fn path_bytes(&self) -> Cow<'_, [u8]> {
        match &self.path {
            Some(path) => Cow::Borrowed(path),
            None => self.header.path_bytes(),
        }
    }

    pub(super) fn link_name_bytes(&self) -> Option<Cow<'_, [u8]>> {
        match &self.link {
            Some(link) => Some(Cow::Borrowed(link)),
            None => self.header.link_name_bytes(),
        }
    }
}

impl Pax {
    fn parse(mut bytes: &[u8]) -> io::Result<Self> {
        let mut pax = Self {
            path: None,
            link: None,
            numbers: Ok(PaxNumbers::default()),
        };
        while !bytes.is_empty() {
            let (rest, key, value) =
                pax_record(bytes).ok_or_else(|| invalid("malformed pax extension"))?;
            bytes = rest;
            if value.is_empty() {
                return Err(invalid(
                    "empty values are not supported in local pax extensions",
                ));
            }
            match key {
                b"path" => pax.path = Some(value.to_vec()),
                b"linkpath" => pax.link = Some(value.to_vec()),
                _ => {
                    if let Ok(numbers) = &mut pax.numbers
                        && let Ok(key) = str::from_utf8(key)
                        && let Err(err) = numbers.apply(key, value)
                    {
                        // Only a subsequent non-extension member uses these
                        // values. A global header does not apply them.
                        pax.numbers = Err(err);
                    }
                }
            }
        }
        if let Ok(numbers) = &pax.numbers
            && numbers.sparse
            && !(numbers.recognized_sparse || numbers.sparse_major_1 && numbers.sparse_minor_0)
        {
            pax.numbers = Err(invalid("orphaned GNU sparse pax metadata is not supported"));
        }
        Ok(pax)
    }
}

impl PaxNumbers {
    fn apply(&mut self, key: &str, value: &[u8]) -> io::Result<()> {
        self.sparse |= key.starts_with("GNU.sparse.");
        match key {
            "size" => self.size = Some(pax_decimal(value, "failed to parse pax size")?),
            "uid" => self.uid = Some(pax_decimal(value, "failed to parse pax uid")?),
            "gid" => self.gid = Some(pax_decimal(value, "failed to parse pax gid")?),
            "GNU.sparse.map" | "GNU.sparse.size" => self.recognized_sparse = true,
            "GNU.sparse.major" => self.sparse_major_1 = value == b"1",
            "GNU.sparse.minor" => self.sparse_minor_0 = value == b"0",
            _ => {}
        }
        Ok(())
    }
}

impl SparseLayout {
    fn add(&mut self, blocks: &[GnuSparseHeader]) -> io::Result<()> {
        for block in blocks {
            if block.offset[0] == 0 && block.numbytes[0] == 0 {
                continue;
            }
            let offset = block.offset()?;
            let len = block.length()?;
            if len != 0 && !(self.stored - self.remaining).is_multiple_of(BLOCK_SIZE) {
                return Err(invalid(
                    "previous GNU sparse block was not aligned to 512 bytes",
                ));
            }
            if offset < self.end {
                return Err(invalid("out of order or overlapping GNU sparse blocks"));
            }
            self.end = offset
                .checked_add(len)
                .ok_or_else(|| invalid("GNU sparse layout overflow"))?;
            self.remaining = self
                .remaining
                .checked_sub(len)
                .ok_or_else(|| invalid("GNU sparse layout exceeds the stored body size"))?;
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn pax_record(bytes: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    // The length counts bytes, including the prefix and trailing newline.
    // Searching for the next newline would misframe values containing one.
    let space = bytes.iter().position(|&byte| byte == b' ')?;
    let size = str::from_utf8(&bytes[..space])
        .ok()?
        .parse::<usize>()
        .ok()?;
    let (record, rest) = bytes.split_at_checked(size)?;
    let fields = record.get(space + 1..)?.strip_suffix(b"\n")?;
    let equals = fields.iter().position(|&byte| byte == b'=')?;
    Some((rest, &fields[..equals], &fields[equals + 1..]))
}

fn pax_decimal(value: &[u8], message: &'static str) -> io::Result<u64> {
    str::from_utf8(value)
        .ok()
        .filter(|text| text.bytes().all(|byte| byte.is_ascii_digit()))
        .and_then(|text| text.parse().ok())
        .ok_or_else(|| invalid(message))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::other(message.into())
}
