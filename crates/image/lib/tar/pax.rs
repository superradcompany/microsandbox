//! Removal of empty xattr records from local PAX headers.
//!
//! Rootless image builders can leave records such as `SCHILY.xattr.user.overlay.origin=` in
//! layer tarballs. The tar parser rejects every empty local PAX value because an empty `path`
//! or `size` can make parsers disagree about an archive. Xattr records cannot change where an
//! entry lands or how long it is, and layer ingestion does not read them, so dropping the
//! empty ones lets those images load without relaxing the check for any other key.
//!
//! This filter sits in front of the parser and must never disagree with it about entry
//! boundaries, so it only follows framing it fully understands. Anything else switches it to
//! passthrough for the rest of the stream, which leaves the parser's own checks in charge.

use std::io;
use std::ops::Range;
use std::pin::Pin;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, ReadBuf};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Tar block size.
const BLOCK_SIZE: usize = 512;

/// Octal entry size in a tar header.
const SIZE_FIELD: Range<usize> = 124..136;

/// Octal checksum in a tar header.
const CHECKSUM_FIELD: Range<usize> = 148..156;

/// Entry type in a tar header.
const TYPEFLAG_OFFSET: usize = 156;

/// Magic and version in a tar header.
const MAGIC_FIELD: Range<usize> = 257..265;

/// The only magic and version the parser accepts for PAX extension headers.
const USTAR_MAGIC: &[u8] = b"ustar\x0000";

/// Largest local PAX header held in memory. Larger ones pass through to the parser.
const MAX_PAX_HEADER_SIZE: u64 = 1 << 20;

/// Key prefix of the records this filter may remove.
const XATTR_KEY_PREFIX: &[u8] = b"SCHILY.xattr.";

/// PAX key that overrides the next entry's size.
const SIZE_KEY: &[u8] = b"size";

/// Key prefix of PAX records that describe sparse data.
const SPARSE_KEY_PREFIX: &[u8] = b"GNU.sparse.";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Reader that removes empty xattr records from local PAX headers.
pub(super) struct EmptyXattrFilter<R> {
    /// Decompressed tar stream.
    inner: R,

    /// Position in the tar framing.
    state: State,

    /// Header block being assembled, followed by the body of a local PAX header.
    pending: Vec<u8>,

    /// Bytes ready to hand to the parser.
    ready: Vec<u8>,

    /// Offset of the next unread byte in `ready`.
    ready_offset: usize,
}

/// Position in the tar framing.
#[derive(Clone, Copy)]
enum State {
    /// At the start of a header block.
    Header,

    /// Forwarding entry data and its padding.
    Data { remaining: u64 },

    /// Assembling a local PAX header of `size` bytes.
    LocalPax { size: usize },

    /// Forwarding everything unchanged.
    Passthrough,
}

/// What a header block means for the framing that follows it.
enum HeaderKind {
    /// An entry followed by `padded_size` bytes of data and padding.
    Entry { padded_size: u64 },

    /// A local PAX header with a body of `size` bytes.
    LocalPax { size: usize },

    /// Anything this filter does not follow.
    Unsupported,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<R> EmptyXattrFilter<R> {
    /// Wrap a decompressed tar stream.
    pub(super) fn new(inner: R) -> Self {
        Self {
            inner,
            state: State::Header,
            pending: Vec::with_capacity(BLOCK_SIZE),
            ready: Vec::with_capacity(BLOCK_SIZE),
            ready_offset: 0,
        }
    }

    /// Queue the assembled bytes for the parser.
    fn release_pending(&mut self) {
        std::mem::swap(&mut self.pending, &mut self.ready);
        self.pending.clear();
        self.ready_offset = 0;
    }

    /// Hand the assembled bytes to the parser and stop following the framing.
    fn fall_back_to_passthrough(&mut self) {
        self.release_pending();
        self.state = State::Passthrough;
    }
}

impl<R: AsyncRead + Unpin> EmptyXattrFilter<R> {
    /// Read until `pending` holds `target` bytes. Resolves to `false` if the stream ends first.
    fn poll_fill_pending(&mut self, cx: &mut Context<'_>, target: usize) -> Poll<io::Result<bool>> {
        while self.pending.len() < target {
            let filled = self.pending.len();
            self.pending.resize(target, 0);

            let mut unread = ReadBuf::new(&mut self.pending[filled..]);
            let result = Pin::new(&mut self.inner).poll_read(cx, &mut unread);
            let read = unread.filled().len();
            self.pending.truncate(filled + read);

            ready!(result)?;
            if read == 0 {
                return Poll::Ready(Ok(false));
            }
        }

        Poll::Ready(Ok(true))
    }

    /// Forward up to `remaining` bytes of entry data.
    fn poll_read_data(
        &mut self,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
        remaining: u64,
    ) -> Poll<io::Result<()>> {
        let limit = remaining.min(buf.remaining() as u64) as usize;
        let mut limited = ReadBuf::new(buf.initialize_unfilled_to(limit));
        ready!(Pin::new(&mut self.inner).poll_read(cx, &mut limited))?;
        let read = limited.filled().len();
        buf.advance(read);

        self.state = if read == 0 {
            State::Passthrough
        } else {
            State::Data {
                remaining: remaining - read as u64,
            }
        };
        Poll::Ready(Ok(()))
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<R: AsyncRead + Unpin> AsyncRead for EmptyXattrFilter<R> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }

        loop {
            if this.ready_offset < this.ready.len() {
                let count = buf.remaining().min(this.ready.len() - this.ready_offset);
                buf.put_slice(&this.ready[this.ready_offset..this.ready_offset + count]);
                this.ready_offset += count;
                return Poll::Ready(Ok(()));
            }

            match this.state {
                State::Passthrough => return Pin::new(&mut this.inner).poll_read(cx, buf),
                State::Data { remaining: 0 } => this.state = State::Header,
                State::Data { remaining } => return this.poll_read_data(cx, buf, remaining),
                State::Header => {
                    if !ready!(this.poll_fill_pending(cx, BLOCK_SIZE))? {
                        this.fall_back_to_passthrough();
                        continue;
                    }

                    match classify_header(&this.pending) {
                        HeaderKind::Entry { padded_size } => {
                            this.release_pending();
                            this.state = State::Data {
                                remaining: padded_size,
                            };
                        }
                        HeaderKind::LocalPax { size } => this.state = State::LocalPax { size },
                        HeaderKind::Unsupported => this.fall_back_to_passthrough(),
                    }
                }
                State::LocalPax { size } => {
                    let entry_size = BLOCK_SIZE + padded_size(size as u64) as usize;
                    if !ready!(this.poll_fill_pending(cx, entry_size))? {
                        this.fall_back_to_passthrough();
                        continue;
                    }

                    if rewrite_local_pax_entry(&mut this.pending, size) {
                        this.release_pending();
                        this.state = State::Header;
                    } else {
                        this.fall_back_to_passthrough();
                    }
                }
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Decide how to follow a header block.
fn classify_header(block: &[u8]) -> HeaderKind {
    if block.iter().all(|byte| *byte == 0) || !has_valid_checksum(block) {
        return HeaderKind::Unsupported;
    }

    let Some(size) = parse_octal(&block[SIZE_FIELD]) else {
        return HeaderKind::Unsupported;
    };

    match block[TYPEFLAG_OFFSET] {
        b'x' | b'X' if &block[MAGIC_FIELD] == USTAR_MAGIC && size <= MAX_PAX_HEADER_SIZE => {
            HeaderKind::LocalPax {
                size: size as usize,
            }
        }
        0 | b'0' | b'7' | b'L' | b'K' => HeaderKind::Entry {
            padded_size: padded_size(size),
        },
        b'1'..=b'6' if size == 0 => HeaderKind::Entry { padded_size: 0 },
        _ => HeaderKind::Unsupported,
    }
}

/// Remove empty xattr records from a local PAX entry held in `entry`.
///
/// Returns whether the framing after this entry can still be followed.
fn rewrite_local_pax_entry(entry: &mut Vec<u8>, size: usize) -> bool {
    let body = &entry[BLOCK_SIZE..BLOCK_SIZE + size];
    let mut retained = Vec::with_capacity(size);
    let mut framing_known = true;
    let mut offset = 0;

    while offset < body.len() {
        let Some((record, key, value)) = parse_record(&body[offset..]) else {
            return false;
        };

        offset += record.len();
        framing_known &= key != SIZE_KEY && !key.starts_with(SPARSE_KEY_PREFIX);
        if !(key.starts_with(XATTR_KEY_PREFIX) && value.is_empty()) {
            retained.extend_from_slice(record);
        }
    }

    if retained.len() != size {
        entry.truncate(BLOCK_SIZE);
        write_octal(&mut entry[SIZE_FIELD], retained.len() as u64);
        write_checksum(entry);
        entry.extend_from_slice(&retained);
        entry.resize(BLOCK_SIZE + padded_size(retained.len() as u64) as usize, 0);
    }

    framing_known
}

/// Parse the first `<length> <key>=<value>\n` record, returning the record, key and value.
fn parse_record(body: &[u8]) -> Option<(&[u8], &[u8], &[u8])> {
    let digits = body.iter().position(|byte| *byte == b' ')?;
    if digits == 0 || !body[..digits].iter().all(u8::is_ascii_digit) {
        return None;
    }

    let length: usize = std::str::from_utf8(&body[..digits]).ok()?.parse().ok()?;
    if length <= digits + 1 || length > body.len() || body[length - 1] != b'\n' {
        return None;
    }

    let fields = &body[digits + 1..length - 1];
    let separator = fields.iter().position(|byte| *byte == b'=')?;
    Some((
        &body[..length],
        &fields[..separator],
        &fields[separator + 1..],
    ))
}

/// Compare a header's stored checksum with its contents.
fn has_valid_checksum(block: &[u8]) -> bool {
    parse_octal(&block[CHECKSUM_FIELD]).is_some_and(|stored| stored == header_sum(block))
}

/// Sum a header block with its checksum field read as spaces.
fn header_sum(block: &[u8]) -> u64 {
    let spaces = (CHECKSUM_FIELD.len() as u64) * u64::from(b' ');
    let bytes = block[..CHECKSUM_FIELD.start]
        .iter()
        .chain(&block[CHECKSUM_FIELD.end..]);

    bytes.fold(spaces, |sum, byte| sum + u64::from(*byte))
}

/// Parse a NUL or space terminated octal field. Base-256 values are not supported.
fn parse_octal(field: &[u8]) -> Option<u64> {
    let digits = field.iter().skip_while(|byte| **byte == b' ');
    let mut value = 0u64;
    let mut seen = 0;

    for byte in digits {
        match byte {
            b'0'..=b'7' => {
                value = value.checked_mul(8)?.checked_add(u64::from(byte - b'0'))?;
                seen += 1;
            }
            0 | b' ' => break,
            _ => return None,
        }
    }

    (seen > 0).then_some(value)
}

/// Write `value` as a NUL-terminated octal field.
fn write_octal(field: &mut [u8], value: u64) {
    let digits = field.len() - 1;
    let text = format!("{value:0digits$o}\0");
    field.copy_from_slice(text.as_bytes());
}

/// Recompute the checksum of the header at the start of `entry`.
fn write_checksum(entry: &mut [u8]) {
    let sum = header_sum(&entry[..BLOCK_SIZE]);
    let text = format!("{sum:06o}\0 ");
    entry[CHECKSUM_FIELD].copy_from_slice(text.as_bytes());
}

/// Round a body size up to whole tar blocks.
fn padded_size(size: u64) -> u64 {
    size.div_ceil(BLOCK_SIZE as u64) * BLOCK_SIZE as u64
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::io::Cursor;
    use std::pin::Pin;
    use std::task::{Context, Poll};

    use sha2::{Digest, Sha256};
    use tokio::io::{AsyncRead, AsyncReadExt, ReadBuf};

    use super::*;
    use crate::tar::{Compression, ingest_compressed_tar, ingest_tar};
    use crate::tree::{FileData, ResourceLimits, TreeNode};

    /// Build a ustar header block.
    fn header(path: &str, entry_type: u8, size: u64) -> Vec<u8> {
        let mut header = tokio_tar::Header::new_ustar();
        header.set_path(path).unwrap();
        header.set_entry_type(tokio_tar::EntryType::new(entry_type));
        header.set_size(size);
        header.set_mode(0o644);
        header.set_cksum();
        header.as_bytes().to_vec()
    }

    /// Append a body with its padding.
    fn append_body(archive: &mut Vec<u8>, body: &[u8]) {
        archive.extend_from_slice(body);
        archive.resize(
            archive.len() + (padded_size(body.len() as u64) as usize - body.len()),
            0,
        );
    }

    /// Encode one PAX record.
    fn record(key: &str, value: &str) -> Vec<u8> {
        let payload = format!("{key}={value}\n");
        let mut length = payload.len() + 2;
        while format!("{length} {payload}").len() != length {
            length = format!("{length} {payload}").len();
        }
        format!("{length} {payload}").into_bytes()
    }

    /// Append a local PAX header.
    fn append_pax(archive: &mut Vec<u8>, records: &[Vec<u8>]) {
        let body = records.concat();
        archive.extend(header("PaxHeaders/etc", b'x', body.len() as u64));
        append_body(archive, &body);
    }

    /// Append a regular file.
    fn append_file(archive: &mut Vec<u8>, path: &str, contents: &[u8]) {
        archive.extend(header(path, b'0', contents.len() as u64));
        append_body(archive, contents);
    }

    /// End an archive with its two zero blocks.
    fn finish(archive: &mut Vec<u8>) {
        archive.resize(archive.len() + 2 * BLOCK_SIZE, 0);
    }

    /// Run bytes through the filter.
    async fn filter(archive: &[u8]) -> Vec<u8> {
        let mut filtered = Vec::new();
        EmptyXattrFilter::new(Cursor::new(archive))
            .read_to_end(&mut filtered)
            .await
            .unwrap();
        filtered
    }

    /// Read a regular file's contents from a tree.
    fn file_contents(tree: &crate::tree::FileTree, path: &[u8]) -> Vec<u8> {
        let Some(TreeNode::RegularFile(file)) = tree.get(path) else {
            panic!("{} is not a regular file", String::from_utf8_lossy(path));
        };
        let FileData::Memory(data) = &file.data else {
            panic!("expected in-memory data");
        };
        data.clone()
    }

    /// Reader that returns one byte per poll.
    struct OneByteReader(Cursor<Vec<u8>>);

    impl AsyncRead for OneByteReader {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let mut one = [0u8; 1];
            let mut limited = ReadBuf::new(&mut one);
            std::task::ready!(Pin::new(&mut self.0).poll_read(cx, &mut limited))?;
            buf.put_slice(limited.filled());
            Poll::Ready(Ok(()))
        }
    }

    #[tokio::test]
    async fn accepts_layers_with_empty_xattr_records() {
        let mut archive = Vec::new();
        append_pax(
            &mut archive,
            &[
                record("SCHILY.xattr.user.overlay.origin", ""),
                record("mtime", "1733000000.5"),
            ],
        );
        append_file(&mut archive, "etc/hosts", b"127.0.0.1 localhost\n");
        finish(&mut archive);

        let tree = ingest_tar(Cursor::new(&archive), &ResourceLimits::default(), None)
            .await
            .unwrap();

        assert_eq!(
            file_contents(&tree, b"etc/hosts"),
            b"127.0.0.1 localhost\n".to_vec()
        );
    }

    #[tokio::test]
    async fn accepts_pax_headers_that_only_held_empty_xattrs() {
        let mut archive = Vec::new();
        append_pax(
            &mut archive,
            &[record("SCHILY.xattr.user.overlay.origin", "")],
        );
        append_file(&mut archive, "etc/passwd", b"root:x:0:0\n");
        finish(&mut archive);

        let tree = ingest_tar(Cursor::new(&archive), &ResourceLimits::default(), None)
            .await
            .unwrap();

        assert_eq!(
            file_contents(&tree, b"etc/passwd"),
            b"root:x:0:0\n".to_vec()
        );
    }

    #[tokio::test]
    async fn keeps_path_records_next_to_removed_xattrs() {
        let long_path = format!("usr/{}/bin", "a".repeat(150));
        let mut archive = Vec::new();
        append_pax(
            &mut archive,
            &[
                record("SCHILY.xattr.user.overlay.origin", ""),
                record("path", &long_path),
            ],
        );
        append_file(&mut archive, "short", b"data");
        finish(&mut archive);

        let tree = ingest_tar(Cursor::new(&archive), &ResourceLimits::default(), None)
            .await
            .unwrap();

        assert_eq!(file_contents(&tree, long_path.as_bytes()), b"data".to_vec());
    }

    #[tokio::test]
    async fn still_rejects_other_empty_pax_values() {
        for key in [
            "path",
            "linkpath",
            "size",
            "VENDOR.unknown",
            "LIBARCHIVE.xattr.user.a",
        ] {
            let mut archive = Vec::new();
            append_pax(&mut archive, &[record(key, "")]);
            append_file(&mut archive, "file", b"data");
            finish(&mut archive);

            let result = ingest_tar(Cursor::new(&archive), &ResourceLimits::default(), None).await;

            assert!(result.is_err(), "empty {key} was accepted");
        }
    }

    #[tokio::test]
    async fn digest_covers_the_original_layer_bytes() {
        let mut archive = Vec::new();
        append_pax(
            &mut archive,
            &[record("SCHILY.xattr.user.overlay.origin", "")],
        );
        append_file(&mut archive, "file", b"data");
        finish(&mut archive);
        archive.resize(archive.len() + 4 * BLOCK_SIZE, 0);

        let result = ingest_compressed_tar(
            Cursor::new(&archive),
            Compression::None,
            &ResourceLimits::default(),
            None,
        )
        .await
        .unwrap();

        assert_eq!(
            result.uncompressed_digest,
            hex::encode(Sha256::digest(&archive))
        );
    }

    #[tokio::test]
    async fn leaves_layers_without_empty_xattrs_unchanged() {
        let mut archive = Vec::new();
        append_pax(
            &mut archive,
            &[
                record("SCHILY.xattr.user.kept", "value"),
                record("mtime", "1733000000.5"),
            ],
        );
        append_file(&mut archive, "file", b"data");
        archive.extend(header("dir/", b'5', 0));
        archive.extend(header("link", b'2', 0));
        finish(&mut archive);

        assert_eq!(filter(&archive).await, archive);
    }

    #[tokio::test]
    async fn handles_reads_split_across_block_boundaries() {
        let mut archive = Vec::new();
        append_pax(
            &mut archive,
            &[record("SCHILY.xattr.user.overlay.origin", "")],
        );
        append_file(&mut archive, "file", b"data");
        finish(&mut archive);

        let mut split = Vec::new();
        EmptyXattrFilter::new(OneByteReader(Cursor::new(archive.clone())))
            .read_to_end(&mut split)
            .await
            .unwrap();

        assert_eq!(split, filter(&archive).await);
    }

    #[tokio::test]
    async fn ignores_pax_lookalikes_inside_file_data() {
        let mut inner = Vec::new();
        append_pax(
            &mut inner,
            &[record("SCHILY.xattr.user.overlay.origin", "")],
        );

        let mut archive = Vec::new();
        append_file(&mut archive, "payload", &inner);
        finish(&mut archive);

        assert_eq!(filter(&archive).await, archive);
    }

    #[tokio::test]
    async fn stops_following_after_a_pax_size_override() {
        let mut trailing = Vec::new();
        append_pax(
            &mut trailing,
            &[record("SCHILY.xattr.user.overlay.origin", "")],
        );

        let mut archive = Vec::new();
        append_pax(&mut archive, &[record("size", "1024")]);
        archive.extend(header("file", b'0', 0));
        let prefix = archive.len();
        archive.extend_from_slice(&trailing);
        finish(&mut archive);

        let filtered = filter(&archive).await;

        assert_eq!(filtered[prefix..], archive[prefix..]);
    }

    #[tokio::test]
    async fn stops_following_after_entries_it_does_not_understand() {
        for entry_type in *b"SgD" {
            let mut archive = Vec::new();
            archive.extend(header("other", entry_type, 0));
            append_pax(
                &mut archive,
                &[record("SCHILY.xattr.user.overlay.origin", "")],
            );
            finish(&mut archive);

            assert_eq!(filter(&archive).await, archive);
        }
    }

    #[tokio::test]
    async fn passes_corrupt_and_truncated_input_to_the_parser() {
        let mut corrupt = header("file", b'x', 12);
        corrupt[0] ^= 0xff;
        corrupt.extend_from_slice(b"12 a=b\n");
        assert_eq!(filter(&corrupt).await, corrupt);

        let mut truncated = header("PaxHeaders/etc", b'x', 512);
        truncated.extend_from_slice(b"partial");
        assert_eq!(filter(&truncated).await, truncated);

        let short = vec![1u8; 100];
        assert_eq!(filter(&short).await, short);
    }

    #[tokio::test]
    async fn passes_malformed_pax_bodies_to_the_parser() {
        for body in [&b"x"[..], b"99 a=b\n", b"+6 a=b\n", b"6 ab c\n", b"3  \n"] {
            let mut archive = header("PaxHeaders/etc", b'x', body.len() as u64);
            append_body(&mut archive, body);
            append_file(&mut archive, "file", b"data");

            assert_eq!(filter(&archive).await, archive);
        }
    }

    #[test]
    fn rewritten_headers_have_valid_checksums() {
        let body = record("SCHILY.xattr.user.overlay.origin", "");
        let mut entry = header("PaxHeaders/etc", b'x', body.len() as u64);
        append_body(&mut entry, &body);

        assert!(rewrite_local_pax_entry(&mut entry, body.len()));

        assert_eq!(entry.len(), BLOCK_SIZE);
        assert!(has_valid_checksum(&entry));
        assert_eq!(parse_octal(&entry[SIZE_FIELD]), Some(0));
    }
}
