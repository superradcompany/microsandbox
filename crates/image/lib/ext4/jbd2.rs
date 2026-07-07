//! Offline jbd2 (ext4 journal) recovery for images produced by this crate's formatter.
//!
//! A guest that is stopped without unmounting leaves `EXT4_FEATURE_INCOMPAT_RECOVER` set and committed-but-not-checkpointed transactions in the journal. Growing such an image
//! without replaying would leave the pending log free to clobber appended metadata the next time a kernel mounts (and recovers) the filesystem, so the resizer replays the log
//! here first. The implementation mirrors the kernel's three-pass recovery (SCAN, REVOKE, REPLAY) but supports exactly the journal the formatter writes — v2 superblock, 4 KiB
//! blocks, `REVOKE|64BIT|CSUM_V3`, crc32c — and refuses anything else. All validation (checksums, sequence chaining, target bounds) happens before the first byte is written,
//! so a journal this module rejects leaves the image untouched.

use std::collections::HashMap;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};

use super::format::{
    EXT4_BLOCK_SIZE, EXT4_EH_MAGIC, EXT4_EXTENTS_FL, EXT4_INODE_SIZE, EXT4_JOURNAL_INO, JBD2_MAGIC,
    JBD2_SUPERBLOCK_V2, S_IFREG,
};
use super::formatter::Ext4Error;
use super::layout::{get_be32, get_le16, get_le32, inode_checksum, put_be32};
use crate::crc32c;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// jbd2 block types (header field `h_blocktype`).
const JBD2_DESCRIPTOR_BLOCK: u32 = 1;
const JBD2_COMMIT_BLOCK: u32 = 2;
const JBD2_REVOKE_BLOCK: u32 = 5;

/// Descriptor tag flags. `DELETED` (0x4) is legacy and never written by the kernel or the formatter, so it is rejected along with any other unknown bit.
const JBD2_FLAG_ESCAPE: u32 = 1;
const JBD2_FLAG_SAME_UUID: u32 = 2;
const JBD2_FLAG_LAST_TAG: u32 = 8;

/// REVOKE (0x1) | 64BIT (0x2) | CSUM_V3 (0x10) — exactly what the formatter writes into `s_feature_incompat`. The kernel never adds features to an existing journal, so any
/// other combination means the journal is not ours.
const JBD2_EXPECTED_INCOMPAT: u32 = 0x13;

/// `s_checksum_type` value for crc32c.
const JBD2_CHECKSUM_TYPE_CRC32C: u8 = 4;

/// jbd2 superblocks are always 1024 bytes, even on 4 KiB block filesystems; the superblock checksum covers exactly this span.
const JBD2_SB_SIZE: usize = 1024;

/// Common 12-byte header (`h_magic`, `h_blocktype`, `h_sequence`) at the start of every log block.
const JBD2_HEADER_SIZE: usize = 12;

/// With CSUM_V3 every tag is a fixed-size `journal_block_tag3_t` (`t_blocknr`, `t_flags`, `t_blocknr_high`, `t_checksum`, all be32).
const JBD2_TAG3_SIZE: usize = 16;

/// Descriptor and revoke blocks end with a 4-byte `jbd2_journal_block_tail` holding the block checksum.
const JBD2_TAIL_SIZE: usize = 4;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Physical placement of the journal file, recovered from inode 8's single extent.
pub(super) struct JournalLocation {
    /// First filesystem block of the journal; log block 0 (the jbd2 superblock) lives here.
    pub(super) start_block: u64,

    /// Journal length in 4 KiB blocks.
    pub(super) len_blocks: u32,
}

/// Fields of the on-disk jbd2 superblock the recovery pass needs, plus the raw bytes so the post-replay reset preserves everything it does not change.
struct JournalSuperblock {
    raw: Vec<u8>,
    maxlen: u32,
    first: u32,
    sequence: u32,
    start: u32,
}

/// One journaled block write discovered during SCAN. The data stays in the journal until REPLAY so the scan pass is purely read-only.
struct TagOp {
    target: u64,
    log_block: u32,
    escaped: bool,
}

/// A fully committed transaction: its block writes plus the revocations it declared.
struct Transaction {
    seq: u32,
    ops: Vec<TagOp>,
    revoked: Vec<u64>,
}

/// A parsed descriptor tag (before its data block has been checksum-verified).
struct DescriptorTag {
    target: u64,
    escaped: bool,
    checksum: u32,
}

//--------------------------------------------------------------------------------------------------
// Functions: Recovery
//--------------------------------------------------------------------------------------------------

/// Locate the journal via inode 8, trusting nothing: the inode checksum, file type, extent flag, and the formatter's single depth-0 extent shape are all verified. The journal
/// inode is never itself journaled, so the on-disk copy is authoritative even on a dirty image.
pub(super) fn locate_journal(
    file: &mut File,
    inode_table_block: u64,
    csum_seed: u32,
) -> Result<JournalLocation, Ext4Error> {
    let mut inode = vec![0u8; EXT4_INODE_SIZE as usize];
    file.seek(SeekFrom::Start(
        inode_table_block * EXT4_BLOCK_SIZE as u64
            + (EXT4_JOURNAL_INO as u64 - 1) * EXT4_INODE_SIZE as u64,
    ))?;
    file.read_exact(&mut inode)?;

    let stored = get_le16(&inode, 0x7C) as u32 | ((get_le16(&inode, 0x82) as u32) << 16);
    let generation = get_le32(&inode, 0x64);
    if inode_checksum(csum_seed, EXT4_JOURNAL_INO, generation, &inode) != stored {
        return Err(unsupported("journal inode checksum mismatch"));
    }
    if get_le16(&inode, 0x00) & 0xF000 != S_IFREG {
        return Err(unsupported("journal inode is not a regular file"));
    }
    if get_le32(&inode, 0x20) & EXT4_EXTENTS_FL == 0 {
        return Err(unsupported("journal inode does not use extents"));
    }
    if get_le16(&inode, 0x28) != EXT4_EH_MAGIC
        || get_le16(&inode, 0x2A) != 1
        || get_le16(&inode, 0x2E) != 0
    {
        return Err(unsupported(
            "journal inode extent tree is not a single leaf extent",
        ));
    }
    if get_le32(&inode, 0x34) != 0 {
        return Err(unsupported(
            "journal extent does not start at logical block 0",
        ));
    }
    // ee_len with bit 15 set would mean an unwritten extent, which the formatter never produces for the journal.
    let len = get_le16(&inode, 0x38);
    if len == 0 || len > 0x7FFF {
        return Err(unsupported("journal extent is empty or unwritten"));
    }
    let start = get_le32(&inode, 0x3C) as u64 | ((get_le16(&inode, 0x3A) as u64) << 32);
    let size = get_le32(&inode, 0x04) as u64 | ((get_le32(&inode, 0x6C) as u64) << 32);
    if size != len as u64 * EXT4_BLOCK_SIZE as u64 {
        return Err(unsupported("journal inode size does not match its extent"));
    }

    Ok(JournalLocation {
        start_block: start,
        len_blocks: len as u32,
    })
}

/// Replay the pending jbd2 log onto the filesystem and reset the journal to empty.
///
/// SCAN validates the whole log (checksums, sequence chaining, wraparound, target bounds) before REPLAY performs the first write, so an inconsistent journal returns
/// [`Ext4Error::Unsupported`] with the image untouched. A journal with `s_start == 0` needs no recovery and is not written at all. After replay the data is fsynced, then the
/// jbd2 superblock is rewritten with `s_start = 0` and `s_sequence` advanced past every replayed transaction so stale commit blocks can never match again.
pub(super) fn recover_journal(
    file: &mut File,
    loc: &JournalLocation,
    fs_uuid: &[u8; 16],
    fs_num_blocks: u64,
) -> Result<(), Ext4Error> {
    let jsb = read_journal_superblock(file, loc, fs_uuid)?;
    if jsb.start == 0 {
        return Ok(());
    }

    let jseed = crc32c::crc32c_raw(0xFFFF_FFFF, fs_uuid);
    let (transactions, end_seq) = scan_log(file, loc, &jsb, jseed, fs_num_blocks)?;

    // REVOKE pass: a block revoked in transaction R must not be replayed by any transaction with sequence <= R, so keep the highest revoking sequence per block.
    let mut revoked: HashMap<u64, u32> = HashMap::new();
    for txn in &transactions {
        for block in &txn.revoked {
            let entry = revoked.entry(*block).or_insert(txn.seq);
            if txn.seq > *entry {
                *entry = txn.seq;
            }
        }
    }

    // REPLAY pass: transactions in commit order, later writes of the same block simply overwriting earlier ones.
    for txn in &transactions {
        for op in &txn.ops {
            if revoked.get(&op.target).is_some_and(|seq| *seq >= txn.seq) {
                continue;
            }
            let mut data = read_log_block(file, loc, op.log_block)?;
            if op.escaped {
                put_be32(&mut data, 0, JBD2_MAGIC);
            }
            file.seek(SeekFrom::Start(op.target * EXT4_BLOCK_SIZE as u64))?;
            file.write_all(&data)?;
        }
    }
    file.sync_all()?;

    let mut raw = jsb.raw;
    put_be32(&mut raw, 0x18, end_seq.wrapping_add(1));
    put_be32(&mut raw, 0x1C, 0);
    raw[0xFC..0x100].fill(0);
    let csum = crc32c::crc32c_raw(0xFFFF_FFFF, &raw);
    put_be32(&mut raw, 0xFC, csum);
    file.seek(SeekFrom::Start(loc.start_block * EXT4_BLOCK_SIZE as u64))?;
    file.write_all(&raw)?;
    file.sync_all()?;

    Ok(())
}

/// SCAN pass: walk the log from `s_start`/`s_sequence` following descriptor → data → commit chains (with wraparound at `s_maxlen`), collecting committed transactions. Returns
/// them along with the first sequence number that was NOT committed, which becomes the journal's next sequence after reset.
///
/// End-of-log conditions mirror the kernel: a block without the jbd2 magic or with the wrong sequence, an unexpected block type, or any failed checksum (descriptor tail, data
/// tag, commit) simply terminates the walk — the partially written transaction was never committed, so ignoring it is the correct crash semantics. Only impossible states
/// (targets out of bounds, malformed tags or revoke counts) are hard errors.
fn scan_log(
    file: &mut File,
    loc: &JournalLocation,
    jsb: &JournalSuperblock,
    jseed: u32,
    fs_num_blocks: u64,
) -> Result<(Vec<Transaction>, u32), Ext4Error> {
    let mut transactions = Vec::new();
    let mut seq = jsb.sequence;
    let mut cursor = jsb.start;
    let mut visited = 0u64;

    // Blocks of the transaction currently being scanned; discarded unless its commit block validates.
    let mut ops: Vec<TagOp> = Vec::new();
    let mut revoked: Vec<u64> = Vec::new();

    'log: loop {
        // A valid log occupies fewer than s_maxlen blocks (sequence chaining makes a full wrap impossible), so exceeding it means a self-referential corruption.
        if visited >= jsb.maxlen as u64 {
            return Err(unsupported("journal log walk exceeded the journal size"));
        }
        let header = read_log_block(file, loc, cursor)?;
        if get_be32(&header, 0) != JBD2_MAGIC || get_be32(&header, 8) != seq {
            break;
        }
        match get_be32(&header, 4) {
            JBD2_DESCRIPTOR_BLOCK => {
                if !tail_checksum_ok(&header, jseed) {
                    break;
                }
                let tags = parse_descriptor_tags(&header)?;
                visited += 1;
                let mut data_cursor = advance(cursor, jsb);
                for tag in tags {
                    if tag.target >= fs_num_blocks {
                        return Err(unsupported(format!(
                            "journal transaction {seq} writes block {} beyond the filesystem's {fs_num_blocks} blocks",
                            tag.target
                        )));
                    }
                    if tag.target >= loc.start_block
                        && tag.target < loc.start_block + loc.len_blocks as u64
                    {
                        return Err(unsupported(format!(
                            "journal transaction {seq} writes block {} inside the journal itself",
                            tag.target
                        )));
                    }
                    let data = read_log_block(file, loc, data_cursor)?;
                    if !tag_checksum_ok(&data, jseed, seq, tag.checksum) {
                        break 'log;
                    }
                    ops.push(TagOp {
                        target: tag.target,
                        log_block: data_cursor,
                        escaped: tag.escaped,
                    });
                    visited += 1;
                    data_cursor = advance(data_cursor, jsb);
                }
                cursor = data_cursor;
            }
            JBD2_COMMIT_BLOCK => {
                if !commit_checksum_ok(&header, jseed) {
                    break;
                }
                transactions.push(Transaction {
                    seq,
                    ops: std::mem::take(&mut ops),
                    revoked: std::mem::take(&mut revoked),
                });
                seq = seq.wrapping_add(1);
                visited += 1;
                cursor = advance(cursor, jsb);
            }
            JBD2_REVOKE_BLOCK => {
                if !tail_checksum_ok(&header, jseed) {
                    break;
                }
                parse_revoke_records(&header, &mut revoked)?;
                visited += 1;
                cursor = advance(cursor, jsb);
            }
            _ => break,
        }
    }

    Ok((transactions, seq))
}

//--------------------------------------------------------------------------------------------------
// Functions: Parsing
//--------------------------------------------------------------------------------------------------

/// Read and strictly validate the jbd2 superblock: magic, v2 block type, checksum, feature masks (exactly the formatter's), crc32c checksum type, matching filesystem UUID, no
/// recorded error, 4 KiB block size, and geometry fields consistent with the journal extent.
fn read_journal_superblock(
    file: &mut File,
    loc: &JournalLocation,
    fs_uuid: &[u8; 16],
) -> Result<JournalSuperblock, Ext4Error> {
    let mut raw = vec![0u8; JBD2_SB_SIZE];
    file.seek(SeekFrom::Start(loc.start_block * EXT4_BLOCK_SIZE as u64))?;
    file.read_exact(&mut raw)?;

    if get_be32(&raw, 0x00) != JBD2_MAGIC || get_be32(&raw, 0x04) != JBD2_SUPERBLOCK_V2 {
        return Err(unsupported(
            "journal superblock has bad magic or block type",
        ));
    }
    let mut copy = raw.clone();
    copy[0xFC..0x100].fill(0);
    if crc32c::crc32c_raw(0xFFFF_FFFF, &copy) != get_be32(&raw, 0xFC) {
        return Err(unsupported("journal superblock checksum mismatch"));
    }
    let compat = get_be32(&raw, 0x24);
    let incompat = get_be32(&raw, 0x28);
    let ro_compat = get_be32(&raw, 0x2C);
    if compat != 0 || incompat != JBD2_EXPECTED_INCOMPAT || ro_compat != 0 {
        return Err(unsupported(format!(
            "journal feature flags do not match this crate's formatter (compat={compat:#x}, incompat={incompat:#x}, ro_compat={ro_compat:#x})"
        )));
    }
    if raw[0x50] != JBD2_CHECKSUM_TYPE_CRC32C {
        return Err(unsupported("journal checksum type is not crc32c"));
    }
    if &raw[0x30..0x40] != fs_uuid {
        return Err(unsupported(
            "journal uuid does not match the filesystem uuid",
        ));
    }
    // A non-zero s_errno means the kernel aborted the journal after a filesystem error; replaying and growing on top of that would hide real damage.
    if get_be32(&raw, 0x20) != 0 {
        return Err(unsupported(
            "journal records a filesystem error (s_errno set)",
        ));
    }

    let blocksize = get_be32(&raw, 0x0C);
    let maxlen = get_be32(&raw, 0x10);
    let first = get_be32(&raw, 0x14);
    let sequence = get_be32(&raw, 0x18);
    let start = get_be32(&raw, 0x1C);
    if blocksize != EXT4_BLOCK_SIZE {
        return Err(unsupported("journal block size is not 4096"));
    }
    if maxlen != loc.len_blocks {
        return Err(unsupported(
            "journal s_maxlen does not match the journal inode extent",
        ));
    }
    if first == 0 || first >= maxlen {
        return Err(unsupported("journal s_first is out of range"));
    }
    if start != 0 && (start < first || start >= maxlen) {
        return Err(unsupported("journal s_start is out of range"));
    }

    Ok(JournalSuperblock {
        raw,
        maxlen,
        first,
        sequence,
        start,
    })
}

/// Parse the tag3 array of a descriptor block. Tags run from the end of the 12-byte header to the 4-byte tail; a tag without SAME_UUID is followed by 16 UUID bytes (ignored,
/// as in the kernel). Unknown flag bits are a hard error rather than end-of-log because they would change how many data blocks follow.
fn parse_descriptor_tags(block: &[u8]) -> Result<Vec<DescriptorTag>, Ext4Error> {
    let limit = EXT4_BLOCK_SIZE as usize - JBD2_TAIL_SIZE;
    let mut tags = Vec::new();
    let mut off = JBD2_HEADER_SIZE;
    while off + JBD2_TAG3_SIZE <= limit {
        let target = get_be32(block, off) as u64 | ((get_be32(block, off + 8) as u64) << 32);
        let flags = get_be32(block, off + 4);
        let checksum = get_be32(block, off + 12);
        if flags & !(JBD2_FLAG_ESCAPE | JBD2_FLAG_SAME_UUID | JBD2_FLAG_LAST_TAG) != 0 {
            return Err(unsupported(format!(
                "journal descriptor tag has unsupported flags {flags:#x}"
            )));
        }
        off += JBD2_TAG3_SIZE;
        if flags & JBD2_FLAG_SAME_UUID == 0 {
            off += 16;
        }
        tags.push(DescriptorTag {
            target,
            escaped: flags & JBD2_FLAG_ESCAPE != 0,
            checksum,
        });
        if flags & JBD2_FLAG_LAST_TAG != 0 {
            break;
        }
    }
    // A descriptor that maps no data blocks would make the scan cursor stand still; the kernel never writes one.
    if tags.is_empty() {
        return Err(unsupported("journal descriptor block contains no tags"));
    }

    Ok(tags)
}

/// Parse a revoke block: `r_count` (bytes used, including the 16-byte header) followed by be64 block numbers, since the formatter's journal always has the 64BIT feature.
fn parse_revoke_records(block: &[u8], revoked: &mut Vec<u64>) -> Result<(), Ext4Error> {
    let count = get_be32(block, 12) as usize;
    let limit = EXT4_BLOCK_SIZE as usize - JBD2_TAIL_SIZE;
    if count < 16 || count > limit || !(count - 16).is_multiple_of(8) {
        return Err(unsupported(
            "journal revoke block has an invalid record count",
        ));
    }
    let mut off = 16;
    while off < count {
        let hi = get_be32(block, off) as u64;
        let lo = get_be32(block, off + 4) as u64;
        revoked.push((hi << 32) | lo);
        off += 8;
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Checksums
//--------------------------------------------------------------------------------------------------

/// Descriptor/revoke block checksum: crc32c over the whole block with the 4-byte tail zeroed, seeded with the journal seed (crc32c of ~0 over the UUID).
fn tail_checksum_ok(block: &[u8], jseed: u32) -> bool {
    let tail = EXT4_BLOCK_SIZE as usize - JBD2_TAIL_SIZE;
    let mut copy = block.to_vec();
    copy[tail..].fill(0);
    crc32c::crc32c_raw(jseed, &copy) == get_be32(block, tail)
}

/// Commit block checksum: crc32c over the whole block with `h_chksum[0]` (bytes 16..20) zeroed. `h_chksum_type`/`h_chksum_size` are written as zero under CSUM_V3.
fn commit_checksum_ok(block: &[u8], jseed: u32) -> bool {
    let mut copy = block.to_vec();
    copy[16..20].fill(0);
    crc32c::crc32c_raw(jseed, &copy) == get_be32(block, 16)
}

/// Per-tag data checksum: crc32c over the transaction sequence (be32) then the data block exactly as stored in the journal (escaped form included).
fn tag_checksum_ok(data: &[u8], jseed: u32, seq: u32, expected: u32) -> bool {
    let crc = crc32c::crc32c_raw(jseed, &seq.to_be_bytes());
    crc32c::crc32c_raw(crc, data) == expected
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn read_log_block(
    file: &mut File,
    loc: &JournalLocation,
    index: u32,
) -> Result<Vec<u8>, Ext4Error> {
    let mut buf = vec![0u8; EXT4_BLOCK_SIZE as usize];
    file.seek(SeekFrom::Start(
        (loc.start_block + index as u64) * EXT4_BLOCK_SIZE as u64,
    ))?;
    file.read_exact(&mut buf)?;
    Ok(buf)
}

fn advance(cursor: u32, jsb: &JournalSuperblock) -> u32 {
    let next = cursor + 1;
    if next >= jsb.maxlen { jsb.first } else { next }
}

fn unsupported(message: impl Into<String>) -> Ext4Error {
    Ext4Error::Unsupported(message.into())
}

//--------------------------------------------------------------------------------------------------
// Test Support
//--------------------------------------------------------------------------------------------------

/// One transaction for [`write_test_log`]: block writes, revocations, and optionally a deliberately corrupted commit checksum to exercise end-of-log detection.
#[cfg(test)]
pub(super) struct TestTransaction {
    pub(super) writes: Vec<(u64, Vec<u8>)>,
    pub(super) revokes: Vec<u64>,
    pub(super) corrupt_commit: bool,
}

/// Hand-write a jbd2 log the way the kernel would (revoke block, descriptor + data blocks, commit block per transaction, then `s_start = 1` / `s_sequence = start_seq` in the
/// journal superblock) so replay fixtures exercise the same on-disk format the recovery code parses. Data blocks beginning with the jbd2 magic are escaped automatically.
#[cfg(test)]
pub(super) fn write_test_log(
    file: &mut File,
    loc: &JournalLocation,
    fs_uuid: &[u8; 16],
    start_seq: u32,
    transactions: &[TestTransaction],
) -> Result<(), Ext4Error> {
    let jseed = crc32c::crc32c_raw(0xFFFF_FFFF, fs_uuid);
    let mut cursor = 1u32;
    let emit = |file: &mut File, cursor: &mut u32, block: &[u8]| -> Result<(), Ext4Error> {
        assert!(
            *cursor < loc.len_blocks,
            "test log fixture overflows the journal"
        );
        file.seek(SeekFrom::Start(
            (loc.start_block + *cursor as u64) * EXT4_BLOCK_SIZE as u64,
        ))?;
        file.write_all(block)?;
        *cursor += 1;
        Ok(())
    };

    for (index, txn) in transactions.iter().enumerate() {
        let seq = start_seq + index as u32;

        if !txn.revokes.is_empty() {
            let mut block = vec![0u8; EXT4_BLOCK_SIZE as usize];
            put_be32(&mut block, 0, JBD2_MAGIC);
            put_be32(&mut block, 4, JBD2_REVOKE_BLOCK);
            put_be32(&mut block, 8, seq);
            put_be32(&mut block, 12, (16 + 8 * txn.revokes.len()) as u32);
            let mut off = 16;
            for target in &txn.revokes {
                put_be32(&mut block, off, (*target >> 32) as u32);
                put_be32(&mut block, off + 4, *target as u32);
                off += 8;
            }
            set_tail_checksum(&mut block, jseed);
            emit(file, &mut cursor, &block)?;
        }

        if !txn.writes.is_empty() {
            let mut stored: Vec<Vec<u8>> = Vec::new();
            let mut desc = vec![0u8; EXT4_BLOCK_SIZE as usize];
            put_be32(&mut desc, 0, JBD2_MAGIC);
            put_be32(&mut desc, 4, JBD2_DESCRIPTOR_BLOCK);
            put_be32(&mut desc, 8, seq);
            let mut off = JBD2_HEADER_SIZE;
            for (i, (target, data)) in txn.writes.iter().enumerate() {
                assert_eq!(data.len(), EXT4_BLOCK_SIZE as usize);
                let mut data = data.clone();
                let mut flags = 0u32;
                if get_be32(&data, 0) == JBD2_MAGIC {
                    put_be32(&mut data, 0, 0);
                    flags |= JBD2_FLAG_ESCAPE;
                }
                if i > 0 {
                    flags |= JBD2_FLAG_SAME_UUID;
                }
                if i + 1 == txn.writes.len() {
                    flags |= JBD2_FLAG_LAST_TAG;
                }
                let crc = crc32c::crc32c_raw(jseed, &seq.to_be_bytes());
                let checksum = crc32c::crc32c_raw(crc, &data);
                put_be32(&mut desc, off, *target as u32);
                put_be32(&mut desc, off + 4, flags);
                put_be32(&mut desc, off + 8, (*target >> 32) as u32);
                put_be32(&mut desc, off + 12, checksum);
                off += JBD2_TAG3_SIZE;
                if i == 0 {
                    desc[off..off + 16].copy_from_slice(fs_uuid);
                    off += 16;
                }
                stored.push(data);
            }
            set_tail_checksum(&mut desc, jseed);
            emit(file, &mut cursor, &desc)?;
            for data in &stored {
                emit(file, &mut cursor, data)?;
            }
        }

        let mut commit = vec![0u8; EXT4_BLOCK_SIZE as usize];
        put_be32(&mut commit, 0, JBD2_MAGIC);
        put_be32(&mut commit, 4, JBD2_COMMIT_BLOCK);
        put_be32(&mut commit, 8, seq);
        let checksum = crc32c::crc32c_raw(jseed, &commit);
        put_be32(
            &mut commit,
            16,
            if txn.corrupt_commit {
                checksum ^ 0xFFFF_FFFF
            } else {
                checksum
            },
        );
        emit(file, &mut cursor, &commit)?;
    }

    let mut raw = vec![0u8; JBD2_SB_SIZE];
    file.seek(SeekFrom::Start(loc.start_block * EXT4_BLOCK_SIZE as u64))?;
    file.read_exact(&mut raw)?;
    put_be32(&mut raw, 0x18, start_seq);
    put_be32(&mut raw, 0x1C, 1);
    raw[0xFC..0x100].fill(0);
    let csum = crc32c::crc32c_raw(0xFFFF_FFFF, &raw);
    put_be32(&mut raw, 0xFC, csum);
    file.seek(SeekFrom::Start(loc.start_block * EXT4_BLOCK_SIZE as u64))?;
    file.write_all(&raw)?;

    Ok(())
}

#[cfg(test)]
fn set_tail_checksum(block: &mut [u8], jseed: u32) {
    let tail = EXT4_BLOCK_SIZE as usize - JBD2_TAIL_SIZE;
    block[tail..].fill(0);
    let csum = crc32c::crc32c_raw(jseed, block);
    put_be32(block, tail, csum);
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_descriptor_tags_rejects_unknown_flags() {
        let mut block = vec![0u8; EXT4_BLOCK_SIZE as usize];
        put_be32(&mut block, JBD2_HEADER_SIZE + 4, 0x10 | JBD2_FLAG_LAST_TAG);
        let result = parse_descriptor_tags(&block);
        assert!(matches!(result, Err(Ext4Error::Unsupported(_))));
    }

    #[test]
    fn test_parse_revoke_records_rejects_bad_counts() {
        let mut block = vec![0u8; EXT4_BLOCK_SIZE as usize];
        for count in [0u32, 15, 17, 4093] {
            put_be32(&mut block, 12, count);
            let mut revoked = Vec::new();
            assert!(
                matches!(
                    parse_revoke_records(&block, &mut revoked),
                    Err(Ext4Error::Unsupported(_))
                ),
                "count {count} should be rejected"
            );
        }
    }

    #[test]
    fn test_parse_revoke_records_reads_be64_entries() {
        let mut block = vec![0u8; EXT4_BLOCK_SIZE as usize];
        put_be32(&mut block, 12, 16 + 16);
        put_be32(&mut block, 16, 0x1);
        put_be32(&mut block, 20, 0x2);
        put_be32(&mut block, 24, 0x0);
        put_be32(&mut block, 28, 0x42);
        let mut revoked = Vec::new();
        parse_revoke_records(&block, &mut revoked).unwrap();
        assert_eq!(revoked, vec![0x1_0000_0002, 0x42]);
    }
}
