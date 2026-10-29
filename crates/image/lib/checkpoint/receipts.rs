//! Host-local receipts for the integrity roots of immutable disk inputs.
//!
//! Restores verify external bases and sealed layers against their recorded sparse roots, and
//! hashing a multi-gigabyte file at every restore re-reads bytes this host already verified. A
//! receipt binds one root to the identity its file had while it was hashed, under the canonical
//! path it was resolved through. Any difference, and any missing, unreadable or malformed
//! receipt, means hashing the file again and rewriting its receipt.
//!
//! Who may change a file decides its identity. A layer this runtime sealed in its own store is
//! afterwards only linked or renamed, which moves its change time and nothing else, so its identity
//! is the device, inode, length and modification time, and the links and renames this runtime makes
//! carry its receipt to the new path. A caller-owned input such as an external base may be rewritten
//! outside the runtime with its modification time restored; userspace cannot restore the change
//! time, so that identity binds it too.
//!
//! A file the runtime can still write, such as a writable head or a copy about to have its header
//! relocated, is never resolved through receipts.

use std::fs::{File, Metadata, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use super::store::{SparseFileIntegrity, sparse_file_integrity, sparse_open_file_integrity};
use crate::error::ImageResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const RECEIPT_SCHEMA: &str = "microsandbox.integrity-receipt/2";
const MAX_RECEIPT_BYTES: u64 = 16 * 1024;

/// Restore staging paths are unique, so receipts for them accumulate. Past this bound, receipts
/// whose file is gone or changed are removed first, then the oldest.
#[cfg(not(test))]
const MAX_RECEIPTS: usize = 4096;
#[cfg(test)]
const MAX_RECEIPTS: usize = 8;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A host-local directory of integrity receipts.
///
/// Receipts are trusted only from a directory owned by the current user with no group or other
/// access; nothing is created until the first receipt is recorded.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct IntegrityReceipts {
    root: PathBuf,
}

/// Who may change a file, which decides the identity its receipt binds.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReceiptKind {
    /// A layer this runtime wrote and sealed in its own store, then only linked or renamed.
    SealedLayer,
    /// A caller-owned input, such as an external base, that may be rewritten outside the runtime.
    ExternalInput,
}

/// How a verification uses host receipts.
#[derive(Clone, Copy, Debug)]
pub enum ReceiptUse<'a> {
    /// Hash and record nothing.
    Ignore,
    /// Hash, then record the receipt: the caller has just published the file and reads it anyway.
    Record(&'a IntegrityReceipts),
    /// Take the root from a receipt for the file's exact identity; hash and record otherwise.
    Trust(&'a IntegrityReceipts),
}

/// What a file must still be for its receipt to stand, by kind. The kinds never compare equal,
/// so a receipt recorded for one kind can never answer for the other.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
enum FileIdentity {
    SealedLayer(SealedIdentity),
    ExternalInput(ExternalIdentity),
}

/// Everything about a sealed layer but the change time, which its links and renames move.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SealedIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    length: u64,
    modified_ns: i64,
}

/// A caller-owned input's identity. Any rewrite moves at least its change time.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ExternalIdentity {
    path: PathBuf,
    device: u64,
    inode: u64,
    length: u64,
    modified_ns: i64,
    changed_ns: i64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    identity: FileIdentity,
    integrity_root: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl IntegrityReceipts {
    /// Keep receipts under `root`.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Directory holding the receipts.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Sparse integrity of an immutable file: from a receipt for its exact current identity, or
    /// hashed and then recorded.
    pub fn sparse_file_integrity(
        &self,
        path: &Path,
        kind: ReceiptKind,
    ) -> ImageResult<SparseFileIntegrity> {
        self.verify(path, kind, true)
    }

    /// Hash an immutable file and record its receipt without consulting one.
    pub fn record_sparse_file_integrity(
        &self,
        path: &Path,
        kind: ReceiptKind,
    ) -> ImageResult<SparseFileIntegrity> {
        self.verify(path, kind, false)
    }

    /// Whether this host holds a receipt for `path` that disagrees with `expected_root`: one
    /// recorded under an identity the file no longer has, or naming another root for the file as
    /// it is now. A weaker stamp cannot see what such a receipt can, such as a rewrite that
    /// restored the modification time. Without a receipt there is no contradiction.
    pub fn contradicts(&self, path: &Path, kind: ReceiptKind, expected_root: &str) -> bool {
        let Ok(canonical) = std::fs::canonicalize(path) else {
            return false;
        };
        if !protected_directory(&self.root).unwrap_or(false) {
            return false;
        }
        let Ok(receipt) = read_receipt(&self.receipt_path(kind, &canonical)) else {
            return false;
        };
        let current = std::fs::symlink_metadata(&canonical)
            .ok()
            .and_then(|metadata| FileIdentity::read(kind, canonical.clone(), &metadata));
        receipt.schema == RECEIPT_SCHEMA
            && (current.as_ref() != Some(&receipt.identity)
                || receipt.integrity_root != expected_root)
    }

    /// Record under `to` the sealed-layer receipt held for `from`, after a link or rename this
    /// runtime made. `from` names the path the receipt was recorded under; after a rename, the
    /// caller passes its canonical form from before the rename. Nothing is recorded unless `to` is
    /// the recorded inode with its recorded length and modification time.
    pub fn carry(&self, from: &Path, to: &Path) {
        if let Err(error) = self.try_carry(from, to) {
            tracing::debug!(%error, from = %from.display(), to = %to.display(), "integrity receipt not carried");
        }
    }

    /// [`carry`](Self::carry) every regular file under `to` from the same relative path under
    /// `from`, after this runtime linked or renamed a directory of sealed layers.
    pub fn carry_tree(&self, from: &Path, to: &Path) {
        let Ok(entries) = std::fs::read_dir(to) else {
            return;
        };
        for entry in entries.flatten() {
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            let source = from.join(entry.file_name());
            if file_type.is_dir() {
                self.carry_tree(&source, &entry.path());
            } else if file_type.is_file() {
                self.carry(&source, &entry.path());
            }
        }
    }

    fn verify(
        &self,
        path: &Path,
        kind: ReceiptKind,
        consult: bool,
    ) -> ImageResult<SparseFileIntegrity> {
        let canonical = std::fs::canonicalize(path)?;
        let mut file = open_nofollow(&canonical)?;
        let Some(identity) = FileIdentity::read(kind, canonical, &file.metadata()?) else {
            return sparse_open_file_integrity(&mut file);
        };
        if consult && let Some(root) = self.lookup(&identity) {
            tracing::info!(target: "microsandbox_checkpoint_timing", operation = "disk_receipt", kind = ?kind, logical_bytes = identity.length(), path = %identity.path().display(), "sealed disk integrity from receipt");
            return Ok(SparseFileIntegrity {
                root,
                logical_size: identity.length(),
            });
        }

        let integrity = sparse_open_file_integrity(&mut file)?;

        // Record only bytes that held still while they were hashed, and only once they are
        // durable: a receipt that survives a crash must not vouch for data the disk never got.
        let unchanged = FileIdentity::read(kind, identity.path().to_path_buf(), &file.metadata()?)
            .is_some_and(|after| after == identity);
        if unchanged
            && file.sync_all().is_ok()
            && let Err(error) = self.record(&identity, &integrity.root)
        {
            tracing::debug!(%error, path = %identity.path().display(), "integrity receipt not recorded");
        }
        Ok(integrity)
    }

    fn try_carry(&self, from: &Path, to: &Path) -> io::Result<()> {
        if !protected_directory(&self.root)? {
            return Ok(());
        }
        let from = std::fs::canonicalize(from).unwrap_or_else(|_| from.to_path_buf());
        let to = std::fs::canonicalize(to)?;
        let recorded_at = self.receipt_path(ReceiptKind::SealedLayer, &from);
        let receipt = match read_receipt(&recorded_at) {
            Ok(receipt) => receipt,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error),
        };
        let FileIdentity::SealedLayer(recorded) = &receipt.identity else {
            return Ok(());
        };
        let metadata = std::fs::symlink_metadata(&to)?;
        let Some(FileIdentity::SealedLayer(current)) =
            FileIdentity::read(ReceiptKind::SealedLayer, to, &metadata)
        else {
            return Ok(());
        };
        if receipt.schema != RECEIPT_SCHEMA
            || recorded.path != from
            || !is_sparse_root(&receipt.integrity_root)
            || (
                recorded.device,
                recorded.inode,
                recorded.length,
                recorded.modified_ns,
            ) != (
                current.device,
                current.inode,
                current.length,
                current.modified_ns,
            )
        {
            return Ok(());
        }
        self.record(&FileIdentity::SealedLayer(current), &receipt.integrity_root)?;
        // After a rename nothing is left at the old path for its receipt to describe.
        if matches!(std::fs::symlink_metadata(&from), Err(error) if error.kind() == io::ErrorKind::NotFound)
        {
            let _ = std::fs::remove_file(recorded_at);
        }
        Ok(())
    }

    fn lookup(&self, identity: &FileIdentity) -> Option<String> {
        if !protected_directory(&self.root).ok()? {
            return None;
        }
        let receipt = read_receipt(&self.receipt_path(identity.kind(), identity.path())).ok()?;
        (receipt.schema == RECEIPT_SCHEMA
            && receipt.identity == *identity
            && is_sparse_root(&receipt.integrity_root))
        .then_some(receipt.integrity_root)
    }

    fn record(&self, identity: &FileIdentity, integrity_root: &str) -> io::Result<()> {
        create_protected_directory(&self.root)?;
        let bytes = serde_json::to_vec(&Receipt {
            schema: RECEIPT_SCHEMA.into(),
            identity: identity.clone(),
            integrity_root: integrity_root.into(),
        })
        .map_err(io::Error::other)?;

        // A torn or lost receipt only costs one hash, so it is replaced atomically but not synced.
        let staged = self
            .root
            .join(format!(".{:016x}.tmp", rand::random::<u64>()));
        let published = create_private(&staged)
            .and_then(|mut file| file.write_all(&bytes))
            .and_then(|()| {
                std::fs::rename(&staged, self.receipt_path(identity.kind(), identity.path()))
            });
        if published.is_err() {
            let _ = std::fs::remove_file(&staged);
        }
        published?;

        self.prune();
        Ok(())
    }

    /// Keep the directory bounded. Removing a receipt that still matches only costs a hash.
    fn prune(&self) {
        let Ok(entries) = std::fs::read_dir(&self.root) else {
            return;
        };
        let mut receipts = Vec::new();
        let mut staged = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            match path.extension().and_then(|extension| extension.to_str()) {
                Some("json") => receipts.push(path),
                Some("tmp") => staged.push(path),
                _ => {}
            }
        }
        if receipts.len() <= MAX_RECEIPTS {
            return;
        }
        // Writers rename within microseconds; a leftover is a crashed writer's.
        for path in staged {
            let _ = std::fs::remove_file(path);
        }

        let mut current = Vec::with_capacity(receipts.len());
        for path in receipts {
            let still_valid =
                read_receipt(&path).is_ok_and(|receipt| receipt.identity.matches_current_file());
            if !still_valid {
                let _ = std::fs::remove_file(&path);
                continue;
            }
            let modified = std::fs::symlink_metadata(&path)
                .and_then(|metadata| metadata.modified())
                .unwrap_or(SystemTime::UNIX_EPOCH);
            current.push((modified, path));
        }
        if current.len() > MAX_RECEIPTS {
            current.sort();
            let excess = current.len() - MAX_RECEIPTS * 3 / 4;
            for (_, path) in current.into_iter().take(excess) {
                let _ = std::fs::remove_file(path);
            }
        }
    }

    fn receipt_path(&self, kind: ReceiptKind, path: &Path) -> PathBuf {
        let mut hasher = blake3::Hasher::new();
        hasher.update(kind.tag().as_bytes());
        hasher.update(b"\0");
        hasher.update(path.as_os_str().as_encoded_bytes());
        self.root
            .join(format!("{}.json", hasher.finalize().to_hex()))
    }
}

impl ReceiptKind {
    fn tag(self) -> &'static str {
        match self {
            Self::SealedLayer => "sealed_layer",
            Self::ExternalInput => "external_input",
        }
    }
}

impl<'a> ReceiptUse<'a> {
    /// Trust `receipts` when the caller has a store; otherwise hash.
    pub fn trusting(receipts: Option<&'a IntegrityReceipts>) -> Self {
        receipts.map_or(Self::Ignore, Self::Trust)
    }

    /// Record into `receipts` when the caller has a store; hash either way.
    pub fn recording(receipts: Option<&'a IntegrityReceipts>) -> Self {
        receipts.map_or(Self::Ignore, Self::Record)
    }

    /// Sparse integrity of an immutable file of `kind` under this policy.
    pub fn sparse_file_integrity(
        self,
        path: &Path,
        kind: ReceiptKind,
    ) -> ImageResult<SparseFileIntegrity> {
        match self {
            Self::Ignore => sparse_file_integrity(path),
            Self::Record(receipts) => receipts.record_sparse_file_integrity(path, kind),
            Self::Trust(receipts) => receipts.sparse_file_integrity(path, kind),
        }
    }
}

impl FileIdentity {
    #[cfg(unix)]
    fn read(kind: ReceiptKind, path: PathBuf, metadata: &Metadata) -> Option<Self> {
        use std::os::unix::fs::MetadataExt;

        if !metadata.is_file() {
            return None;
        }
        let modified_ns = nanoseconds(metadata.mtime(), metadata.mtime_nsec())?;
        Some(match kind {
            ReceiptKind::SealedLayer => Self::SealedLayer(SealedIdentity {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                modified_ns,
            }),
            ReceiptKind::ExternalInput => Self::ExternalInput(ExternalIdentity {
                path,
                device: metadata.dev(),
                inode: metadata.ino(),
                length: metadata.len(),
                modified_ns,
                changed_ns: nanoseconds(metadata.ctime(), metadata.ctime_nsec())?,
            }),
        })
    }

    /// Without an inode and a change time no identity is stable enough to trust.
    #[cfg(not(unix))]
    fn read(_kind: ReceiptKind, _path: PathBuf, _metadata: &Metadata) -> Option<Self> {
        None
    }

    fn kind(&self) -> ReceiptKind {
        match self {
            Self::SealedLayer(_) => ReceiptKind::SealedLayer,
            Self::ExternalInput(_) => ReceiptKind::ExternalInput,
        }
    }

    fn path(&self) -> &Path {
        match self {
            Self::SealedLayer(identity) => &identity.path,
            Self::ExternalInput(identity) => &identity.path,
        }
    }

    fn length(&self) -> u64 {
        match self {
            Self::SealedLayer(identity) => identity.length,
            Self::ExternalInput(identity) => identity.length,
        }
    }

    fn matches_current_file(&self) -> bool {
        std::fs::symlink_metadata(self.path()).is_ok_and(|metadata| {
            Self::read(self.kind(), self.path().to_path_buf(), &metadata).as_ref() == Some(self)
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn read_receipt(path: &Path) -> io::Result<Receipt> {
    let file = open_nofollow(path)?;
    if !file.metadata()?.is_file() {
        return Err(io::Error::other("integrity receipt is not a regular file"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_RECEIPT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_RECEIPT_BYTES {
        return Err(io::Error::other("integrity receipt exceeds its size bound"));
    }
    serde_json::from_slice(&bytes).map_err(io::Error::other)
}

fn is_sparse_root(root: &str) -> bool {
    root.strip_prefix("blake3:").is_some_and(|digest| {
        digest.len() == 64
            && digest
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn nanoseconds(seconds: i64, nanoseconds: i64) -> Option<i64> {
    seconds.checked_mul(1_000_000_000)?.checked_add(nanoseconds)
}

fn open_nofollow(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options.open(path)
}

fn create_private(path: &Path) -> io::Result<File> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// Whether receipts in `path` can be trusted: a real directory only this user can change.
#[cfg(unix)]
fn protected_directory(path: &Path) -> io::Result<bool> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};

    let metadata = std::fs::symlink_metadata(path)?;
    Ok(metadata.is_dir()
        && metadata.uid() == unsafe { libc::geteuid() }
        && metadata.permissions().mode() & 0o077 == 0)
}

#[cfg(not(unix))]
fn protected_directory(_path: &Path) -> io::Result<bool> {
    Ok(false)
}

fn create_protected_directory(path: &Path) -> io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(path)?;
    if !protected_directory(path)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "integrity receipt directory is not private to this user",
        ));
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::fs::FileTimes;
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::time::Duration;

    use super::*;

    const KINDS: [ReceiptKind; 2] = [ReceiptKind::SealedLayer, ReceiptKind::ExternalInput];
    const PLANTED: &str = "blake3:0000000000000000000000000000000000000000000000000000000000000000";

    fn fixture() -> (tempfile::TempDir, IntegrityReceipts, PathBuf) {
        let directory = tempfile::tempdir().unwrap();
        let receipts = IntegrityReceipts::new(directory.path().join("integrity"));
        let path = directory.path().join("layer.raw");
        let mut bytes = vec![0_u8; 256 * 1024];
        bytes[..5].copy_from_slice(b"layer");
        std::fs::write(&path, bytes).unwrap();
        (directory, receipts, path)
    }

    /// Rewrite a recorded receipt's root without touching the file it describes. A later answer
    /// equal to `root` proves it came from the receipt, not from reading the file.
    fn plant_root(receipts: &IntegrityReceipts, kind: ReceiptKind, path: &Path, root: &str) {
        let location = receipts.receipt_path(kind, &std::fs::canonicalize(path).unwrap());
        let mut receipt = read_receipt(&location).unwrap();
        receipt.integrity_root = root.into();
        std::fs::write(&location, serde_json::to_vec(&receipt).unwrap()).unwrap();
    }

    fn trusted_root(receipts: &IntegrityReceipts, kind: ReceiptKind, path: &Path) -> String {
        receipts.sparse_file_integrity(path, kind).unwrap().root
    }

    /// Coarse kernel clocks can leave two changes in one tick; wait for a distinct change time.
    fn advance_change_time(path: &Path, modified: SystemTime) {
        let before = std::fs::metadata(path).unwrap();
        for _ in 0..400 {
            std::thread::sleep(Duration::from_millis(5));
            let file = OpenOptions::new().write(true).open(path).unwrap();
            file.set_times(FileTimes::new().set_modified(modified))
                .unwrap();
            let after = std::fs::metadata(path).unwrap();
            if (after.ctime(), after.ctime_nsec()) != (before.ctime(), before.ctime_nsec()) {
                return;
            }
        }
        panic!("change time never advanced");
    }

    #[test]
    fn receipt_hit_answers_without_reading_the_file() {
        for kind in KINDS {
            let (_directory, receipts, path) = fixture();
            let hashed = receipts.sparse_file_integrity(&path, kind).unwrap();
            assert_eq!(hashed, sparse_file_integrity(&path).unwrap());
            assert_eq!(
                receipts.root().metadata().unwrap().permissions().mode() & 0o777,
                0o700
            );

            plant_root(&receipts, kind, &path, PLANTED);
            let trusted = receipts.sparse_file_integrity(&path, kind).unwrap();
            assert_eq!(trusted.root, PLANTED);
            assert_eq!(trusted.logical_size, hashed.logical_size);
            // Recording reads the file whatever a receipt says, and rewrites it.
            let recorded = receipts.record_sparse_file_integrity(&path, kind).unwrap();
            assert_eq!(recorded, hashed);
            assert_eq!(trusted_root(&receipts, kind, &path), hashed.root);
        }
    }

    #[test]
    fn kinds_never_answer_for_each_other() {
        let (_directory, receipts, path) = fixture();
        let expected = sparse_file_integrity(&path).unwrap().root;
        receipts
            .sparse_file_integrity(&path, ReceiptKind::SealedLayer)
            .unwrap();
        plant_root(&receipts, ReceiptKind::SealedLayer, &path, PLANTED);

        assert_eq!(
            trusted_root(&receipts, ReceiptKind::ExternalInput, &path),
            expected
        );
        assert_eq!(
            trusted_root(&receipts, ReceiptKind::SealedLayer, &path),
            PLANTED
        );
    }

    #[test]
    fn a_sealed_layer_hard_linked_into_a_child_still_hits() {
        let (directory, receipts, path) = fixture();
        receipts
            .sparse_file_integrity(&path, ReceiptKind::SealedLayer)
            .unwrap();
        plant_root(&receipts, ReceiptKind::SealedLayer, &path, PLANTED);

        // The link moves the shared inode's change time, which a sealed identity ignores.
        let child = directory.path().join("child");
        std::fs::create_dir(&child).unwrap();
        let linked = child.join("sealed-000.raw");
        std::fs::hard_link(&path, &linked).unwrap();
        assert_eq!(
            trusted_root(&receipts, ReceiptKind::SealedLayer, &path),
            PLANTED
        );

        // The runtime carries the receipt to the path it made, and then across a rename.
        receipts.carry(&path, &linked);
        assert_eq!(
            trusted_root(&receipts, ReceiptKind::SealedLayer, &linked),
            PLANTED
        );
        let staged = std::fs::canonicalize(&child).unwrap();
        let published = directory.path().join("published");
        std::fs::rename(&child, &published).unwrap();
        receipts.carry_tree(&staged, &published);
        let renamed = published.join("sealed-000.raw");
        assert_eq!(
            trusted_root(&receipts, ReceiptKind::SealedLayer, &renamed),
            PLANTED
        );
        // The receipt for the name the rename removed is gone with it.
        assert!(
            !receipts
                .receipt_path(ReceiptKind::SealedLayer, &staged.join("sealed-000.raw"))
                .exists()
        );
    }

    #[test]
    fn a_link_the_runtime_did_not_carry_is_hashed() {
        let (directory, receipts, path) = fixture();
        let expected = receipts
            .sparse_file_integrity(&path, ReceiptKind::SealedLayer)
            .unwrap()
            .root;
        plant_root(&receipts, ReceiptKind::SealedLayer, &path, PLANTED);
        let linked = directory.path().join("linked.raw");
        std::fs::hard_link(&path, &linked).unwrap();
        assert_eq!(
            trusted_root(&receipts, ReceiptKind::SealedLayer, &linked),
            expected
        );
    }

    #[test]
    fn a_sealed_layer_whose_bytes_change_misses() {
        let (_directory, receipts, path) = fixture();
        receipts
            .sparse_file_integrity(&path, ReceiptKind::SealedLayer)
            .unwrap();
        plant_root(&receipts, ReceiptKind::SealedLayer, &path, PLANTED);

        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        writer.write_all(b"LAYER").unwrap();
        writer
            .set_times(FileTimes::new().set_modified(modified + Duration::from_secs(1)))
            .unwrap();
        drop(writer);

        let current = receipts
            .sparse_file_integrity(&path, ReceiptKind::SealedLayer)
            .unwrap();
        assert_ne!(current.root, PLANTED);
        assert_eq!(current, sparse_file_integrity(&path).unwrap());
    }

    #[test]
    fn carrying_refuses_another_inode_or_a_changed_layer() {
        let (directory, receipts, path) = fixture();
        let expected = receipts
            .sparse_file_integrity(&path, ReceiptKind::SealedLayer)
            .unwrap()
            .root;
        plant_root(&receipts, ReceiptKind::SealedLayer, &path, PLANTED);

        let copied = directory.path().join("copied.raw");
        std::fs::copy(&path, &copied).unwrap();
        receipts.carry(&path, &copied);
        assert_eq!(
            trusted_root(&receipts, ReceiptKind::SealedLayer, &copied),
            expected
        );

        let linked = directory.path().join("linked.raw");
        std::fs::hard_link(&path, &linked).unwrap();
        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        OpenOptions::new()
            .write(true)
            .open(&path)
            .unwrap()
            .set_times(FileTimes::new().set_modified(modified + Duration::from_secs(1)))
            .unwrap();
        receipts.carry(&path, &linked);
        assert_eq!(
            trusted_root(&receipts, ReceiptKind::SealedLayer, &linked),
            expected
        );
    }

    #[test]
    fn changed_identity_hashes_again_and_rewrites_the_receipt() {
        for kind in KINDS {
            let (_directory, receipts, path) = fixture();
            receipts.sparse_file_integrity(&path, kind).unwrap();
            plant_root(&receipts, kind, &path, PLANTED);

            // Same bytes, new modification time: the identity differs, so the receipt is unused.
            let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
            advance_change_time(&path, modified + Duration::from_secs(1));
            let rehashed = receipts.sparse_file_integrity(&path, kind).unwrap();
            assert_eq!(rehashed, sparse_file_integrity(&path).unwrap());

            // The fresh receipt now serves the new identity.
            plant_root(&receipts, kind, &path, PLANTED);
            assert_eq!(trusted_root(&receipts, kind, &path), PLANTED);

            // A replacement under the same name is another inode.
            let replacement = path.with_extension("tmp");
            std::fs::write(&replacement, b"other bytes").unwrap();
            std::fs::rename(&replacement, &path).unwrap();
            assert_eq!(
                receipts.sparse_file_integrity(&path, kind).unwrap(),
                sparse_file_integrity(&path).unwrap()
            );
        }
    }

    #[test]
    fn an_external_input_rewritten_with_its_old_modification_time_is_caught_by_change_time() {
        let (_directory, receipts, path) = fixture();
        let original = receipts
            .sparse_file_integrity(&path, ReceiptKind::ExternalInput)
            .unwrap();
        let before = std::fs::metadata(&path).unwrap();
        let modified = before.modified().unwrap();

        // Same inode, same length, same modification time; only the bytes and ctime differ.
        let mut writer = OpenOptions::new().write(true).open(&path).unwrap();
        writer.write_all(b"LAYER").unwrap();
        drop(writer);
        advance_change_time(&path, modified);
        let after = std::fs::metadata(&path).unwrap();
        assert_eq!(
            (after.ino(), after.len(), after.modified().unwrap()),
            (before.ino(), before.len(), modified)
        );

        let current = receipts
            .sparse_file_integrity(&path, ReceiptKind::ExternalInput)
            .unwrap();
        assert_ne!(current.root, original.root);
        assert_eq!(current, sparse_file_integrity(&path).unwrap());
    }

    #[test]
    fn a_receipt_contradicts_another_root_or_a_file_that_changed_since() {
        let (_directory, receipts, path) = fixture();
        let kind = ReceiptKind::ExternalInput;
        let root = sparse_file_integrity(&path).unwrap().root;
        assert!(!receipts.contradicts(&path, kind, PLANTED));
        receipts.sparse_file_integrity(&path, kind).unwrap();
        assert!(!receipts.contradicts(&path, kind, &root));
        assert!(receipts.contradicts(&path, kind, PLANTED));

        let modified = std::fs::metadata(&path).unwrap().modified().unwrap();
        advance_change_time(&path, modified);
        assert!(receipts.contradicts(&path, kind, &root));
    }

    #[test]
    fn corrupted_or_missing_receipts_hash_again_and_are_rewritten() {
        for kind in KINDS {
            let (_directory, receipts, path) = fixture();
            let expected = receipts.sparse_file_integrity(&path, kind).unwrap();
            let location = receipts.receipt_path(kind, &std::fs::canonicalize(&path).unwrap());

            for damage in [&b"{\"schema\":"[..], b"", b"not json at all"] {
                std::fs::write(&location, damage).unwrap();
                assert_eq!(
                    receipts.sparse_file_integrity(&path, kind).unwrap(),
                    expected
                );
                assert_eq!(
                    read_receipt(&location).unwrap().integrity_root,
                    expected.root
                );
            }

            std::fs::remove_file(&location).unwrap();
            assert_eq!(
                receipts.sparse_file_integrity(&path, kind).unwrap(),
                expected
            );
            assert!(location.is_file());

            // A malformed root is not trusted even when the identity matches.
            plant_root(&receipts, kind, &path, "blake3:not-a-digest");
            assert_eq!(
                receipts.sparse_file_integrity(&path, kind).unwrap(),
                expected
            );
        }
    }

    #[test]
    fn receipts_are_ignored_outside_a_private_directory() {
        let (_directory, receipts, path) = fixture();
        let kind = ReceiptKind::SealedLayer;
        receipts.sparse_file_integrity(&path, kind).unwrap();
        plant_root(&receipts, kind, &path, PLANTED);
        std::fs::set_permissions(receipts.root(), std::fs::Permissions::from_mode(0o777)).unwrap();

        let hashed = receipts.sparse_file_integrity(&path, kind).unwrap();
        assert_eq!(hashed, sparse_file_integrity(&path).unwrap());
    }

    #[test]
    fn pruning_removes_stale_receipts_first_and_bounds_the_directory() {
        let directory = tempfile::tempdir().unwrap();
        let receipts = IntegrityReceipts::new(directory.path().join("integrity"));
        let kind = ReceiptKind::SealedLayer;
        let mut files = Vec::new();
        for index in 0..MAX_RECEIPTS {
            let path = directory.path().join(format!("layer-{index}.raw"));
            std::fs::write(&path, vec![index as u8; 4096]).unwrap();
            receipts.sparse_file_integrity(&path, kind).unwrap();
            files.push(path);
        }
        let count = || std::fs::read_dir(receipts.root()).unwrap().count();
        assert_eq!(count(), MAX_RECEIPTS);

        // Over the bound, receipts for removed files go first; current ones survive.
        for path in &files[..2] {
            std::fs::remove_file(path).unwrap();
        }
        let extra = directory.path().join("extra.raw");
        std::fs::write(&extra, b"extra").unwrap();
        receipts.sparse_file_integrity(&extra, kind).unwrap();
        assert_eq!(count(), MAX_RECEIPTS - 1);
        for path in files[2..].iter().chain([&extra]) {
            plant_root(&receipts, kind, path, PLANTED);
            assert_eq!(trusted_root(&receipts, kind, path), PLANTED);
        }

        // With nothing stale, the oldest are dropped to make room.
        for index in 0..4 {
            let path = directory.path().join(format!("more-{index}.raw"));
            std::fs::write(&path, vec![0xa5; 4096 + index]).unwrap();
            receipts.sparse_file_integrity(&path, kind).unwrap();
        }
        assert!(count() <= MAX_RECEIPTS);
    }
}
