//! Immutable, self-contained generations of sandbox-owned directory storage.
//!
//! Callers must exclude every writer until capture finishes. Payloads are separate files so
//! filesystem device state stays bounded independently of the amount of application data.
//! Directory metadata is platform-family-specific: Unix generations cannot be restored on
//! Windows, or vice versa. This also applies when embedded in a disk-only snapshot archive.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

#[cfg(unix)]
#[path = "owned_unix.rs"]
mod platform;
#[cfg(windows)]
#[path = "owned_windows.rs"]
mod platform;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SCHEMA: &str = "microsandbox.owned-directory/1";
const DESCRIPTOR: &str = "directory.bin";
const MAX_DESCRIPTOR_BYTES: usize = 64 * 1024 * 1024;
const MAX_OBJECTS: usize = 1_000_000;
const MAX_PATH_DEPTH: usize = 256;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A separately stored immutable file, addressed by lowercase SHA-256 of its complete bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedDirectoryPayload {
    /// Lowercase, 64-character SHA-256 digest; payload path is `files/<digest>`.
    pub digest: String,
    /// Logical byte length, including sparse holes.
    pub bytes: u64,
}

/// Complete namespace and metadata for one immutable owned directory generation.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OwnedDirectorySnapshot {
    schema: String,
    platform: String,
    entries: Vec<NamespaceEntry>,
    objects: Vec<DirectoryObject>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct NamespaceEntry {
    components: Vec<Vec<u8>>,
    object: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) struct DirectoryObject {
    pub(super) kind: ObjectKind,
    metadata: platform::ObjectMetadata,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(super) enum ObjectKind {
    Directory,
    File(OwnedDirectoryPayload),
    Symlink(Vec<u8>),
}

/// Capture/restore coordination shared by the runtime and its moved filesystem backend.
///
/// Only explicit checkpoints touch this mutex; ordinary filesystem operations do not.
#[derive(Clone, Debug, Default)]
pub struct OwnedDirectoryCheckpoint {
    inner: Arc<Mutex<CheckpointState>>,
}

#[derive(Debug, Default)]
struct CheckpointState {
    capture: Option<PathBuf>,
    completed: Option<OwnedDirectorySnapshot>,
    restore: Option<PathBuf>,
}

/// An unpublished generation. Its caller retains the quiescence boundary through `finish`.
pub(super) struct DirectoryCapture {
    source: PathBuf,
    destination: PathBuf,
    snapshot: OwnedDirectorySnapshot,
    identities: BTreeMap<platform::FileIdentity, u64>,
    published: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OwnedDirectoryCheckpoint {
    /// Arrange the next filesystem device capture to publish into a new private directory.
    pub fn prepare_capture(&self, generation_dir: &Path) -> io::Result<()> {
        let mut state = self.inner.lock().map_err(poisoned)?;
        if state.capture.is_some() {
            return Err(invalid("owned directory capture is already prepared"));
        }
        if generation_dir.try_exists()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "owned generation exists",
            ));
        }
        state.completed = None;
        state.capture = Some(generation_dir.to_path_buf());
        Ok(())
    }

    /// Retrieve the generation sealed by a successful filesystem device capture.
    pub fn finish_capture(&self) -> io::Result<OwnedDirectorySnapshot> {
        self.inner
            .lock()
            .map_err(poisoned)?
            .completed
            .take()
            .ok_or_else(|| invalid("owned filesystem did not complete its prepared capture"))
    }

    /// Discard a prepared capture after a failed VM operation. Does not delete caller-owned paths.
    pub fn cancel_capture(&self) -> io::Result<()> {
        let mut state = self.inner.lock().map_err(poisoned)?;
        state.capture = None;
        state.completed = None;
        Ok(())
    }

    /// Set the verified generation used to reconstruct detached handles during full restore.
    ///
    /// The visible namespace must already have been privately materialized before constructing
    /// the destination backend. The owned device frame authenticates this descriptor's digest.
    pub fn set_restore(&self, generation_dir: &Path) -> io::Result<()> {
        self.inner.lock().map_err(poisoned)?.restore = Some(generation_dir.to_path_buf());
        Ok(())
    }

    pub(super) fn take_capture(&self) -> io::Result<PathBuf> {
        self.inner
            .lock()
            .map_err(poisoned)?
            .capture
            .take()
            .ok_or_else(|| invalid("owned filesystem capture has no prepared generation"))
    }

    pub(super) fn completed(&self, snapshot: OwnedDirectorySnapshot) -> io::Result<()> {
        self.inner.lock().map_err(poisoned)?.completed = Some(snapshot);
        Ok(())
    }

    pub(super) fn restore(&self) -> io::Result<PathBuf> {
        self.inner
            .lock()
            .map_err(poisoned)?
            .restore
            .clone()
            .ok_or_else(|| invalid("owned filesystem restore has no private generation"))
    }
}

impl OwnedDirectorySnapshot {
    /// Capture visible data while the caller holds the stopped/quiesced storage boundary.
    /// Detached process-owned objects are added by the live filesystem provider instead.
    pub fn capture(source: &Path, destination: &Path) -> io::Result<Self> {
        DirectoryCapture::new(source, destination)?.finish()
    }

    /// Read the bounded descriptor and verify every separately stored file payload.
    pub fn open(generation_dir: &Path) -> io::Result<Self> {
        platform::open_nofollow(generation_dir, true)?;
        platform::open_nofollow(&generation_dir.join("files"), true)?;
        let descriptor = open_regular(&generation_dir.join(DESCRIPTOR))?;
        let mut bytes = Vec::new();
        descriptor
            .take(MAX_DESCRIPTOR_BYTES as u64 + 1)
            .read_to_end(&mut bytes)?;
        let snapshot = Self::from_descriptor_bytes(&bytes)?;
        for payload in snapshot.payloads() {
            verify_payload(
                &generation_dir.join("files").join(&payload.digest),
                &payload,
            )?;
        }
        Ok(snapshot)
    }

    /// Open a generation whose descriptor digest came from the enclosing verified artifact.
    pub fn open_expected(generation_dir: &Path, digest: &str) -> io::Result<Self> {
        let snapshot = Self::open(generation_dir)?;
        if snapshot.digest()? != digest {
            return Err(invalid("owned directory descriptor digest differs"));
        }
        Ok(snapshot)
    }

    /// Decode and structurally validate a descriptor, without opening its payload paths.
    pub fn from_descriptor_bytes(bytes: &[u8]) -> io::Result<Self> {
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(invalid("owned directory descriptor exceeds 64 MiB"));
        }
        let (snapshot, consumed): (Self, usize) = bincode::serde::decode_from_slice(
            bytes,
            bincode::config::standard()
                .with_little_endian()
                .with_fixed_int_encoding()
                .with_limit::<MAX_DESCRIPTOR_BYTES>(),
        )
        .map_err(invalid)?;
        if consumed != bytes.len() {
            return Err(invalid("owned directory descriptor has trailing bytes"));
        }
        snapshot.validate()?;
        Ok(snapshot)
    }

    /// Return the deterministic bytes stored as `directory.bin`.
    pub fn descriptor_bytes(&self) -> io::Result<Vec<u8>> {
        self.validate()?;
        let bytes = bincode::serde::encode_to_vec(
            self,
            bincode::config::standard()
                .with_little_endian()
                .with_fixed_int_encoding()
                .with_limit::<MAX_DESCRIPTOR_BYTES>(),
        )
        .map_err(invalid)?;
        if bytes.len() > MAX_DESCRIPTOR_BYTES {
            return Err(invalid("owned directory descriptor exceeds 64 MiB"));
        }
        Ok(bytes)
    }

    /// Lowercase SHA-256 over the exact `directory.bin` bytes.
    pub fn digest(&self) -> io::Result<String> {
        Ok(hex::encode(Sha256::digest(self.descriptor_bytes()?)))
    }

    /// Sorted, deduplicated file payload inventory, including detached execution objects.
    pub fn payloads(&self) -> Vec<OwnedDirectoryPayload> {
        self.objects
            .iter()
            .filter_map(|object| match &object.kind {
                ObjectKind::File(payload) => Some((payload.digest.clone(), payload.clone())),
                _ => None,
            })
            .collect::<BTreeMap<_, _>>()
            .into_values()
            .collect()
    }

    /// Create an independent visible namespace at a previously absent destination.
    ///
    /// Detached objects are intentionally omitted for cold boot. Full restore reconstructs
    /// them through the backend state. No writable inode is hardlinked to sealed payloads.
    pub fn materialize(&self, generation_dir: &Path, child_root: &Path) -> io::Result<()> {
        self.validate()?;
        platform::open_nofollow(generation_dir, true)?;
        platform::open_nofollow(&generation_dir.join("files"), true)?;
        let parent = child_root
            .parent()
            .ok_or_else(|| invalid("owned root has no parent"))?;
        let stage = tempfile::Builder::new()
            .prefix(".owned-directory-")
            .tempdir_in(parent)?;
        let root = stage.path().join("data");
        fs::create_dir(&root)?;
        let mut materialized = BTreeMap::<u64, PathBuf>::new();
        for entry in &self.entries {
            let path = join_components(&root, &entry.components)?;
            if entry.components.is_empty() {
                materialized.insert(entry.object, path);
                continue;
            }
            if let Some(existing) = materialized.get(&entry.object) {
                // Only internal aliases share an inode; payload files themselves never do.
                platform::hardlink(existing, &path)?;
            } else {
                self.materialize_object_at(generation_dir, entry.object, &path, &root)?;
                materialized.insert(entry.object, path);
            }
        }
        // Metadata is applied after children so restrictive directory modes do not obstruct
        // construction and restored modification times are not overwritten by insertion.
        for entry in self.entries.iter().rev() {
            let path = join_components(&root, &entry.components)?;
            platform::apply_metadata(&root, &path, &self.object(entry.object)?.metadata)?;
        }
        if child_root.try_exists()? {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "owned destination exists",
            ));
        }
        fs::rename(&root, child_root)?;
        sync_directory(parent)?;
        Ok(())
    }

    pub(super) fn object(&self, id: u64) -> io::Result<&DirectoryObject> {
        self.objects
            .get(usize::try_from(id).map_err(invalid)?)
            .ok_or_else(|| invalid("owned directory references an absent object"))
    }

    /// A retained inode can still have an unobserved hardlink in the captured namespace.
    /// Reuse that child inode rather than cloning a detached copy and breaking the alias.
    pub(super) fn visible_object_path(&self, root: &Path, id: u64) -> io::Result<Option<PathBuf>> {
        self.entries
            .iter()
            .find(|entry| entry.object == id)
            .map(|entry| join_components(root, &entry.components))
            .transpose()
    }

    pub(super) fn materialize_object(
        &self,
        generation_dir: &Path,
        id: u64,
        destination: &Path,
    ) -> io::Result<()> {
        let root = destination
            .parent()
            .ok_or_else(|| invalid("owned object has no parent"))?;
        self.materialize_object_at(generation_dir, id, destination, root)
    }

    fn materialize_object_at(
        &self,
        generation_dir: &Path,
        id: u64,
        destination: &Path,
        metadata_root: &Path,
    ) -> io::Result<()> {
        let object = self.object(id)?;
        match &object.kind {
            ObjectKind::Directory => fs::create_dir(destination)?,
            ObjectKind::Symlink(target) => platform::symlink(target, destination)?,
            ObjectKind::File(payload) => {
                let source = generation_dir.join("files").join(&payload.digest);
                verify_payload(&source, payload)?;
                microsandbox_utils::copy::fast_copy(&source, destination)?;
                platform::clear_payload_metadata(destination)?;
                verify_payload(destination, payload)?;
            }
        }
        platform::apply_metadata(metadata_root, destination, &object.metadata)?;
        Ok(())
    }

    fn validate(&self) -> io::Result<()> {
        if self.schema != SCHEMA
            || self.platform != capture_platform()
            || self.entries.is_empty()
            || self.objects.len() > MAX_OBJECTS
            || self.entries.len() > MAX_OBJECTS
        {
            return Err(invalid("invalid owned directory schema or inventory size"));
        }
        let mut paths = BTreeMap::new();
        let mut aliases = BTreeSet::new();
        for (index, entry) in self.entries.iter().enumerate() {
            validate_components(&entry.components)?;
            let object = self.object(entry.object)?;
            if index == 0 {
                if !entry.components.is_empty() || !matches!(object.kind, ObjectKind::Directory) {
                    return Err(invalid(
                        "owned namespace must start with its directory root",
                    ));
                }
            } else {
                let mut parent = entry.components.clone();
                if parent.pop().is_none()
                    || !paths.get(&parent).is_some_and(|id| {
                        self.object(*id)
                            .is_ok_and(|object| matches!(object.kind, ObjectKind::Directory))
                    })
                {
                    return Err(invalid(
                        "owned namespace parent is missing or not a directory",
                    ));
                }
            }
            if paths
                .insert(entry.components.clone(), entry.object)
                .is_some()
                || (!aliases.insert(entry.object) && matches!(object.kind, ObjectKind::Directory))
            {
                return Err(invalid(
                    "duplicate owned path or unsupported directory alias",
                ));
            }
        }
        let mut payload_sizes = BTreeMap::new();
        for object in &self.objects {
            platform::validate_metadata(&object.metadata)?;
            if let ObjectKind::File(payload) = &object.kind
                && (!valid_digest(&payload.digest)
                    || payload_sizes
                        .insert(&payload.digest, payload.bytes)
                        .is_some_and(|size| size != payload.bytes))
            {
                return Err(invalid("invalid or inconsistent owned payload identity"));
            }
            if let ObjectKind::Symlink(target) = &object.kind
                && (target.is_empty() || target.contains(&0) || target.len() > 65536)
            {
                return Err(invalid("invalid owned symlink target"));
            }
        }
        Ok(())
    }
}

impl DirectoryCapture {
    pub(super) fn new(source: &Path, destination: &Path) -> io::Result<Self> {
        if !fs::symlink_metadata(source)?.is_dir() {
            return Err(invalid("owned source must be a real directory"));
        }
        let parent = destination
            .parent()
            .ok_or_else(|| invalid("owned generation has no parent"))?;
        if parent.canonicalize()?.starts_with(source.canonicalize()?) {
            return Err(invalid(
                "owned generation cannot be written inside its source namespace",
            ));
        }
        fs::create_dir(destination)?;
        let mut capture = Self {
            source: source.into(),
            destination: destination.into(),
            snapshot: OwnedDirectorySnapshot {
                schema: SCHEMA.into(),
                platform: capture_platform().into(),
                entries: Vec::new(),
                objects: Vec::new(),
            },
            identities: BTreeMap::new(),
            published: false,
        };
        fs::create_dir(destination.join("files"))?;
        capture.walk(source, Vec::new())?;
        Ok(capture)
    }

    pub(super) fn add_detached(&mut self, file: &File) -> io::Result<u64> {
        let metadata = file.metadata()?;
        if !metadata.is_file() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "owned checkpoint supports detached regular files only",
            ));
        }
        let id = platform::file_identity(file, &metadata)?;
        if let Some(id) = self.identities.get(&id) {
            return Ok(*id);
        }
        let metadata = platform::file_metadata(file, &self.source, None)?;
        let object = DirectoryObject {
            kind: ObjectKind::File(self.seal_file(file)?),
            metadata,
        };
        self.insert_object(id, object)
    }

    pub(super) fn finish(mut self) -> io::Result<OwnedDirectorySnapshot> {
        let bytes = self.snapshot.descriptor_bytes()?;
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(self.destination.join(DESCRIPTOR))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        sync_directory(&self.destination.join("files"))?;
        sync_directory(&self.destination)?;
        self.published = true;
        Ok(std::mem::replace(
            &mut self.snapshot,
            OwnedDirectorySnapshot {
                schema: SCHEMA.into(),
                platform: capture_platform().into(),
                entries: Vec::new(),
                objects: Vec::new(),
            },
        ))
    }

    /// Store guest metadata known only to the live backend, particularly for detached files.
    pub(super) fn set_guest_metadata(
        &mut self,
        object: u64,
        uid: u32,
        gid: u32,
        mode: u32,
        rdev: u32,
    ) -> io::Result<()> {
        let object = self
            .snapshot
            .objects
            .get_mut(usize::try_from(object).map_err(invalid)?)
            .ok_or_else(|| invalid("owned metadata references an absent object"))?;
        platform::set_guest_metadata(&mut object.metadata, uid, gid, mode, rdev)
    }

    fn walk(&mut self, path: &Path, components: Vec<Vec<u8>>) -> io::Result<()> {
        validate_components(&components)?;
        if self.snapshot.entries.len() >= MAX_OBJECTS {
            return Err(invalid("owned directory has too many entries"));
        }
        let metadata = fs::symlink_metadata(path)?;
        let (identity, object) = if metadata.is_symlink() {
            let identity = platform::symlink_identity(&metadata)?;
            if let Some(object) = self.identities.get(&identity).copied() {
                self.snapshot
                    .entries
                    .push(NamespaceEntry { components, object });
                return Ok(());
            }
            (
                Some(identity),
                DirectoryObject {
                    kind: ObjectKind::Symlink(platform::path_bytes(&fs::read_link(path)?)?),
                    metadata: platform::path_metadata(&self.source, path, true)?,
                },
            )
        } else {
            let file = platform::open_nofollow(path, metadata.is_dir())?;
            let pinned = file.metadata()?;
            if !pinned.is_dir() && !pinned.is_file() {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "owned directory contains a special host object",
                ));
            }
            let identity = platform::file_identity(&file, &pinned)?;
            // Read metadata before copying bytes: our reads can update access time.
            let metadata = platform::file_metadata(&file, &self.source, Some(path))?;
            if let Some(object) = self.identities.get(&identity).copied() {
                platform::validate_alias_metadata(
                    &self.snapshot.object(object)?.metadata,
                    &metadata,
                )?;
                self.snapshot
                    .entries
                    .push(NamespaceEntry { components, object });
                return Ok(());
            }
            let kind = if pinned.is_dir() {
                ObjectKind::Directory
            } else {
                ObjectKind::File(self.seal_file(&file)?)
            };
            (Some(identity), DirectoryObject { kind, metadata })
        };
        let directory = matches!(object.kind, ObjectKind::Directory);
        let object = match identity {
            Some(identity) => self.insert_object(identity, object)?,
            None => {
                let id = self.snapshot.objects.len() as u64;
                self.snapshot.objects.push(object);
                id
            }
        };
        self.snapshot.entries.push(NamespaceEntry {
            components: components.clone(),
            object,
        });
        if directory {
            let mut children = fs::read_dir(path)?
                .map(|entry| entry.map(|entry| entry.file_name()))
                .collect::<io::Result<Vec<_>>>()?;
            children.sort();
            for name in children {
                if platform::skip_entry(&name) {
                    continue;
                }
                let mut child = components.clone();
                child.push(platform::path_bytes(Path::new(&name))?);
                self.walk(&path.join(name), child)?;
            }
        }
        Ok(())
    }

    fn insert_object(
        &mut self,
        identity: platform::FileIdentity,
        object: DirectoryObject,
    ) -> io::Result<u64> {
        if self.snapshot.objects.len() >= MAX_OBJECTS {
            return Err(invalid("too many owned objects"));
        }
        let id = self.snapshot.objects.len() as u64;
        self.identities.insert(identity, id);
        self.snapshot.objects.push(object);
        Ok(id)
    }

    fn seal_file(&self, file: &File) -> io::Result<OwnedDirectoryPayload> {
        let before = platform::stamp(file)?;
        let directory = self.destination.join("files");
        let staging = tempfile::Builder::new()
            .prefix(".file-")
            .tempdir_in(&directory)?;
        let path = staging.path().join("data");
        platform::copy_detached(file, &path)?;
        // Content deduplication must never make one object's xattrs become another object's
        // defaults. Payload inodes contain bytes only; each object owns its separate metadata.
        platform::clear_payload_metadata(&path)?;
        if before != platform::stamp(file)? {
            return Err(invalid("owned file changed during quiesced capture"));
        }
        let payload = hash_payload(&path)?;
        if payload.bytes != file.metadata()?.len() {
            return Err(invalid("owned file size changed during capture"));
        }
        let destination = directory.join(&payload.digest);
        if destination.try_exists()? {
            verify_payload(&destination, &payload)?;
        } else {
            OpenOptions::new().write(true).open(&path)?.sync_all()?;
            fs::rename(&path, destination)?;
        }
        Ok(payload)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for DirectoryCapture {
    fn drop(&mut self) {
        if !self.published {
            // This capture exclusively created the directory. Never apply cleanup to the
            // source namespace or to a pre-existing generation supplied by another caller.
            if let Err(error) = fs::remove_dir_all(&self.destination) {
                tracing::warn!(path = %self.destination.display(), %error, "failed to remove incomplete owned directory generation");
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn hash_payload(path: &Path) -> io::Result<OwnedDirectoryPayload> {
    let mut file = open_regular(path)?;
    let bytes = file.metadata()?.len();
    let mut digest = Sha256::new();
    let mut buffer = vec![0; 1024 * 1024];
    let mut total = 0_u64;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        total = total
            .checked_add(count as u64)
            .ok_or_else(|| invalid("owned payload length overflow"))?;
        digest.update(&buffer[..count]);
    }
    if total != bytes {
        return Err(invalid("owned payload changed while hashing"));
    }
    Ok(OwnedDirectoryPayload {
        digest: hex::encode(digest.finalize()),
        bytes,
    })
}

fn capture_platform() -> &'static str {
    if cfg!(windows) { "windows" } else { "unix" }
}

fn verify_payload(path: &Path, expected: &OwnedDirectoryPayload) -> io::Result<()> {
    if hash_payload(path)? != *expected {
        return Err(invalid("owned payload integrity differs"));
    }
    Ok(())
}

fn open_regular(path: &Path) -> io::Result<File> {
    let file = platform::open_nofollow(path, false)?;
    if !file.metadata()?.is_file() {
        return Err(invalid("owned payload is not a regular file"));
    }
    Ok(file)
}

fn valid_digest(digest: &str) -> bool {
    digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_components(components: &[Vec<u8>]) -> io::Result<()> {
    if components.len() > MAX_PATH_DEPTH
        || components.iter().any(|part| {
            part.is_empty()
                || part.len() > 255
                || part == b"."
                || part == b".."
                || part.contains(&0)
                || part.contains(&b'/')
        })
    {
        return Err(invalid("invalid owned namespace path"));
    }
    // Reject platform aliases (notably Win32 device names and ADS separators) while
    // admitting the descriptor, before creating any destination namespace entries.
    for component in components {
        platform::component(component)?;
    }
    Ok(())
}

fn join_components(root: &Path, components: &[Vec<u8>]) -> io::Result<PathBuf> {
    validate_components(components)?;
    let mut path = root.to_path_buf();
    for component in components {
        path.push(platform::component(component)?);
    }
    Ok(path)
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn invalid(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}
fn poisoned<T>(error: std::sync::PoisonError<T>) -> io::Error {
    invalid(error)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(all(test, unix))]
mod tests {
    use std::os::unix::fs::{FileExt, MetadataExt};

    use super::*;

    #[test]
    fn namespace_roundtrip_preserves_hardlinks_symlinks_sparse_data_and_privacy() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::create_dir(source.join("nested")).unwrap();
        let file = File::create(source.join("nested/data")).unwrap();
        file.set_len(8 * 1024 * 1024).unwrap();
        file.write_all_at(b"tail", 8 * 1024 * 1024 - 4).unwrap();
        file.sync_all().unwrap();
        let source_blocks = file.metadata().unwrap().blocks();
        fs::hard_link(source.join("nested/data"), source.join("alias")).unwrap();
        std::os::unix::fs::symlink("/never-follow-this", source.join("link")).unwrap();
        let generation = temporary.path().join("generation");
        let captured = OwnedDirectorySnapshot::capture(&source, &generation).unwrap();
        let expected = captured.digest().unwrap();
        fs::remove_dir_all(&source).unwrap();
        let snapshot = OwnedDirectorySnapshot::open_expected(&generation, &expected).unwrap();
        let child = temporary.path().join("child");
        let sibling = temporary.path().join("sibling");
        snapshot.materialize(&generation, &child).unwrap();
        snapshot.materialize(&generation, &sibling).unwrap();
        assert_eq!(
            fs::metadata(child.join("alias")).unwrap().ino(),
            fs::metadata(child.join("nested/data")).unwrap().ino()
        );
        assert_ne!(
            fs::metadata(child.join("alias")).unwrap().ino(),
            fs::metadata(sibling.join("alias")).unwrap().ino()
        );
        assert_eq!(
            fs::read_link(child.join("link")).unwrap(),
            Path::new("/never-follow-this")
        );
        // Some APFS temporary volumes allocate ftruncate-created ranges eagerly. Preserve
        // sparse allocation where the source supports it; never require unavailable holes.
        assert!(fs::metadata(child.join("alias")).unwrap().blocks() <= source_blocks + 16);
        OpenOptions::new()
            .write(true)
            .open(child.join("alias"))
            .unwrap()
            .write_all_at(b"child", 0)
            .unwrap();
        let mut bytes = [1; 5];
        File::open(sibling.join("alias"))
            .unwrap()
            .read_exact_at(&mut bytes, 0)
            .unwrap();
        assert_eq!(bytes, [0; 5]);
        OwnedDirectorySnapshot::open_expected(&generation, &expected).unwrap();
    }

    #[test]
    fn malformed_namespace_and_changed_payload_are_rejected() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        fs::write(source.join("file"), b"data").unwrap();
        let generation = temp.path().join("generation");
        let mut snapshot = OwnedDirectorySnapshot::capture(&source, &generation).unwrap();
        snapshot.entries[1].components = vec![b"..".to_vec(), b"escape".to_vec()];
        assert!(snapshot.descriptor_bytes().is_err());
        let payload = snapshot.payloads().remove(0);
        fs::write(generation.join("files").join(payload.digest), b"changed").unwrap();
        assert!(OwnedDirectorySnapshot::open(&generation).is_err());
    }

    #[test]
    fn native_symlink_hardlinks_preserve_identity_without_following_target() {
        let temporary = tempfile::tempdir().unwrap();
        let source = temporary.path().join("source");
        fs::create_dir(&source).unwrap();
        std::os::unix::fs::symlink("/absent-owned-test-target", source.join("link")).unwrap();
        platform::hardlink(&source.join("link"), &source.join("alias")).unwrap();
        let original = fs::symlink_metadata(source.join("link")).unwrap();
        assert_eq!(
            original.ino(),
            fs::symlink_metadata(source.join("alias")).unwrap().ino()
        );
        assert_eq!(original.nlink(), 2);
        let generation = temporary.path().join("generation");
        let snapshot = OwnedDirectorySnapshot::capture(&source, &generation).unwrap();
        assert_eq!(
            snapshot.objects.len(),
            2,
            "root and one shared symlink object"
        );
        fs::remove_dir_all(&source).unwrap();
        let snapshot = OwnedDirectorySnapshot::open(&generation).unwrap();
        let child = temporary.path().join("child");
        snapshot.materialize(&generation, &child).unwrap();
        let link = fs::symlink_metadata(child.join("link")).unwrap();
        assert!(link.is_symlink());
        assert_eq!(
            link.ino(),
            fs::symlink_metadata(child.join("alias")).unwrap().ino()
        );
        assert_eq!(link.nlink(), 2);
        fs::remove_file(child.join("link")).unwrap();
        assert_eq!(
            fs::symlink_metadata(child.join("alias")).unwrap().nlink(),
            1
        );
        assert_eq!(
            fs::read_link(child.join("alias")).unwrap(),
            Path::new("/absent-owned-test-target")
        );
    }

    #[test]
    fn identical_payloads_keep_distinct_guest_metadata() {
        use crate::backends::shared::stat_override;
        use std::os::fd::AsRawFd;

        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        fs::create_dir(&source).unwrap();
        for name in ["a", "b"] {
            fs::write(source.join(name), b"identical bytes").unwrap();
        }
        let a = File::open(source.join("a")).unwrap();
        stat_override::set_override(a.as_raw_fd(), 1234, 4321, 0o100640, 0).unwrap();
        let generation = temp.path().join("generation");
        let snapshot = OwnedDirectorySnapshot::capture(&source, &generation).unwrap();
        assert_eq!(snapshot.payloads().len(), 1);
        let child = temp.path().join("child");
        snapshot.materialize(&generation, &child).unwrap();
        let a = File::open(child.join("a")).unwrap();
        let a_metadata = stat_override::get_override(a.as_raw_fd(), true, true)
            .unwrap()
            .unwrap();
        let owner = (a_metadata.uid, a_metadata.gid, a_metadata.mode);
        assert_eq!(owner, (1234, 4321, 0o100640));
        let b = File::open(child.join("b")).unwrap();
        assert!(
            stat_override::get_override(b.as_raw_fd(), true, true)
                .unwrap()
                .is_none()
        );
        assert_ne!(a.metadata().unwrap().ino(), b.metadata().unwrap().ino());
    }
}
