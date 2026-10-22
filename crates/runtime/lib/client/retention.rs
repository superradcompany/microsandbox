//! Host-private last-active evidence. These records are never snapshot archive members.
//!
//! The caller must hold the sandbox's runtime/lifecycle authority. A file's presence is not
//! evidence of current ownership: readers must independently validate its catalog and run.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use sea_orm::{ConnectionTrait, DbBackend, Statement};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[path = "retention/mounted_storage.rs"]
mod mounted_storage;

#[path = "retention/capture.rs"]
mod capture;

#[path = "retention/init.rs"]
mod init;

#[path = "retention/live.rs"]
mod live;

#[path = "retention/selection.rs"]
mod selection;

#[path = "retention/script_backing.rs"]
mod script_backing;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SCHEMA: u32 = 1;
const DIRECTORY: &str = "last-active";
const RECORD: &str = "state.json";
const TERMINAL: &str = "terminal.json";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Optional launcher handoff. Debug output must never expose the retained local source.
#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionSource {
    /// Exact local persistence projection, never an archive-ready document.
    pub configuration: Value,
}

/// Exact local owner of configuration evidence, including a fresh identity on every runtime boot.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionOwner {
    /// Identity of the catalog file, not its mutable contents or pathname.
    pub catalog_file: [u64; 2],
    /// Sandbox row identity in that catalog.
    pub sandbox_id: i32,
    /// Creation timestamp guards against row reuse in externally reconstructed catalogs.
    pub sandbox_created_at: Option<String>,
    /// Latest run row identity.
    pub run_id: i32,
    /// Runtime-written start timestamp guards against reused run rows.
    pub run_started_at: String,
    /// Runtime control identity; a run ID alone cannot fence same-run changes.
    pub runtime_boot_id: String,
}

/// One confirmed local configuration and the generation in which it was applied.
///
/// Deliberately lacks Debug: the local source can contain sensitive configuration. Portable
/// writers must run the saved-config exclusions and binding projection instead of copying it.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetainedConfiguration {
    /// Owner which actually applied this configuration.
    pub owner: RetentionOwner,
    /// Monotonic transition number, not guest resource convergence.
    pub generation: u64,
    /// Source configuration supplied by a capable launcher; absence is unknown, not defaults.
    pub source: Option<Value>,
}

/// Why evidence cannot yet describe the complete current configuration.
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionTransition {
    /// A new runtime has not confirmed activation.
    Start,
    /// A live configuration change has not confirmed publication.
    Modify,
}

/// Durable fence written before an effect; retains prior confirmation independently.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionRecord {
    schema: u32,
    /// Current attempted owner, even if activation never completed.
    pub owner: RetentionOwner,
    /// Last allocated transition number, including uncertain attempts.
    pub generation: u64,
    /// Most recent confirmed state, possibly historical after a failed/newer transition.
    pub confirmed: Option<RetainedConfiguration>,
    /// A missing confirmation must never resurrect the previous state as current.
    pub pending: Option<RetentionTransition>,
    /// An uncertain partial change remains uncertain after later independent successes.
    pub uncertain_since: Option<u64>,
}

/// Runtime-owned writer outside the guest-visible runtime directory.
pub struct RetentionJournal {
    directory: PathBuf,
    record: RetentionRecord,
}

/// Who established that the recorded runtime no longer owns the sandbox.
#[derive(Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetentionTerminalOrigin {
    /// The VM's exit observer, before clearing active configuration.
    RuntimeExit,
    /// Maintenance proved the process dead while holding lifecycle ownership.
    ReconciledDeath,
}

/// A local terminal receipt preserves catalog provenance before terminal cleanup clears it.
///
/// It contains no configuration values. An absent digest means evidence was unavailable or
/// inconsistent; neither a terminal run nor an old journal alone can fill that gap.
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RetentionTerminal {
    schema: u32,
    owner: RetentionOwner,
    generation: u64,
    origin: RetentionTerminalOrigin,
    source_sha256: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RetentionTerminal {
    /// Match a terminal receipt to independently checked ownership and the exact retained source.
    /// Callers must still establish that this is the latest run and that its process is gone.
    pub fn current<'a>(
        &self,
        owner: &RetentionOwner,
        record: &'a RetentionRecord,
    ) -> Option<&'a RetainedConfiguration> {
        if self.schema != SCHEMA || self.owner != *owner || self.generation != record.generation {
            return None;
        }
        let confirmed = record.current(owner)?;
        let digest = source_digest(confirmed.source.as_ref()?).ok()?;
        (self.source_sha256.as_deref() == Some(digest.as_str())).then_some(confirmed)
    }
}

impl RetentionOwner {
    /// Read existing catalog rows without adding columns, tables or migration ledger entries.
    pub async fn for_run(
        db: &microsandbox_db::DbWriteConnection,
        catalog_path: &Path,
        sandbox_id: i32,
        run_id: i32,
        runtime_boot_id: String,
    ) -> io::Result<Self> {
        let row = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT s.created_at AS sandbox_created_at, r.started_at AS run_started_at \
                 FROM sandbox s JOIN run r ON r.sandbox_id = s.id \
                 WHERE s.id = ? AND r.id = ?",
                [sandbox_id.into(), run_id.into()],
            ))
            .await
            .map_err(|_| invalid("could not read retention owner"))?
            .ok_or_else(|| invalid("retention owner is missing"))?;
        Ok(Self {
            catalog_file: catalog_file_identity(catalog_path)?,
            sandbox_id,
            sandbox_created_at: row
                .try_get("", "sandbox_created_at")
                .map_err(|_| invalid("invalid retention sandbox identity"))?,
            run_id,
            run_started_at: row
                .try_get("", "run_started_at")
                .map_err(|_| invalid("invalid retention run identity"))?,
            runtime_boot_id,
        })
    }
}

impl RetentionRecord {
    /// Select only complete evidence for an independently established current owner.
    /// Catalog metadata provenance and capture generation checks remain the caller's obligation.
    pub fn current(&self, owner: &RetentionOwner) -> Option<&RetainedConfiguration> {
        if self.owner != *owner || self.pending.is_some() || self.uncertain_since.is_some() {
            return None;
        }
        self.confirmed.as_ref().filter(|confirmed| {
            confirmed.owner == *owner
                && confirmed.generation == self.generation
                && confirmed.source.is_some()
        })
    }
}

impl RetentionJournal {
    /// Read without creating, repairing or treating a missing record as confirmed configuration.
    pub fn read(sandbox_directory: &Path) -> io::Result<Option<RetentionRecord>> {
        let Some(record) = read_private_json::<RetentionRecord>(sandbox_directory, RECORD)? else {
            return Ok(None);
        };
        if record.schema != SCHEMA || record.generation == 0 {
            return Err(invalid("unsupported retention record"));
        }
        if record
            .confirmed
            .as_ref()
            .is_some_and(|value| value.generation == 0 || value.generation > record.generation)
            || record
                .uncertain_since
                .is_some_and(|generation| generation == 0 || generation > record.generation)
        {
            return Err(invalid("inconsistent retention generation"));
        }
        Ok(Some(record))
    }

    /// Read a terminal receipt without creating one or changing lifecycle state.
    pub fn read_terminal(sandbox_directory: &Path) -> io::Result<Option<RetentionTerminal>> {
        let receipt = read_private_json::<RetentionTerminal>(sandbox_directory, TERMINAL)?;
        if receipt
            .as_ref()
            .is_some_and(|receipt| receipt.schema != SCHEMA || receipt.generation == 0)
        {
            return Err(invalid("unsupported retention terminal receipt"));
        }
        Ok(receipt)
    }

    /// Durably fence activation before entering the guest. Previous confirmed evidence survives,
    /// but cannot describe this run until activation is independently confirmed.
    pub fn begin_start(sandbox_directory: &Path, owner: RetentionOwner) -> io::Result<Self> {
        #[cfg(all(feature = "retention-test-hooks", debug_assertions))]
        inject_failure("before-start")?;
        let previous = Self::read(sandbox_directory)?;
        let generation = previous
            .as_ref()
            .map_or(0, |record| record.generation)
            .checked_add(1)
            .ok_or_else(|| invalid("retention generation exhausted"))?;
        let journal = Self {
            directory: sandbox_directory.join(DIRECTORY),
            record: RetentionRecord {
                schema: SCHEMA,
                owner,
                generation,
                confirmed: previous.and_then(|record| record.confirmed),
                pending: Some(RetentionTransition::Start),
                uncertain_since: None,
            },
        };
        journal.write(&journal.record)?;
        #[cfg(all(feature = "retention-test-hooks", debug_assertions))]
        inject_failure("after-start-prepare")?;
        Ok(journal)
    }

    /// Allocate and persist a live transition before dispatching it.
    pub fn begin_modify(&mut self) -> io::Result<()> {
        #[cfg(all(feature = "retention-test-hooks", debug_assertions))]
        inject_failure("before-modify")?;
        let mut next = self.record.clone();
        if next.pending.is_some() {
            // A prior effect may have happened. A later successful CPU change, for example,
            // cannot certify a previously interrupted secret update.
            next.uncertain_since.get_or_insert(next.generation);
        }
        next.generation = next
            .generation
            .checked_add(1)
            .ok_or_else(|| invalid("retention generation exhausted"))?;
        next.pending = Some(RetentionTransition::Modify);
        self.write(&next)?;
        self.record = next;
        #[cfg(all(feature = "retention-test-hooks", debug_assertions))]
        inject_failure("after-modify-prepare")?;
        Ok(())
    }

    /// Confirm an applied configuration. Failure leaves the in-memory pending fence intact;
    /// callers report uncertainty instead of retrying or treating the prior record as current.
    pub fn confirm(&mut self, source: Option<Value>) -> io::Result<()> {
        self.confirm_with(source, |journal, next| {
            #[cfg(all(feature = "retention-test-hooks", debug_assertions))]
            inject_failure(match journal.record.pending {
                Some(RetentionTransition::Start) => "after-start-effect",
                _ => "after-modify-effect",
            })?;
            journal.write(next)?;
            #[cfg(all(feature = "retention-test-hooks", debug_assertions))]
            inject_failure(match journal.record.pending {
                Some(RetentionTransition::Start) => "after-start-publication",
                _ => "after-modify-publication",
            })?;
            Ok(())
        })
    }

    fn confirm_with(
        &mut self,
        source: Option<Value>,
        publish: impl FnOnce(&Self, &RetentionRecord) -> io::Result<()>,
    ) -> io::Result<()> {
        if self.record.pending.is_none() {
            return Err(invalid("no retention transition to confirm"));
        }
        let mut next = self.record.clone();
        next.confirmed = Some(RetainedConfiguration {
            owner: next.owner.clone(),
            generation: next.generation,
            source,
        });
        next.pending = None;
        publish(self, &next)?;
        self.record = next;
        Ok(())
    }

    /// Last confirmation may be historical. Never use it without validating current evidence.
    pub fn record(&self) -> &RetentionRecord {
        &self.record
    }

    fn write(&self, record: &RetentionRecord) -> io::Result<()> {
        write_private_json(&self.directory, RECORD, record)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl std::fmt::Debug for RetentionSource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("RetentionSource(<private>)")
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Preserve last-run provenance before clearing active configuration.
///
/// The caller must be the exiting runtime or hold lifecycle ownership after proving its
/// process dead. This never changes the catalog and never turns unknown evidence into defaults.
pub async fn seal_terminal(
    db: &microsandbox_db::DbWriteConnection,
    sandbox_directory: &Path,
    sandbox_id: i32,
    run_id: i32,
    expected_boot_id: Option<&str>,
    origin: RetentionTerminalOrigin,
) -> io::Result<bool> {
    let Some(record) = RetentionJournal::read(sandbox_directory)? else {
        return Ok(false);
    };
    if record.owner.sandbox_id != sandbox_id
        || record.owner.run_id != run_id
        || expected_boot_id.is_some_and(|boot| record.owner.runtime_boot_id != boot)
    {
        return Ok(false);
    }
    let catalog = db
        .query_one_raw(Statement::from_string(
            DbBackend::Sqlite,
            "SELECT file FROM pragma_database_list WHERE name = 'main'",
        ))
        .await
        .map_err(|_| invalid("could not identify retention catalog"))?
        .ok_or_else(|| invalid("retention catalog is missing"))?;
    let path: String = catalog
        .try_get("", "file")
        .map_err(|_| invalid("invalid retention catalog path"))?;
    if path.is_empty() {
        return Ok(false);
    }
    let owner = RetentionOwner::for_run(
        db,
        Path::new(&path),
        sandbox_id,
        run_id,
        record.owner.runtime_boot_id.clone(),
    )
    .await?;
    if owner != record.owner {
        return Ok(false);
    }
    // A retry after catalog cleanup must not erase a valid earlier receipt merely because
    // active_config has already been cleared. A later owner/generation cannot reuse it.
    if RetentionJournal::read_terminal(sandbox_directory)?
        .is_some_and(|receipt| receipt.current(&owner, &record).is_some())
    {
        return Ok(true);
    }
    let active = if microsandbox_db::catalog::has_column(db, "sandbox", "active_config")
        .await
        .map_err(|_| invalid("could not inspect active configuration support"))?
    {
        let row = db
            .query_one_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "SELECT active_config FROM sandbox WHERE id = ?",
                [sandbox_id.into()],
            ))
            .await
            .map_err(|_| invalid("could not read terminal active configuration"))?
            .ok_or_else(|| invalid("terminal sandbox is missing"))?;
        let json: Option<String> = row
            .try_get("", "active_config")
            .map_err(|_| invalid("invalid terminal active configuration"))?;
        json.map(|json| {
            serde_json::from_str::<Value>(&json)
                .map_err(|_| invalid("invalid terminal configuration document"))
        })
        .transpose()?
    } else {
        None
    };
    publish_terminal(sandbox_directory, &record, active.as_ref(), origin)
}

fn publish_terminal(
    sandbox_directory: &Path,
    record: &RetentionRecord,
    active: Option<&Value>,
    origin: RetentionTerminalOrigin,
) -> io::Result<bool> {
    let source_sha256 = record
        .current(&record.owner)
        .and_then(|confirmed| confirmed.source.as_ref())
        .filter(|source| Some(*source) == active)
        .map(source_digest)
        .transpose()?;
    let receipt = RetentionTerminal {
        schema: SCHEMA,
        owner: record.owner.clone(),
        generation: record.generation,
        origin,
        source_sha256,
    };
    write_private_json(&sandbox_directory.join(DIRECTORY), TERMINAL, &receipt)?;
    Ok(true)
}

fn source_digest(source: &Value) -> io::Result<String> {
    let bytes =
        serde_json::to_vec(source).map_err(|_| invalid("could not fingerprint retained source"))?;
    Ok(hex::encode(Sha256::digest(bytes)))
}

fn read_private_json<T: serde::de::DeserializeOwned>(
    sandbox_directory: &Path,
    name: &str,
) -> io::Result<Option<T>> {
    let directory = sandbox_directory.join(DIRECTORY);
    match fs::symlink_metadata(&directory) {
        Ok(metadata) if metadata.is_dir() && !metadata.file_type().is_symlink() => {}
        Ok(_) => return Err(invalid("retention directory is not a real directory")),
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = match options.open(directory.join(name)) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !file.metadata()?.is_file() {
        return Err(invalid("retention record is not a regular file"));
    }
    serde_json::from_reader(file)
        .map(Some)
        .map_err(|_| invalid("invalid retention record"))
}

fn write_private_json(directory: &Path, name: &str, value: &impl Serialize) -> io::Result<()> {
    private_directory(directory)?;
    // Sync the new directory's parent before publication, then the record and its own directory.
    sync_directory(
        directory
            .parent()
            .ok_or_else(|| invalid("retention directory has no parent"))?,
    )?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)?;
    serde_json::to_writer(&mut temporary, value)
        .map_err(|_| invalid("could not encode retention record"))?;
    temporary.flush()?;
    temporary.as_file().sync_all()?;
    crate::checkpoint::replace_file(temporary.path(), &directory.join(name))?;
    sync_directory(directory)
}

/// Identity of the catalog pathname, including deliberate symlinked catalog paths.
pub fn catalog_file_identity(path: &Path) -> io::Result<[u64; 2]> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        // SQLite uses process-owned POSIX record locks. Closing any descriptor for
        // this inode would release this process's locks, even though its database
        // connection remains open. stat follows intentional symlinks without opening
        // another descriptor; do not replace it with File::open(...).metadata().
        let metadata = fs::metadata(path)?;
        if !metadata.is_file() {
            return Err(invalid("catalog is not a regular file"));
        }
        Ok([metadata.dev(), metadata.ino()])
    }
    #[cfg(windows)]
    {
        use std::os::windows::io::AsRawHandle;
        use windows_sys::Win32::Storage::FileSystem::{
            BY_HANDLE_FILE_INFORMATION, GetFileInformationByHandle,
        };
        let file = File::open(path)?;
        if !file.metadata()?.is_file() {
            return Err(invalid("catalog is not a regular file"));
        }
        let mut info = std::mem::MaybeUninit::<BY_HANDLE_FILE_INFORMATION>::zeroed();
        // SAFETY: the file owns a live handle and info is valid writable output storage.
        if unsafe { GetFileInformationByHandle(file.as_raw_handle(), info.as_mut_ptr()) } == 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: a successful call initialized the complete output structure.
        let info = unsafe { info.assume_init() };
        Ok([
            u64::from(info.dwVolumeSerialNumber),
            u64::from(info.nFileIndexHigh) << 32 | u64::from(info.nFileIndexLow),
        ])
    }
}

fn private_directory(path: &Path) -> io::Result<()> {
    let builder = fs::DirBuilder::new();
    #[cfg(unix)]
    let builder = {
        use std::os::unix::fs::DirBuilderExt;
        let mut builder = builder;
        builder.mode(0o700);
        builder
    };
    match builder.create(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
            let metadata = fs::symlink_metadata(path)?;
            if metadata.is_dir() && !metadata.file_type().is_symlink() {
                Ok(())
            } else {
                Err(invalid("retention directory is not a real directory"))
            }
        }
        Err(error) => Err(error),
    }
}

fn sync_directory(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    // Windows replace_file uses MOVEFILE_WRITE_THROUGH after flushing the temporary file.
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// Both debug assertions and an explicit feature are required, so release builds never
/// interpret the test environment variable even when built with all features.
#[cfg(all(feature = "retention-test-hooks", debug_assertions))]
fn inject_failure(phase: &str) -> io::Result<()> {
    if std::env::var("MSB_TEST_RETENTION_FAILURE").as_deref() == Ok(phase) {
        return Err(io::Error::other(format!(
            "injected retention failure: {phase}"
        )));
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::{
        os::{fd::AsRawFd, unix::fs::MetadataExt},
        process::Command,
    };

    use super::*;

    #[cfg(unix)]
    fn record_lock() -> libc::flock {
        // SAFETY: all-zero is valid for the integer fields in flock; set the operation
        // and range explicitly. POSIX locks, unlike flock locks, are process-owned.
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = libc::F_WRLCK as _;
        lock.l_whence = libc::SEEK_SET as _;
        lock.l_start = 0x4000_0002; // SQLite's SHARED_FIRST byte.
        lock.l_len = 1;
        lock
    }

    #[cfg(unix)]
    #[test]
    #[ignore = "subprocess-only POSIX catalog lock observer"]
    fn catalog_record_lock_observer() {
        let path = std::env::var_os("MSB_TEST_CATALOG_LOCK_PATH").expect("lock fixture path");
        let expected_pid: libc::pid_t = std::env::var("MSB_TEST_CATALOG_LOCK_PID")
            .unwrap()
            .parse()
            .unwrap();
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
            .unwrap();
        let mut lock = record_lock();
        // SAFETY: the file descriptor and mutable flock output remain live for fcntl.
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) },
            0
        );
        assert_eq!(
            lock.l_type,
            libc::F_WRLCK as libc::c_short,
            "catalog writer lock was released"
        );
        assert_eq!(
            lock.l_pid, expected_pid,
            "lock belongs to a different process"
        );
    }

    #[cfg(unix)]
    #[test]
    fn catalog_identity_preserves_existing_posix_record_locks() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("catalog.db");
        let file = File::create(&path).unwrap();
        let lock = record_lock();
        // SAFETY: the file descriptor and immutable input flock are valid for the call.
        assert_eq!(
            unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) },
            0
        );
        let observe = || {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--ignored",
                    "--exact",
                    "client::retention::tests::catalog_record_lock_observer",
                    "--nocapture",
                ])
                .env("MSB_TEST_CATALOG_LOCK_PATH", &path)
                .env("MSB_TEST_CATALOG_LOCK_PID", std::process::id().to_string())
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
        };
        observe();
        let identity = catalog_file_identity(&path).unwrap();
        let metadata = file.metadata().unwrap();
        assert_eq!(identity, [metadata.dev(), metadata.ino()]);
        observe();
        // Deliberately symlinked catalog paths keep their established target identity
        // without opening/closing a second descriptor for the locked database.
        let alias = directory.path().join("catalog-alias.db");
        std::os::unix::fs::symlink(&path, &alias).unwrap();
        assert_eq!(catalog_file_identity(&alias).unwrap(), identity);
        observe();
        drop(file);
    }

    fn owner(boot: &str, run: i32) -> RetentionOwner {
        RetentionOwner {
            catalog_file: [1, 2],
            sandbox_id: 3,
            sandbox_created_at: Some("created".into()),
            run_id: run,
            run_started_at: format!("start-{run}"),
            runtime_boot_id: boot.into(),
        }
    }

    #[test]
    fn failed_restart_preserves_history_without_certifying_new_owner() {
        let dir = tempfile::tempdir().unwrap();
        let first = owner("first", 1);
        let mut journal = RetentionJournal::begin_start(dir.path(), first.clone()).unwrap();
        journal
            .confirm(Some(serde_json::json!({"memory": 256})))
            .unwrap();
        let before = RetentionJournal::read(dir.path()).unwrap().unwrap();
        assert!(before.current(&first).is_some());
        let second = owner("second", 2);
        let mut next = RetentionJournal::begin_start(dir.path(), second.clone()).unwrap();
        assert!(next.record().current(&second).is_none());
        assert!(next.record().current(&first).is_none());
        assert_eq!(next.record().confirmed.as_ref().unwrap().generation, 1);
        next.confirm(Some(serde_json::json!({"memory": 512})))
            .unwrap();
        assert_eq!(next.record().current(&second).unwrap().generation, 2);
    }

    #[test]
    fn confirmation_failure_and_later_partial_success_remain_unknown() {
        for after_publication in [false, true] {
            let dir = tempfile::tempdir().unwrap();
            let owner = owner("boot", 1);
            let mut journal = RetentionJournal::begin_start(dir.path(), owner.clone()).unwrap();
            journal
                .confirm(Some(serde_json::json!({"memory": 256})))
                .unwrap();
            journal.begin_modify().unwrap();
            assert!(
                RetentionJournal::read(dir.path())
                    .unwrap()
                    .unwrap()
                    .current(&owner)
                    .is_none()
            );
            let result =
                journal.confirm_with(Some(serde_json::json!({"memory": 512})), |store, record| {
                    if after_publication {
                        store.write(record)?;
                    }
                    Err(io::Error::other("injected confirmation failure"))
                });
            assert!(result.is_err());
            assert!(journal.record().current(&owner).is_none());
            assert_eq!(
                journal
                    .record()
                    .confirmed
                    .as_ref()
                    .unwrap()
                    .source
                    .as_ref()
                    .unwrap()["memory"],
                256
            );
            journal.begin_modify().unwrap();
            journal
                .confirm(Some(serde_json::json!({"memory": 512, "cpus": 2})))
                .unwrap();
            assert!(journal.record().current(&owner).is_none());
            assert_eq!(journal.record().uncertain_since, Some(2));
        }
    }

    #[test]
    fn failed_prepare_preserves_previous_confirmed_state_and_generation() {
        let dir = tempfile::tempdir().unwrap();
        let owner = owner("boot", 1);
        let mut journal = RetentionJournal::begin_start(dir.path(), owner.clone()).unwrap();
        journal.confirm(Some(serde_json::json!({}))).unwrap();
        let record = journal.directory.join(RECORD);
        fs::rename(&record, journal.directory.join("previous")).unwrap();
        fs::create_dir(&record).unwrap();
        assert!(journal.begin_modify().is_err());
        assert_eq!(journal.record().generation, 1);
        assert!(journal.record().current(&owner).is_some());
        fs::remove_dir(record).unwrap();
    }

    #[test]
    fn unsupported_launcher_or_changed_owner_never_invents_configuration() {
        let dir = tempfile::tempdir().unwrap();
        let owner = owner("boot", 1);
        let mut journal = RetentionJournal::begin_start(dir.path(), owner.clone()).unwrap();
        journal.confirm(None).unwrap();
        assert!(journal.record().current(&owner).is_none());
        journal.begin_modify().unwrap();
        journal.confirm(Some(serde_json::json!({}))).unwrap();
        for changed in [
            RetentionOwner {
                runtime_boot_id: "other".into(),
                ..owner.clone()
            },
            RetentionOwner {
                run_id: 2,
                ..owner.clone()
            },
            RetentionOwner {
                catalog_file: [1, 9],
                ..owner.clone()
            },
            RetentionOwner {
                sandbox_created_at: None,
                ..owner.clone()
            },
        ] {
            assert!(journal.record().current(&changed).is_none());
        }
    }

    #[test]
    fn terminal_receipt_requires_matching_catalog_source_and_generation() {
        let dir = tempfile::tempdir().unwrap();
        let owner = owner("boot", 1);
        let source = serde_json::json!({"env": ["PRIVATE_SENTINEL"], "labels": {"stage": "one"}});
        let mut journal = RetentionJournal::begin_start(dir.path(), owner.clone()).unwrap();
        journal.confirm(Some(source.clone())).unwrap();

        for active in [
            None,
            Some(serde_json::json!({"env": ["PRIVATE_SENTINEL"], "labels": {"stage": "two"}})),
        ] {
            publish_terminal(
                dir.path(),
                journal.record(),
                active.as_ref(),
                RetentionTerminalOrigin::RuntimeExit,
            )
            .unwrap();
            assert!(
                RetentionJournal::read_terminal(dir.path())
                    .unwrap()
                    .unwrap()
                    .current(&owner, journal.record())
                    .is_none()
            );
        }
        publish_terminal(
            dir.path(),
            journal.record(),
            Some(&source),
            RetentionTerminalOrigin::RuntimeExit,
        )
        .unwrap();
        let receipt = RetentionJournal::read_terminal(dir.path())
            .unwrap()
            .unwrap();
        assert!(receipt.current(&owner, journal.record()).is_some());
        let bytes = fs::read_to_string(dir.path().join(DIRECTORY).join(TERMINAL)).unwrap();
        assert!(!bytes.contains("PRIVATE_SENTINEL"));
        assert!(!bytes.contains("labels"));

        journal.begin_modify().unwrap();
        assert!(receipt.current(&owner, journal.record()).is_none());
        journal.confirm(Some(source.clone())).unwrap();
        assert!(receipt.current(&owner, journal.record()).is_none());
        publish_terminal(
            dir.path(),
            journal.record(),
            Some(&source),
            RetentionTerminalOrigin::ReconciledDeath,
        )
        .unwrap();
        let receipt = RetentionJournal::read_terminal(dir.path())
            .unwrap()
            .unwrap();
        assert!(receipt.current(&owner, journal.record()).is_some());

        let replacement_owner = RetentionOwner {
            runtime_boot_id: "other".into(),
            run_id: 2,
            run_started_at: "start-2".into(),
            ..owner.clone()
        };
        let replacement = RetentionJournal::begin_start(dir.path(), replacement_owner).unwrap();
        assert!(
            receipt
                .current(&replacement.record().owner, replacement.record())
                .is_none()
        );
    }

    #[tokio::test]
    async fn terminal_catalog_admission_preserves_receipts_after_cleanup_and_reads_old_schemas() {
        let dir = tempfile::tempdir().unwrap();
        let catalog = dir.path().join("catalog.db");
        let db = microsandbox_db::DbWriteConnection::open(
            &catalog,
            std::time::Duration::from_secs(1),
            std::time::Duration::from_secs(1),
        )
        .await
        .unwrap();
        db.execute_unprepared(
            "CREATE TABLE sandbox (id INTEGER PRIMARY KEY, created_at TEXT, active_config TEXT);
             CREATE TABLE run (id INTEGER PRIMARY KEY, sandbox_id INTEGER, started_at TEXT);
             INSERT INTO sandbox VALUES (1, 'sandbox-created', '{\"labels\":{}}');
             INSERT INTO run VALUES (1, 1, 'run-started');",
        )
        .await
        .unwrap();
        let owner = RetentionOwner::for_run(&db, &catalog, 1, 1, "boot".into())
            .await
            .unwrap();
        let source = serde_json::json!({"labels": {}});
        let mut journal = RetentionJournal::begin_start(dir.path(), owner.clone()).unwrap();
        journal.confirm(Some(source.clone())).unwrap();
        assert!(
            !seal_terminal(
                &db,
                dir.path(),
                1,
                1,
                Some("wrong-boot"),
                RetentionTerminalOrigin::RuntimeExit,
            )
            .await
            .unwrap()
        );
        assert!(
            RetentionJournal::read_terminal(dir.path())
                .unwrap()
                .is_none()
        );
        assert!(
            seal_terminal(
                &db,
                dir.path(),
                1,
                1,
                Some("boot"),
                RetentionTerminalOrigin::RuntimeExit,
            )
            .await
            .unwrap()
        );
        assert!(
            RetentionJournal::read_terminal(dir.path())
                .unwrap()
                .unwrap()
                .current(&owner, journal.record())
                .is_some()
        );
        db.execute_unprepared("UPDATE sandbox SET active_config = NULL")
            .await
            .unwrap();
        seal_terminal(
            &db,
            dir.path(),
            1,
            1,
            None,
            RetentionTerminalOrigin::ReconciledDeath,
        )
        .await
        .unwrap();
        assert!(
            RetentionJournal::read_terminal(dir.path())
                .unwrap()
                .unwrap()
                .current(&owner, journal.record())
                .is_some()
        );

        // A later generation cannot borrow the old receipt. Missing historical columns are
        // observed as unavailable evidence; no schema creation or fallback write is attempted.
        journal.begin_modify().unwrap();
        journal.confirm(Some(source)).unwrap();
        db.execute_unprepared("ALTER TABLE sandbox DROP COLUMN active_config")
            .await
            .unwrap();
        seal_terminal(
            &db,
            dir.path(),
            1,
            1,
            None,
            RetentionTerminalOrigin::ReconciledDeath,
        )
        .await
        .unwrap();
        assert!(
            RetentionJournal::read_terminal(dir.path())
                .unwrap()
                .unwrap()
                .current(&owner, journal.record())
                .is_none()
        );
        assert!(
            !microsandbox_db::catalog::has_column(&db, "sandbox", "active_config")
                .await
                .unwrap()
        );
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use capture::{CapturedConfiguration, disk_configuration_root};
#[cfg(feature = "runner")]
pub(crate) use capture::{ConfigurationCaptureContext, PreparedConfigurationReceipt};
pub use init::read_retained_init;
pub use live::LiveConfigurationSelection;
pub use script_backing::{
    CapturedScriptBacking, CapturedScriptDirectory, ScriptBackingEvidence, ScriptBackingUnknown,
};
pub use selection::select_stopped_configuration;

pub use mounted_storage::{MountedFilesystem, MountedFilesystemKind, MountedStorageEvidence};
