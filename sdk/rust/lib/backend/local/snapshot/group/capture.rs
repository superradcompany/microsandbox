//! Capture destination identity and ownership of unpublished groups, including cancellation cleanup.

use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use microsandbox_utils::process_lock;

use super::super::source::Source;
use super::super::writer::WriterLease;
use super::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const OWNER_FILENAME: &str = ".capture-owner";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Clones retain name ownership until every capture/publication worker has finished.
#[derive(Clone)]
pub(crate) struct CaptureReservation {
    inner: Arc<Reservation>,
}

/// Non-locking identity pin for an existing capture destination. Holding its file
/// prevents inode reuse; ordinary generation exchanges preserve this same lock inode.
pub(in crate::backend::local::snapshot) struct CaptureTarget {
    lock: File,
    source: Source,
}

struct Reservation {
    directory: PathBuf,
    token: String,
    writer: WriterLease,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CaptureTarget {
    /// Capture against the source binding validated in this admission interval.
    pub(in crate::backend::local::snapshot) async fn admit(
        directory: &Path,
        source: Source,
    ) -> MicrosandboxResult<Self> {
        let writer = WriterLease::acquire(directory).await?;
        let directory = directory.to_path_buf();
        super::blocking(move || {
            let _writer = writer;
            let group_lock = super::lock_group(&directory)?;
            super::require_source(&directory, &source)?;
            // Open separately rather than clone the locked descriptor: a clone would
            // keep its OS lock and block imports throughout guest capture.
            let lock = open_identity_file(&directory)?;
            if super::super::file_identity::key(&lock)?
                != super::super::file_identity::key(&group_lock)?
            {
                return Err(super::integrity(
                    "capture destination changed during admission".into(),
                ));
            }
            Ok(Self { lock, source })
        })
        .await
    }

    /// The publisher already owns writer admission. Recheck before preparing any
    /// catalog publication intent, including recreation bound to the same sandbox.
    pub(in crate::backend::local::snapshot) async fn validate(
        self,
        directory: &Path,
    ) -> MicrosandboxResult<()> {
        let directory = directory.to_path_buf();
        super::blocking(move || {
            // Do not create a missing lock or recover a replacement history before
            // establishing that this is the destination admitted before capture.
            let current = open_identity_file(&directory)?;
            if super::super::file_identity::key(&self.lock)?
                != super::super::file_identity::key(&current)?
            {
                return Err(super::integrity(format!(
                    "snapshot group '{}' was removed or replaced during capture; checkpoint was not published",
                    directory.display()
                )));
            }
            process_lock::lock_exclusive(&current)?;
            super::read_group(&directory)?;
            super::require_source(&directory, &self.source)
        }).await
    }
}

impl CaptureReservation {
    pub(crate) fn directory(&self) -> &Path {
        &self.inner.directory
    }

    pub(crate) fn writer(&self) -> WriterLease {
        self.inner.writer.clone()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for Reservation {
    fn drop(&mut self) {
        // Keep external writer ownership until rollback is complete. Cleanup only
        // recognizes this attempt's token and never removes a published checkpoint.
        if let Err(error) = retire_empty(&self.directory, &self.token) {
            tracing::warn!(%error, path = %self.directory.display(), "initial capture cleanup remains recoverable");
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn open_identity_file(directory: &Path) -> std::io::Result<File> {
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    let file = options.open(directory.join(".group.lock"))?;
    if !file.metadata()?.is_file() {
        return Err(std::io::Error::other(
            "capture destination lock is not a regular file",
        ));
    }
    Ok(file)
}

pub(super) fn claim(
    root: &Path,
    name: &str,
    source: Source,
) -> MicrosandboxResult<CaptureReservation> {
    super::validate_group_name(name)?;
    fs::create_dir_all(root)?;
    super::require_directory(root)?;
    let creation = process_lock::open_lock_file(&root.join(".groups.lock"))?;
    process_lock::lock_exclusive(&creation)?;
    let directory = root.canonicalize()?.join(name);
    let writer = WriterLease::try_reserve(&directory)?
        .ok_or_else(|| MicrosandboxError::SnapshotAlreadyExists(name.into()))?;
    if super::path_exists(&directory)? {
        super::require_directory(&directory)?;
        // A terminated creator may have left an unpublished reservation. Recover
        // only a marked attempt while owning its stable writer key, never by name alone.
        if super::path_exists(&directory.join(OWNER_FILENAME))? {
            let token: String = serde_json::from_slice(&super::read_regular(
                &directory.join(OWNER_FILENAME),
                128,
            )?)?;
            retire_empty(&directory, &token)?;
        }
        if super::path_exists(&directory)? {
            return Err(MicrosandboxError::SnapshotAlreadyExists(name.into()));
        }
    }
    let staged = tempfile::Builder::new()
        .prefix(".group-new-")
        .tempdir_in(root)?;
    let token = format!("{:032x}", rand::random::<u128>());
    super::write_json(
        staged.path(),
        super::CREATING_FILENAME,
        &super::CREATING_SCHEMA,
    )?;
    super::write_json(
        staged.path(),
        super::super::source::SOURCE_FILENAME,
        &source,
    )?;
    super::write_json(staged.path(), OWNER_FILENAME, &token)?;
    process_lock::create_new_lock_file(&staged.path().join(".group.lock"))?.sync_all()?;
    super::sync_directory(staged.path())?;
    fs::rename(staged.path(), &directory)?;
    let reservation = CaptureReservation {
        inner: Arc::new(Reservation {
            directory,
            token,
            writer,
        }),
    };
    // Construct rollback ownership before this fallible flush. Cancellation or a
    // flush error must not strand an empty, apparently successful history.
    super::sync_directory(root)?;
    Ok(reservation)
}

fn retire_empty(directory: &Path, token: &str) -> MicrosandboxResult<()> {
    if !super::path_exists(directory)? {
        return Ok(());
    }
    if !super::path_exists(&directory.join(OWNER_FILENAME))? {
        return Ok(());
    }
    let current: String =
        serde_json::from_slice(&super::read_regular(&directory.join(OWNER_FILENAME), 128)?)?;
    if current != token {
        return Ok(());
    }
    let lock = process_lock::open_existing_lock_file(&directory.join(".group.lock"))?;
    if !process_lock::try_lock_exclusive(&lock)? {
        return Err(super::integrity(
            "capture reservation is still in use; cleanup will retry".into(),
        ));
    }
    super::transaction::recover(directory)?;
    if super::path_exists(&directory.join(super::GROUP_FILENAME))?
        || !super::read_members(directory, true)?.is_empty()
    {
        // Published state wins, including a successful capture followed by source
        // recovery failure. Never undo that publication while unwinding an error.
        fs::remove_file(directory.join(OWNER_FILENAME))?;
        super::sync_directory(directory)?;
        return Ok(());
    }
    if !super::is_creating(directory)? {
        return Ok(());
    }
    let parent = directory
        .parent()
        .ok_or_else(|| super::integrity("capture group has no parent".into()))?;
    let retired = parent.join(format!(".capture-aborted-{:032x}", rand::random::<u128>()));
    fs::rename(directory, &retired)?;
    super::sync_directory(parent)?;
    drop(lock);
    fs::remove_dir_all(retired)?;
    super::sync_directory(parent)?;
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::tests::{descriptor, id, stage};
    use super::*;

    async fn source(home: &Path) -> Source {
        let local = crate::test_support::local_backend_builder(home)
            .build()
            .await
            .unwrap();
        Source::capture(local.db().await.unwrap().write(), 1, "source")
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn capture_target_rejects_group_recreation_even_with_the_same_source() {
        for replacement in ["same", "other", "unbound", "missing", "missing-lock"] {
            let root = tempfile::tempdir().unwrap();
            let source = source(&root.path().join("home")).await;
            let directory = super::super::ensure_capture(root.path(), "history", source.clone())
                .await
                .unwrap();
            let target = CaptureTarget::admit(&directory, source.clone())
                .await
                .unwrap();
            // The retained identity must not own writer admission. A parallel test's
            // fork can briefly inherit the released flock until its child execs, so
            // bound reacquisition instead of requiring scheduler-dependent immediacy.
            let writer = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                WriterLease::acquire(&directory),
            )
            .await
            .expect("capture identity retained writer admission")
            .unwrap();
            drop(writer);
            fs::remove_dir_all(&directory).unwrap();
            match replacement {
                "same" => {
                    super::super::ensure_capture(root.path(), "history", source)
                        .await
                        .unwrap();
                }
                "other" => {
                    let other = self::source(&root.path().join("other-home")).await;
                    super::super::ensure_capture(root.path(), "history", other)
                        .await
                        .unwrap();
                }
                "unbound" | "missing-lock" => {
                    super::super::ensure(root.path(), Some("history"))
                        .await
                        .unwrap();
                    if replacement == "missing-lock" {
                        fs::remove_file(directory.join(".group.lock")).unwrap();
                    }
                }
                _ => {}
            }
            let _writer = if directory.exists() {
                WriterLease::try_acquire(&directory).unwrap()
            } else {
                None
            };
            assert!(target.validate(&directory).await.is_err(), "{replacement}");
            if replacement == "missing-lock" {
                assert!(!directory.join(".group.lock").exists());
            }
        }
    }

    #[tokio::test]
    async fn capture_target_rechecks_the_binding_without_requiring_a_writable_lock() {
        let root = tempfile::tempdir().unwrap();
        let original = source(&root.path().join("home")).await;
        let other = source(&root.path().join("other-home")).await;
        let directory = super::super::ensure_capture(root.path(), "history", original.clone())
            .await
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                directory.join(".group.lock"),
                fs::Permissions::from_mode(0o400),
            )
            .unwrap();
        }
        let target = CaptureTarget::admit(&directory, original).await.unwrap();
        let _writer = WriterLease::acquire(&directory).await.unwrap();
        super::super::write_json(
            &directory,
            super::super::super::source::SOURCE_FILENAME,
            &other,
        )
        .unwrap();
        let error = target.validate(&directory).await.unwrap_err();
        assert!(
            error
                .to_string()
                .contains("bound to another sandbox instance"),
            "{error}"
        );
    }

    #[tokio::test]
    async fn capture_target_survives_generation_exchange_without_blocking_publication() {
        let root = tempfile::tempdir().unwrap();
        let source = source(&root.path().join("home")).await;
        let directory = super::super::ensure_capture(root.path(), "history", source.clone())
            .await
            .unwrap();
        let target = CaptureTarget::admit(&directory, source).await.unwrap();
        let incoming = stage(root.path(), &[descriptor(1, None)]);
        tokio::time::timeout(
            std::time::Duration::from_secs(5),
            super::super::publish(&directory, incoming.path(), &BTreeMap::new(), &id(1), false),
        )
        .await
        .expect("identity pin blocked group publication")
        .unwrap();
        let _writer = WriterLease::acquire(&directory).await.unwrap();
        target.validate(&directory).await.unwrap();
    }

    #[test]
    fn reservation_is_hidden_and_last_worker_drop_releases_its_name() {
        // A sibling test can fork while this fixture holds writer admission. Its child
        // retains the descriptor until exec, so immediate reuse needs process isolation.
        // Keep every ownership and cleanup assertion in the isolated worker below.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::local::snapshot::group::capture::tests::hidden_reservation_cleanup_worker",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    #[ignore = "subprocess-only reservation cleanup assertions"]
    async fn hidden_reservation_cleanup_worker() {
        let root = tempfile::tempdir().unwrap();
        let source = source(&root.path().join("home")).await;
        let directory = root.path().join("snapshots");
        let reservation = claim(&directory, "history", source.clone()).unwrap();
        let worker = reservation.clone();
        assert!(
            !reservation
                .directory()
                .join(super::super::GROUP_FILENAME)
                .exists()
        );
        assert!(
            WriterLease::try_acquire(reservation.directory())
                .unwrap()
                .is_none()
        );
        drop(reservation);
        assert!(directory.join("history").is_dir());
        assert!(claim(&directory, "history", source.clone()).is_err());
        // An unrelated group need not wait for this capture to finish.
        drop(claim(&directory, "other", source.clone()).unwrap());
        drop(worker);
        assert!(!directory.join("history").exists());
        drop(claim(&directory, "history", source).unwrap());
        assert!(!directory.join("history").exists());
    }

    #[test]
    fn published_checkpoint_survives_reservation_error_cleanup() {
        // Unrelated tests can fork while publication holds the group lock. The child
        // inherits that lock until exec, so immediate marker cleanup is not guaranteed
        // in the parallel parent harness. Isolate the no-contention assertion and test
        // deliberately deferred cleanup separately inside the worker.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::local::snapshot::group::capture::tests::published_reservation_cleanup_worker",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    #[ignore = "subprocess-only reservation cleanup assertions"]
    async fn published_reservation_cleanup_worker() {
        for busy in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let source = source(&root.path().join("home")).await;
            let reservation = claim(root.path(), "history", source).unwrap();
            let directory = reservation.directory().to_path_buf();
            let token = reservation.inner.token.clone();
            let staged = stage(root.path(), &[descriptor(1, None)]);
            let update = super::super::publish_admitted(
                &directory,
                staged.path(),
                &BTreeMap::new(),
                &id(1),
                reservation.writer(),
            )
            .await
            .unwrap();
            assert_eq!(update.head, Some(id(1).to_string()));
            let reader = if busy {
                let lock =
                    process_lock::open_existing_lock_file(&directory.join(".group.lock")).unwrap();
                process_lock::lock_shared(&lock).unwrap();
                Some(lock)
            } else {
                None
            };
            // Same drop path runs when publication succeeded but source recovery failed.
            drop(reservation);
            assert!(directory.join(id(1).as_str()).is_dir());
            assert_eq!(
                super::super::read_group(&directory).unwrap().head,
                Some(id(1).to_string())
            );
            assert_eq!(directory.join(OWNER_FILENAME).exists(), busy);
            drop(reader);
            if busy {
                // Deferred cleanup must remain retryable without undoing published state.
                retire_empty(&directory, &token).unwrap();
                assert!(!directory.join(OWNER_FILENAME).exists());
                assert!(directory.join(id(1).as_str()).is_dir());
                assert_eq!(
                    super::super::read_group(&directory).unwrap().head,
                    Some(id(1).to_string())
                );
            }
        }
    }

    #[tokio::test]
    async fn cleanup_never_deletes_a_different_attempt_at_the_same_name() {
        let root = tempfile::tempdir().unwrap();
        let source = source(&root.path().join("home")).await;
        let reservation = claim(root.path(), "history", source).unwrap();
        let directory = reservation.directory().to_path_buf();
        super::super::write_json(&directory, OWNER_FILENAME, &"another-owner").unwrap();
        drop(reservation);
        assert!(directory.exists());
        assert_eq!(
            serde_json::from_slice::<String>(&fs::read(directory.join(OWNER_FILENAME)).unwrap())
                .unwrap(),
            "another-owner"
        );
    }

    #[test]
    fn abandoned_empty_reservation_is_recovered_before_retry() {
        // Model a terminated creator after all of its descriptors have closed.
        // Concurrent subprocess tests can briefly inherit its lock across fork,
        // so run this immediate-reclaim assertion in its own process.
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "backend::local::snapshot::group::capture::tests::abandoned_reservation_worker",
                "--ignored",
                "--nocapture",
            ])
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{}\n{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[tokio::test]
    #[ignore = "subprocess-only immediate reservation recovery"]
    async fn abandoned_reservation_worker() {
        let root = tempfile::tempdir().unwrap();
        let source = source(&root.path().join("home")).await;
        let reservation = claim(root.path(), "history", source.clone()).unwrap();
        let directory = reservation.directory().to_path_buf();
        let records = [
            OWNER_FILENAME,
            super::super::CREATING_FILENAME,
            super::super::super::source::SOURCE_FILENAME,
        ]
        .map(|name| (name, fs::read(directory.join(name)).unwrap()));
        drop(reservation);
        // Reconstruct the on-disk state left by a killed creator after the OS
        // releases its writer lock. No live lease is silently bypassed.
        fs::create_dir(&directory).unwrap();
        for (name, bytes) in records {
            fs::write(directory.join(name), bytes).unwrap();
        }
        process_lock::create_new_lock_file(&directory.join(".group.lock")).unwrap();
        let retried = claim(root.path(), "history", source).unwrap();
        assert!(
            !retried
                .directory()
                .join(super::super::GROUP_FILENAME)
                .exists()
        );
        drop(retried);
        assert!(!directory.exists());
    }

    #[test]
    fn cancelled_creation_waiter_does_not_leave_a_group() {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .max_blocking_threads(1)
            .build()
            .unwrap()
            .block_on(async {
                let root = tempfile::tempdir().unwrap();
                let source = source(&root.path().join("home")).await;
                let directory = root.path().join("snapshots");
                let (started, ready) = tokio::sync::oneshot::channel();
                let (release, wait) = std::sync::mpsc::channel();
                let blocker = tokio::task::spawn_blocking(move || {
                    started.send(()).unwrap();
                    wait.recv_timeout(std::time::Duration::from_secs(5))
                        .unwrap();
                });
                ready.await.unwrap();
                let mut creation = Box::pin(super::super::ensure_new_capture(
                    &directory,
                    "cancelled",
                    source,
                ));
                assert!(futures::poll!(creation.as_mut()).is_pending());
                drop(creation);
                release.send(()).unwrap();
                blocker.await.unwrap();
                tokio::task::spawn_blocking(|| {}).await.unwrap();
                assert!(!directory.join("cancelled").exists());
            });
    }
}
