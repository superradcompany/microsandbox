//! Preserve the exact stopped identity until its replacement publishes.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use microsandbox_db::DbWriteConnection;
use microsandbox_utils::private_file;
use sea_orm::{ConnectionTrait, DatabaseBackend, Statement};

use super::{LocalContext, creation};
use crate::context::local::creation::CreationStorage;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(super) struct Attempt {
    pub(super) name: String,
    pub(super) token: Option<String>,
    pub(super) original: i32,
}

struct Record {
    original: i32,
    candidate: Option<i32>,
    token: String,
    had_directory: bool,
    published: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalContext {
    pub(super) async fn finish_replacement(&self, attempt: &Attempt) -> MicrosandboxResult<bool> {
        let _guard =
            Self::acquire_sandbox_transition_guard(&self.config().run_dir(), &attempt.name).await?;
        if let Some(token) = &attempt.token
            && self.recover_replacement(&attempt.name, Some(token)).await?
        {
            return Ok(true);
        }
        // A different client may already have recovered this very attempt, or
        // parking may have failed after shutdown but before releasing the name.
        Ok(self
            .db()
            .await?
            .write()
            .query_one_raw(sql(
                "SELECT id FROM sandbox WHERE id = ? AND name = ? AND status = 'Stopped'",
                [attempt.original.into(), attempt.name.as_str().into()],
            ))
            .await?
            .is_some())
    }

    /// Called by name-based lookups before selecting an identity. Never wait on
    /// ordinary reads unless this specific sandbox has a replacement in progress.
    pub(crate) async fn recover_replacement_for_lookup(
        &self,
        name: &str,
    ) -> MicrosandboxResult<()> {
        if name.starts_with(".msb-retained-") {
            return Err(MicrosandboxError::Runtime(
                "sandbox is retained for replacement recovery".into(),
            ));
        }
        let pools = self.db().await?;
        if storage_token(pools.write(), name).await?.is_some() {
            let file = super::open_transition_lock(&self.config().run_dir(), name).await?;
            if !microsandbox_utils::process_lock::try_lock_exclusive(&file)? {
                return Err(MicrosandboxError::Runtime(format!(
                    "replacement for {name:?} is in progress"
                )));
            }
            self.recover_replacement(name, None).await?;
        }
        Ok(())
    }

    /// Caller owns the name transition. An attempt token prevents a returning
    /// caller from rolling back a later replacement that has reused the same name.
    pub(crate) async fn recover_replacement(
        &self,
        name: &str,
        expected: Option<&str>,
    ) -> MicrosandboxResult<bool> {
        let pools = self.db().await?;
        let db = pools.write();
        let Some(token) = storage_token(db, name).await? else {
            return Ok(false);
        };
        if expected.is_some_and(|expected| expected != token) {
            return Ok(false);
        }
        let Some(record) = lookup(db, name).await? else {
            clear_storage(db, &self.sandboxes_dir(), name, &token).await?;
            return Ok(false);
        };
        if token != record.token {
            return Err(MicrosandboxError::Runtime(
                "replacement storage identity mismatch".into(),
            ));
        }

        let root = self.sandboxes_dir();
        let saved = backup_dir(&root, &record.token)?;
        let original = record.original;
        if !record.published {
            let _lineage =
                crate::snapshot::lineage::lock_source(&self.config().run_dir(), name).await?;
            let current = db
                .query_one_raw(sql("SELECT id FROM sandbox WHERE name = ?", [name.into()]))
                .await?
                .map(|row| row.try_get::<i32>("", "id"))
                .transpose()?;
            if current.is_some() && current != record.candidate {
                return Err(MicrosandboxError::Runtime(format!(
                    "replacement recovery found an unexpected sandbox at {name:?}"
                )));
            }
            let run_dir = self.config().run_dir();
            let pid = match current {
                Some(id) => Self::load_latest_run(pools.read(), id)
                    .await?
                    .and_then(|run| run.pid),
                None => None,
            };
            #[cfg(any(target_os = "linux", target_os = "macos"))]
            let departing = super::super::process_exit::RuntimeExit::capture(
                pid,
                &microsandbox_runtime::ipc::lifecycle_lock_path(&run_dir, name),
            )?;
            let _runtime =
                match microsandbox_runtime::ipc::try_acquire_lifecycle_guard(&run_dir, name)? {
                    Some(guard) => guard,
                    None => {
                        // Creator death can leave an unpublished detached guest alive. The
                        // agent path checks the exact catalog identity before dispatch.
                        let id = current.ok_or_else(|| {
                            MicrosandboxError::Runtime(format!(
                                "runtime ownership unresolved for {name:?}"
                            ))
                        })?;
                        self.request_agent_shutdown(name, id).await?;
                        crate::runtime::acquire_sandbox_lifecycle_guard(
                            &run_dir,
                            name,
                            Duration::from_secs(10),
                        )
                        .await?
                    }
                };
            if let Some(id) = current {
                // The runtime can drop its lifecycle lock before its final disk
                // descriptors close. Observe process-wide exit without reaping it.
                let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
                loop {
                    #[cfg(any(target_os = "linux", target_os = "macos"))]
                    let exited = match &departing {
                        Some(process) => process.has_exited()?,
                        None => pid.is_none_or(Self::pid_has_exited),
                    };
                    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                    let exited = pid.is_none_or(Self::pid_has_exited);
                    if exited {
                        break;
                    }
                    if tokio::time::Instant::now() >= deadline {
                        return Err(MicrosandboxError::Runtime(format!(
                            "replacement runtime for {name:?} still owns its files"
                        )));
                    }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
                self.remove_incomplete_sandbox(id, name, creation::RemovalMode::Recovery)
                    .await?;
            }
            let _storage = CreationStorage::acquire(self, name)?;
            let public = root.join(name);
            let source = saved.join("original");
            if record.had_directory && !source.is_dir() {
                return Err(MicrosandboxError::Runtime(format!(
                    "missing retained storage for sandbox {name:?}"
                )));
            }
            crate::sandbox::remove_dir_if_exists(&public)?;
            if record.had_directory {
                let tree = saved.join("tree");
                if tree.try_exists()? {
                    move_stopped_directory(&tree, &public).await?;
                    sync_dir(&saved)?;
                } else {
                    retain_tree(&source, &public)?;
                }
            }
            sync_dir(&root)?;
        }
        if record.published {
            microsandbox_runtime::checkpoint::remove_sandbox_identity(
                &self.config().home(),
                original,
            )
            .map_err(MicrosandboxError::Runtime)?;
        }
        db.transaction(|txn| {
            let token = &token;
            async move {
                let removed = txn
                    .execute_raw(sql(
                        "DELETE FROM sandbox_replacement WHERE original = ? AND token = ?",
                        [original.into(), token.as_str().into()],
                    ))
                    .await?;
                if removed.rows_affected() != 1 {
                    return Err(MicrosandboxError::Runtime(
                        "replacement journal changed during recovery".into(),
                    ));
                }
                if record.published {
                    txn.execute_raw(sql("DELETE FROM sandbox WHERE id = ?", [original.into()]))
                        .await?;
                } else {
                    txn.execute_raw(sql(
                        "UPDATE sandbox SET name = ? WHERE id = ?",
                        [name.into(), original.into()],
                    ))
                    .await?;
                }
                Ok((txn, ()))
            }
        })
        .await?;
        clear_storage(db, &root, name, &token).await?;
        Ok(!record.published)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn sql(query: &str, args: impl IntoIterator<Item = sea_orm::Value>) -> Statement {
    Statement::from_sql_and_values(DatabaseBackend::Sqlite, query, args)
}

async fn lookup(db: &DbWriteConnection, name: &str) -> MicrosandboxResult<Option<Record>> {
    if !microsandbox_db::catalog::has_table(db, "sandbox_replacement").await? {
        return Ok(None);
    }
    db.query_one_raw(sql(
        "SELECT * FROM sandbox_replacement WHERE name = ?",
        [name.into()],
    ))
    .await?
    .map(|row| {
        Ok(Record {
            original: row.try_get("", "original")?,
            candidate: row.try_get("", "candidate")?,
            token: row.try_get("", "token")?,
            published: row.try_get("", "published")?,
            had_directory: row.try_get("", "had_directory")?,
        })
    })
    .transpose()
}

async fn storage_token(db: &DbWriteConnection, name: &str) -> MicrosandboxResult<Option<String>> {
    if !microsandbox_db::catalog::has_table(db, "sandbox_replacement_storage").await? {
        return Ok(None);
    }
    db.query_one_raw(sql(
        "SELECT token FROM sandbox_replacement_storage WHERE name = ?",
        [name.into()],
    ))
    .await?
    .map(|row| Ok(row.try_get("", "token")?))
    .transpose()
}

async fn clear_storage(
    db: &DbWriteConnection,
    root: &Path,
    name: &str,
    token: &str,
) -> MicrosandboxResult<()> {
    crate::sandbox::remove_dir_if_exists(&backup_dir(root, token)?)?;
    db.execute_raw(sql(
        "DELETE FROM sandbox_replacement_storage WHERE name = ? AND token = ?",
        [name.into(), token.into()],
    ))
    .await?;
    Ok(())
}

fn backup_dir(root: &Path, token: &str) -> MicrosandboxResult<PathBuf> {
    if !token.starts_with("saved-")
        || !token
            .bytes()
            .all(|b| b == b'-' || b.is_ascii_alphanumeric())
    {
        return Err(MicrosandboxError::Runtime(
            "invalid replacement recovery token".into(),
        ));
    }
    Ok(root.join(".msb-replacements").join(token))
}

fn sync_dir(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    fs::File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

async fn move_stopped_directory(source: &Path, target: &Path) -> io::Result<()> {
    #[cfg(windows)]
    {
        // Windows may briefly deny a directory rename while the filesystem
        // finishes closing handles to a stopped guest's disk. Keep ownership
        // throughout the retry and surface persistent denials to the caller.
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            match fs::rename(source, target) {
                Err(error)
                    if matches!(error.raw_os_error(), Some(5 | 32 | 33))
                        && tokio::time::Instant::now() < deadline =>
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
                result => return result,
            }
        }
    }
    #[cfg(not(windows))]
    fs::rename(source, target)
}

/// Sandbox files can be sparse. Link the stopped generation before releasing its
/// name so even an older remover unlinking the public tree cannot destroy it.
/// Each directory is independent. Links to external files are never followed.
fn retain_tree(source: &Path, target: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(source)?;
    let kind = metadata.file_type();
    if kind.is_dir() {
        fs::create_dir(target)?;
        for entry in fs::read_dir(source)? {
            let entry = entry?;
            retain_tree(&entry.path(), &target.join(entry.file_name())).map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("retaining {}: {error}", entry.path().display()),
                )
            })?;
        }
        fs::set_permissions(target, metadata.permissions())?;
        return sync_dir(target);
    }
    if kind.is_symlink() {
        #[cfg(unix)]
        return std::os::unix::fs::symlink(fs::read_link(source)?, target);
        #[cfg(windows)]
        {
            use std::os::windows::fs::{FileTypeExt, symlink_dir, symlink_file};
            let link = fs::read_link(source)?;
            return if kind.is_symlink_dir() {
                symlink_dir(link, target)
            } else {
                symlink_file(link, target)
            };
        }
    }
    if !kind.is_file() {
        return Err(io::Error::other(format!(
            "cannot retain special sandbox file {}",
            source.display()
        )));
    }
    if fs::hard_link(source, target).is_err() {
        microsandbox_utils::copy::fast_copy(source, target)?;
        fs::set_permissions(target, metadata.permissions())?;
    }
    Ok(())
}

pub(super) async fn retain_ephemeral(db: &DbWriteConnection, id: i32) -> MicrosandboxResult<()> {
    db.execute_unprepared(include_str!("replacement.sql"))
        .await?;
    db.transaction(|txn| async move {
        txn.execute_raw(sql("INSERT OR IGNORE INTO sandbox_replacement_ephemeral(original) SELECT id FROM sandbox WHERE id = ? AND ephemeral = 1", [id.into()])).await?;
        txn.execute_raw(sql("UPDATE sandbox SET ephemeral = 0 WHERE id = ? AND ephemeral = 1", [id.into()])).await?;
        Ok::<_, MicrosandboxError>((txn, ()))
    }).await
}

pub(super) async fn park(
    db: &DbWriteConnection,
    name: &str,
    original: i32,
    directory: &Path,
    attempt: &mut Option<Attempt>,
) -> MicrosandboxResult<()> {
    let root = directory
        .parent()
        .ok_or_else(|| io::Error::other("missing sandboxes root"))?;
    let backups = root.join(".msb-replacements");
    private_file::create_private_dir_all(&backups)?;
    let temp = tempfile::Builder::new()
        .prefix("saved-")
        .tempdir_in(&backups)?;
    let token = temp
        .path()
        .file_name()
        .unwrap()
        .to_string_lossy()
        .into_owned();
    db.execute_unprepared(include_str!("replacement.sql"))
        .await?;
    db.execute_raw(sql(
        "INSERT INTO sandbox_replacement_storage(name, token) VALUES (?, ?)",
        [name.into(), token.as_str().into()],
    ))
    .await?;
    *attempt = Some(Attempt {
        name: name.into(),
        original,
        token: Some(token.clone()),
    });
    let backup = temp.keep();
    let had_directory = directory.try_exists()?;
    // This step must finish under the caller's transition and storage ownership,
    // including on cancellation; no detached copy worker may outlive either guard.
    if had_directory {
        retain_tree(directory, &backup.join("original")).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("back up sandbox {}: {error}", directory.display()),
            )
        })?;
    }
    sync_dir(&backup)?;
    sync_dir(&backups)?;
    db.transaction(|txn| {
        let token = token.clone();
        async move {
            let alias = format!(".msb-retained-{original}");
            let updated = txn.execute_raw(sql(
                "UPDATE sandbox SET name = ?, status = 'Stopped', ephemeral = 0 WHERE id = ? AND name = ? AND creation_state IS NULL",
                [alias.into(), original.into(), name.into()],
            )).await?;
            if updated.rows_affected() != 1 {
                return Err(MicrosandboxError::Runtime(format!("sandbox {name:?} changed during replacement")));
            }
            txn.execute_raw(sql(
                "INSERT INTO sandbox_replacement (name, original, token, had_directory) VALUES (?, ?, ?, ?)",
                [name.into(), original.into(), token.into(), had_directory.into()],
            )).await?;
            Ok((txn, ()))
        }
    }).await?;
    if had_directory {
        // Keep the actual directory too. Its inode, ACLs and directory metadata
        // return intact on rollback. The linked tree covers both rename/SQL gaps.
        move_stopped_directory(directory, &backup.join("tree"))
            .await
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("park sandbox directory {}: {error}", directory.display()),
                )
            })?;
        sync_dir(&backup)?;
        sync_dir(root)?;
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::{SandboxConfig, SandboxStatus};

    #[tokio::test]
    async fn replacement_reopens_durable_state_and_fences_only_its_original() {
        for published in [false, true] {
            let temp = tempfile::tempdir().unwrap();
            let backend = crate::test_support::local_backend_builder(temp.path())
                .build()
                .unwrap();
            let db = backend.db().await.unwrap().write();
            let mut config = SandboxConfig::default();
            config.spec.name = "kept".into();
            config.spec.lifecycle.ephemeral = true;
            let id = LocalContext::insert_sandbox_record_with_status(
                db,
                &config,
                SandboxStatus::Stopped,
            )
            .await
            .unwrap();
            retain_ephemeral(db, id).await.unwrap();
            let dir = backend.sandboxes_dir().join("kept");
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join("sentinel"), "original").unwrap();
            let mut attempt = None;
            park(db, "kept", id, &dir, &mut attempt).await.unwrap();
            let token = attempt.unwrap().token.unwrap();

            // Older clients issue ordinary SQL. Their other sandbox mutations still
            // work while the old identity and the public name are reserved.
            assert!(
                db.execute_raw(sql("DELETE FROM sandbox WHERE id = ?", [id.into()]))
                    .await
                    .is_err()
            );
            assert!(
                db.execute_raw(sql(
                    "UPDATE sandbox SET status = 'Starting' WHERE id = ?",
                    [id.into()]
                ))
                .await
                .is_err()
            );
            assert!(
                LocalContext::insert_sandbox_record(db, &config)
                    .await
                    .is_err()
            );
            let mut other = config.clone();
            other.spec.name = "independent".into();
            LocalContext::insert_sandbox_record(db, &other)
                .await
                .unwrap();

            let candidate = LocalContext::insert_with_replacement(
                db,
                &config,
                SandboxStatus::Starting,
                true,
                Some(&token),
            )
            .await
            .unwrap();
            fs::create_dir(&dir).unwrap();
            fs::write(dir.join("sentinel"), "replacement").unwrap();
            if published {
                // Publication survives even when an ephemeral candidate exits before
                // the launcher reopens the journal to retire the old generation.
                db.execute_raw(sql(
                    "UPDATE sandbox SET status = 'Running', creation_state = NULL WHERE id = ?",
                    [candidate.into()],
                ))
                .await
                .unwrap();
                db.execute_raw(sql("DELETE FROM sandbox WHERE id = ?", [candidate.into()]))
                    .await
                    .unwrap();
            }
            if published {
                // Legacy writers may reuse a published ephemeral name immediately.
                // Retiring the original must never touch that later generation.
                LocalContext::insert_sandbox_record(db, &config)
                    .await
                    .unwrap();
            }
            drop(backend);
            let reopened = crate::test_support::local_backend_builder(temp.path())
                .build()
                .unwrap();
            reopened
                .recover_replacement_for_lookup("kept")
                .await
                .unwrap();
            let db = reopened.db().await.unwrap().write();
            assert!(storage_token(db, "kept").await.unwrap().is_none());
            if published {
                assert!(
                    db.query_one_raw(sql("SELECT id FROM sandbox WHERE id = ?", [id.into()]))
                        .await
                        .unwrap()
                        .is_none()
                );
                assert_eq!(
                    fs::read_to_string(dir.join("sentinel")).unwrap(),
                    "replacement"
                );
            } else {
                let row = db
                    .query_one_raw(sql(
                        "SELECT name, status, ephemeral FROM sandbox WHERE id = ?",
                        [id.into()],
                    ))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(row.try_get::<String>("", "name").unwrap(), "kept");
                assert_eq!(row.try_get::<String>("", "status").unwrap(), "Stopped");
                assert!(!row.try_get::<bool>("", "ephemeral").unwrap());
                assert_eq!(
                    fs::read_to_string(dir.join("sentinel")).unwrap(),
                    "original"
                );
                for status in ["Starting", "Running"] {
                    db.execute_raw(sql(
                        "UPDATE sandbox SET status = ? WHERE id = ?",
                        [status.into(), id.into()],
                    ))
                    .await
                    .unwrap();
                }
                assert!(
                    db.query_one_raw(sql(
                        "SELECT id FROM sandbox WHERE id = ? AND ephemeral = 1",
                        [id.into()]
                    ))
                    .await
                    .unwrap()
                    .is_some()
                );
            }
        }
    }
}
