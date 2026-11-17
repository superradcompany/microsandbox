use std::fs;
use std::os::darwin::fs::MetadataExt as DarwinMetadataExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use sea_orm::{ConnectionTrait, DbBackend, Statement};

use crate::{DbReadConnection, DbWriteConnection};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct CatalogFixture {
    _root: tempfile::TempDir,
    directory: PathBuf,
    database: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CatalogFixture {
    async fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let directory = root.path().join("db");
        let database = directory.join("msb.db");
        let db = DbWriteConnection::open(&database, Duration::from_secs(5), Duration::from_secs(5))
            .await
            .unwrap();
        db.execute_unprepared(
            "CREATE TABLE sample(value TEXT); INSERT INTO sample VALUES ('preserved'); PRAGMA journal_mode=DELETE",
        )
        .await
        .unwrap();
        // Close SQLite before making the fixture read-only: inspection must not need
        // writable WAL sidecars, and setting flags must not disturb a live connection.
        db.inner().clone().close().await.unwrap();
        Self {
            _root: root,
            directory,
            database,
        }
    }

    fn make_read_only(&self, immutable: &Path) {
        fs::set_permissions(&self.database, fs::Permissions::from_mode(0o400)).unwrap();
        fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o500)).unwrap();
        command("chflags", &["uchg"], immutable);
    }

    async fn read(&self) -> Result<String, sqlx::Error> {
        let reader = DbReadConnection::open_read_only(
            &self.database,
            Duration::from_secs(5),
            Duration::from_secs(5),
        )
        .await?;
        let row = reader
            .query_one_raw(Statement::from_string(
                DbBackend::Sqlite,
                "SELECT value FROM sample",
            ))
            .await
            .unwrap()
            .unwrap();
        let value = row.try_get_by_index::<String>(0).unwrap();
        reader.inner().clone().close().await.unwrap();
        Ok(value)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for CatalogFixture {
    fn drop(&mut self) {
        // Restore only our disposable fixture, including on assertion failure. Otherwise
        // immutable flags and deny-delete ACLs would prevent TempDir cleanup.
        for path in [&self.directory, &self.database] {
            let _ = Command::new("chflags").arg("nouchg").arg(path).output();
            let _ = Command::new("chmod").arg("-N").arg(path).output();
        }
        let _ = fs::set_permissions(&self.directory, fs::Permissions::from_mode(0o700));
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn command(program: &str, args: &[&str], path: &Path) {
    let output = Command::new(program).args(args).arg(path).output().unwrap();
    assert!(output.status.success(), "{program} {args:?}: {output:?}");
}

fn acl(path: &Path) -> Vec<String> {
    let output = Command::new("ls").arg("-lde").arg(path).output().unwrap();
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .skip(1)
        .map(str::to_owned)
        .collect()
}

fn metadata(path: &Path) -> (u32, u32, i64, i64) {
    let metadata = fs::metadata(path).unwrap();
    (
        metadata.mode(),
        metadata.st_flags(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

async fn preserves_harmless_acls(on_directory: bool) {
    let identity = Command::new("id").arg("-un").output().unwrap();
    assert!(identity.status.success());
    let owner = String::from_utf8(identity.stdout).unwrap();
    for entry in [
        "everyone deny delete".to_owned(),
        format!(
            "user:{} allow read,readattr,readextattr,readsecurity",
            owner.trim()
        ),
        "user:root allow read,readattr,readextattr,readsecurity".to_owned(),
    ] {
        let fixture = CatalogFixture::new().await;
        let target = if on_directory {
            &fixture.directory
        } else {
            &fixture.database
        };
        command("chmod", &["+a", &entry], target);
        fixture.make_read_only(target);
        let before_acl = acl(target);
        assert!(!before_acl.is_empty(), "fixture must have an ACL");
        let before_file = metadata(&fixture.database);
        let before_directory = metadata(&fixture.directory);

        assert_eq!(fixture.read().await.unwrap(), "preserved", "{entry}");
        crate::backup::validate_backup(&fixture.database)
            .await
            .unwrap();

        assert_eq!(acl(target), before_acl, "{entry}");
        assert_eq!(metadata(&fixture.database), before_file, "{entry}");
        assert_eq!(metadata(&fixture.directory), before_directory, "{entry}");
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn read_only_catalog_preserves_harmless_file_acls() {
    preserves_harmless_acls(false).await;
}

#[tokio::test]
async fn read_only_catalog_preserves_harmless_directory_acls() {
    preserves_harmless_acls(true).await;
}

#[tokio::test]
async fn immutable_catalog_with_untrusted_acl_grants_is_refused() {
    for on_directory in [false, true] {
        for entry in [
            "everyone allow read",
            "user:nobody allow read",
            "group:staff allow read",
        ] {
            let fixture = CatalogFixture::new().await;
            let target = if on_directory {
                &fixture.directory
            } else {
                &fixture.database
            };
            // A harmless entry must not hide a later unsafe grant.
            command("chmod", &["+a", "everyone deny delete"], target);
            command("chmod", &["+a", entry], target);
            fixture.make_read_only(target);
            let before_acl = acl(target);
            let before_metadata = metadata(target);
            let error = fixture.read().await.unwrap_err();
            assert!(
                error.to_string().contains("cannot make catalog storage"),
                "{error}"
            );
            assert_eq!(acl(target), before_acl);
            assert_eq!(metadata(target), before_metadata);
        }
    }
}

#[tokio::test]
async fn inherit_only_grants_are_removed_before_creating_catalog_files() {
    let fixture = CatalogFixture::new().await;
    command("chmod", &["+a", "everyone deny delete"], &fixture.directory);
    command(
        "chmod",
        &[
            "+a",
            "everyone allow read,file_inherit,directory_inherit,only_inherit",
        ],
        &fixture.directory,
    );
    assert!(
        acl(&fixture.directory)
            .iter()
            .any(|entry| entry.contains("only_inherit"))
    );
    let new_file = super::prepare_database_file(&fixture.directory.join("fresh.db"), true).unwrap();
    assert!(acl(&fixture.directory).is_empty());
    assert!(acl(&new_file).is_empty());
    assert_eq!(fs::metadata(new_file).unwrap().len(), 0);
}
