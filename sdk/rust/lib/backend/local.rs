//! Local backend implementation — wraps today's libkrun + agentd path.
//!
//! Holds local-only state (DB pool, paths config, sandbox defaults, registry
//! config) as fields on a single struct, replacing the per-process global
//! config + DB pool statics that lived in `crate::config` / `crate::db`. Two
//! construction paths:
//!
//! - [`LocalBackend::lazy`] — sync ambient default. Initialises its DB pool +
//!   config lazily on first access. Used by the ambient `default_backend()`
//!   when no explicit backend is installed.
//! - [`LocalBackend::builder`] — programmatic config. `.build().await`
//!   constructs eagerly with all DB pools + config resolved up front.
//!
//! Per D6.7 Layer 2a in the SDK local-cloud parity plan: this struct absorbs
//! the bulk of the old global config singleton plus the SQLite pool, so multiple
//! backends can hold different configurations for tests / migrations.

use std::{
    collections::HashMap,
    num::NonZero,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
#[cfg(unix)]
use std::{
    fs::{File, OpenOptions},
    os::fd::AsRawFd,
};

use microsandbox_db::pool::DbPools;
use microsandbox_migration::{Migrator, MigratorTrait};
use tokio::sync::OnceCell;

use super::{Backend, BackendKind, SandboxBackend, VolumeBackend};
use crate::config::{DatabaseConfig, LocalConfig, RegistryEntry, load_persisted_config_or_default};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Local-runtime backend: spawns microVMs via libkrun on the calling host.
///
/// Owns the persisted [`LocalConfig`] (paths, sandbox defaults, registry
/// settings, database tuning) and the SQLite [`DbPools`] for this instance.
/// Built via either [`LocalBackend::lazy`] (no-explicit-setup ambient
/// default, lazily initialised) or [`LocalBackend::builder`] (programmatic).
pub struct LocalBackend {
    config: Arc<LocalConfig>,
    db: OnceCell<DbPools>,
}

/// Fluent builder for [`LocalBackend`]. Construct via [`LocalBackend::builder`].
///
/// All fields are optional. [`build`](Self::build)`.await` produces a
/// `LocalBackend` whose DB pool has already been opened and migrated.
///
/// `build` overlays the builder's overrides on top of the persisted
/// `~/.microsandbox/config.json` (honouring `MSB_CONFIG_PATH`). Persisted
/// values fill in everything the builder didn't set; builder overrides win.
/// Override the `home()` setter to point the merge at a different config
/// file (the underlying loader still respects `MSB_CONFIG_PATH`).
#[derive(Default)]
pub struct LocalBackendBuilder {
    home: Option<PathBuf>,
    sandboxes_dir: Option<PathBuf>,
    volumes_dir: Option<PathBuf>,
    snapshots_dir: Option<PathBuf>,
    cache_dir: Option<PathBuf>,
    logs_dir: Option<PathBuf>,
    secrets_dir: Option<PathBuf>,
    max_connections: Option<u32>,
    connect_timeout_secs: Option<u64>,
    busy_timeout_secs: Option<u64>,
    default_cpus: Option<u8>,
    default_memory_mib: Option<u32>,
    shell: Option<String>,
    workdir: Option<String>,
    metrics_sample_interval_ms: Option<Option<NonZero<u64>>>,
    disable_metrics_sample: Option<bool>,
    ca_certs: Option<Option<PathBuf>>,
    registry_hosts: Option<HashMap<String, RegistryEntry>>,
    log_level: Option<microsandbox_runtime::logging::LogLevel>,
}

struct MigrationLock {
    #[cfg(unix)]
    file: File,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    /// Construct a `LocalBackend` whose DB pool initialises on first access.
    ///
    /// The config is read from `~/.microsandbox/config.json` (honouring
    /// `MSB_CONFIG_PATH`) at construction; a missing file resolves to the
    /// hard-coded defaults. The DB pool is created (and migrations applied)
    /// on first call to [`Self::db`].
    ///
    /// Process-wide singleton access goes through
    /// [`default_backend()`](super::default_backend) +
    /// [`Backend::as_local`]; the process default lazy-initialises a single
    /// `LocalBackend` instance, so callers never end up with two backends
    /// racing on the same SQLite file.
    pub fn lazy() -> Self {
        let config = Arc::new(load_persisted_config_or_default().unwrap_or_default());
        Self {
            config,
            db: OnceCell::new(),
        }
    }

    /// Eagerly construct a `LocalBackend` from `~/.microsandbox/config.json`,
    /// opening (and migrating) the DB pool up front.
    pub async fn new() -> MicrosandboxResult<Self> {
        let backend = Self::lazy();
        let _ = backend.db().await?;
        Ok(backend)
    }

    /// Start a builder for programmatic configuration.
    pub fn builder() -> LocalBackendBuilder {
        LocalBackendBuilder::default()
    }

    /// Access the open DB pool, initialising it (and applying migrations) on
    /// first call.
    pub async fn db(&self) -> MicrosandboxResult<&DbPools> {
        self.db
            .get_or_try_init(|| async {
                let db_dir = self.config.home().join(microsandbox_utils::DB_SUBDIR);
                connect_and_migrate(&db_dir, &self.config.database).await
            })
            .await
    }

    /// Borrow this backend's [`LocalConfig`].
    pub fn config(&self) -> &LocalConfig {
        &self.config
    }

    /// Host-side directory rooted at `volumes_dir/<name>` for a named volume.
    ///
    /// Non-trait helper used by [`VolumeFs`](crate::volume::VolumeFs)
    /// streaming methods and FFI shims that need a path before any backend
    /// trait call.
    pub fn volume_path(&self, name: &str) -> PathBuf {
        self.config.volumes_dir().join(name)
    }

    /// Resolved sandboxes directory.
    pub fn sandboxes_dir(&self) -> PathBuf {
        self.config.sandboxes_dir()
    }

    /// Resolved volumes directory.
    pub fn volumes_dir(&self) -> PathBuf {
        self.config.volumes_dir()
    }

    /// Resolved snapshots directory.
    pub fn snapshots_dir(&self) -> PathBuf {
        self.config.snapshots_dir()
    }

    /// Resolved cache directory.
    pub fn cache_dir(&self) -> PathBuf {
        self.config.cache_dir()
    }

    /// Resolved logs directory.
    pub fn logs_dir(&self) -> PathBuf {
        self.config.logs_dir()
    }

    /// Resolved secrets directory.
    pub fn secrets_dir(&self) -> PathBuf {
        self.config.secrets_dir()
    }
}

impl LocalBackendBuilder {
    /// Override the home directory (default: `~/.microsandbox`).
    pub fn home(mut self, path: impl Into<PathBuf>) -> Self {
        self.home = Some(path.into());
        self
    }

    /// Override the sandboxes directory.
    pub fn sandboxes_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.sandboxes_dir = Some(path.into());
        self
    }

    /// Override the volumes directory.
    pub fn volumes_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.volumes_dir = Some(path.into());
        self
    }

    /// Override the snapshots directory.
    pub fn snapshots_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.snapshots_dir = Some(path.into());
        self
    }

    /// Override the cache directory.
    pub fn cache_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.cache_dir = Some(path.into());
        self
    }

    /// Override the logs directory.
    pub fn logs_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.logs_dir = Some(path.into());
        self
    }

    /// Override the secrets directory.
    pub fn secrets_dir(mut self, path: impl Into<PathBuf>) -> Self {
        self.secrets_dir = Some(path.into());
        self
    }

    /// Override the DB max connections (default: 5).
    pub fn max_connections(mut self, n: u32) -> Self {
        self.max_connections = Some(n);
        self
    }

    /// Override the DB connect timeout in seconds.
    pub fn connect_timeout_secs(mut self, secs: u64) -> Self {
        self.connect_timeout_secs = Some(secs);
        self
    }

    /// Override SQLite's `busy_timeout` in seconds.
    pub fn busy_timeout_secs(mut self, secs: u64) -> Self {
        self.busy_timeout_secs = Some(secs);
        self
    }

    /// Override the default sandbox vCPU count.
    pub fn default_cpus(mut self, cpus: u8) -> Self {
        self.default_cpus = Some(cpus);
        self
    }

    /// Override the default sandbox guest memory (MiB).
    pub fn default_memory_mib(mut self, mib: u32) -> Self {
        self.default_memory_mib = Some(mib);
        self
    }

    /// Override the default shell used for interactive sessions and scripts.
    pub fn shell(mut self, shell: impl Into<String>) -> Self {
        self.shell = Some(shell.into());
        self
    }

    /// Override the default working directory inside sandboxes.
    pub fn workdir(mut self, workdir: impl Into<String>) -> Self {
        self.workdir = Some(workdir.into());
        self
    }

    /// Override the sandbox metrics sampling interval. Pass `0` to disable
    /// sampling globally.
    pub fn metrics_sample_interval_ms(mut self, ms: u64) -> Self {
        self.metrics_sample_interval_ms = Some(NonZero::new(ms));
        self
    }

    /// Force-disable sandbox metrics sampling regardless of the configured
    /// interval.
    pub fn disable_metrics_sample(mut self, disable: bool) -> Self {
        self.disable_metrics_sample = Some(disable);
        self
    }

    /// Override the path to additional CA root certificates trusted by
    /// registry connections. Pass `None` to clear a persisted value.
    pub fn ca_certs(mut self, path: Option<PathBuf>) -> Self {
        self.ca_certs = Some(path);
        self
    }

    /// Replace the per-registry hosts map. The provided map fully replaces
    /// any persisted `registries.hosts` — additive merging isn't supported
    /// by the builder (use a persisted config file for incremental edits).
    pub fn registry_hosts(mut self, hosts: HashMap<String, RegistryEntry>) -> Self {
        self.registry_hosts = Some(hosts);
        self
    }

    /// Override the runtime log level applied to SDK-spawned sandboxes.
    pub fn log_level(mut self, level: microsandbox_runtime::logging::LogLevel) -> Self {
        self.log_level = Some(level);
        self
    }

    /// Build the `LocalBackend`. Opens the DB pool and applies migrations.
    ///
    /// Reads `~/.microsandbox/config.json` (or `MSB_CONFIG_PATH`) and
    /// overlays the builder's overrides on top. Builder values win;
    /// anything the builder didn't set falls through to the persisted
    /// config (or the hard-coded defaults if no config file exists).
    pub async fn build(self) -> MicrosandboxResult<LocalBackend> {
        let persisted = load_persisted_config_or_default().unwrap_or_default();
        let config = self.merge_into(persisted);
        let backend = LocalBackend {
            config: Arc::new(config),
            db: OnceCell::new(),
        };
        let _ = backend.db().await?;
        Ok(backend)
    }

    /// Overlay the builder's overrides on top of `base`. Builder values win;
    /// `None` builder fields fall through to `base`.
    fn merge_into(self, mut base: LocalConfig) -> LocalConfig {
        let LocalBackendBuilder {
            home,
            sandboxes_dir,
            volumes_dir,
            snapshots_dir,
            cache_dir,
            logs_dir,
            secrets_dir,
            max_connections,
            connect_timeout_secs,
            busy_timeout_secs,
            default_cpus,
            default_memory_mib,
            shell,
            workdir,
            metrics_sample_interval_ms,
            disable_metrics_sample,
            ca_certs,
            registry_hosts,
            log_level,
        } = self;

        if let Some(home) = home {
            base.home = Some(home);
        }
        if let Some(level) = log_level {
            base.log_level = Some(level);
        }

        if let Some(v) = max_connections {
            base.database.max_connections = v;
        }
        if let Some(v) = connect_timeout_secs {
            base.database.connect_timeout_secs = v;
        }
        if let Some(v) = busy_timeout_secs {
            base.database.busy_timeout_secs = v;
        }

        if let Some(p) = cache_dir {
            base.paths.cache = Some(p);
        }
        if let Some(p) = sandboxes_dir {
            base.paths.sandboxes = Some(p);
        }
        if let Some(p) = volumes_dir {
            base.paths.volumes = Some(p);
        }
        if let Some(p) = snapshots_dir {
            base.paths.snapshots = Some(p);
        }
        if let Some(p) = logs_dir {
            base.paths.logs = Some(p);
        }
        if let Some(p) = secrets_dir {
            base.paths.secrets = Some(p);
        }

        if let Some(v) = default_cpus {
            base.sandbox_defaults.cpus = v;
        }
        if let Some(v) = default_memory_mib {
            base.sandbox_defaults.memory_mib = v;
        }
        if let Some(v) = shell {
            base.sandbox_defaults.shell = v;
        }
        if let Some(v) = workdir {
            base.sandbox_defaults.workdir = Some(v);
        }
        if let Some(v) = metrics_sample_interval_ms {
            base.sandbox_defaults.metrics_sample_interval_ms = v;
        }
        if let Some(v) = disable_metrics_sample {
            base.sandbox_defaults.disable_metrics_sample = v;
        }

        if let Some(v) = ca_certs {
            base.registries.ca_certs = v;
        }
        if let Some(v) = registry_hosts {
            base.registries.hosts = v;
        }

        base
    }
}

impl MigrationLock {
    #[cfg(unix)]
    fn acquire(path: PathBuf) -> MicrosandboxResult<Self> {
        let file = OpenOptions::new()
            .create(true)
            .truncate(false)
            .read(true)
            .write(true)
            .open(&path)
            .map_err(|err| {
                MicrosandboxError::Runtime(format!("open migration lock {}: {err}", path.display()))
            })?;

        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return Err(MicrosandboxError::Runtime(format!(
                "lock migration file {}: {}",
                path.display(),
                std::io::Error::last_os_error()
            )));
        }

        Ok(Self { file })
    }

    #[cfg(not(unix))]
    fn acquire(_path: PathBuf) -> MicrosandboxResult<Self> {
        Ok(Self {})
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Backend for LocalBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Local
    }

    fn sandboxes(&self) -> &dyn SandboxBackend {
        self
    }

    fn volumes(&self) -> &dyn VolumeBackend {
        self
    }

    fn as_local(&self) -> Option<&LocalBackend> {
        Some(self)
    }
}

impl Default for LocalBackend {
    fn default() -> Self {
        Self::lazy()
    }
}

impl From<LocalBackend> for Arc<dyn Backend> {
    fn from(backend: LocalBackend) -> Self {
        Arc::new(backend)
    }
}

#[cfg(unix)]
impl Drop for MigrationLock {
    fn drop(&mut self) {
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Open both pools for `db_dir/msb.db` and run migrations on the writer.
///
/// The write pool connects first so WAL mode (persisted in the database
/// header) is set before the read pool opens.
async fn connect_and_migrate(
    db_dir: &Path,
    database: &DatabaseConfig,
) -> MicrosandboxResult<DbPools> {
    tokio::fs::create_dir_all(db_dir).await?;
    let _migration_lock = acquire_migration_lock(db_dir).await?;

    let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);
    let pools = DbPools::open(
        &db_path,
        database.max_connections,
        Duration::from_secs(database.connect_timeout_secs),
        Duration::from_secs(database.busy_timeout_secs),
    )
    .await
    .map_err(|e| MicrosandboxError::Custom(format!("connect to {}: {e}", db_path.display())))?;

    Migrator::up(pools.write().inner(), None).await?;

    Ok(pools)
}

async fn acquire_migration_lock(db_dir: &Path) -> MicrosandboxResult<MigrationLock> {
    let path = db_dir.join(format!(
        "{}.migration.lock",
        microsandbox_utils::DB_FILENAME
    ));
    tokio::task::spawn_blocking(move || MigrationLock::acquire(path))
        .await
        .map_err(|err| MicrosandboxError::Runtime(format!("migration lock task failed: {err}")))?
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use sea_orm::{ConnectionTrait, Database, DatabaseBackend, Statement};

    use super::*;
    use crate::backend::with_backend;
    use crate::volume::VolumeConfig;

    #[tokio::test]
    async fn test_connect_and_migrate_creates_db_and_tables() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");
        let database = DatabaseConfig::default();

        let pools = connect_and_migrate(&db_dir, &database).await.unwrap();
        let conn = pools.read();

        // DB file should exist on disk.
        assert!(db_dir.join(microsandbox_utils::DB_FILENAME).exists());

        // All migrated tables should be present.
        let rows = conn
            .query_all(Statement::from_string(
                sea_orm::DatabaseBackend::Sqlite,
                "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'seaql_%' AND name != 'sqlite_sequence' ORDER BY name",
            ))
            .await
            .unwrap();

        let table_names: Vec<String> = rows
            .iter()
            .map(|r| r.try_get_by_index::<String>(0).unwrap())
            .collect();

        let expected = vec![
            "config",
            "image_ref",
            "layer",
            "maintenance_lease",
            "manifest",
            "manifest_layer",
            "run",
            "sandbox",
            "sandbox_labels",
            "sandbox_rootfs",
            "snapshot_index",
            "volume",
            "volume_attach",
        ];

        assert_eq!(table_names, expected);
    }

    #[tokio::test]
    async fn test_connect_and_migrate_is_idempotent() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");
        let database = DatabaseConfig::default();

        let pools = connect_and_migrate(&db_dir, &database).await.unwrap();

        // Running migrations again on the same DB should succeed.
        Migrator::up(pools.write().inner(), None).await.unwrap();
    }

    #[tokio::test]
    async fn test_connect_and_migrate_recovers_from_partial_storage_migration() {
        let tmp = tempfile::tempdir().unwrap();
        let db_dir = tmp.path().join("db");
        tokio::fs::create_dir_all(&db_dir).await.unwrap();

        let db_path = db_dir.join(microsandbox_utils::DB_FILENAME);
        let db_url = format!("sqlite://{}?mode=rwc", db_path.display());

        let conn = Database::connect(&db_url).await.unwrap();

        conn.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "PRAGMA foreign_keys = ON;",
        ))
        .await
        .unwrap();

        // Apply only migrations 1 and 2 so migration 3 is still pending.
        Migrator::up(&conn, Some(2)).await.unwrap();

        // Simulate a half-applied migration 3.
        conn.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "CREATE TABLE IF NOT EXISTS volume (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                quota_mib INTEGER,
                size_bytes BIGINT,
                labels TEXT,
                created_at DATETIME,
                updated_at DATETIME
            )",
        ))
        .await
        .unwrap();

        conn.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "CREATE TABLE IF NOT EXISTS snapshot (
                id INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                sandbox_id INTEGER,
                size_bytes BIGINT,
                description TEXT,
                created_at DATETIME,
                FOREIGN KEY (sandbox_id) REFERENCES sandbox(id) ON DELETE SET NULL
            )",
        ))
        .await
        .unwrap();

        conn.execute(Statement::from_string(
            DatabaseBackend::Sqlite,
            "CREATE UNIQUE INDEX idx_snapshots_name_sandbox_unique ON snapshot (name, sandbox_id)",
        ))
        .await
        .unwrap();

        drop(conn);

        let database = DatabaseConfig::default();
        let recovered = connect_and_migrate(&db_dir, &database).await.unwrap();

        let migration_row_count = recovered
            .read()
            .query_one(Statement::from_string(
                DatabaseBackend::Sqlite,
                "SELECT COUNT(*) FROM seaql_migrations WHERE version = 'm20260305_000003_create_storage_tables'",
            ))
            .await
            .unwrap()
            .unwrap()
            .try_get_by_index::<i64>(0)
            .unwrap();
        assert_eq!(migration_row_count, 1);
    }

    /// Regression test for Defect 1: under `with_backend(custom_local, ...)`,
    /// volume FS ops must route to the custom backend's `volumes_dir`, not
    /// the resolved default's.
    ///
    /// Pre-fix, `volume::fs::local::*` reached into `LocalBackend::ambient()`
    /// so a `with_backend` scope would write the DB row to the custom but
    /// route filesystem ops to the ambient default. Two backends with
    /// distinct `volumes_dir`s make the leak observable: writes through B's
    /// trait impl must land under B's `volumes_dir`, not under A's.
    #[tokio::test]
    async fn with_backend_scope_isolates_volume_fs_paths() {
        let home_a = tempfile::tempdir().unwrap();
        let home_b = tempfile::tempdir().unwrap();

        let backend_a: Arc<dyn Backend> = Arc::new(
            LocalBackend::builder()
                .home(home_a.path())
                .build()
                .await
                .unwrap(),
        );
        let backend_b: Arc<dyn Backend> = Arc::new(
            LocalBackend::builder()
                .home(home_b.path())
                .build()
                .await
                .unwrap(),
        );

        // Create the volume in backend B only.
        backend_b
            .volumes()
            .create(
                backend_b.clone(),
                VolumeConfig {
                    name: "vol".into(),
                    kind: crate::volume::VolumeKind::Directory,
                    quota_mib: None,
                    capacity_mib: None,
                    labels: Vec::new(),
                },
            )
            .await
            .unwrap();

        // Inside a `with_backend(B)` scope, write a file through B's trait.
        // Without the fix, `fs_write` would re-resolve via the ambient
        // `LocalBackend` and write to A (or to the global ambient).
        let backend_b_clone = backend_b.clone();
        with_backend(backend_a.clone(), async move {
            backend_b_clone
                .volumes()
                .fs_write("vol", "hello.txt", b"world".to_vec())
                .await
                .unwrap();
        })
        .await;

        // Expect the file under B's volumes_dir, not A's.
        let expected_path = backend_b
            .as_local()
            .unwrap()
            .volume_path("vol")
            .join("hello.txt");
        let unexpected_path = backend_a
            .as_local()
            .unwrap()
            .volumes_dir()
            .join("vol")
            .join("hello.txt");

        let contents = tokio::fs::read_to_string(&expected_path)
            .await
            .expect("file should exist under backend B's volumes_dir");
        assert_eq!(contents, "world");
        assert!(
            !unexpected_path.exists(),
            "file must NOT appear under backend A's volumes_dir; \
             ambient() leak regressed"
        );
    }

    /// `LocalBackendBuilder::build()` overlays builder overrides on top of
    /// the persisted config — values the builder didn't set must be
    /// preserved from the base. This test runs `merge_into` directly so it
    /// doesn't have to mutate `MSB_CONFIG_PATH` (which races other tests).
    #[test]
    fn builder_merge_preserves_persisted_fields_when_not_overridden() {
        // Persisted base: a fully-populated config the user supposedly
        // wrote to ~/.microsandbox/config.json.
        let base = LocalConfig {
            log_level: Some(microsandbox_runtime::logging::LogLevel::Debug),
            database: DatabaseConfig {
                url: None,
                max_connections: 9,
                connect_timeout_secs: 17,
                busy_timeout_secs: 23,
            },
            sandbox_defaults: crate::config::SandboxDefaults {
                cpus: 4,
                memory_mib: 2048,
                oci: crate::config::OciSandboxDefaults::default(),
                shell: "/bin/zsh".into(),
                workdir: Some("/work".into()),
                metrics_sample_interval_ms: NonZero::new(750),
                disable_metrics_sample: true,
            },
            ..Default::default()
        };

        // Builder overrides only one knob — vCPU count.
        let merged = LocalBackend::builder().default_cpus(2).merge_into(base);

        // The overridden field reflects the builder.
        assert_eq!(merged.sandbox_defaults.cpus, 2);

        // Everything else must survive from the persisted base.
        assert_eq!(merged.sandbox_defaults.memory_mib, 2048);
        assert_eq!(merged.sandbox_defaults.shell, "/bin/zsh");
        assert_eq!(merged.sandbox_defaults.workdir, Some("/work".into()));
        assert_eq!(
            merged.sandbox_defaults.metrics_sample_interval_ms,
            NonZero::new(750)
        );
        assert!(merged.sandbox_defaults.disable_metrics_sample);

        assert_eq!(merged.database.max_connections, 9);
        assert_eq!(merged.database.connect_timeout_secs, 17);
        assert_eq!(merged.database.busy_timeout_secs, 23);

        assert_eq!(
            merged.log_level,
            Some(microsandbox_runtime::logging::LogLevel::Debug)
        );
    }
}
