//! Graceful stop completion for one persisted sandbox and runtime generation.

use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    sync::{Arc, LazyLock, Mutex},
    time::Duration,
};

use microsandbox_runtime::ipc::try_acquire_lifecycle_guard;
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};

use crate::db::entity::run;
use crate::sandbox::SandboxStatus;
use crate::{MicrosandboxError, MicrosandboxResult, SandboxConfig};

use super::LocalBackend;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const STOP_MEMORY_SWEEP_INTERVAL: Duration = Duration::from_secs(30);

static STOP_MEMORY_SWEEPS: LazyLock<Mutex<HashMap<PathBuf, StopMemorySweep>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct StopMemorySweep {
    // The token distinguishes this worker from one registered after it has exited.
    token: Arc<()>,
    pending: bool,
}

struct StopMemorySweepRegistration {
    root: PathBuf,
    token: Arc<()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    /// Send shutdown and prove terminal state plus ownership release for the same run.
    pub(crate) async fn stop_complete(
        &self,
        name: &str,
        id: i32,
        ephemeral: bool,
    ) -> MicrosandboxResult<()> {
        let run_dir = self.config().run_dir();
        let transition = Self::acquire_sandbox_transition_guard(&run_dir, name).await?;
        let (model, _) = match self.sandbox_handle_state_owned(name, Some(id), true).await {
            Ok(state) => state,
            Err(MicrosandboxError::SandboxNotFound(_)) if ephemeral => {
                // Ephemeral teardown can remove the row before dropping runtime ownership.
                // A same-name replacement is still rejected by the identity-aware lookup.
                drop(transition);
                return self
                    .wait_stop_complete(
                        name,
                        id,
                        None,
                        true,
                        #[cfg(windows)]
                        None,
                    )
                    .await;
            }
            Err(error) => return Err(error),
        };
        let run = self.latest_stop_run(id).await?;
        let run_id = run.as_ref().map(|run| run.id);
        #[cfg(windows)]
        let owner = run
            .as_ref()
            .map(|run| {
                crate::runtime::ownership::recorded_owner(
                    &self.sandboxes_dir().join(name).join("runtime"),
                    run,
                )
            })
            .transpose()?
            .flatten();
        let lock_owned = try_acquire_lifecycle_guard(&run_dir, name)?.is_none();
        #[cfg(windows)]
        let legacy_alive = match &owner {
            Some(owner) if !owner.lifecycle_lock => owner
                .process
                .as_ref()
                .map(|process| process.alive())
                .transpose()?
                .unwrap_or(false),
            None if !lock_owned
                && run
                    .as_ref()
                    .and_then(|run| run.pid)
                    .is_some_and(Self::pid_is_alive) =>
            {
                return Err(MicrosandboxError::Runtime("cannot prove legacy runtime ownership: no matching SDK process record; refusing to report stop complete".into()));
            }
            _ => false,
        };
        #[cfg(not(windows))]
        let legacy_alive = false;
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        let departing = super::process_exit::RuntimeExit::capture(
            run.as_ref().and_then(|run| run.pid),
            &microsandbox_runtime::ipc::lifecycle_lock_path(&run_dir, name),
        )?;
        // Ownership, not a potentially recycled PID, decides whether there is a
        // runtime to signal. A stale Running row must still converge successfully.
        if (lock_owned || legacy_alive)
            && let Err(error) = self.request_stop_owned(name, &model).await
        {
            // The runtime can finish between the ownership probe and dispatch.
            // Preserve a real unreachable-owner failure; reconcile only after
            // proving that this run has released its runtime resources.
            #[cfg(windows)]
            let legacy_alive = owner
                .as_ref()
                .filter(|owner| !owner.lifecycle_lock)
                .and_then(|owner| owner.process.as_ref())
                .map(|process| process.alive())
                .transpose()?
                .unwrap_or(false);
            if try_acquire_lifecycle_guard(&run_dir, name)?.is_none() || legacy_alive {
                return Err(error);
            }
        }
        // Exit cleanup also needs transition ownership. Never retain this guard while waiting.
        drop(transition);
        #[cfg(any(target_os = "linux", target_os = "macos"))]
        if let Some(departing) = departing {
            // Do not poll the external upper's lock: a different sandbox may legitimately
            // own it by now. Wait only for the process selected before shutdown dispatch.
            while !departing.has_exited()? {
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }
        self.wait_stop_complete(
            name,
            id,
            run_id,
            model.ephemeral,
            #[cfg(windows)]
            owner,
        )
        .await
    }

    async fn latest_stop_run(&self, id: i32) -> MicrosandboxResult<Option<run::Model>> {
        Ok(run::Entity::find()
            .filter(run::Column::SandboxId.eq(id))
            .order_by_desc(run::Column::Id)
            .one(self.db().await?.read())
            .await?)
    }

    async fn wait_stop_complete(
        &self,
        name: &str,
        id: i32,
        run_id: Option<i32>,
        ephemeral: bool,
        #[cfg(windows)] owner: Option<crate::runtime::ownership::RecordedOwner>,
    ) -> MicrosandboxResult<()> {
        let run_dir = self.config().run_dir();
        // Retain the pre-dispatch process object even if ephemeral teardown deletes its record.
        loop {
            let transition = Self::acquire_sandbox_transition_guard(&run_dir, name).await?;
            // Reconcile a crashed owner using the existing recovery rules before inspecting the
            // selected run. A reused name or restarted run must never redirect this operation.
            let model = match self.sandbox_handle_state_owned(name, Some(id), true).await {
                Ok((model, _)) => Some(model),
                Err(MicrosandboxError::SandboxNotFound(_)) if ephemeral => None,
                Err(error) => return Err(error),
            };
            let latest = self.latest_stop_run(id).await?;
            if model.is_some() && latest.as_ref().map(|run| run.id) != run_id {
                return Err(MicrosandboxError::Runtime(format!(
                    "sandbox {name:?} (id {id}) restarted while stopping run {run_id:?}; refusing to follow run {:?}",
                    latest.as_ref().map(|run| run.id)
                )));
            }
            #[cfg(windows)]
            let process_released = !owner
                .as_ref()
                .filter(|owner| !owner.lifecycle_lock)
                .and_then(|owner| owner.process.as_ref())
                .map(|process| process.alive())
                .transpose()?
                .unwrap_or(false);
            #[cfg(not(windows))]
            let process_released = true;
            if process_released
                && let Some(_ownership) = try_acquire_lifecycle_guard(&run_dir, name)?
            {
                // Both guards fence cooperative restart/removal. Legacy Windows additionally
                // requires the retained process object to exit; its unused lock proves nothing.
                let _disk_guards = if let Some(model) = model.as_ref() {
                    let config: crate::sandbox::SandboxConfig =
                        serde_json::from_str::<SandboxConfig>(&model.config)?;
                    match crate::runtime::owned_volumes::try_acquire_disk_guards(
                        &self.sandboxes_dir().join(name),
                        &config.spec.mounts,
                    )? {
                        Some(guards) => guards,
                        None => {
                            drop(_ownership);
                            drop(transition);
                            tokio::time::sleep(Duration::from_millis(1)).await;
                            continue;
                        }
                    }
                } else {
                    Vec::new()
                };
                if let Some(model) = model {
                    let terminal = matches!(
                        model.status,
                        SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed
                    ) && latest
                        .as_ref()
                        .is_none_or(|run| run.status == run::RunStatus::Terminated);
                    if !terminal {
                        // A crashed runtime may not have published its terminal row. Ownership
                        // and owned-disk release prove completion even if its PID is recycled.
                        let (status, reason) = Self::stale_runtime_terminal_state(model.status);
                        Self::mark_sandbox_runtime_stale(
                            self.db().await?.write(),
                            id,
                            run_id,
                            status,
                            reason,
                        )
                        .await?;
                    }
                }
                // VM teardown uses _exit(), which bypasses Rust drop guards. Only retry
                // cache reclamation after runtime ownership is gone; surviving source,
                // paused-child and pending-handoff locks still protect shared generations.
                // Release sandbox ownership before scheduling unrelated cache I/O. A slow
                // sweep must not delay restart/removal or occupy an async runtime worker.
                drop(_disk_guards);
                drop(_ownership);
                drop(transition);
                schedule_stopped_memory_sweep(self.cache_dir().join("memory"));
                return Ok(());
            }
            drop(transition);
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for StopMemorySweepRegistration {
    fn drop(&mut self) {
        // Also clear the registration if its Tokio runtime shuts down during the
        // cooldown. Never remove a newer worker registered for the same root.
        let mut sweeps = STOP_MEMORY_SWEEPS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if sweeps
            .get(&self.root)
            .is_some_and(|sweep| Arc::ptr_eq(&sweep.token, &self.token))
        {
            sweeps.remove(&self.root);
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn schedule_stopped_memory_sweep(root: PathBuf) {
    schedule_stopped_memory_sweep_with(root, STOP_MEMORY_SWEEP_INTERVAL, |root| {
        let options = microsandbox_runtime::checkpoint::MemoryPruneOptions {
            branches_only: true,
            max_entries: Some(256),
            ..Default::default()
        };
        match microsandbox_runtime::checkpoint::prune_memory_cache(root, &options) {
            Ok(report) => report.truncated,
            Err(error) => {
                tracing::debug!(%error, "deferred stopped sandbox memory cleanup");
                false
            }
        }
    });
}

fn schedule_stopped_memory_sweep_with(
    root: PathBuf,
    interval: Duration,
    sweep: impl Fn(&Path) -> bool + Send + Sync + 'static,
) {
    let token = {
        let mut sweeps = STOP_MEMORY_SWEEPS
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        if let Some(active) = sweeps.get_mut(&root) {
            // Coalesce stops during an active scan or cooldown into one
            // follow-up pass, while the worker also drains truncated scans.
            active.pending = true;
            return;
        }
        let token = Arc::new(());
        sweeps.insert(
            root.clone(),
            StopMemorySweep {
                token: Arc::clone(&token),
                pending: false,
            },
        );
        token
    };
    let sweep = Arc::new(sweep);
    tokio::spawn(async move {
        let _registration = StopMemorySweepRegistration {
            root: root.clone(),
            token,
        };
        loop {
            let scan_root = root.clone();
            let scan = Arc::clone(&sweep);
            let truncated = match tokio::task::spawn_blocking(move || scan(&scan_root)).await {
                Ok(truncated) => truncated,
                Err(error) => {
                    tracing::debug!(%error, "stopped sandbox memory cleanup worker failed");
                    false
                }
            };
            // Follow the bounded directory cursor until it completes a full
            // traversal. Delaying each pass keeps filesystem pressure bounded.
            tokio::time::sleep(interval).await;
            let mut sweeps = STOP_MEMORY_SWEEPS
                .lock()
                .unwrap_or_else(|error| error.into_inner());
            if let Some(active) = sweeps.get_mut(&root)
                && (active.pending || truncated)
            {
                active.pending = false;
                continue;
            }
            sweeps.remove(&root);
            break;
        }
    });
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{
        Condvar,
        atomic::{AtomicUsize, Ordering},
    };

    use sea_orm::Set;
    use tokio::sync::Notify;

    use super::*;
    use crate::db::entity::sandbox;
    use crate::sandbox::SandboxConfig;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn stopped_memory_sweeps_coalesce_without_blocking_other_roots() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("first");
        let other_root = home.path().join("second");
        let started = Arc::new(Notify::new());
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let scans = Arc::new(AtomicUsize::new(0));
        let unexpected = Arc::new(AtomicUsize::new(0));
        schedule_stopped_memory_sweep_with(root.clone(), Duration::from_millis(10), {
            let started = Arc::clone(&started);
            let release = Arc::clone(&release);
            let scans = Arc::clone(&scans);
            move |_| {
                let number = scans.fetch_add(1, Ordering::SeqCst);
                started.notify_one();
                if number == 0 {
                    let (lock, ready) = &*release;
                    let mut released = lock.lock().unwrap();
                    while !*released {
                        released = ready.wait(released).unwrap();
                    }
                }
                false
            }
        });
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .unwrap();

        // A burst while the first scan is blocked must request only one trailing pass.
        for _ in 0..100 {
            schedule_stopped_memory_sweep_with(root.clone(), Duration::from_millis(10), {
                let unexpected = Arc::clone(&unexpected);
                move |_| {
                    unexpected.fetch_add(1, Ordering::SeqCst);
                    false
                }
            });
        }
        assert_eq!(scans.load(Ordering::SeqCst), 1);

        // The per-root limit must not serialize an unrelated cache root.
        let other_started = Arc::new(Notify::new());
        schedule_stopped_memory_sweep_with(other_root, Duration::from_millis(10), {
            let other_started = Arc::clone(&other_started);
            move |_| {
                other_started.notify_one();
                false
            }
        });
        tokio::time::timeout(Duration::from_secs(2), other_started.notified())
            .await
            .unwrap();

        let (lock, ready) = &*release;
        *lock.lock().unwrap() = true;
        ready.notify_one();
        tokio::time::timeout(Duration::from_secs(2), started.notified())
            .await
            .unwrap();
        assert_eq!(scans.load(Ordering::SeqCst), 2);
        assert_eq!(unexpected.load(Ordering::SeqCst), 0);
        tokio::time::timeout(Duration::from_secs(2), async {
            loop {
                if !STOP_MEMORY_SWEEPS.lock().unwrap().contains_key(&root) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        })
        .await
        .unwrap();
        assert_eq!(scans.load(Ordering::SeqCst), 2);

        // A later stop starts a fresh worker after the previous cooldown ends.
        let fresh = Arc::new(Notify::new());
        schedule_stopped_memory_sweep_with(root, Duration::from_millis(10), {
            let fresh = Arc::clone(&fresh);
            move |_| {
                fresh.notify_one();
                false
            }
        });
        tokio::time::timeout(Duration::from_secs(2), fresh.notified())
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn stopped_memory_sweep_finishes_a_large_bounded_traversal() {
        use microsandbox_utils::process_lock::lock_shared;

        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("memory");
        let branches = root.join("branches");
        std::fs::create_dir_all(&branches).unwrap();
        let mut pins = Vec::new();
        for id in 0..611 {
            let path = branches.join(format!("branch-{id:04}-4096.ram"));
            std::fs::write(&path, [7_u8]).unwrap();
            std::fs::File::create(path.with_extension("handoff-lock")).unwrap();
            if id < 10 {
                let pin = std::fs::File::open(&path).unwrap();
                lock_shared(&pin).unwrap();
                pins.push(pin);
            }
        }

        let passes = Arc::new(AtomicUsize::new(0));
        schedule_stopped_memory_sweep_with(root.clone(), Duration::from_millis(1), {
            let passes = Arc::clone(&passes);
            move |root| {
                let report = microsandbox_runtime::checkpoint::prune_memory_cache(
                    root,
                    &microsandbox_runtime::checkpoint::MemoryPruneOptions {
                        branches_only: true,
                        max_entries: Some(256),
                        ..Default::default()
                    },
                )
                .unwrap();
                passes.fetch_add(1, Ordering::SeqCst);
                report.truncated
            }
        });
        tokio::time::timeout(Duration::from_secs(30), async {
            loop {
                if !STOP_MEMORY_SWEEPS.lock().unwrap().contains_key(&root) {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();

        // The first 512 directory positions cannot cover 611 RAM files, let alone
        // their lock files. A full traversal removes every unpinned generation.
        assert!(passes.load(Ordering::SeqCst) >= 5);
        for id in 0..611 {
            let path = branches.join(format!("branch-{id:04}-4096.ram"));
            assert_eq!(path.exists(), id < 10, "{}", path.display());
        }
        assert_eq!(pins.len(), 10);
    }

    #[test]
    fn stopped_memory_sweep_registration_clears_on_runtime_shutdown() {
        let home = tempfile::tempdir().unwrap();
        let root = home.path().join("memory");
        let started = Arc::new(Notify::new());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            schedule_stopped_memory_sweep_with(root.clone(), Duration::from_secs(30), {
                let started = Arc::clone(&started);
                move |_| {
                    started.notify_one();
                    false
                }
            });
            tokio::time::timeout(Duration::from_secs(2), started.notified())
                .await
                .unwrap();
        });
        drop(runtime);
        assert!(!STOP_MEMORY_SWEEPS.lock().unwrap().contains_key(&root));
    }

    async fn fixture(name: &str) -> (tempfile::TempDir, LocalBackend, i32, i32) {
        let home = tempfile::tempdir().unwrap();
        let backend = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        let config = SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                name: name.into(),
                ..Default::default()
            },
            ..Default::default()
        };
        let pools = backend.db().await.unwrap();
        let id = LocalBackend::insert_sandbox_record(pools.write(), &config)
            .await
            .unwrap();
        LocalBackend::update_sandbox_status(pools.write(), id, SandboxStatus::Stopped)
            .await
            .unwrap();
        let run_id = run::Entity::insert(run::ActiveModel {
            sandbox_id: Set(id),
            // A visible PID cannot substitute for the runtime's ownership lock.
            pid: Set(Some(std::process::id() as i32)),
            status: Set(run::RunStatus::Terminated),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap()
        .last_insert_id;
        #[cfg(windows)]
        {
            // This fixture models a current runtime whose lifecycle lock is authoritative.
            let directory = backend.sandboxes_dir().join(name).join("runtime");
            std::fs::create_dir_all(&directory).unwrap();
            let run = backend.latest_stop_run(id).await.unwrap().unwrap();
            crate::runtime::ownership::RuntimeProcess::capture(std::process::id() as i32)
                .unwrap()
                .unwrap()
                .publish(&directory, &run, true)
                .unwrap();
        }
        (home, backend, id, run_id)
    }

    async fn owned_disk_fixture(
        name: &str,
    ) -> (
        tempfile::TempDir,
        LocalBackend,
        i32,
        i32,
        Vec<crate::sandbox::VolumeMount>,
    ) {
        let (home, backend, id, run_id) = fixture(name).await;
        let mounts: Vec<_> = ["/data", "/logs"]
            .into_iter()
            .map(|guest| {
                crate::sandbox::MountBuilder::new(guest)
                    .owned_with(|owned| owned.disk().size(1_u32))
                    .build()
                    .unwrap()
            })
            .collect();
        let config = SandboxConfig {
            spec: microsandbox_types::SandboxSpec {
                name: name.into(),
                mounts: mounts.clone(),
                ..Default::default()
            },
            ..Default::default()
        };
        sandbox::Entity::update_many()
            .col_expr(
                sandbox::Column::Config,
                sea_orm::sea_query::Expr::value(serde_json::to_string(&config).unwrap()),
            )
            .filter(sandbox::Column::Id.eq(id))
            .exec(backend.db().await.unwrap().write())
            .await
            .unwrap();
        for mount in &mounts {
            let directory = backend
                .sandboxes_dir()
                .join(name)
                .join("owned-volumes")
                .join(microsandbox_types::owned_volume_mount_id(mount.guest()));
            std::fs::create_dir_all(directory).unwrap();
            crate::runtime::owned_volumes::disk_lock_path(
                &backend.sandboxes_dir().join(name),
                mount.guest(),
            )
            .unwrap();
            #[cfg(windows)]
            {
                let marker = crate::runtime::owned_volumes::disk_lock_path(
                    &backend.sandboxes_dir().join(name),
                    mount.guest(),
                )
                .unwrap();
                drop(
                    std::fs::File::create(
                        crate::runtime::spawn::windows_disk_lock_path(&marker).unwrap(),
                    )
                    .unwrap(),
                );
            }
        }
        (home, backend, id, run_id, mounts)
    }

    #[tokio::test]
    async fn stop_waits_for_every_owned_disk_after_lifecycle_release() {
        use crate::backend::Backend;
        use crate::runtime::owned_volumes::try_acquire_disk_guards;
        let (_home, backend, _, _, mounts) = owned_disk_fixture("disk-teardown").await;
        let directory = backend.sandboxes_dir().join("disk-teardown");
        let mut disks = try_acquire_disk_guards(&directory, &mounts)
            .unwrap()
            .unwrap();
        // Deterministically reproduce the kernel trace's critical state: terminal row and
        // available lifecycle lock, but disk descriptors still owned by an exiting worker.
        let lifecycle = try_acquire_lifecycle_guard(&backend.config().run_dir(), "disk-teardown")
            .unwrap()
            .unwrap();
        drop(lifecycle);
        let backend: std::sync::Arc<dyn Backend> = std::sync::Arc::new(backend);
        let handle = backend
            .sandboxes()
            .get(backend.clone(), "disk-teardown")
            .await
            .unwrap();
        for _ in 0..2 {
            assert!(matches!(
                handle.stop_with_timeout(Duration::from_millis(20)).await,
                Err(MicrosandboxError::StopTimeout { .. })
            ));
            assert!(
                try_acquire_disk_guards(&directory, &mounts)
                    .unwrap()
                    .is_none()
            );
            // Releasing just one device is insufficient; both must be available.
            disks.pop();
        }
        handle.stop().await.unwrap();
        assert_eq!(
            try_acquire_disk_guards(&directory, &mounts)
                .unwrap()
                .unwrap()
                .len(),
            2
        );
        handle.remove().await.unwrap();
    }

    #[tokio::test]
    async fn cancelled_disk_teardown_stop_preserves_locks_and_rejects_new_run() {
        use crate::runtime::owned_volumes::try_acquire_disk_guards;
        let (_home, backend, id, run_id, mounts) = owned_disk_fixture("disk-new-run").await;
        let directory = backend.sandboxes_dir().join("disk-new-run");
        let owner = try_acquire_disk_guards(&directory, &mounts)
            .unwrap()
            .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(20),
                backend.wait_stop_complete(
                    "disk-new-run",
                    id,
                    Some(run_id),
                    false,
                    #[cfg(windows)]
                    None,
                )
            )
            .await
            .is_err()
        );
        assert!(
            try_acquire_disk_guards(&directory, &mounts)
                .unwrap()
                .is_none()
        );
        run::Entity::insert(run::ActiveModel {
            sandbox_id: Set(id),
            status: Set(run::RunStatus::Terminated),
            ..Default::default()
        })
        .exec(backend.db().await.unwrap().write())
        .await
        .unwrap();
        let error = backend
            .wait_stop_complete(
                "disk-new-run",
                id,
                Some(run_id),
                false,
                #[cfg(windows)]
                None,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("refusing to follow run"));
        drop(owner);
    }

    #[tokio::test]
    async fn terminal_database_does_not_complete_stop_until_runtime_releases_ownership() {
        let (_home, backend, id, _) = fixture("delayed-teardown").await;
        let ownership =
            try_acquire_lifecycle_guard(&backend.config().run_dir(), "delayed-teardown")
                .unwrap()
                .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(80),
                backend.stop_complete("delayed-teardown", id, false)
            )
            .await
            .is_err()
        );
        assert!(
            try_acquire_lifecycle_guard(&backend.config().run_dir(), "delayed-teardown")
                .unwrap()
                .is_none()
        );
        drop(ownership);
        backend
            .stop_complete("delayed-teardown", id, false)
            .await
            .unwrap();
        crate::sandbox::remove_local_persisted_sandbox(&backend, "delayed-teardown", id)
            .await
            .unwrap();
        assert!(
            sandbox::Entity::find_by_id(id)
                .one(backend.db().await.unwrap().read())
                .await
                .unwrap()
                .is_none()
        );
    }

    #[tokio::test]
    async fn stopped_wait_rejects_a_new_run_of_the_same_persisted_sandbox() {
        let (_home, backend, id, run_id) = fixture("restarted").await;
        run::Entity::insert(run::ActiveModel {
            sandbox_id: Set(id),
            status: Set(run::RunStatus::Terminated),
            ..Default::default()
        })
        .exec(backend.db().await.unwrap().write())
        .await
        .unwrap();
        let error = backend
            .wait_stop_complete(
                "restarted",
                id,
                Some(run_id),
                false,
                #[cfg(windows)]
                None,
            )
            .await
            .unwrap_err();
        assert!(error.to_string().contains("refusing to follow run"));
    }

    #[tokio::test]
    async fn ownership_release_reconciles_a_stale_run_despite_a_visible_pid() {
        let (_home, backend, id, run_id) = fixture("stale-run").await;
        run::Entity::update_many()
            .col_expr(
                run::Column::Status,
                sea_orm::sea_query::Expr::value(run::RunStatus::Running),
            )
            .filter(run::Column::Id.eq(run_id))
            .exec(backend.db().await.unwrap().write())
            .await
            .unwrap();
        LocalBackend::update_sandbox_status(
            backend.db().await.unwrap().write(),
            id,
            SandboxStatus::Running,
        )
        .await
        .unwrap();
        use crate::backend::Backend;
        let backend: std::sync::Arc<dyn Backend> = std::sync::Arc::new(backend);
        // Exercise public Stop, including dispatch selection, not just the polling helper.
        let handle = backend
            .sandboxes()
            .get(backend.clone(), "stale-run")
            .await
            .unwrap();
        handle.stop().await.unwrap();
        let backend = backend.as_local().unwrap();
        assert_eq!(
            backend.latest_stop_run(id).await.unwrap().unwrap().status,
            run::RunStatus::Terminated
        );
    }

    #[tokio::test]
    async fn public_stop_zero_and_wait_timeout_preserve_runtime_ownership() {
        use crate::backend::Backend;
        let (_home, backend, _, _) = fixture("public-stop").await;
        let backend: std::sync::Arc<dyn Backend> = std::sync::Arc::new(backend);
        let local = backend.as_local().unwrap();
        let owner = try_acquire_lifecycle_guard(&local.config().run_dir(), "public-stop")
            .unwrap()
            .unwrap();
        let handle = backend
            .sandboxes()
            .get(backend.clone(), "public-stop")
            .await
            .unwrap();
        for budget in [Duration::ZERO, Duration::from_millis(80)] {
            assert!(matches!(handle.stop_with_timeout(budget).await,
                Err(MicrosandboxError::StopTimeout { timeout, .. }) if timeout == budget));
            assert!(
                try_acquire_lifecycle_guard(&local.config().run_dir(), "public-stop")
                    .unwrap()
                    .is_none()
            );
        }
        // Dropping an indefinitely pending Stop future cancels only this observer.
        assert!(
            tokio::time::timeout(Duration::from_millis(80), handle.stop())
                .await
                .is_err()
        );
        assert!(
            try_acquire_lifecycle_guard(&local.config().run_dir(), "public-stop")
                .unwrap()
                .is_none()
        );
        drop(owner);
        handle.stop().await.unwrap();
        handle.remove().await.unwrap();
    }

    #[tokio::test]
    async fn public_stop_budget_includes_waiting_for_transition_ownership() {
        use crate::backend::Backend;
        let (_home, backend, _, _) = fixture("transition-budget").await;
        let backend: std::sync::Arc<dyn Backend> = std::sync::Arc::new(backend);
        let handle = backend
            .sandboxes()
            .get(backend.clone(), "transition-budget")
            .await
            .unwrap();
        let local = backend.as_local().unwrap();
        let _transition = LocalBackend::acquire_sandbox_transition_guard(
            &local.config().run_dir(),
            "transition-budget",
        )
        .await
        .unwrap();
        assert!(matches!(
            handle.stop_with_timeout(Duration::from_millis(30)).await,
            Err(MicrosandboxError::StopTimeout { .. })
        ));
    }

    #[tokio::test]
    async fn ephemeral_row_disappearance_still_waits_for_ownership_release() {
        let (_home, backend, id, _) = fixture("ephemeral-stop").await;
        let owner = try_acquire_lifecycle_guard(&backend.config().run_dir(), "ephemeral-stop")
            .unwrap()
            .unwrap();
        sandbox::Entity::delete_by_id(id)
            .exec(backend.db().await.unwrap().write())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(
                Duration::from_millis(80),
                backend.stop_complete("ephemeral-stop", id, true)
            )
            .await
            .is_err()
        );
        drop(owner);
        backend
            .stop_complete("ephemeral-stop", id, true)
            .await
            .unwrap();
    }
    #[cfg(windows)]
    #[tokio::test]
    async fn legacy_terminal_row_waits_for_exact_process_even_without_its_sidecar() {
        use std::process::{Command, Stdio};
        let (_home, backend, id, run_id) = fixture("legacy-exit").await;
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "runtime::ownership::tests::ownership_child",
                "--ignored",
            ])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let process = crate::runtime::ownership::RuntimeProcess::capture(child.id() as i32)
            .unwrap()
            .unwrap();
        let directory = backend.sandboxes_dir().join("legacy-exit").join("runtime");
        run::Entity::update_many()
            .col_expr(
                run::Column::Pid,
                sea_orm::sea_query::Expr::value(child.id() as i32),
            )
            .filter(run::Column::Id.eq(run_id))
            .exec(backend.db().await.unwrap().write())
            .await
            .unwrap();
        let run = backend.latest_stop_run(id).await.unwrap().unwrap();
        process.publish(&directory, &run, false).unwrap();
        let owner = crate::runtime::ownership::recorded_owner(&directory, &run).unwrap();
        std::fs::remove_file(directory.join("sdk-process.json")).unwrap();
        let mut wait =
            Box::pin(backend.wait_stop_complete("legacy-exit", id, Some(run_id), false, owner));
        let pending = tokio::time::timeout(Duration::from_millis(80), &mut wait)
            .await
            .is_err();
        // Always clean up the fixture before asserting, including a regression returning early.
        child.kill().unwrap();
        child.wait().unwrap();
        assert!(
            pending,
            "a terminal row and an unused lock cannot prove legacy process exit"
        );
        tokio::time::timeout(Duration::from_secs(2), wait)
            .await
            .unwrap()
            .unwrap();
    }
}
