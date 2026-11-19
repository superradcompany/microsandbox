//! Resource collections retain an explicit destination without ambient scope changes.

use std::sync::Arc;

use super::Context;
use crate::sandbox::SandboxBuilder;
use crate::snapshot::{HeadUpdate, SnapshotId};
use crate::volume::VolumeBuilder;
use crate::{
    Checkpoint, MicrosandboxError, MicrosandboxResult, Sandbox, SandboxListBuilder, SandboxPage,
    SnapshotBuilder, SnapshotConfig, SnapshotReference, Volume, VolumeConfig,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Sandbox factories and lookup operations bound to one context.
#[derive(Clone)]
pub struct Sandboxes {
    pub(crate) context: Arc<dyn Context>,
}

/// Volume factories and lookup operations bound to one context.
#[derive(Clone)]
pub struct Volumes {
    pub(crate) context: Arc<dyn Context>,
}

/// Named checkpoint histories on one destination.
#[derive(Clone)]
pub struct Snapshots {
    pub(crate) context: Arc<dyn Context>,
}

/// Checkpoint factories and lookup operations bound to one context.
#[derive(Clone)]
pub struct Checkpoints {
    pub(crate) context: Arc<dyn Context>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandboxes {
    /// Restore onto this destination; the deferred builder retains it through progress tasks.
    pub fn restore(&self, reference: impl Into<String>) -> crate::sandbox::RestoreBuilder {
        self.restore_ref(SnapshotReference::auto(reference))
    }

    /// Restore an explicitly interpreted provider ID or path onto this destination.
    pub fn restore_ref(
        &self,
        reference: impl Into<SnapshotReference>,
    ) -> crate::sandbox::RestoreBuilder {
        crate::sandbox::RestoreBuilder::for_context(self.context.clone(), reference.into())
    }

    /// Create directly from a complete configuration on this destination.
    pub async fn create(&self, config: crate::SandboxConfig) -> MicrosandboxResult<Sandbox> {
        self.context
            .sandbox_ops()
            .create(self.context.clone(), config, true)
            .await
    }

    /// Create without acquiring local process cleanup ownership.
    pub async fn create_detached(
        &self,
        config: crate::SandboxConfig,
    ) -> MicrosandboxResult<Sandbox> {
        self.context
            .sandbox_ops()
            .create_detached(self.context.clone(), config)
            .await
    }

    /// Borrow the retained destination. This performs no backend I/O.
    pub fn context(&self) -> &dyn Context {
        self.context.as_ref()
    }

    /// Prepare creation on this destination. The builder retains the context.
    pub fn builder(&self, name: impl Into<String>) -> SandboxBuilder {
        SandboxBuilder::for_context(self.context.clone(), name)
    }

    /// Look up a sandbox on this destination.
    pub async fn get(&self, name: &str) -> MicrosandboxResult<Sandbox> {
        self.context
            .sandbox_ops()
            .get(self.context.clone(), name)
            .await
            .map(Sandbox::from_record)
    }

    /// Get an existing sandbox and connect or start it on this destination.
    ///
    /// Does not create missing resources. A newly started attached local run is
    /// owned by the returned Sandbox; connecting to an existing run is non-owning.
    pub async fn get_running(&self, name: &str) -> MicrosandboxResult<Sandbox> {
        // Carry the lookup's identity and context through the start decision.
        let sandbox = self.get(name).await?;
        sandbox.ensure_running().await?;
        Ok(sandbox)
    }

    /// Start a stopped sandbox and retain ownership of its new local run.
    /// An already running sandbox is an error; use `get_running` for idempotent preparation.
    pub async fn start(&self, name: &str) -> MicrosandboxResult<Sandbox> {
        self.context
            .sandbox_ops()
            .get(self.context.clone(), name)
            .await?
            .start()
            .await
    }

    /// Start a stopped sandbox without assigning cleanup ownership to the result.
    pub async fn start_detached(&self, name: &str) -> MicrosandboxResult<Sandbox> {
        self.context
            .sandbox_ops()
            .get(self.context.clone(), name)
            .await?
            .start_detached()
            .await
    }

    /// Delete the resource selected by name in this destination.
    /// Use `Sandbox::destroy` for deletion bound to an already captured identity.
    pub async fn remove(&self, name: &str) -> MicrosandboxResult<()> {
        self.context
            .sandbox_ops()
            .remove(self.context.clone(), name)
            .await
    }

    /// Fetch one page with the default limit.
    pub async fn list(&self) -> MicrosandboxResult<SandboxPage> {
        self.list_with(|list| list).await
    }

    /// Fetch one page with explicit filters and an opaque continuation cursor.
    pub async fn list_with(
        &self,
        configure: impl FnOnce(SandboxListBuilder) -> SandboxListBuilder,
    ) -> MicrosandboxResult<SandboxPage> {
        let query = configure(SandboxListBuilder::default());
        let max = crate::sandbox::MAX_SANDBOX_LIST_LIMIT;
        if !(1..=max).contains(&query.limit) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "sandbox list limit must be between 1 and {max}"
            )));
        }
        self.context
            .sandbox_ops()
            .list(self.context.clone(), query)
            .await
            .map(SandboxPage::from_records)
    }
}

impl Volumes {
    /// Borrow the retained destination. This performs no backend I/O.
    pub fn context(&self) -> &dyn Context {
        self.context.as_ref()
    }

    /// Prepare creation on this destination. The builder retains the context.
    pub fn builder(&self, name: impl Into<String>) -> VolumeBuilder {
        VolumeBuilder::for_context(self.context.clone(), name)
    }

    /// Create a volume on this destination.
    pub async fn create(&self, config: VolumeConfig) -> MicrosandboxResult<Volume> {
        self.context
            .volume_ops()
            .create(self.context.clone(), config)
            .await
    }

    /// Look up a volume on this destination.
    pub async fn get(&self, name: &str) -> MicrosandboxResult<Volume> {
        self.context
            .volume_ops()
            .get(self.context.clone(), name)
            .await
    }

    /// List volumes on this destination.
    pub async fn list(&self) -> MicrosandboxResult<Vec<Volume>> {
        self.context.volume_ops().list(self.context.clone()).await
    }

    /// Look up the destination's default volume; local contexts have none.
    pub async fn get_default(&self) -> MicrosandboxResult<Volume> {
        self.context
            .volume_ops()
            .get_default(self.context.clone())
            .await
    }

    /// Select a volume by name for deletion in this context.
    /// Use `Volume::destroy` to delete an already captured identity instead.
    pub async fn remove(&self, name: &str) -> MicrosandboxResult<()> {
        self.context
            .volume_ops()
            .remove(self.context.clone(), name)
            .await
    }
}

impl Snapshots {
    /// Destination retained by this collection and the groups it returns.
    pub fn context(&self) -> &dyn Context {
        self.context.as_ref()
    }

    /// Open a named history without resolving its mutable head.
    pub async fn get(&self, name: &str) -> MicrosandboxResult<crate::Snapshot> {
        self.context
            .snapshot_ops()
            .get_group(self.context.clone(), name)
            .await
    }

    /// List named histories, including groups with a cleared head.
    pub async fn list(&self) -> MicrosandboxResult<Vec<crate::Snapshot>> {
        self.context
            .snapshot_ops()
            .list_groups(self.context.clone())
            .await
    }

    /// Open an external local history. Anchor the path before the caller can defer polling.
    pub fn open<P: AsRef<std::path::Path>>(
        &self,
        path: P,
    ) -> impl std::future::Future<Output = MicrosandboxResult<crate::Snapshot>> + Send + use<P>
    {
        let context = self.context.clone();
        let path = path.as_ref();
        let directory = if path.as_os_str().is_empty() {
            Err(MicrosandboxError::InvalidConfig(
                "snapshot group path cannot be empty".into(),
            ))
        } else {
            std::path::absolute(path).map_err(MicrosandboxError::from)
        };
        async move {
            context
                .snapshot_ops()
                .open_group(context.clone(), &directory?)
                .await
        }
    }

    /// Bind archive and destination paths to this context before a language binding defers work.
    pub fn prepare_import(
        &self,
        files: Vec<std::path::PathBuf>,
        options: crate::snapshot::LoadOpts,
    ) -> MicrosandboxResult<crate::snapshot::PreparedSnapshotImport> {
        crate::snapshot::PreparedSnapshotImport::with_backend(self.context.clone(), files, options)
    }

    /// Import an archive set atomically with default options.
    pub async fn load(
        &self,
        group: &str,
        files: &[std::path::PathBuf],
    ) -> MicrosandboxResult<crate::SnapshotImportResult> {
        self.load_with(group, files, |options| options).await
    }

    /// Import with the selected destination, dependencies and head policy.
    pub async fn load_with(
        &self,
        group: &str,
        files: &[std::path::PathBuf],
        configure: impl FnOnce(crate::SnapshotImportOptions) -> crate::SnapshotImportOptions,
    ) -> MicrosandboxResult<crate::SnapshotImportResult> {
        let options = configure(Default::default()).into_load_opts();
        self.context
            .snapshot_ops()
            .load_group(self.context.clone(), group, files, options)
            .await
    }

    /// Authenticate encrypted inputs inside the selected local context before publication.
    #[cfg(feature = "local")]
    pub async fn load_encrypted(
        &self,
        group: &str,
        files: &[std::path::PathBuf],
        identity: &std::path::Path,
        configure: impl FnOnce(crate::SnapshotImportOptions) -> crate::SnapshotImportOptions,
    ) -> MicrosandboxResult<crate::SnapshotImportResult> {
        let local = self
            .context
            .as_local()
            .ok_or_else(|| MicrosandboxError::local_only(crate::Operation::SnapshotOps))?;
        local
            .import_encrypted(
                self.context.clone(),
                group,
                files,
                configure(Default::default()).into_load_opts(),
                identity,
            )
            .await
    }
}

impl Checkpoints {
    /// Read the selected snapshot ID. An existing headless group returns None.
    pub async fn group_head(&self, group: &str) -> MicrosandboxResult<Option<SnapshotId>> {
        self.context.snapshot_ops().group_head(group).await
    }

    /// Select a member of this group by its stable ID.
    pub async fn set_group_head(
        &self,
        group: &str,
        id: &SnapshotId,
    ) -> MicrosandboxResult<HeadUpdate> {
        self.context.snapshot_ops().set_group_head(group, id).await
    }

    /// Inspect artifacts in a provider-supported directory.
    pub async fn list_dir(
        &self,
        dir: impl AsRef<std::path::Path>,
    ) -> MicrosandboxResult<Vec<Checkpoint>> {
        self.context
            .snapshot_ops()
            .list_dir(self.context.clone(), dir.as_ref().to_path_buf())
            .await
    }

    /// Rebuild the selected provider's snapshot index.
    pub async fn reindex(&self, dir: impl AsRef<std::path::Path>) -> MicrosandboxResult<usize> {
        self.context
            .snapshot_ops()
            .reindex(Some(dir.as_ref().to_path_buf()))
            .await
    }

    /// Rebuild the selected provider's default snapshot index.
    pub async fn reindex_default(&self) -> MicrosandboxResult<usize> {
        self.context.snapshot_ops().reindex(None).await
    }

    /// Export a selected snapshot using this provider's path interpretation.
    pub async fn save(
        &self,
        reference: impl Into<SnapshotReference>,
        out: &std::path::Path,
        opts: crate::snapshot::SaveOpts,
    ) -> MicrosandboxResult<()> {
        self.context
            .snapshot_ops()
            .save(reference.into(), out, opts)
            .await
    }

    /// Import one archive into this destination.
    pub async fn load(
        &self,
        path: &std::path::Path,
        dest: Option<&std::path::Path>,
    ) -> MicrosandboxResult<Checkpoint> {
        self.context
            .snapshot_ops()
            .load(self.context.clone(), path, dest)
            .await
    }

    /// Import with an explicit dependency base and publication policy.
    pub async fn load_with_options(
        &self,
        path: &std::path::Path,
        opts: crate::snapshot::LoadOpts,
    ) -> MicrosandboxResult<Checkpoint> {
        let mut snapshots = self.load_many(&[path.to_path_buf()], opts).await?;
        snapshots.pop().ok_or_else(|| {
            MicrosandboxError::InvalidConfig("provider returned no imported snapshot".into())
        })
    }

    /// Validate the complete import set before publication.
    pub async fn load_many(
        &self,
        paths: &[std::path::PathBuf],
        opts: crate::snapshot::LoadOpts,
    ) -> MicrosandboxResult<Vec<Checkpoint>> {
        self.context
            .snapshot_ops()
            .load_many(self.context.clone(), paths, opts)
            .await
    }

    /// Capture directly to an archive in this destination.
    pub async fn create_archive(
        &self,
        config: SnapshotConfig,
        out: &std::path::Path,
        plain_tar: bool,
    ) -> MicrosandboxResult<crate::snapshot::SnapshotArchive> {
        self.context
            .snapshot_ops()
            .create_archive(config, out, plain_tar)
            .await
    }

    /// Borrow the retained destination. This performs no backend I/O.
    pub fn context(&self) -> &dyn Context {
        self.context.as_ref()
    }

    /// Prepare a capture on this destination. The builder retains the context.
    pub fn builder(&self, name: impl Into<String>) -> SnapshotBuilder {
        SnapshotBuilder::for_context(self.context.clone(), name)
    }

    /// Capture a snapshot on this destination.
    pub async fn create(&self, config: SnapshotConfig) -> MicrosandboxResult<Checkpoint> {
        self.context
            .snapshot_ops()
            .create(self.context.clone(), config)
            .await
    }

    /// Open an existing snapshot on this destination.
    pub async fn open(&self, reference: impl AsRef<str>) -> MicrosandboxResult<Checkpoint> {
        self.open_ref(SnapshotReference::auto(reference.as_ref()))
            .await
    }

    /// Open an explicit snapshot reference on this destination.
    pub async fn open_ref(
        &self,
        reference: impl Into<SnapshotReference>,
    ) -> MicrosandboxResult<Checkpoint> {
        self.context
            .snapshot_ops()
            .open(self.context.clone(), reference.into())
            .await
    }

    /// Look up a snapshot on this destination.
    pub async fn get(&self, name: &str) -> MicrosandboxResult<Checkpoint> {
        self.context
            .snapshot_ops()
            .get(self.context.clone(), name)
            .await
    }

    /// List snapshots on this destination.
    pub async fn list(&self) -> MicrosandboxResult<Vec<Checkpoint>> {
        self.context.snapshot_ops().list(self.context.clone()).await
    }

    /// Select a snapshot for deletion in this context. For a captured identity use `destroy`.
    pub async fn remove(&self, reference: impl AsRef<str>, force: bool) -> MicrosandboxResult<()> {
        self.remove_ref(SnapshotReference::auto(reference.as_ref()), force)
            .await
    }

    /// Delete an explicitly selected name, ID or path in this context.
    pub async fn remove_ref(
        &self,
        reference: impl Into<SnapshotReference>,
        force: bool,
    ) -> MicrosandboxResult<()> {
        self.context
            .snapshot_ops()
            .remove(self.context.clone(), reference.into(), force)
            .await
    }
}

impl Sandbox {
    /// Select the default-local destination without consulting ambient remote selection.
    #[cfg(feature = "local")]
    pub fn local() -> Sandboxes {
        super::default_local_context().sandboxes()
    }

    /// Capture remote credentials and endpoint from the environment, without backend I/O.
    /// Existing collections and resources keep their previously captured destination.
    #[cfg(feature = "cloud")]
    pub fn remote() -> MicrosandboxResult<Sandboxes> {
        Ok(super::RemoteContext::from_env()?.sandboxes())
    }

    /// Bind sandbox factories to an explicit context, retaining its shared state.
    pub fn ctx(context: &dyn Context) -> Sandboxes {
        context.sandboxes()
    }
}

impl Volume {
    /// Select the default-local destination without consulting ambient remote selection.
    #[cfg(feature = "local")]
    pub fn local() -> Volumes {
        super::default_local_context().volumes()
    }

    /// Capture remote credentials and endpoint from the environment, without backend I/O.
    /// Existing collections and resources keep their previously captured destination.
    #[cfg(feature = "cloud")]
    pub fn remote() -> MicrosandboxResult<Volumes> {
        Ok(super::RemoteContext::from_env()?.volumes())
    }

    /// Bind volume factories to an explicit context, retaining its shared state.
    pub fn ctx(context: &dyn Context) -> Volumes {
        context.volumes()
    }
}

impl Checkpoint {
    /// Select the default-local destination without consulting ambient remote selection.
    #[cfg(feature = "local")]
    pub fn local() -> Checkpoints {
        super::default_local_context().checkpoints()
    }

    /// Capture remote credentials and endpoint from the environment, without backend I/O.
    /// Existing collections and resources keep their previously captured destination.
    #[cfg(feature = "cloud")]
    pub fn remote() -> MicrosandboxResult<Checkpoints> {
        Ok(super::RemoteContext::from_env()?.checkpoints())
    }

    /// Bind snapshot factories to an explicit context, retaining its shared state.
    pub fn ctx(context: &dyn Context) -> Checkpoints {
        context.checkpoints()
    }
}

impl crate::Snapshot {
    /// Select the default-local destination without consulting ambient remote selection.
    #[cfg(feature = "local")]
    pub fn local() -> Snapshots {
        super::default_local_context().snapshots()
    }

    /// Capture remote credentials and endpoint from the environment, without backend I/O.
    /// Existing collections and resources keep their previously captured destination.
    #[cfg(feature = "cloud")]
    pub fn remote() -> MicrosandboxResult<Snapshots> {
        Ok(super::RemoteContext::from_env()?.snapshots())
    }

    /// Bind snapshot factories to an explicit context, retaining its shared state.
    pub fn ctx(context: &dyn Context) -> Snapshots {
        context.snapshots()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(all(feature = "local", feature = "cloud"))]
    #[test]
    fn selectors_override_the_configured_destination_and_builders_retain_it() {
        let _guard = crate::test_support::lock_env();
        let home = tempfile::tempdir().unwrap();
        let names = [
            "MSB_HOME",
            "MSB_CONFIG_PATH",
            "MSB_BACKEND",
            "MSB_PROFILE",
            "MSB_API_KEY",
            "MSB_API_URL",
        ];
        let previous = names.map(|name| (name, std::env::var_os(name)));
        // All environment-mutating SDK tests serialize with lock_env.
        unsafe {
            std::env::set_var("MSB_HOME", home.path());
            std::env::set_var("MSB_CONFIG_PATH", home.path().join("config.json"));
            std::env::set_var("MSB_BACKEND", "local");
            std::env::set_var("MSB_PROFILE", "missing");
            std::env::remove_var("MSB_API_KEY");
            std::env::set_var("MSB_API_URL", "https://first.example");
        }
        assert!(Sandbox::remote().is_err());
        assert!(Volume::remote().is_err());
        assert!(Checkpoint::remote().is_err());
        unsafe {
            std::env::set_var("MSB_API_KEY", "fixture-key");
        }
        let local_builder = Sandbox::builder("captured-local");
        let selected = Sandbox::remote().unwrap();
        let builder = selected.builder("retained");
        assert_eq!(
            Volume::remote().unwrap().context().kind(),
            crate::ContextKind::Remote
        );
        assert_eq!(
            Checkpoint::remote().unwrap().context().kind(),
            crate::ContextKind::Remote
        );
        unsafe {
            std::env::set_var("MSB_API_URL", "https://second.example");
            std::env::set_var("MSB_BACKEND", "remote");
        }
        assert_eq!(
            selected.context().info().unwrap().api_url.as_deref(),
            Some("https://first.example")
        );
        assert_eq!(
            builder.context().info().unwrap().api_url.as_deref(),
            Some("https://first.example")
        );
        assert_eq!(
            Sandbox::remote()
                .unwrap()
                .context()
                .info()
                .unwrap()
                .api_url
                .as_deref(),
            Some("https://second.example")
        );
        assert_eq!(Sandbox::local().context().kind(), crate::ContextKind::Local);
        assert_eq!(Volume::local().context().kind(), crate::ContextKind::Local);
        assert_eq!(
            Checkpoint::local().context().kind(),
            crate::ContextKind::Local
        );
        assert_eq!(
            Sandbox::builder("default").context().kind(),
            crate::ContextKind::Remote
        );
        assert_eq!(
            Volume::builder("vol").context().kind(),
            crate::ContextKind::Remote
        );
        assert_eq!(
            Checkpoint::builder("snap").context().kind(),
            crate::ContextKind::Remote
        );
        assert_eq!(local_builder.context().kind(), crate::ContextKind::Local);
        for (name, value) in previous {
            unsafe {
                match value {
                    Some(value) => std::env::set_var(name, value),
                    None => std::env::remove_var(name),
                }
            }
        }
    }
    use crate::context::misconfigured::ConfigurationErrorBackend;

    fn destination(name: &str) -> ConfigurationErrorBackend {
        ConfigurationErrorBackend::new(MicrosandboxError::InvalidConfig(name.to_owned()))
    }

    fn assert_destination<T>(result: MicrosandboxResult<T>, name: &str) {
        match result {
            Err(MicrosandboxError::InvalidConfig(message)) => assert_eq!(message, name),
            Err(error) => panic!("wrong destination error: {error}"),
            Ok(_) => panic!("operation escaped the selected destination"),
        }
    }

    #[test]
    fn builders_reuse_the_collections_retained_context() {
        let context = destination("retained");
        let sandboxes = context.sandboxes();
        let volumes = context.volumes();
        let snapshots = context.checkpoints();
        assert!(std::ptr::eq(
            sandboxes.context(),
            sandboxes.builder("task").context()
        ));
        assert!(std::ptr::eq(
            volumes.context(),
            volumes.builder("data").context()
        ));
        assert!(std::ptr::eq(
            snapshots.context(),
            snapshots.builder("checkpoint").context()
        ));
    }

    #[tokio::test]
    async fn collections_retain_distinct_destinations_after_contexts_are_dropped() {
        let collections = |name| {
            let context = destination(name);
            let erased: &dyn Context = &context;
            (
                Sandbox::ctx(erased),
                Volume::ctx(erased),
                Checkpoint::ctx(erased),
            )
        };
        let (a, av, ass) = collections("destination-a");
        let (b, bv, bs) = collections("destination-b");
        let (ar, br) = tokio::join!(a.get("same-name"), b.get("same-name"));
        assert_destination(ar, "destination-a");
        assert_destination(br, "destination-b");
        assert_destination(av.get("same-name").await, "destination-a");
        assert_destination(bv.get("same-name").await, "destination-b");
        assert_destination(ass.get("same-name").await, "destination-a");
        assert_destination(bs.get("same-name").await, "destination-b");
        assert_destination(a.list().await, "destination-a");
        assert_destination(bv.list().await, "destination-b");
        assert_destination(ass.open("same-name").await, "destination-a");
        assert_destination(ass.group_head("same-group").await, "destination-a");
        let id = SnapshotId::new(format!("snap_{:032x}", 1)).unwrap();
        assert_destination(bs.set_group_head("same-group", &id).await, "destination-b");
    }

    #[tokio::test]
    async fn explicit_builders_ignore_an_unrelated_ambient_scope() {
        let (sandbox, volume, snapshot) = {
            let context = destination("retained");
            (
                context.sandboxes().builder("same-name").image("python"),
                context.volumes().builder("same-name"),
                context
                    .checkpoints()
                    .builder("same-name")
                    .from_sandbox("source"),
            )
        };
        // Until facade migration removes scopes, verify they cannot redirect bound work.
        async {
            let _unrelated_context: std::sync::Arc<dyn crate::Context> =
                Arc::new(destination("unrelated")) as Arc<dyn Context>;

            assert_destination(sandbox.create().await, "retained");
            assert_destination(volume.create().await, "retained");
            assert_destination(snapshot.create().await, "retained");
        }
        .await;
    }

    #[cfg(feature = "local")]
    #[tokio::test]
    async fn spawned_progress_retains_the_builder_destination() {
        let context = destination("retained-progress");
        let builder = context.sandboxes().builder("same-name").image("python");
        drop(context);
        let (progress, task) = builder.create_with_progress().unwrap();
        drop(progress);
        assert_destination(task.await.unwrap(), "retained-progress");
    }
}
