//! Source identity for private checkpoint receipts, selected before dispatch.

use std::{path::PathBuf, sync::Arc};

use microsandbox_db::DbWriteConnection;
use microsandbox_protocol::control::ConfigurationCaptureReceipt;
use microsandbox_protocol::init_observation::InitObservation;
use microsandbox_runtime::ipc::SandboxLifecycleGuard;
use microsandbox_runtime::retention::{
    CapturedConfiguration, RetainedConfiguration, RetentionOwner, ScriptBackingEvidence,
    read_retained_init, select_stopped_configuration,
};
use sea_orm::{ConnectionTrait, DbBackend, Statement};

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, MAX_SAVED_SCRIPT_BYTES, MAX_SAVED_SCRIPTS_BYTES,
    SavedBindingReference, SavedOrigin, SavedSandboxConfig, SavedValue,
};

use crate::backend::{ControlSession, LocalBackend};
use crate::sandbox::SandboxConfig;
use crate::snapshot::saved_config::{
    CaptureDocumentRequest, NetworkCaptureBindings, NetworkCaptureSection, PendingCaptureSource,
    RuntimeCaptureSource, StorageCaptureBindings,
};
use crate::{MicrosandboxError, MicrosandboxResult};

use super::stopped_script_backing::StoppedScriptObservation;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Confirmed source and backing retained together through local publication.
/// No Debug/serialization: portable emission must project and apply exclusions explicitly.
pub(crate) struct CapturedSandboxConfiguration {
    // Keep the guarded source verbatim: decoding SandboxConfig supplies defaults for
    // absent fields, and reserializing it would manufacture historical evidence. The
    // owner/generation identify the captured transition, not current mutable state.
    source: RetainedConfiguration,
    pending: Option<serde_json::Value>,
    configuration: SandboxConfig,
    scripts: Option<ScriptBackingEvidence>,
    init: Option<InitObservation>,
    storage: Option<microsandbox_runtime::retention::MountedStorageEvidence>,
    exec_limits: Option<microsandbox_types::ExecLimits>,
}

/// No Debug or serialization: the eventual receipt can contain private local configuration.
pub(crate) struct ExpectedConfigurationCapture {
    directory: PathBuf,
    owner: RetentionOwner,
    storage_requested: bool,
    exec_limits_requested: bool,
}

/// Retains lifecycle ownership and exact evidence through a stopped disk cut.
/// Raw values remain private and are compared without formatting diagnostics.
pub(crate) struct StoppedConfigurationCapture {
    db: DbWriteConnection,
    directory: PathBuf,
    sandbox_id: i32,
    guard: Arc<SandboxLifecycleGuard>,
    source: Option<RetainedConfiguration>,
    pending: Option<serde_json::Value>,
    scripts: StoppedScriptObservation,
    init: Option<InitObservation>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CapturedSandboxConfiguration {
    fn new(
        source: RetainedConfiguration,
        scripts: Option<ScriptBackingEvidence>,
        init: Option<InitObservation>,
        pending: Option<serde_json::Value>,
    ) -> MicrosandboxResult<Option<Self>> {
        let Some(configuration) = decode_configuration(source.source.as_ref())? else {
            return Ok(None);
        };
        let captured = Self {
            source,
            pending,
            configuration,
            scripts,
            init,
            storage: None,
            exec_limits: None,
        };
        if let Some(origin) = &captured.configuration.command_provenance
            && (!origin.matches(&captured.configuration.spec.runtime.cmd)
                || captured
                    .source
                    .source
                    .as_ref()
                    .and_then(|source| source.pointer("/runtime/cmd"))
                    .is_none())
        {
            return Err(invalid(
                "captured command provenance contradicts its source configuration",
            ));
        }
        if captured
            .configuration
            .environment_provenance
            .as_ref()
            .is_some_and(|origin| {
                !origin.matches(
                    &captured.configuration.spec.env,
                    captured.configuration.spec.init.as_ref(),
                )
            })
        {
            return Err(invalid(
                "captured environment provenance contradicts its source configuration",
            ));
        }
        captured.validate_init_observation()?;
        captured.validate_script_inventory()?;
        Ok(Some(captured))
    }

    /// Actual mounted kind/quota; missing evidence cannot certify a reusable binding.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "portable publication remains gated")
    )]
    pub(crate) fn mounted_storage(
        &self,
    ) -> Option<&microsandbox_runtime::retention::MountedStorageEvidence> {
        self.storage.as_ref()
    }

    /// Exact policy advertised by the captured guest, never a reconstructed SDK default.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "portable publication remains gated")
    )]
    pub(crate) fn execution_limits(&self) -> Option<microsandbox_types::ExecLimits> {
        self.exec_limits
    }

    pub(crate) fn configuration(&self) -> &SandboxConfig {
        &self.configuration
    }

    /// Derive active requirements exclusively from the selected receipt or stopped cut.
    /// The caller must establish host-trust backing independently under the same guard.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "portable publication remains gated")
    )]
    pub(crate) fn network_requirements(
        &self,
        guest_trust: Vec<SavedBindingReference>,
    ) -> MicrosandboxResult<NetworkCaptureBindings> {
        let raw = self
            .source
            .source
            .as_ref()
            .ok_or_else(|| invalid("capture has no recorded source"))?;
        RuntimeCaptureSource::from_recorded(raw, self.init.as_ref(), self.scripts.as_ref())?
            .network_requirements(NetworkCaptureSection::Active, guest_trust)
    }

    /// Build pending projection input exclusively from the selected receipt or stopped cut.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "portable publication remains gated")
    )]
    pub(crate) fn pending_source(
        &self,
        guest_trust: Vec<SavedBindingReference>,
        storage: StorageCaptureBindings,
    ) -> MicrosandboxResult<Option<PendingCaptureSource<'_>>> {
        self.pending
            .as_ref()
            .map(|pending| {
                let source = RuntimeCaptureSource::from_recorded(pending, None, None)?;
                let network =
                    source.network_requirements(NetworkCaptureSection::Pending, guest_trust)?;
                PendingCaptureSource::from_recorded(pending, network, storage)
            })
            .transpose()
    }

    /// Assemble only from this immutable receipt/guard selection. Do not reload current
    /// catalog intent or infer generation from a mutable sidecar during projection.
    /// Publication remains disabled until complete destination enforcement is available.
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "portable publication remains gated")
    )]
    pub(crate) fn project_document(
        &self,
        request: CaptureDocumentRequest<'_>,
    ) -> MicrosandboxResult<SavedSandboxConfig> {
        // Reject a caller substituting later catalog intent, omitting selected intent, or
        // manufacturing pending defaults for an older receipt that did not record them.
        if !match (&self.pending, &request.pending) {
            (None, None) => true,
            (Some(recorded), Some(pending)) => pending.matches_recorded(recorded),
            _ => false,
        } {
            return Err(invalid(
                "pending capture selection does not match its source evidence",
            ));
        }
        let raw = self
            .source
            .source
            .as_ref()
            .ok_or_else(|| invalid("capture has no recorded source"))?;
        RuntimeCaptureSource::from_recorded(raw, self.init.as_ref(), self.scripts.as_ref())?
            .project_document(
                request,
                SavedValue::Value {
                    value: self.source.generation.to_string(),
                    origin: SavedOrigin::Observed,
                },
            )
    }

    fn validate_init_observation(&self) -> MicrosandboxResult<()> {
        if let Some(origin) = &self.configuration.init_provenance
            && (!origin.matches(self.configuration.spec.init.as_ref())
                || self
                    .source
                    .source
                    .as_ref()
                    .and_then(|source| source.get("init"))
                    .is_none())
        {
            return Err(invalid(
                "captured init provenance contradicts its source configuration",
            ));
        }
        let Some(observed) = &self.init else {
            return Ok(());
        };
        let recorded = self
            .source
            .source
            .as_ref()
            .and_then(|source| source.get("init"));
        let consistent = match observed {
            InitObservation::Builtin => recorded.is_none_or(serde_json::Value::is_null),
            InitObservation::Handoff { path } => {
                // Guest paths remain guest paths; never resolve them on the host. Preserve
                // the preflighted spelling, including a symlink such as /sbin/init.
                !path.is_empty()
                    && !path.contains('\0')
                    && path.len() <= 4096
                    && path != "auto"
                    && recorded.is_none_or(|init| {
                        init.get("cmd")
                            .and_then(serde_json::Value::as_str)
                            .is_some_and(|cmd| cmd == "auto" || cmd == path)
                    })
            }
        };
        if !consistent {
            return Err(invalid(
                "captured init observation contradicts its source configuration",
            ));
        }
        Ok(())
    }

    fn validate_script_inventory(&self) -> MicrosandboxResult<()> {
        let Some(ScriptBackingEvidence::Observed {
            files,
            runtime_directory,
            scripts_directory,
        }) = &self.scripts
        else {
            return Ok(());
        };
        let expected = self
            .source
            .source
            .as_ref()
            .and_then(|source| source.pointer("/runtime/scripts"))
            .and_then(serde_json::Value::as_object);
        // A runtime's claimed inventory must match its recorded source registration. Body
        // equality is deliberately not required: the guest can have changed the actual files.
        // An older source with no registration field still accepts an empty observation;
        // the original absence stays in `source`, rather than becoming a recorded default.
        let matches = expected.map_or(files.is_empty(), |expected| {
            files.len() == expected.len() && files.keys().all(|name| expected.contains_key(name))
        });
        if files.len() > MAX_SAVED_CONFIG_ENTRIES
            || !matches
            || runtime_directory.mode > 0o777
            || scripts_directory.mode > 0o777
        {
            return Err(invalid(
                "captured script inventory or directory metadata is invalid",
            ));
        }
        let mut total = 0usize;
        for script in files.values() {
            if script.mode > 0o777 || script.content.len() > MAX_SAVED_SCRIPT_BYTES {
                return Err(invalid(
                    "captured script backing exceeds its representation",
                ));
            }
            total = total
                .checked_add(script.content.len())
                .ok_or_else(|| invalid("captured scripts exceed their size bound"))?;
            if total > MAX_SAVED_SCRIPTS_BYTES {
                return Err(invalid("captured scripts exceed their size bound"));
            }
        }
        Ok(())
    }
}

impl ExpectedConfigurationCapture {
    /// Older peers keep the original request and perform no retention catalog/file reads.
    pub(crate) async fn prepare(
        local: &LocalBackend,
        name: &str,
        session: &ControlSession,
    ) -> MicrosandboxResult<Option<Self>> {
        if !session.capabilities().configuration_capture {
            return Ok(None);
        }
        let run = session.run_identity();
        let catalog = local
            .config()
            .home()
            .join(microsandbox_utils::DB_SUBDIR)
            .join(microsandbox_utils::DB_FILENAME);
        let owner = RetentionOwner::for_run(
            local.db().await?.write(),
            &catalog,
            run.sandbox_id,
            run.run_id,
            String::new(),
        )
        .await
        .map_err(|_| invalid("could not establish capture configuration owner"))?;
        Ok(Some(Self {
            directory: local.sandboxes_dir().join(name),
            owner,
            storage_requested: session.capabilities().configuration_storage,
            exec_limits_requested: session.capabilities().configuration_exec_limits,
        }))
    }

    /// Consume evidence only after the caller verifies the immutable capture and its root.
    /// The source lineage guard must remain held, so removal cannot recycle this directory.
    pub(crate) fn read(
        mut self,
        checkpoint_id: &str,
        capture_root: &str,
        receipt: Option<&ConfigurationCaptureReceipt>,
    ) -> MicrosandboxResult<Option<CapturedSandboxConfiguration>> {
        let receipt =
            receipt.ok_or_else(|| invalid("runtime omitted requested configuration receipt"))?;
        let captured =
            CapturedConfiguration::read(&self.directory, checkpoint_id, capture_root, receipt)
                .map_err(|_| invalid("invalid checkpoint configuration receipt"))?;
        // A negotiated producer may omit optional evidence to preserve the receipt budget.
        // Unsolicited evidence remains invalid; requested but absent evidence is unknown.
        if !self.storage_requested && captured.storage().is_some() {
            return Err(invalid(
                "runtime storage evidence did not match capture negotiation",
            ));
        }
        if !self.exec_limits_requested && captured.exec_limits().is_some() {
            return Err(invalid(
                "runtime execution-limit evidence did not match capture negotiation",
            ));
        }
        let exec_limits = captured.exec_limits();
        let storage = captured.storage().cloned();
        let init = captured.init().cloned();
        let pending = captured.pending_configuration().cloned();
        let (source, scripts) = captured.into_parts();
        let Some(source) = source else {
            return Ok(None);
        };
        // The authenticated, run-bound control response supplies the receipt digest and hence
        // boot identity. Catalog file/row incarnations were selected independently before dispatch.
        // Do not compare current generation: a subsequent modify must not invalidate this capture.
        self.owner
            .runtime_boot_id
            .clone_from(&source.owner.runtime_boot_id);
        if source.owner != self.owner
            || source.owner.runtime_boot_id.is_empty()
            || source.generation == 0
        {
            return Err(invalid(
                "checkpoint configuration belongs to another source run",
            ));
        }
        let mut configuration = CapturedSandboxConfiguration::new(source, scripts, init, pending)?;
        if let Some(configuration) = &mut configuration {
            configuration.storage = storage;
            configuration.exec_limits = exec_limits;
        }
        Ok(configuration)
    }
}

impl StoppedConfigurationCapture {
    pub(crate) async fn prepare(
        db: DbWriteConnection,
        directory: PathBuf,
        sandbox_id: i32,
        guard: Arc<SandboxLifecycleGuard>,
    ) -> MicrosandboxResult<Self> {
        let source = select_stopped_configuration(&db, &directory, sandbox_id, &guard)
            .await
            .map_err(|_| invalid("could not select stopped capture configuration"))?;
        // Lifecycle ownership excludes a runtime changing active state. Retain desired
        // settings now, before the disk cut; later desired-only edits are a different intent.
        // Unknown legacy active evidence must not be promoted from desired configuration.
        let pending = if source.is_some() {
            select_pending_configuration(&db, sandbox_id).await?
        } else {
            None
        };
        let configuration =
            decode_configuration(source.as_ref().and_then(|source| source.source.as_ref()))?;
        let scripts = StoppedScriptObservation::observe(&directory, configuration.as_ref());
        let init = source
            .as_ref()
            .map(|source| read_retained_init(&directory, source))
            .transpose()
            .map_err(|_| invalid("could not read stopped init evidence"))?
            .flatten();
        Ok(Self {
            scripts,
            init,
            db,
            directory,
            sandbox_id,
            guard,
            source,
            pending,
        })
    }

    pub(crate) fn configuration(&self) -> MicrosandboxResult<Option<SandboxConfig>> {
        decode_configuration(
            self.source
                .as_ref()
                .and_then(|record| record.source.as_ref()),
        )
    }

    /// Lifecycle ownership excludes a runtime restart, but older metadata writers can still
    /// change catalog provenance. Detect an observed change rather than publishing stale evidence.
    pub(crate) async fn finish(self) -> MicrosandboxResult<Option<CapturedSandboxConfiguration>> {
        let current =
            select_stopped_configuration(&self.db, &self.directory, self.sandbox_id, &self.guard)
                .await
                .map_err(|_| invalid("could not revalidate stopped capture configuration"))?;
        let unchanged = match (&self.source, &current) {
            (None, None) => true,
            (Some(before), Some(after)) => {
                before.owner == after.owner
                    && before.generation == after.generation
                    && before.source == after.source
            }
            _ => false,
        };
        if !unchanged {
            return Err(invalid(
                "configuration evidence changed during stopped capture",
            ));
        }
        let current_init = current
            .as_ref()
            .map(|source| read_retained_init(&self.directory, source))
            .transpose()
            .map_err(|_| invalid("could not revalidate stopped init evidence"))?
            .flatten();
        if self.init != current_init {
            return Err(invalid("init evidence changed during stopped capture"));
        }
        let scripts = self.scripts.finish();
        match self.source {
            Some(source) => {
                CapturedSandboxConfiguration::new(source, Some(scripts), self.init, self.pending)
            }
            None => Ok(None),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn select_pending_configuration(
    db: &DbWriteConnection,
    sandbox_id: i32,
) -> MicrosandboxResult<Option<serde_json::Value>> {
    let row = db
        .query_one_raw(Statement::from_sql_and_values(
            DbBackend::Sqlite,
            "SELECT config FROM sandbox WHERE id = ?",
            [sandbox_id.into()],
        ))
        .await
        .map_err(|_| invalid("could not read pending capture configuration"))?
        .ok_or_else(|| invalid("pending capture sandbox disappeared"))?;
    let pending: Option<String> = row
        .try_get("", "config")
        .map_err(|_| invalid("invalid pending capture configuration"))?;
    pending
        .map(|pending| {
            serde_json::from_str(&pending)
                .map_err(|_| invalid("invalid pending capture configuration document"))
        })
        .transpose()
}

fn decode_configuration(
    value: Option<&serde_json::Value>,
) -> MicrosandboxResult<Option<SandboxConfig>> {
    value
        .map(|value| serde_json::from_value(value.clone()))
        .transpose()
        // Serde diagnostics can contain literal values. Never forward them from this boundary.
        .map_err(|_| invalid("invalid captured sandbox configuration"))
}

fn invalid(message: &str) -> MicrosandboxError {
    MicrosandboxError::SnapshotIntegrity(message.into())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use microsandbox_runtime::retention::ScriptBackingUnknown;
    use sea_orm::ConnectionTrait;
    use sha2::{Digest, Sha256};

    use super::*;

    struct Fixture {
        home: tempfile::TempDir,
        owner: RetentionOwner,
        value: serde_json::Value,
    }

    impl Fixture {
        fn new() -> Self {
            let home = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(home.path().join("last-active/captures")).unwrap();
            let owner = RetentionOwner {
                catalog_file: [1, 2],
                sandbox_id: 3,
                sandbox_created_at: Some("created".into()),
                run_id: 4,
                run_started_at: "started".into(),
                runtime_boot_id: "boot".into(),
            };
            let mut config = SandboxConfig::default();
            config.spec.runtime.user = Some("captured-user".into());
            let value = serde_json::json!({
                "schema": 1, "checkpoint_id": "capture_one", "capture_root": "full:root",
                "source": {"owner": owner, "generation": 2,
                    "source": serde_json::to_value(config.clone_for_persistence()).unwrap()},
            });
            Self { home, owner, value }
        }

        fn read(
            &self,
            value: &serde_json::Value,
        ) -> MicrosandboxResult<Option<CapturedSandboxConfiguration>> {
            self.read_with_storage(value, false)
        }

        fn read_with_storage(
            &self,
            value: &serde_json::Value,
            storage_requested: bool,
        ) -> MicrosandboxResult<Option<CapturedSandboxConfiguration>> {
            self.read_with_evidence(value, storage_requested, false)
        }

        fn read_with_evidence(
            &self,
            value: &serde_json::Value,
            storage_requested: bool,
            exec_limits_requested: bool,
        ) -> MicrosandboxResult<Option<CapturedSandboxConfiguration>> {
            let bytes = serde_json::to_vec(value).unwrap();
            std::fs::write(
                self.home
                    .path()
                    .join("last-active/captures/capture_one.json"),
                &bytes,
            )
            .unwrap();
            let mut owner = self.owner.clone();
            // Boot identity is authenticated by the control response, never read from current state.
            owner.runtime_boot_id.clear();
            ExpectedConfigurationCapture {
                directory: self.home.path().to_path_buf(),
                owner,
                storage_requested,
                exec_limits_requested,
            }
            .read(
                "capture_one",
                "full:root",
                Some(&ConfigurationCaptureReceipt {
                    sha256: hex::encode(Sha256::digest(bytes)),
                }),
            )
        }
    }

    #[test]
    fn execution_limit_receipt_rejects_unsolicited_evidence_and_keeps_absence_unknown() {
        let fixture = Fixture::new();
        let limits = microsandbox_types::ExecLimits {
            max_executions: 9,
            ..Default::default()
        };
        let mut extended = fixture.value.clone();
        extended["exec_limits"] = serde_json::to_value(limits).unwrap();
        assert!(fixture.read(&extended).is_err());
        assert_eq!(
            fixture
                .read_with_evidence(&extended, false, true)
                .unwrap()
                .unwrap()
                .execution_limits(),
            Some(limits)
        );
        assert!(
            fixture
                .read_with_evidence(&fixture.value, false, true)
                .unwrap()
                .unwrap()
                .execution_limits()
                .is_none()
        );
    }

    #[test]
    fn storage_receipt_requires_matching_negotiation_and_preserves_unknowns() {
        let fixture = Fixture::new();
        assert!(
            fixture
                .read(&fixture.value)
                .unwrap()
                .unwrap()
                .mounted_storage()
                .is_none()
        );
        assert!(
            fixture
                .read_with_storage(&fixture.value, true)
                .unwrap()
                .unwrap()
                .mounted_storage()
                .is_none()
        );
        let mut extended = fixture.value.clone();
        extended["storage"] = serde_json::json!({
            "/data": {"kind":"directory", "quota_bytes":0},
            "/file": {"kind":"file", "quota_bytes":null},
        });
        assert!(fixture.read(&extended).is_err());
        let captured = fixture.read_with_storage(&extended, true).unwrap().unwrap();
        let storage = captured.mounted_storage().unwrap();
        assert_eq!(storage.get("/data").unwrap().quota_bytes, Some(0));
        assert_eq!(storage.get("/file").unwrap().quota_bytes, None);
        assert!(storage.get("/unknown").is_none());
    }

    #[test]
    fn receipt_selects_captured_configuration_without_consulting_current_generation() {
        let mut fixture = Fixture::new();
        // A real captured sandbox has a valid name; the minimal receipt fixture's
        // empty default cannot establish a valid generated guest hostname.
        fixture.value["source"]["source"]["name"] = serde_json::json!("captured-source");
        fixture.value["source"]["source"]["network"]["dns"] = serde_json::json!({
            "nameservers": ["PRIVATE_ACTIVE_RESOLVER"], "rebind_protection": true,
            "query_timeout_ms": 5000
        });
        fixture.value["pending"] = fixture.value["source"]["source"].clone();
        fixture.value["pending"]["runtime"]["user"] = "pending-user".into();
        fixture.value["pending"]["network"]["dns"]["nameservers"] =
            serde_json::json!(["PRIVATE_PENDING_RESOLVER", "PRIVATE_PENDING_SECOND"]);
        // These files deliberately disagree. Neither is authoritative for an immutable capture.
        std::fs::write(
            fixture.home.path().join("last-active/state.json"),
            b"new generation",
        )
        .unwrap();
        std::fs::write(
            fixture.home.path().join("config.json"),
            b"pending desired config",
        )
        .unwrap();
        let selected = fixture.read(&fixture.value).unwrap().unwrap();
        assert_eq!(
            selected.configuration().spec.runtime.user.as_deref(),
            Some("captured-user")
        );
        // Assembly must retain the same immutable source/generation even though the
        // mutable state and pending files above are intentionally unreadable JSON.
        let descriptor: crate::snapshot::Manifest = serde_json::from_value(serde_json::json!({
            "schema":"microsandbox.snapshot/1", "snapshot_id":"snap_0123456789abcdef0123456789abcdef", "scope":"file",
            "state":{"kind":"file","disk_format":"raw","filesystem":"ext4","virtual_size":4,"head":"layer_0123456789abcdef0123456789abcdef",
              "layers":[{"layer_id":"layer_0123456789abcdef0123456789abcdef","format":"raw","virtual_size":4,"backing":null,"payload":{"file_kind":"regular","integrity":null}}]},
            "capture":{"created_at":"2026-08-29T00:00:00Z","source_lineage":null,"source_checkpoint":null,"consistency":"crash-consistent"},
            "image":{"reference":"alpine:latest","manifest_digest":format!("sha256:{}","a".repeat(64))},
            "parent":null,"requires":[],"extensions":{}
        })).unwrap();
        let runtime_controls = std::collections::BTreeMap::new();
        let execution_controls = crate::snapshot::saved_config::ExecutionCaptureControls::default();
        let network_controls = crate::snapshot::saved_config::NetworkCaptureControls::default();
        let request = |pending| CaptureDocumentRequest {
            manifest: &descriptor,
            resources: Default::default(),
            network: selected.network_requirements(Default::default()).unwrap(),
            storage: Default::default(),
            runtime_controls: &runtime_controls,
            execution_controls: &execution_controls,
            network_controls: &network_controls,
            pending,
            include_source_name: false,
            construction_resources: None,
        };
        let missing = selected
            .project_document(request(None))
            .err()
            .unwrap()
            .to_string();
        assert!(missing.contains("pending capture selection"));
        let different = serde_json::json!({"name":"PRIVATE_WRONG_SOURCE"});
        let wrong =
            PendingCaptureSource::from_recorded(&different, Default::default(), Default::default())
                .unwrap();
        let error = selected
            .project_document(request(Some(wrong)))
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("pending capture selection"));
        assert!(!error.contains("PRIVATE_WRONG_SOURCE"));
        let pending = selected
            .pending_source(Default::default(), Default::default())
            .unwrap();
        let document = selected.project_document(request(pending)).unwrap();
        assert_eq!(
            document
                .provenance
                .active_generation
                .value()
                .map(String::as_str),
            Some("2")
        );
        assert_eq!(
            document
                .active
                .runtime
                .user
                .as_ref()
                .and_then(SavedValue::value)
                .map(String::as_str),
            Some("captured-user")
        );
        let encoded = serde_json::to_value(&document).unwrap();
        // Requirements are derived separately from the immutable active/pending cuts.
        // Neither private endpoints nor a later mutable catalog record enter the artifact.
        let active_dns = document
            .active
            .network
            .dns
            .as_ref()
            .unwrap()
            .value()
            .unwrap();
        assert_eq!(active_dns.resolvers.len(), 1);
        assert_eq!(active_dns.resolvers[0].id, "active.network.dns.resolvers.0");
        let pending_dns = document
            .pending
            .as_ref()
            .unwrap()
            .network
            .dns
            .as_ref()
            .unwrap()
            .value()
            .unwrap();
        assert_eq!(pending_dns.resolvers.len(), 2);
        assert_eq!(
            pending_dns.resolvers[1].id,
            "pending.network.dns.resolvers.1"
        );
        assert!(!encoded.to_string().contains("PRIVATE_"));
        assert_eq!(
            document
                .pending
                .as_ref()
                .unwrap()
                .runtime
                .user
                .as_ref()
                .and_then(SavedValue::value)
                .map(String::as_str),
            Some("pending-user")
        );
        assert!(encoded["provenance"].get("runtime_boot_id").is_none());
        assert!(encoded["provenance"].get("catalog_file").is_none());
    }

    #[test]
    fn init_receipt_preserves_selection_and_rejects_contradictions_without_values() {
        let fixture = Fixture::new();
        let mut value = fixture.value.clone();
        assert!(fixture.read(&value).unwrap().unwrap().init.is_none());
        value["init"] = serde_json::json!({"kind":"builtin"});
        assert_eq!(
            fixture.read(&value).unwrap().unwrap().init,
            Some(InitObservation::Builtin)
        );
        for choice in ["auto", "/sbin/init"] {
            value["source"]["source"]["init"] =
                serde_json::json!({"cmd":choice,"args":[],"env":[]});
            value["init"] = serde_json::json!({"kind":"handoff","path":"/sbin/init"});
            let selected = fixture.read(&value).unwrap().unwrap();
            assert_eq!(
                selected.init,
                Some(InitObservation::Handoff {
                    path: "/sbin/init".into()
                })
            );
            // Resolved selection never rewrites the original source intent.
            assert_eq!(selected.source.source.unwrap()["init"]["cmd"], choice);
        }
        value["source"]["source"]["init"]["cmd"] = serde_json::json!("/PRIVATE_OTHER_INIT");
        let error = fixture.read(&value).err().unwrap().to_string();
        assert!(error.contains("contradicts"));
        assert!(!error.contains("PRIVATE"));
        value["init"] = serde_json::json!({"kind":"builtin"});
        assert!(fixture.read(&value).is_err());
    }

    #[test]
    fn init_receipt_keeps_original_auto_intent_separate_from_selected_path() {
        let fixture = Fixture::new();
        let mut value = fixture.value.clone();
        value["source"]["source"]["init"] =
            serde_json::json!({"cmd":"/sbin/init","args":[],"env":[]});
        value["source"]["source"]["init_provenance"] =
            serde_json::json!({"kind":"auto","configured":"/sbin/init"});
        value["init"] = serde_json::json!({"kind":"handoff","path":"/sbin/init"});
        let selected = fixture.read(&value).unwrap().unwrap();
        assert_eq!(
            selected.configuration().init_provenance,
            Some(crate::sandbox::init_provenance::InitProvenance::Auto {
                configured: "/sbin/init".into(),
            })
        );
        assert_eq!(
            selected.source.source.as_ref().unwrap()["init"]["cmd"],
            "/sbin/init"
        );

        // Older writers can preserve the resolved executable without preserving why it was
        // selected. The receipt must not manufacture explicit-path intent in that case.
        value["source"]["source"]
            .as_object_mut()
            .unwrap()
            .remove("init_provenance");
        let selected = fixture.read(&value).unwrap().unwrap();
        assert!(selected.configuration().init_provenance.is_none());
        assert!(selected.init.is_some());
    }

    #[test]
    fn init_receipt_rejects_unbound_provenance_without_exposing_private_values() {
        let fixture = Fixture::new();
        let mut value = fixture.value.clone();
        value["source"]["source"]["init"] =
            serde_json::json!({"cmd":"/sbin/init","args":[],"env":[]});
        value["source"]["source"]["init_provenance"] =
            serde_json::json!({"kind":"auto","configured":"/PRIVATE_OTHER_INIT"});
        let error = fixture.read(&value).err().unwrap().to_string();
        assert!(error.contains("contradicts"));
        assert!(!error.contains("PRIVATE"));

        // A decoded default is not evidence that an older producer recorded builtin init.
        value["source"]["source"]["init_provenance"] = serde_json::json!({"kind":"builtin"});
        value["source"]["source"]
            .as_object_mut()
            .unwrap()
            .remove("init");
        assert!(fixture.read(&value).is_err());
        value["source"]["source"]["init"] = serde_json::Value::Null;
        assert!(fixture.read(&value).unwrap().is_some());
    }

    #[test]
    fn receipt_preserves_field_presence_and_confirmed_generation_without_defaulting_evidence() {
        let fixture = Fixture::new();
        let mut value = fixture.value.clone();
        value["scripts"] = serde_json::json!({
            "state": "observed",
            "runtime_directory": {"uid": 0, "gid": 0, "mode": 493},
            "scripts_directory": {"uid": 0, "gid": 0, "mode": 493},
            "files": {},
        });
        // All three decode successfully, but they are different evidence for portable capture.
        // Missing means not recorded; null and an empty command are deliberate source values.
        for command in [
            None,
            Some(serde_json::Value::Null),
            Some(serde_json::json!([])),
        ] {
            let raw = value["source"]["source"].as_object_mut().unwrap();
            raw.remove("resources");
            raw.remove("init");
            let runtime = raw.get_mut("runtime").unwrap().as_object_mut().unwrap();
            runtime.remove("scripts");
            runtime.remove("cmd");
            if let Some(command) = command {
                runtime.insert("cmd".into(), command);
            }
            let selected = fixture.read(&value).unwrap().unwrap();
            assert!(selected.configuration().spec.resources.cpus > 0);
            assert_eq!(selected.source.generation, 2);
            assert!(selected.source.owner == fixture.owner);
            assert_eq!(
                selected.source.source.as_ref(),
                Some(&value["source"]["source"])
            );
            let source = selected.source.source.as_ref().unwrap();
            assert!(source.get("resources").is_none());
            assert!(source.get("init").is_none());
            assert!(source.pointer("/runtime/scripts").is_none());
        }
        value["scripts"]["files"]["unregistered"] = serde_json::json!({
            "content": "PRIVATE_INVENTED_SCRIPT", "uid": 0, "gid": 0, "mode": 493,
        });
        let error = fixture.read(&value).err().unwrap().to_string();
        assert!(error.contains("captured script inventory"));
        assert!(!error.contains("PRIVATE_INVENTED_SCRIPT"));
    }

    #[test]
    fn configuration_receipt_rejects_cross_catalog_row_and_run_evidence() {
        let fixture = Fixture::new();
        for (field, value) in [
            ("catalog_file", serde_json::json!([8, 9])),
            ("sandbox_id", serde_json::json!(5)),
            ("sandbox_created_at", serde_json::json!("recreated")),
            ("run_id", serde_json::json!(6)),
            ("run_started_at", serde_json::json!("restarted")),
            ("runtime_boot_id", serde_json::json!("")),
        ] {
            let mut changed = fixture.value.clone();
            changed["source"]["owner"][field] = value;
            assert!(fixture.read(&changed).is_err(), "accepted changed {field}");
        }
        let mut changed = fixture.value.clone();
        changed["source"]["generation"] = serde_json::json!(0);
        assert!(fixture.read(&changed).is_err());
        for field in ["checkpoint_id", "capture_root"] {
            let mut changed = fixture.value.clone();
            changed[field] = serde_json::json!("other_capture");
            assert!(fixture.read(&changed).is_err(), "accepted changed {field}");
        }
    }

    #[test]
    fn unknown_evidence_is_not_a_default_and_invalid_values_are_redacted() {
        let fixture = Fixture::new();
        let mut unknown = fixture.value.clone();
        unknown["source"] = serde_json::Value::Null;
        assert!(fixture.read(&unknown).unwrap().is_none());
        assert!(fixture.read_with_storage(&unknown, true).unwrap().is_none());
        let mut unknown = fixture.value.clone();
        unknown["source"]["source"] = serde_json::Value::Null;
        assert!(fixture.read(&unknown).unwrap().is_none());
        let mut invalid = fixture.value.clone();
        invalid["source"]["source"] = serde_json::json!("PRIVATE_SECRET_VALUE");
        let error = fixture.read(&invalid).err().unwrap().to_string();
        assert!(error.contains("invalid captured sandbox configuration"));
        assert!(!error.contains("PRIVATE_SECRET_VALUE"));
        let error = ExpectedConfigurationCapture {
            directory: fixture.home.path().to_path_buf(),
            owner: fixture.owner,
            storage_requested: false,
            exec_limits_requested: false,
        }
        .read("capture_one", "full:root", None)
        .err()
        .unwrap()
        .to_string();
        assert!(error.contains("omitted requested configuration receipt"));
    }

    struct StoppedFixture {
        home: tempfile::TempDir,
        db: DbWriteConnection,
        guard: Arc<SandboxLifecycleGuard>,
    }

    impl StoppedFixture {
        async fn new() -> Self {
            use microsandbox_runtime::retention::{
                RetentionJournal, RetentionTerminalOrigin, seal_terminal,
            };
            use sea_orm::{DbBackend, Statement};

            let home = tempfile::tempdir().unwrap();
            let path = home.path().join("catalog.db");
            let db = DbWriteConnection::open(
                &path,
                std::time::Duration::from_secs(1),
                std::time::Duration::from_secs(1),
            )
            .await
            .unwrap();
            db.execute_unprepared(
                "CREATE TABLE sandbox (id INTEGER PRIMARY KEY, created_at TEXT, status TEXT, config TEXT, active_config TEXT);
                 CREATE TABLE run (id INTEGER PRIMARY KEY, sandbox_id INTEGER, started_at TEXT, status TEXT, terminated_at TEXT, pid INTEGER);
                 INSERT INTO sandbox VALUES (1, 'created', 'Stopped', '{\"runtime\":{\"user\":\"pending-user\"}}', NULL);
                 INSERT INTO run VALUES (1, 1, 'started', 'Terminated', 'ended', NULL);"
            ).await.unwrap();
            let guard = Arc::new(
                microsandbox_runtime::ipc::try_acquire_lifecycle_guard(home.path(), "source")
                    .unwrap()
                    .unwrap(),
            );
            let owner = RetentionOwner::for_run(&db, &path, 1, 1, "boot".into())
                .await
                .unwrap();
            let mut config = SandboxConfig::default();
            config.spec.runtime.user = Some("last-active-user".into());
            config
                .spec
                .runtime
                .scripts
                .insert("task".into(), "DECLARED_LAST_ACTIVE_SCRIPT".into());
            std::fs::create_dir_all(home.path().join("runtime/scripts")).unwrap();
            std::fs::write(
                home.path().join("runtime/scripts/task"),
                "OBSERVED_LAST_ACTIVE_SCRIPT",
            )
            .unwrap();
            #[cfg(unix)]
            microsandbox_filesystem::PassthroughFs::set_runtime_backing_permissions(
                &std::fs::File::open(home.path().join("runtime/scripts/task")).unwrap(),
                42,
                43,
                0o640,
            )
            .unwrap();
            let source = serde_json::to_value(config.clone_for_persistence()).unwrap();
            db.execute_raw(Statement::from_sql_and_values(
                DbBackend::Sqlite,
                "UPDATE sandbox SET active_config = ?",
                [source.to_string().into()],
            ))
            .await
            .unwrap();
            let mut journal = RetentionJournal::begin_start(home.path(), owner).unwrap();
            journal.confirm(Some(source)).unwrap();
            assert!(
                seal_terminal(
                    &db,
                    home.path(),
                    1,
                    1,
                    Some("boot"),
                    RetentionTerminalOrigin::RuntimeExit
                )
                .await
                .unwrap()
            );
            db.execute_unprepared("UPDATE sandbox SET active_config = NULL")
                .await
                .unwrap();
            Self { home, db, guard }
        }

        async fn select(&self) -> MicrosandboxResult<StoppedConfigurationCapture> {
            StoppedConfigurationCapture::prepare(
                self.db.clone(),
                self.home.path().to_path_buf(),
                1,
                Arc::clone(&self.guard),
            )
            .await
        }
    }

    #[tokio::test]
    async fn stopped_init_uses_owner_bound_selection_and_revalidates_it() {
        let fixture = StoppedFixture::new().await;
        let record = microsandbox_runtime::retention::RetentionJournal::read(fixture.home.path())
            .unwrap()
            .unwrap();
        let path = fixture.home.path().join("last-active/init.json");
        let mut init = serde_json::json!({"schema":1,"owner":record.owner,"start_generation":record.generation,"observation":{"kind":"builtin"}});
        std::fs::write(&path, serde_json::to_vec(&init).unwrap()).unwrap();
        fixture
            .db
            .execute_unprepared(r#"UPDATE sandbox SET config = '{"init":{"cmd":"/pending-init"}}'"#)
            .await
            .unwrap();
        let selected = fixture
            .select()
            .await
            .unwrap()
            .finish()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(selected.init, Some(InitObservation::Builtin));
        let captured = fixture.select().await.unwrap();
        init["observation"] = serde_json::json!({"kind":"handoff","path":"/PRIVATE_CHANGED_INIT"});
        std::fs::write(&path, serde_json::to_vec(&init).unwrap()).unwrap();
        let error = captured.finish().await.err().unwrap().to_string();
        assert!(error.contains("init evidence changed"));
        assert!(!error.contains("PRIVATE"));
        init["owner"]["runtime_boot_id"] = serde_json::json!("stale-boot");
        std::fs::write(&path, serde_json::to_vec(&init).unwrap()).unwrap();
        let selected = fixture
            .select()
            .await
            .unwrap()
            .finish()
            .await
            .unwrap()
            .unwrap();
        assert!(selected.init.is_none());
    }

    #[test]
    fn live_receipt_keeps_observed_backing_separate_and_rejects_forged_inventory() {
        let fixture = Fixture::new();
        let mut value = fixture.value.clone();
        value["source"]["source"]["runtime"]["scripts"] =
            serde_json::json!({"task": "DECLARED_SOURCE"});
        value["scripts"] = serde_json::json!({
            "state": "observed",
            "runtime_directory": {"uid": 0, "gid": 0, "mode": 493},
            "scripts_directory": {"uid": 44, "gid": 45, "mode": 456},
            "files": {"task": {"content": "OBSERVED_BACKING", "uid": 42, "gid": 43, "mode": 416}},
        });
        let selected = fixture.read(&value).unwrap().unwrap();
        assert_eq!(
            selected.configuration().spec.runtime.scripts["task"],
            "DECLARED_SOURCE"
        );
        let Some(ScriptBackingEvidence::Observed { files, .. }) = selected.scripts else {
            panic!("discarded observed backing")
        };
        assert_eq!(files["task"].content, "OBSERVED_BACKING");
        assert_eq!(files["task"].mode, 0o640);
        for invalid_scripts in [
            serde_json::json!({"PRIVATE_UNREGISTERED": {"content": "PRIVATE_CONTENT", "uid": 0, "gid": 0, "mode": 493}}),
            serde_json::json!({"task": {"content": "PRIVATE_CONTENT", "uid": 0, "gid": 0, "mode": 4095}}),
            serde_json::json!({}),
        ] {
            let mut invalid = value.clone();
            invalid["scripts"]["files"] = invalid_scripts;
            let error = fixture.read(&invalid).err().unwrap().to_string();
            assert!(!error.contains("PRIVATE"));
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stopped_script_backing_uses_last_active_inventory_and_observed_bytes() {
        let fixture = StoppedFixture::new().await;
        fixture.db.execute_unprepared(r#"UPDATE sandbox SET config = '{"runtime":{"scripts":{"pending":"PRIVATE_PENDING"}}}'"#).await.unwrap();
        std::fs::write(
            fixture.home.path().join("runtime/scripts/pending"),
            "PRIVATE_UNREGISTERED",
        )
        .unwrap();
        let selected = fixture
            .select()
            .await
            .unwrap()
            .finish()
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            selected.configuration().spec.runtime.scripts["task"],
            "DECLARED_LAST_ACTIVE_SCRIPT"
        );
        let retained =
            select_stopped_configuration(&fixture.db, fixture.home.path(), 1, &fixture.guard)
                .await
                .unwrap()
                .unwrap();
        assert!(selected.source.owner == retained.owner);
        assert_eq!(selected.source.generation, retained.generation);
        assert_eq!(selected.source.source, retained.source);
        let raw = selected.source.source.as_ref().unwrap();
        assert_eq!(
            raw.pointer("/runtime/scripts/task").unwrap(),
            "DECLARED_LAST_ACTIVE_SCRIPT"
        );
        assert!(raw.pointer("/runtime/scripts/pending").is_none());
        let Some(ScriptBackingEvidence::Observed { files, .. }) = selected.scripts else {
            panic!("stopped backing unknown")
        };
        assert_eq!(files.len(), 1);
        assert_eq!(files["task"].content, "OBSERVED_LAST_ACTIVE_SCRIPT");
        assert_eq!(
            (files["task"].uid, files["task"].gid, files["task"].mode),
            (42, 43, 0o640)
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stopped_script_mutation_and_runtime_replacement_become_unknown() {
        for replace_directory in [false, true] {
            let fixture = StoppedFixture::new().await;
            let selected = fixture.select().await.unwrap();
            if replace_directory {
                std::fs::rename(
                    fixture.home.path().join("runtime"),
                    fixture.home.path().join("old-runtime"),
                )
                .unwrap();
                std::fs::create_dir_all(fixture.home.path().join("runtime/scripts")).unwrap();
            }
            std::fs::write(
                fixture.home.path().join("runtime/scripts/task"),
                "PRIVATE_CHANGED",
            )
            .unwrap();
            let selected = selected.finish().await.unwrap().unwrap();
            let evidence = selected.scripts.unwrap();
            assert!(matches!(
                evidence,
                ScriptBackingEvidence::Unknown {
                    reason: ScriptBackingUnknown::Changed
                }
            ));
            assert!(
                !serde_json::to_string(&evidence)
                    .unwrap()
                    .contains("PRIVATE_CHANGED")
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn stopped_runtime_symlink_and_missing_backing_are_not_desired_defaults() {
        for link_runtime in [false, true] {
            let fixture = StoppedFixture::new().await;
            std::fs::remove_file(fixture.home.path().join("runtime/scripts/task")).unwrap();
            let outside = tempfile::tempdir().unwrap();
            if link_runtime {
                std::fs::remove_dir_all(fixture.home.path().join("runtime")).unwrap();
                std::fs::create_dir(outside.path().join("scripts")).unwrap();
                std::fs::write(outside.path().join("scripts/task"), "PRIVATE_OUTSIDE").unwrap();
                std::os::unix::fs::symlink(outside.path(), fixture.home.path().join("runtime"))
                    .unwrap();
            }
            let selected = fixture
                .select()
                .await
                .unwrap()
                .finish()
                .await
                .unwrap()
                .unwrap();
            let evidence = selected.scripts.unwrap();
            assert!(matches!(evidence, ScriptBackingEvidence::Unknown { .. }));
            let encoded = serde_json::to_string(&evidence).unwrap();
            assert!(!encoded.contains("PRIVATE_OUTSIDE"));
            assert!(!encoded.contains("DECLARED_LAST_ACTIVE_SCRIPT"));
        }
    }

    #[tokio::test]
    async fn stopped_capture_keeps_last_active_separate_from_desired_edits() {
        let fixture = StoppedFixture::new().await;
        let selected = fixture.select().await.unwrap();
        assert_eq!(
            selected
                .configuration()
                .unwrap()
                .unwrap()
                .spec
                .runtime
                .user
                .as_deref(),
            Some("last-active-user")
        );
        fixture
            .db
            .execute_unprepared("UPDATE sandbox SET config = 'another pending config'")
            .await
            .unwrap();
        // Dropping the caller's handle cannot release ownership during an admitted cut.
        drop(fixture.guard);
        assert!(
            microsandbox_runtime::ipc::try_acquire_lifecycle_guard(fixture.home.path(), "source")
                .unwrap()
                .is_none()
        );
        let captured = selected.finish().await.unwrap().unwrap();
        assert_eq!(
            captured.pending.as_ref().unwrap()["runtime"]["user"],
            "pending-user"
        );
        let _released = tokio::time::timeout(std::time::Duration::from_secs(2), async {
            loop {
                if let Some(guard) = microsandbox_runtime::ipc::try_acquire_lifecycle_guard(
                    fixture.home.path(),
                    "source",
                )
                .unwrap()
                {
                    break guard;
                }
                tokio::time::sleep(std::time::Duration::from_millis(1)).await;
            }
        })
        .await
        .expect("stopped configuration observer retained lifecycle ownership");
    }

    #[tokio::test]
    async fn stopped_capture_refuses_changed_provenance_after_the_disk_cut() {
        for mutation in [
            "UPDATE sandbox SET active_config = '{\"runtime\":{\"user\":\"PRIVATE_DRIFT\"}}'",
            "INSERT INTO run VALUES (2, 1, 'later', 'Terminated', 'ended', NULL)",
            "UPDATE sandbox SET status = 'Running'",
        ] {
            let fixture = StoppedFixture::new().await;
            let selected = fixture.select().await.unwrap();
            assert!(selected.configuration().unwrap().is_some());
            fixture.db.execute_unprepared(mutation).await.unwrap();
            let error = selected.finish().await.err().unwrap().to_string();
            assert!(error.contains("configuration evidence changed"));
            assert!(!error.contains("PRIVATE_DRIFT"));
        }
    }

    #[tokio::test]
    async fn stopped_capture_missing_legacy_evidence_remains_unknown_and_read_only() {
        let fixture = StoppedFixture::new().await;
        std::fs::remove_dir_all(fixture.home.path().join("last-active")).unwrap();
        let selected = fixture.select().await.unwrap();
        assert!(selected.configuration().unwrap().is_none());
        selected.finish().await.unwrap();
        assert!(!fixture.home.path().join("last-active").exists());
    }

    #[tokio::test]
    async fn stopped_capture_missing_or_corrupt_terminal_evidence_cannot_reuse_confirmation() {
        let fixture = StoppedFixture::new().await;
        let selected = fixture.select().await.unwrap();
        std::fs::remove_file(fixture.home.path().join("last-active/terminal.json")).unwrap();
        assert!(selected.finish().await.is_err());
        assert!(
            fixture
                .select()
                .await
                .unwrap()
                .configuration()
                .unwrap()
                .is_none()
        );
        std::fs::write(
            fixture.home.path().join("last-active/terminal.json"),
            b"PRIVATE_BAD_RECEIPT",
        )
        .unwrap();
        let error = fixture.select().await.err().unwrap().to_string();
        assert!(error.contains("could not select stopped capture configuration"));
        assert!(!error.contains("PRIVATE_BAD_RECEIPT"));
    }
    #[test]
    fn captured_command_origin_requires_matching_raw_configuration() {
        let fixture = Fixture::new();
        let mut valid = fixture.value.clone();
        valid["source"]["source"]["runtime"]["cmd"] = serde_json::json!(["one-shot"]);
        valid["source"]["source"]["command_provenance"] = serde_json::json!({
            "configured": ["one-shot"], "defaults": ["configured-default"]
        });
        let captured = fixture.read(&valid).unwrap().unwrap();
        assert_eq!(
            captured.configuration.command_provenance.unwrap().defaults,
            Some(vec!["configured-default".into()])
        );
        let mut changed = valid.clone();
        changed["source"]["source"]["runtime"]["cmd"] = serde_json::json!(["private-mismatch"]);
        let error = fixture.read(&changed).err().unwrap().to_string();
        assert!(error.contains("command provenance"));
        assert!(!error.contains("private-mismatch"));
        valid["source"]["source"]["runtime"]
            .as_object_mut()
            .unwrap()
            .remove("cmd");
        valid["source"]["source"]["command_provenance"]["configured"] = serde_json::Value::Null;
        assert!(fixture.read(&valid).is_err());
    }
    #[test]
    fn captured_environment_origin_requires_matching_values_and_redacts_failures() {
        let fixture = Fixture::new();
        let config = crate::sandbox::SandboxBuilder::new("env-capture")
            .image("alpine")
            .host_env("HOST".into(), "PRIVATE_ORIGINAL".into())
            .finish(None, None)
            .unwrap();
        let mut value = fixture.value.clone();
        value["source"]["source"] = serde_json::to_value(config).unwrap();
        assert!(fixture.read(&value).unwrap().is_some());
        value["source"]["source"]["env"][0]["value"] = serde_json::json!("PRIVATE_CHANGED");
        let error = fixture.read(&value).err().unwrap().to_string();
        assert!(error.contains("environment provenance"));
        assert!(!error.contains("PRIVATE_"));
        value["source"]["source"]
            .as_object_mut()
            .unwrap()
            .remove("env");
        assert!(fixture.read(&value).is_err());
    }
}
