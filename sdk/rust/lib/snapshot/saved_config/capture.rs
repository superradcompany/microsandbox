//! Assemble one bounded capture document without publishing it or enabling restore activation.

use std::collections::BTreeMap;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, RuntimeCaptureAction, RuntimeCaptureTarget,
    SAVED_CONFIG_SCHEMA_VERSION, SavedActiveConfig, SavedBindingKind, SavedCaptureProvenance,
    SavedResourcesConfig, SavedSandboxConfig, SavedValue, collect_binding_uses,
    project_runtime_capture,
};
use microsandbox_types::snapshot::{Manifest, SnapshotScope};
use serde_json::Value;

use super::{
    ExecutionCaptureControls, NetworkCaptureBindings, NetworkCaptureControls,
    ResourceCaptureObservation, RuntimeCaptureSource, StorageCaptureBindings,
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Raw next-start intent selected under the same capture guard as active state.
/// The assembler classifies every section and applies the document's exclusions before
/// constructing portable values. This source supplies no active fallback or observation.
/// No Debug/serialization: recorded configuration may contain host-private values.
pub struct PendingCaptureSource<'a> {
    source: RuntimeCaptureSource<'a>,
    network: NetworkCaptureBindings,
    storage: StorageCaptureBindings,
}

/// One source-side assembly request. The source adapter supplies all active sections;
/// caller observations, descriptor and pending source must share its capture cut.
/// This request contains no destination resource values or permission to activate them.
pub struct CaptureDocumentRequest<'a> {
    /// Authoritative descriptor from the same capture, including existing owned backing.
    pub manifest: &'a Manifest,
    /// Independently confirmed guest allocation, with explicit unknown/converging reasons.
    pub resources: ResourceCaptureObservation,
    /// Logical network requirements and independently established trust inventory.
    pub network: NetworkCaptureBindings,
    /// Logical external storage requirements and observed backing kinds.
    pub storage: StorageCaptureBindings,
    /// Runtime omissions/bindings apply consistently to active and pending text.
    pub runtime_controls: &'a BTreeMap<RuntimeCaptureTarget, RuntimeCaptureAction>,
    /// User-label exclusions applied across both active and pending sources.
    pub execution_controls: &'a ExecutionCaptureControls,
    /// Network-response exclusions applied to both active and pending sources.
    pub network_controls: &'a NetworkCaptureControls,
    /// Separately selected recorded next-start intent; never active fallback.
    pub pending: Option<PendingCaptureSource<'a>>,
    /// Include the optional source-name provenance field. Captured guest hostname is
    /// independent and remains subject to its own runtime exclusion/full-state rules.
    pub include_source_name: bool,
    /// Independently established original geometry, not the requested resize target.
    pub construction_resources: Option<SavedResourcesConfig>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<'a> PendingCaptureSource<'a> {
    /// Compare provenance without exposing private source values in diagnostics.
    pub(crate) fn matches_recorded(&self, recorded: &Value) -> bool {
        self.source.recorded == recorded
    }

    /// Decode recorded next-start intent without borrowing active init/script observations.
    /// Logical requirements must describe this source, not the active backing inventory.
    /// The caller still owns selection/generation coherence; no catalog or file is read here.
    pub fn from_recorded(
        recorded: &'a Value,
        network: NetworkCaptureBindings,
        storage: StorageCaptureBindings,
    ) -> MicrosandboxResult<Self> {
        Ok(Self {
            source: RuntimeCaptureSource::from_recorded(recorded, None, None)?,
            network,
            storage,
        })
    }
}

impl RuntimeCaptureSource<'_> {
    /// Project one document from this source, deriving its binding inventory from actual
    /// sanitized references. The generation must be supplied by the coherent capture owner;
    /// this pure projection cannot establish freshness, coherent pending selection or backing.
    /// No manifest extension is written and no capability is advertised by this method.
    pub fn project_document(
        &self,
        request: CaptureDocumentRequest<'_>,
        active_generation: SavedValue<String>,
    ) -> MicrosandboxResult<SavedSandboxConfig> {
        let CaptureDocumentRequest {
            manifest,
            resources,
            network,
            storage,
            runtime_controls,
            execution_controls,
            network_controls,
            pending,
            include_source_name,
            construction_resources,
        } = request;
        // Validate selectors against the union, then scope them to each recorded source.
        // A key present only in pending must be removable without weakening typo detection.
        let (active_execution, pending_execution) = partition_execution_controls(
            self,
            pending.as_ref().map(|pending| &pending.source),
            execution_controls,
        )?;
        let runtime = project_runtime_capture(
            self.input(),
            pending
                .as_ref()
                .map(|pending| pending.source.pending_input()),
            runtime_controls,
            manifest.scope == SnapshotScope::Full,
        )
        .map_err(manifest_error)?;
        let active = SavedActiveConfig {
            resources: self.project_resources(resources)?,
            script_backing: self
                .script_backing(&runtime.active, manifest.scope == SnapshotScope::Full)?,
            runtime: runtime.active,
            network: self.project_network(network, network_controls)?,
            execution: self.project_execution(&active_execution)?,
            storage: self.project_storage(storage, manifest)?,
        };
        let pending = match pending {
            Some(pending) => Some(SavedActiveConfig {
                script_backing: None,
                resources: pending.source.project_pending_resources()?,
                runtime: runtime.pending.ok_or_else(|| {
                    MicrosandboxError::InvalidConfig(
                        "SCFG_VALUE: sandbox-config: pending runtime projection is missing".into(),
                    )
                })?,
                network: pending
                    .source
                    .project_network(pending.network, network_controls)?,
                execution: pending.source.project_execution(&pending_execution)?,
                storage: pending.source.project_pending_storage(pending.storage)?,
            }),
            None => None,
        };
        // Build the inventory from references, not caller declarations. Shared IDs must
        // agree across every family and active/pending section; pending uses do not enter
        // activation demand, which the resolver derives separately from active settings.
        let mut bindings = BTreeMap::new();
        add_bindings(&mut bindings, &active)?;
        if let Some(pending) = &pending {
            add_bindings(&mut bindings, pending)?;
        }
        let document = SavedSandboxConfig {
            schema_version: SAVED_CONFIG_SCHEMA_VERSION,
            active,
            pending,
            bindings,
            provenance: SavedCaptureProvenance {
                producer_version: env!("CARGO_PKG_VERSION").into(),
                source_name: if include_source_name {
                    self.recorded
                        .get("name")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                } else {
                    None
                },
                active_generation,
                construction_resources,
            },
        };
        // Validate the aggregate size, active observations, legacy user/clock projection
        // and owned inventory before any caller can serialize or associate this document.
        document
            .validate_legacy_projections(manifest)
            .map_err(manifest_error)?;
        Ok(document)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn partition_execution_controls(
    active: &RuntimeCaptureSource<'_>,
    pending: Option<&RuntimeCaptureSource<'_>>,
    controls: &ExecutionCaptureControls,
) -> MicrosandboxResult<(ExecutionCaptureControls, ExecutionCaptureControls)> {
    if controls.omit_label_keys.len() > MAX_SAVED_CONFIG_ENTRIES {
        return Err(MicrosandboxError::InvalidConfig(
            "SCFG_LIMIT: sandbox-config: too many label exclusions".into(),
        ));
    }
    if controls.omit_labels && !controls.omit_label_keys.is_empty() {
        return Err(MicrosandboxError::InvalidConfig(
            "SCFG_VALUE: sandbox-config: overlapping label exclusions".into(),
        ));
    }
    let mut active_controls = ExecutionCaptureControls {
        omit_labels: controls.omit_labels,
        ..Default::default()
    };
    let mut pending_controls = ExecutionCaptureControls {
        omit_labels: controls.omit_labels,
        ..Default::default()
    };
    for key in &controls.omit_label_keys {
        let active_match = label_is_recorded(active, key);
        let pending_match = pending.is_some_and(|source| label_is_recorded(source, key));
        if crate::sandbox::reserved_label_prefix(key).is_some() || (!active_match && !pending_match)
        {
            return Err(MicrosandboxError::InvalidConfig(
                "SCFG_VALUE: sandbox-config: label exclusion did not match source".into(),
            ));
        }
        if active_match {
            active_controls.omit_label_keys.insert(key.clone());
        }
        if pending_match {
            pending_controls.omit_label_keys.insert(key.clone());
        }
    }
    Ok((active_controls, pending_controls))
}

fn label_is_recorded(source: &RuntimeCaptureSource<'_>, key: &str) -> bool {
    source.recorded.get("labels").is_some() && source.config.spec.labels.contains_key(key)
}

fn add_bindings(
    inventory: &mut BTreeMap<String, SavedBindingKind>,
    section: &SavedActiveConfig,
) -> MicrosandboxResult<()> {
    let network_runtime =
        collect_binding_uses(&section.runtime, &section.network).map_err(manifest_error)?;
    let storage = section.storage.binding_uses().map_err(manifest_error)?;
    for (id, usage) in network_runtime.into_iter().chain(storage) {
        if inventory.get(&id).is_some_and(|kind| *kind != usage.kind) {
            return Err(MicrosandboxError::InvalidConfig("SCFG_BINDING: sandbox-config: shared requirement has incompatible destination kinds".into()));
        }
        inventory.insert(id, usage.kind);
    }
    Ok(())
}

fn manifest_error(error: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(error.to_string())
}
