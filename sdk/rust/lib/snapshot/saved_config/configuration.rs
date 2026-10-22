//! Coordinate all saved-config preparation against one immutable source and destination input.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_BYTES, MAX_SAVED_CONFIG_ENTRIES, SavedBindingConsumer, SavedBindingUses,
    SavedNetworkConfig, SavedOrigin, SavedRuntimeConfig, SavedSandboxConfig, SavedScript,
    SavedScriptBacking, SavedValue, collect_binding_uses,
};
use microsandbox_types::{
    NetworkSpec, SandboxResources, SandboxResourcesPatch, SandboxSpec, SandboxSpecPatch,
    SecurityProfile,
};

use super::destination_inputs::{SavedDestinationInputs, destination_fields};
use super::network_inputs::NetworkInputShape;
use super::{
    BindingDemandContext, BindingDemandPlan, BindingSupplyGaps, ConfigurationBindingInput,
    DestinationGuestSecurity, DestinationNetworkBaseline, ExecutionConfigurationPlan,
    ExecutionDefaultClear, ExecutionRestoreMode, GatewayConfigurationPlan,
    ListenerConfigurationPlan, NetworkPolicyClear, NetworkPolicyConfigurationPlan,
    ResourceConfigurationPlan, ResourceDefaultClear, ResourceRestoreMode, RuntimeConfigurationPlan,
    RuntimeDefaultClear, RuntimeSelectionContext, SecretBindingInput, SecretConfigurationPlan,
    SnapshotConfigMode, StorageConfigurationPlan, plan_binding_demand,
    prepare_execution_configuration, prepare_gateway_configuration, prepare_listener_configuration,
    prepare_network_policy_configuration, prepare_resource_configuration,
    prepare_runtime_configuration, prepare_secret_configuration, prepare_storage_configuration,
    select_gateway_inputs, select_listener_inputs, select_runtime_defaults, select_secret_inputs,
    select_storage_inputs,
};
use crate::{MicrosandboxError, MicrosandboxResult, snapshot::Manifest};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Trusted operation facts. Full resume cannot be requested without separately obtained
/// geometry, guest policy and captured binding evidence; metadata is not that evidence.
pub enum SavedConfigurationContext<'a> {
    /// A new boot, optionally starting a new initial command.
    Disk { starts_command: bool },
    /// Resume existing execution. An empty captured inventory means checked empty, not unknown.
    Full {
        /// Independently checked checkpoint construction geometry.
        resources: &'a SandboxResources,
        /// Independently checked captured guest policy.
        security: SecurityProfile,
        /// Captured requirements, including ones masked by optional-default selection.
        bindings: &'a SavedBindingUses,
    },
}

/// Only existing typed optional-default clears. Required resource inventories have no clear.
#[derive(Default)]
pub struct SavedConfigurationClears {
    /// New-command and cold-boot defaults.
    pub runtime: Vec<RuntimeDefaultClear>,
    /// Optional disk-boot allocation defaults.
    pub resources: Vec<ResourceDefaultClear>,
    /// User metadata, future process limits and duration defaults.
    pub execution: Vec<ExecutionDefaultClear>,
    /// Optional host gateway policy, never resource/credential bindings.
    pub network_policy: Vec<NetworkPolicyClear>,
}

/// One preparation request. All sections use these same source, explicit input and mode
/// values; independently prepared plans from different captures cannot be mixed together.
pub struct SavedConfigurationRequest<'a> {
    /// Immutable, integrity-associated source document.
    pub saved: &'a SavedSandboxConfig,
    /// Authoritative descriptor used to check duplicated legacy and storage projections.
    pub manifest: &'a Manifest,
    /// Already resolved destination/image defaults, never a surviving source sandbox.
    pub lower: &'a SandboxSpec,
    /// Sparse resource defaults retain whether a maximum was actually specified.
    pub lower_resources: &'a SandboxResourcesPatch,
    /// Existing merged sparse destination inputs.
    pub explicit: &'a SandboxSpecPatch,
    /// Typed clears applied before explicit destination inputs.
    pub clears: &'a SavedConfigurationClears,
    /// Whether optional source defaults participate.
    pub mode: SnapshotConfigMode,
    /// Actual operation and independently established full-state evidence.
    pub context: SavedConfigurationContext<'a>,
    /// Destination guest-security baseline and mandatory minimum.
    pub guest_security: DestinationGuestSecurity,
    /// Destination-owned network inspection baseline.
    pub network_baseline: &'a DestinationNetworkBaseline,
}

/// All-or-error preparation with immutable obligations. This deliberately is not a SandboxSpec
/// or activation permit: materialization, mandatory policy, captured identity, persistent
/// deferred enforcement and destination admission must still finish before launch.
pub struct SavedConfigurationPlan {
    destination: SandboxSpec,
    runtime_context: RuntimeSelectionContext,
    runtime: RuntimeConfigurationPlan,
    #[cfg_attr(
        not(all(feature = "local", unix)),
        expect(
            dead_code,
            reason = "full backing obligations retained for platform admission"
        )
    )]
    pub(super) script_backing: Option<SavedValue<SavedScriptBacking>>,
    // Never hash an excluded/bound source body. Missing hashes mean identity is unresolved.
    #[cfg_attr(
        not(all(feature = "local", unix)),
        expect(
            dead_code,
            reason = "full backing obligations retained for platform admission"
        )
    )]
    pub(super) script_digests: Option<BTreeMap<String, (String, u16)>>,
    resources: ResourceConfigurationPlan,
    execution: ExecutionConfigurationPlan,
    network_policy: NetworkPolicyConfigurationPlan,
    network_shape: NetworkInputShape,
    gateway: GatewayConfigurationPlan,
    secrets: SecretConfigurationPlan,
    listeners: ListenerConfigurationPlan,
    storage: StorageConfigurationPlan,
    demand: BindingDemandPlan,
    supply_gaps: BindingSupplyGaps,
    /// Keep the single original registry, including captured-only requirements. Preparing a
    /// selected consumer never proves that a replacement also matches captured backing.
    bindings: BTreeMap<String, ConfigurationBindingInput>,
    unresolved_text_sources: BTreeSet<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SavedConfigurationPlan {
    /// Immutable operation facts used by every selected family. Consumers must not reuse
    /// full-resume inputs as cold-boot inputs, or deferred defaults as an initial command.
    pub fn context(&self) -> RuntimeSelectionContext {
        self.runtime_context
    }

    /// Compose every selected family and retain this plan alongside its native inputs.
    /// Unknown immediate inputs refuse atomically; future command/init requirements remain
    /// guarded on the owned plan. This performs no I/O and grants no activation authority.
    pub fn into_destination_inputs(self) -> MicrosandboxResult<SavedDestinationInputs> {
        let mut spec = self.destination.clone();
        spec.resources = self.resources.resources()?;
        self.execution.apply_to(&mut spec)?;
        self.runtime
            .apply_activation_inputs(&mut spec, self.runtime_context)?;
        spec.network = self.network_inputs()?;
        self.storage.apply_to(&mut spec)?;
        Ok(SavedDestinationInputs::new(spec, self))
    }

    /// New-command defaults, exact script backing and retained deferred requirements.
    pub fn runtime(&self) -> &RuntimeConfigurationPlan {
        &self.runtime
    }
    /// Requested destination geometry, still subject to host and captured-state admission.
    pub fn resources(&self) -> &ResourceConfigurationPlan {
        &self.resources
    }
    /// User metadata, security selection and fresh duration defaults.
    pub fn execution(&self) -> &ExecutionConfigurationPlan {
        &self.execution
    }
    /// Portable policy with explicit-relaxation obligations retained.
    pub fn network_policy(&self) -> &NetworkPolicyConfigurationPlan {
        &self.network_policy
    }
    /// Compose all selected network families without opening files, resolving credentials or
    /// installing policy. This is input to admission, not a launch permit: the original plan
    /// retains approvals, captured-state checks and binding requirements after composition.
    /// Unknown inventories refuse instead of yielding an apparently complete network config.
    pub fn network_inputs(&self) -> MicrosandboxResult<NetworkSpec> {
        super::network_inputs::assemble(self, &self.network_shape)
    }

    /// Prepared gateway references, before file loading and credential resolution.
    pub fn gateway(&self) -> &GatewayConfigurationPlan {
        &self.gateway
    }
    /// Host substitution inputs and retained placeholder/policy obligations.
    pub fn secrets(&self) -> &SecretConfigurationPlan {
        &self.secrets
    }
    /// Listener inputs, before socket allocation and connection checks.
    pub fn listeners(&self) -> &ListenerConfigurationPlan {
        &self.listeners
    }
    /// Mount/IPC inputs, before filesystem and captured backing admission.
    pub fn storage(&self) -> &StorageConfigurationPlan {
        &self.storage
    }
    /// Union of selected and captured consumers, regardless of which inputs were supplied.
    pub fn demand(&self) -> &BindingDemandPlan {
        &self.demand
    }
    /// Missing logical inputs, including future text consumers backed only by unresolved
    /// credential references. An empty result does not prove native resources are usable.
    pub fn supply_gaps(&self) -> &BindingSupplyGaps {
        &self.supply_gaps
    }
    /// Original bounded registry for later materialization and captured-identity checks.
    pub fn bindings(&self) -> &BTreeMap<String, ConfigurationBindingInput> {
        &self.bindings
    }
    /// References requiring destination credential resolution before use. A provided
    /// reference is never an available command value or a resolved host secret.
    pub fn unresolved_text_sources(&self) -> &BTreeSet<String> {
        &self.unresolved_text_sources
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for SavedConfigurationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SavedConfigurationPlan")
            .field("demand", &self.demand)
            .field("supply_gaps", &self.supply_gaps)
            .field(
                "unresolved_source_count",
                &self.unresolved_text_sources.len(),
            )
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Select and prepare all families without I/O or mutation of either source or destination.
/// No partial result escapes on failure. Validate the original document before fresh/clear/
/// explicit selection, so an override cannot conceal malformed metadata or pending state.
pub fn prepare_saved_configuration(
    request: SavedConfigurationRequest<'_>,
    bindings: BTreeMap<String, ConfigurationBindingInput>,
) -> MicrosandboxResult<SavedConfigurationPlan> {
    request
        .saved
        .validate_legacy_projections(request.manifest)
        .map_err(|_| {
            error(
                "SCFG_SCHEMA",
                "invalid source document or legacy projection",
            )
        })?;
    if bindings.len() > MAX_SAVED_CONFIG_ENTRIES {
        return Err(error("SCFG_LIMIT", "too many destination bindings"));
    }
    let mut total_bytes = 0usize;
    for (id, value) in &bindings {
        // Caller-supplied keys are not yet validated demand IDs. Bound their bytes too,
        // before listener routing or the supplied-shape map can duplicate any of them.
        total_bytes = total_bytes
            .checked_add(id.len())
            .filter(|total| *total <= MAX_SAVED_CONFIG_BYTES)
            .ok_or_else(|| error("SCFG_LIMIT", "destination binding registry is too large"))?;
        value.account_bytes(&mut total_bytes)?;
    }
    let saved = &request.saved.active;
    let explicit = request.explicit;
    let (full, starts_command, resource_mode, execution_mode, captured) = match request.context {
        SavedConfigurationContext::Disk { starts_command } => (
            false,
            starts_command,
            ResourceRestoreMode::Disk,
            ExecutionRestoreMode::Disk,
            None,
        ),
        SavedConfigurationContext::Full {
            resources,
            security,
            bindings,
        } => (
            true,
            false,
            ResourceRestoreMode::Full(resources),
            ExecutionRestoreMode::Full {
                captured_security: security,
            },
            Some(bindings),
        ),
    };
    let runtime_context = RuntimeSelectionContext {
        config_mode: request.mode,
        full_resume: full,
        starts_command,
    };
    let runtime_selection = select_runtime_defaults(
        &saved.runtime,
        explicit,
        &request.clears.runtime,
        runtime_context,
    )?;
    let gateway_selection = select_gateway_inputs(&saved.network, &explicit.network, full)?;
    let secret_selection = select_secret_inputs(
        saved.network.secrets.as_ref(),
        explicit.network.secrets.as_ref(),
        full,
    )?;
    // Logical listener bindings disambiguate repeated guest service/transport identities.
    // Supply them during selection, not afterward: an explicit mapping may be ambiguous
    // until another listener for that service has its own logical binding.
    let selected_port_ids: BTreeSet<_> = saved
        .network
        .ports
        .as_ref()
        .and_then(SavedValue::value)
        .into_iter()
        .flatten()
        .map(|port| port.binding.id.as_str())
        .collect();
    let listener_inputs: BTreeMap<_, _> = bindings
        .iter()
        .filter_map(|(id, value)| match value {
            ConfigurationBindingInput::Listener(input)
                if selected_port_ids.contains(id.as_str()) =>
            {
                Some((id.clone(), input.clone()))
            }
            _ => None,
        })
        .collect();
    let listener_selection = select_listener_inputs(
        saved.network.ports.as_ref(),
        explicit.network.ports.as_deref().unwrap_or_default(),
        &listener_inputs,
        full,
    )?;
    let listener_uses = collect_binding_uses(
        &SavedRuntimeConfig::default(),
        &SavedNetworkConfig {
            ports: Some(SavedValue::Value {
                value: listener_selection
                    .entries
                    .iter()
                    .filter_map(|entry| {
                        entry
                            .saved
                            .as_ref()
                            .filter(|saved| {
                                entry.destination.is_none()
                                    || listener_inputs.contains_key(&saved.binding.id)
                            })
                            .cloned()
                    })
                    .collect(),
                origin: SavedOrigin::Configured,
            }),
            ..Default::default()
        },
    )
    .map_err(|_| error("SCFG_BINDING", "invalid selected listener requirements"))?;
    let storage_selection = select_storage_inputs(
        &saved.storage,
        request.manifest,
        explicit,
        request.mode,
        full,
    )?;
    let runtime_uses =
        collect_binding_uses(&runtime_selection.defaults, &SavedNetworkConfig::default())
            .map_err(|_| error("SCFG_BINDING", "invalid selected runtime requirements"))?;
    let mut selected = runtime_uses.clone();
    for uses in [
        &gateway_selection.remaining_bindings,
        &secret_selection.remaining_bindings,
        &listener_uses,
        &storage_selection.remaining_bindings,
    ] {
        merge_uses(&mut selected, uses)?;
    }
    let demand = plan_binding_demand(
        &selected,
        captured,
        BindingDemandContext {
            full_resume: full,
            starts_command,
        },
    )?;
    let supplied = bindings
        .iter()
        .map(|(id, value)| (id.clone(), value.kind()))
        .collect();
    let mut supply_gaps = demand.supply_gaps(&supplied)?;
    if !supply_gaps.immediate.is_empty() {
        return Err(error(
            "SCFG_BINDING",
            "required destination bindings are missing",
        ));
    }
    let mut runtime_inputs = BTreeMap::new();
    let mut secret_inputs = BTreeMap::new();
    let mut gateway_inputs = BTreeMap::new();
    let mut storage_inputs = BTreeMap::new();
    let mut unresolved_text_sources = BTreeSet::new();
    for (id, value) in &bindings {
        match value {
            ConfigurationBindingInput::Text(text) => {
                if runtime_uses.contains_key(id) {
                    runtime_inputs.insert(id.clone(), text.clone());
                }
                if secret_selection.remaining_bindings.contains_key(id) {
                    secret_inputs.insert(id.clone(), SecretBindingInput::Value(text.text.clone()));
                }
            }
            ConfigurationBindingInput::TextSource(source) => {
                unresolved_text_sources.insert(id.clone());
                if let Some(uses) = runtime_uses.get(id) {
                    if uses.consumers.contains(&SavedBindingConsumer::NewCommand) {
                        supply_gaps.before_new_command.insert(id.clone());
                    }
                    if uses.consumers.contains(&SavedBindingConsumer::BootInit) {
                        supply_gaps.before_cold_boot.insert(id.clone());
                    }
                }
                if secret_selection.remaining_bindings.contains_key(id) {
                    secret_inputs.insert(id.clone(), SecretBindingInput::Source(source.clone()));
                }
            }
            ConfigurationBindingInput::Gateway(input) => {
                if gateway_selection.remaining_bindings.contains_key(id) {
                    gateway_inputs.insert(id.clone(), input.clone());
                }
            }
            ConfigurationBindingInput::Storage(input) => {
                if storage_selection.remaining_bindings.contains_key(id) {
                    storage_inputs.insert(id.clone(), input.clone());
                }
            }
            ConfigurationBindingInput::Listener(_) => {}
        }
    }
    // Every family is recomputed from the same immutable inputs. None can observe a changed
    // source or replace another family's prepared value between demand and materialization.
    Ok(SavedConfigurationPlan {
        destination: destination_fields(request.lower, explicit),
        runtime_context,
        script_backing: saved.script_backing.clone(),
        script_digests: saved
            .runtime
            .scripts
            .as_ref()
            .and_then(SavedValue::value)
            .and_then(|scripts| {
                scripts
                    .iter()
                    .map(|(name, script)| match script {
                        SavedScript::Inline { digest, mode, .. } => {
                            Some((name.clone(), (digest.clone(), *mode)))
                        }
                        _ => None,
                    })
                    .collect()
            }),
        runtime: prepare_runtime_configuration(
            &saved.runtime,
            request.lower,
            explicit,
            &request.clears.runtime,
            runtime_context,
            &runtime_inputs,
        )?,
        resources: prepare_resource_configuration(
            &saved.resources,
            request.lower_resources,
            &explicit.resources,
            &request.clears.resources,
            request.mode,
            resource_mode,
        )?,
        execution: prepare_execution_configuration(
            &saved.execution,
            request.lower,
            explicit,
            &request.clears.execution,
            request.mode,
            execution_mode,
            request.guest_security,
        )?,
        network_shape: NetworkInputShape::selected(
            &saved.network,
            &request.lower.network,
            &explicit.network,
            request.mode,
        ),
        network_policy: prepare_network_policy_configuration(
            &saved.network,
            &request.lower.network,
            &explicit.network,
            &request.clears.network_policy,
            request.mode,
            full,
            request.network_baseline,
        )?,
        gateway: prepare_gateway_configuration(
            &saved.network,
            &explicit.network,
            &gateway_inputs,
            full,
        )?,
        secrets: prepare_secret_configuration(
            saved.network.secrets.as_ref(),
            explicit.network.secrets.as_ref(),
            &secret_inputs,
            full,
        )?,
        listeners: prepare_listener_configuration(
            saved.network.ports.as_ref(),
            explicit.network.ports.as_deref().unwrap_or_default(),
            &listener_inputs,
            full,
        )?,
        storage: prepare_storage_configuration(
            &saved.storage,
            request.manifest,
            explicit,
            request.mode,
            full,
            &storage_inputs,
        )?,
        demand,
        supply_gaps,
        bindings,
        unresolved_text_sources,
    })
}

fn merge_uses(into: &mut SavedBindingUses, from: &SavedBindingUses) -> MicrosandboxResult<()> {
    for (id, usage) in from {
        if let Some(existing) = into.get_mut(id) {
            if existing.kind != usage.kind {
                return Err(error(
                    "SCFG_BINDING",
                    "selected consumers require incompatible kinds",
                ));
            }
            existing.consumers.extend(&usage.consumers);
        } else {
            into.insert(id.clone(), usage.clone());
        }
    }
    Ok(())
}

fn error(code: &str, detail: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: sandbox-config: {detail}"))
}
