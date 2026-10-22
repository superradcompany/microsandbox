//! Compute binding timing from selected consumers and independently checked captured execution.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedBindingConsumer, SavedBindingKind, SavedBindingReference,
    SavedBindingUse, SavedBindingUses,
};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Current activation facts. These come from the destination operation, never archive metadata.
#[derive(Debug, Clone, Copy)]
pub struct BindingDemandContext {
    /// Resume captured execution rather than booting a disk.
    pub full_resume: bool,
    /// Start a new command now, including canonical snapshot-backed run.
    pub starts_command: bool,
}

/// Timing for one logical requirement. A shared use always keeps the strongest timing.
#[derive(Clone, PartialEq, Eq)]
pub struct BindingDemand {
    /// Validated destination value shape.
    pub kind: SavedBindingKind,
    /// All selected consumers, retained for future command/boot checks even when needed now.
    pub consumers: BTreeSet<SavedBindingConsumer>,
    /// At least one consumer needs the binding before this operation activates.
    pub required_now: bool,
    /// Independently established captured execution uses this binding.
    pub captured_execution: bool,
}

/// Requirements only: neither binding values nor permission to activate are stored here.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BindingDemandPlan {
    /// Every selected or captured requirement, keyed by its validated logical identity.
    bindings: BTreeMap<String, BindingDemand>,
}

/// Missing inputs after shape checking; supplied values still need preparation and enforcement.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct BindingSupplyGaps {
    /// Missing bindings that must be supplied before the current activation.
    pub immediate: BTreeSet<String>,
    /// Missing future-command defaults; every later exec must recheck its actual inputs.
    pub before_new_command: BTreeSet<String>,
    /// Missing init inputs retained for a later cold boot, not replayed during full resume.
    pub before_cold_boot: BTreeSet<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl BindingDemandPlan {
    /// Read the complete requirements without changing their derived timing.
    pub fn bindings(&self) -> &BTreeMap<String, BindingDemand> {
        &self.bindings
    }

    /// Compare prepared destination value shapes without reading or storing secret material.
    ///
    /// This does not establish that certificates, sockets, storage identity, network policy or
    /// captured connections are usable. Those checks remain required before activation. The
    /// full logical inventory is retained even when a binding is supplied now: a temporary
    /// credential must not turn a future command's persisted requirement into an empty value.
    pub fn supply_gaps(
        &self,
        supplied: &BTreeMap<String, SavedBindingKind>,
    ) -> MicrosandboxResult<BindingSupplyGaps> {
        if supplied.len() > MAX_SAVED_CONFIG_ENTRIES {
            return Err(error("SCFG_LIMIT", "too many destination bindings"));
        }
        for (id, kind) in supplied {
            match self.bindings.get(id) {
                Some(demand) if demand.kind == *kind => {}
                Some(_) => {
                    return Err(error(
                        "SCFG_BINDING",
                        "destination binding has the wrong kind",
                    ));
                }
                None => {
                    return Err(error(
                        "SCFG_BINDING",
                        "destination binding has no selected consumer",
                    ));
                }
            }
        }
        let mut gaps = BindingSupplyGaps::default();
        for (id, demand) in &self.bindings {
            if supplied.contains_key(id) {
                continue;
            }
            if demand.required_now {
                gaps.immediate.insert(id.clone());
            }
            if demand.consumers.contains(&SavedBindingConsumer::NewCommand) {
                gaps.before_new_command.insert(id.clone());
            }
            if demand.consumers.contains(&SavedBindingConsumer::BootInit) {
                gaps.before_cold_boot.insert(id.clone());
            }
        }
        Ok(gaps)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for BindingDemandPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindingDemandPlan")
            .field("binding_count", &self.bindings.len())
            .field(
                "immediate_count",
                &self.bindings.values().filter(|v| v.required_now).count(),
            )
            .field(
                "captured_count",
                &self
                    .bindings
                    .values()
                    .filter(|v| v.captured_execution)
                    .count(),
            )
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for BindingSupplyGaps {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BindingSupplyGaps")
            .field("immediate_count", &self.immediate.len())
            .field("command_count", &self.before_new_command.len())
            .field("cold_boot_count", &self.before_cold_boot.len())
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Combine requirements after saved/fresh, clear and explicit-override resolution.
///
/// `selected` must be derived from effective typed fields, not the artifact inventory or its
/// pending-next-start section. Full resume additionally requires an independently established
/// captured binding inventory. `Some(empty)` means that inventory was checked and contains no
/// bindings; `None` means evidence is unavailable and cannot certify a full activation plan.
/// No saved/fresh switch exists here: mode selection cannot discard captured requirements.
pub fn plan_binding_demand(
    selected: &SavedBindingUses,
    captured: Option<&SavedBindingUses>,
    context: BindingDemandContext,
) -> MicrosandboxResult<BindingDemandPlan> {
    if context.full_resume && context.starts_command {
        return Err(error(
            "SCFG_FULL_STATE",
            "full resume cannot start a new initial command",
        ));
    }
    if context.full_resume != captured.is_some() {
        return Err(error(
            "SCFG_IDENTITY",
            "captured binding evidence must match the activation mode",
        ));
    }
    validate_uses(selected)?;
    if let Some(captured) = captured {
        validate_uses(captured)?;
    }
    let mut plan = BindingDemandPlan::default();
    for (id, usage) in selected {
        plan.bindings.insert(
            id.clone(),
            BindingDemand {
                kind: usage.kind,
                consumers: usage.consumers.clone(),
                required_now: usage.consumers.iter().any(|consumer| match consumer {
                    SavedBindingConsumer::NewCommand => context.starts_command,
                    SavedBindingConsumer::BootInit => !context.full_resume,
                    SavedBindingConsumer::ScriptBacking
                    | SavedBindingConsumer::Gateway
                    | SavedBindingConsumer::GuestTrust
                    | SavedBindingConsumer::Listener
                    | SavedBindingConsumer::Mount
                    | SavedBindingConsumer::Vsock => true,
                }),
                captured_execution: false,
            },
        );
    }
    // A captured placeholder can still be in a running process even when its future-exec
    // default was overridden or cleared. Merge that evidence independently and promote it.
    for (id, usage) in captured.into_iter().flatten() {
        let demand = plan
            .bindings
            .entry(id.clone())
            .or_insert_with(|| BindingDemand {
                kind: usage.kind,
                consumers: BTreeSet::new(),
                required_now: false,
                captured_execution: false,
            });
        if demand.kind != usage.kind {
            return Err(error(
                "SCFG_BINDING",
                "selected and captured binding kinds conflict",
            ));
        }
        demand.consumers.extend(usage.consumers.iter().copied());
        demand.required_now = true;
        demand.captured_execution = true;
    }
    if plan.bindings.len() > MAX_SAVED_CONFIG_ENTRIES {
        return Err(error(
            "SCFG_LIMIT",
            "too many combined binding requirements",
        ));
    }
    Ok(plan)
}

fn validate_uses(uses: &SavedBindingUses) -> MicrosandboxResult<()> {
    if uses.len() > MAX_SAVED_CONFIG_ENTRIES {
        return Err(error("SCFG_LIMIT", "too many binding requirements"));
    }
    for (id, usage) in uses {
        // This boundary receives derived maps rather than serialized records. Reuse the
        // strict portable reference validator so direct construction cannot bypass ID rules.
        SavedBindingReference { id: id.clone() }
            .validate()
            .map_err(|_| error("SCFG_BINDING", "invalid logical binding identifier"))?;
        if usage.consumers.is_empty() || usage.consumers.iter().any(|c| !valid_kind(*c, usage)) {
            return Err(error(
                "SCFG_BINDING",
                "binding kind does not match its consumers",
            ));
        }
    }
    Ok(())
}

fn valid_kind(consumer: SavedBindingConsumer, usage: &SavedBindingUse) -> bool {
    match consumer {
        SavedBindingConsumer::BootInit
        | SavedBindingConsumer::NewCommand
        | SavedBindingConsumer::ScriptBacking => usage.kind == SavedBindingKind::Text,
        SavedBindingConsumer::Gateway => matches!(
            usage.kind,
            SavedBindingKind::Text
                | SavedBindingKind::DnsResolver
                | SavedBindingKind::Certificate
                | SavedBindingKind::TlsIdentity
                | SavedBindingKind::ProxyEndpoint
                | SavedBindingKind::ProxyCredentials
        ),
        SavedBindingConsumer::GuestTrust => usage.kind == SavedBindingKind::Certificate,
        SavedBindingConsumer::Listener => usage.kind == SavedBindingKind::Listener,
        SavedBindingConsumer::Mount => matches!(
            usage.kind,
            SavedBindingKind::FilesystemFile
                | SavedBindingKind::FilesystemDirectory
                | SavedBindingKind::NamedDirectory
                | SavedBindingKind::NamedDisk
                | SavedBindingKind::DiskImage
        ),
        SavedBindingConsumer::Vsock => matches!(
            usage.kind,
            SavedBindingKind::StreamSocket | SavedBindingKind::DatagramSocket
        ),
    }
}

fn error(code: &str, reason: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: bindings: {reason}"))
}
