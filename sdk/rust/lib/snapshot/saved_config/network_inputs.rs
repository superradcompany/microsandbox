//! Compose native network inputs while preserving optional-container and admission semantics.

use microsandbox_types::snapshot::saved_config::{SavedNetworkConfig, SavedValue};
use microsandbox_types::{InterfaceOverrides, NetworkSpec, NetworkSpecPatch, SecretsConfig};

use super::{SavedConfigurationPlan, SnapshotConfigMode};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A recorded builtin section selects the native absent-container default. A concrete
/// recorded section or explicit destination section retains presence even when empty.
pub(super) struct NetworkInputShape {
    dns: bool,
    tls: bool,
    secrets: bool,
    interface: Option<InterfaceOverrides>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl NetworkInputShape {
    pub(super) fn selected(
        saved: &SavedNetworkConfig,
        lower: &NetworkSpec,
        explicit: &NetworkSpecPatch,
        mode: SnapshotConfigMode,
    ) -> Self {
        // Fresh mode discards saved policy defaults, not destination policy. The family
        // assembler retains these lower DNS/TLS settings; do not erase their containers.
        // This carries presence only, never lower host resolver/trust/credential material.
        let retain_lower_policy = mode == SnapshotConfigMode::Fresh;
        Self {
            dns: saved.dns.as_ref().and_then(SavedValue::value).is_some()
                || explicit.dns.is_some()
                || (retain_lower_policy && lower.dns.is_some()),
            tls: saved.tls.as_ref().and_then(SavedValue::value).is_some()
                || explicit.tls.is_some()
                || (retain_lower_policy && lower.tls.is_some()),
            secrets: saved.secrets.as_ref().and_then(SavedValue::value).is_some()
                || explicit.secrets.is_some(),
            // Slot/guest identity never comes from portable defaults. Preserve resolved
            // destination defaults beneath sparse explicit inputs; allocation and captured
            // identity admission still happen later.
            interface: match &explicit.interface {
                Some(patch) => {
                    let mut interface = lower.interface.clone().unwrap_or_default();
                    patch.clone().apply_to(&mut interface);
                    Some(interface)
                }
                None => lower.interface.clone(),
            },
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn assemble(
    plan: &SavedConfigurationPlan,
    shape: &NetworkInputShape,
) -> MicrosandboxResult<NetworkSpec> {
    // Assemble privately and return only after every family accepts its inventory. In
    // particular, a late unknown secret/listener section cannot leak a partial policy.
    let mut network = NetworkSpec {
        interface: shape.interface.clone(),
        ..NetworkSpec::default()
    };
    plan.network_policy().apply_policy_to(&mut network)?;
    plan.gateway().apply_inputs_to(&mut network)?;
    plan.listeners().apply_to(&mut network)?;
    let mut secrets = SecretsConfig::default();
    plan.secrets().apply_to(&mut secrets)?;

    // Family plans materialize defaults in nested structs to compose sibling fields.
    // Restore the selected container presence only after validating all those plans;
    // an unknown section must not masquerade as a known absent/default one.
    if !shape.dns {
        network.dns = None;
    }
    if !shape.tls {
        network.tls = None;
    }
    network.secrets = shape.secrets.then_some(secrets);
    Ok(network)
}
