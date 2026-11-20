//! Select gateway resource inputs without reading files, resolving endpoints or loading secrets.

use std::collections::BTreeSet;
use std::fmt;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedBindingUses, SavedNetworkConfig, SavedRuntimeConfig, SavedValue,
    collect_binding_uses,
};
use microsandbox_types::{DnsConfigPatch, NetworkSpecPatch, TlsConfigPatch};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// DNS, proxy and trust selection. Listener and secret entries have separate keyed selectors.
pub struct GatewayInputPlan {
    /// Unsupplied source resource requirements. DNS/TLS container policy is retained only to
    /// preserve the typed projection; policy defaults come from their separate selector.
    pub requirements: SavedNetworkConfig,
    /// Explicit destination resource inputs only, preserving their existing path/source
    /// semantics. Never serialize this credential-bearing patch into portable metadata.
    pub destination: NetworkSpecPatch,
    /// Unsupplied logical uses, preserving requirements shared across selected fields.
    pub remaining_bindings: SavedBindingUses,
    /// Unrecorded resource fields that explicit destination inputs have not replaced.
    pub unknown_fields: BTreeSet<&'static str>,
    /// Recorded builtin defaults that assembly must not confuse with missing metadata.
    pub defaulted_fields: BTreeSet<&'static str>,
    /// Full resume requires independently checked captured trust, DNS and connection state.
    pub requires_full_compatibility: bool,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for GatewayInputPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GatewayInputPlan")
            .field("binding_count", &self.remaining_bindings.len())
            .field("unknown_fields", &self.unknown_fields)
            .field("defaulted_fields", &self.defaulted_fields)
            .field(
                "requires_full_compatibility",
                &self.requires_full_compatibility,
            )
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Select resource fields after mode/clear selection. Ordered explicit resolver/trust lists
/// replace their selected defaults, including empty lists; policy-only patches do not.
/// Proxy clear is explicit `Some(None)`, never an unavailable credential's implicit fallback.
///
/// A host-trust boolean cannot identify or satisfy a recorded certificate requirement.
/// Full captured requirements must join demand independently even when selected defaults
/// are replaced. Later preparation validates actual material, policy and physical identity;
/// no source host endpoint, path or credential is consulted by this function.
pub fn select_gateway_inputs(
    saved: &SavedNetworkConfig,
    explicit: &NetworkSpecPatch,
    full_resume: bool,
) -> MicrosandboxResult<GatewayInputPlan> {
    saved
        .validate()
        .map_err(|_| error("SCFG_VALUE", "invalid saved gateway metadata"))?;
    // Check original cross-field kinds before overrides can hide a malformed shared ID.
    collect_binding_uses(&SavedRuntimeConfig::default(), saved)
        .map_err(|_| error("SCFG_BINDING", "invalid saved gateway binding kinds"))?;
    let mut plan = GatewayInputPlan {
        requirements: SavedNetworkConfig {
            dns: saved.dns.clone(),
            tls: saved.tls.clone(),
            guest_trust: saved.guest_trust.clone(),
            outbound_proxy: saved.outbound_proxy.clone(),
            ..Default::default()
        },
        destination: NetworkSpecPatch::new(),
        remaining_bindings: Default::default(),
        unknown_fields: BTreeSet::new(),
        defaulted_fields: BTreeSet::new(),
        requires_full_compatibility: full_resume,
    };
    let nameservers = explicit
        .dns
        .as_ref()
        .and_then(|dns| dns.nameservers.as_ref());
    observe(
        saved.dns.as_ref(),
        nameservers.is_some(),
        "network.dns.nameservers",
        &mut plan,
    );
    if let Some(nameservers) = nameservers {
        count(nameservers.len())?;
        let mut input = DnsConfigPatch::new();
        input.nameservers = Some(nameservers.clone());
        plan.destination.dns = Some(input);
        if let Some(SavedValue::Value { value, .. }) = &mut plan.requirements.dns {
            value.resolvers.clear();
        }
    }
    let tls = explicit.tls.as_ref();
    let upstream = tls.and_then(|tls| tls.upstream_ca_cert.as_ref());
    let scoped = tls.and_then(|tls| tls.scoped_upstream_ca_cert.as_ref());
    let identity = tls.and_then(|tls| tls.intercept_ca.as_ref());
    observe(
        saved.tls.as_ref(),
        upstream.is_some(),
        "network.tls.upstream_ca_cert",
        &mut plan,
    );
    observe(
        saved.tls.as_ref(),
        scoped.is_some(),
        "network.tls.scoped_upstream_ca_cert",
        &mut plan,
    );
    observe(
        saved.tls.as_ref(),
        identity.is_some(),
        "network.tls.intercept_ca",
        &mut plan,
    );
    if upstream.is_some() || scoped.is_some() || identity.is_some() {
        let mut input = TlsConfigPatch::new();
        if let Some(upstream) = upstream {
            count(upstream.len())?;
            input.upstream_ca_cert = Some(upstream.clone());
            if let Some(SavedValue::Value { value, .. }) = &mut plan.requirements.tls {
                value.upstream_cas.clear();
            }
        }
        if let Some(scoped) = scoped {
            count(scoped.len())?;
            input.scoped_upstream_ca_cert = Some(scoped.clone());
            if let Some(SavedValue::Value { value, .. }) = &mut plan.requirements.tls {
                value.scoped_upstream_cas.clear();
            }
        }
        if let Some(identity) = identity {
            // Match the existing TLS engine's all-or-neither contract. A partial pair
            // must not silently acquire its missing half from a source sandbox.
            if identity.cert_path.is_some() != identity.key_path.is_some() {
                return Err(error(
                    "SCFG_BINDING",
                    "interception identity requires both certificate and key paths",
                ));
            }
            input.intercept_ca = Some(identity.clone());
            if let Some(SavedValue::Value { value, .. }) = &mut plan.requirements.tls {
                value.intercept_ca = None;
            }
        }
        plan.destination.tls = Some(input);
    }
    observe(
        saved.guest_trust.as_ref(),
        false,
        "network.guest_trust",
        &mut plan,
    );
    // This explicit flag chooses destination host trust policy. It supplies neither a
    // recorded certificate's identity nor authority to read the original host's files.
    plan.destination.trust_host_cas = explicit.trust_host_cas;
    observe(
        saved.outbound_proxy.as_ref(),
        explicit.outbound_proxy.is_some(),
        "network.outbound_proxy",
        &mut plan,
    );
    if explicit.outbound_proxy.is_some() {
        plan.destination.outbound_proxy = explicit.outbound_proxy.clone();
        plan.requirements.outbound_proxy = None;
    }
    plan.remaining_bindings =
        collect_binding_uses(&SavedRuntimeConfig::default(), &plan.requirements)
            .map_err(|_| error("SCFG_BINDING", "invalid remaining gateway requirements"))?;
    Ok(plan)
}

fn observe<T>(
    saved: Option<&SavedValue<T>>,
    overridden: bool,
    field: &'static str,
    plan: &mut GatewayInputPlan,
) {
    if overridden {
        return;
    }
    match saved {
        None | Some(SavedValue::Unknown { .. }) => {
            plan.unknown_fields.insert(field);
        }
        Some(SavedValue::Default {}) => {
            plan.defaulted_fields.insert(field);
        }
        Some(SavedValue::Value { .. }) => {}
    }
}

fn count(count: usize) -> MicrosandboxResult<()> {
    if count > MAX_SAVED_CONFIG_ENTRIES {
        Err(error("SCFG_LIMIT", "too many destination gateway inputs"))
    } else {
        Ok(())
    }
}

fn error(code: &str, reason: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: network: {reason}"))
}
