//! Cross-section binding kinds and consumers, derived from actual typed references.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::SnapshotManifestResult;

use super::validation::{binding, count, invalid};
use super::{RuntimeBindingConsumer, SavedNetworkConfig, SavedRuntimeConfig, SavedValue};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Expected destination value shape, never a source lookup instruction or stored value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SavedBindingKind {
    /// UTF-8 text for argv/env, a registered script body or host secret substitution.
    Text,
    /// Destination DNS resolver configuration.
    DnsResolver,
    /// Destination host listener address/port allocation.
    Listener,
    /// Public trust material supplied by the destination.
    Certificate,
    /// Compatible TLS interception identity including private material kept outside the artifact.
    TlsIdentity,
    /// Destination proxy endpoint, separate from its credentials.
    ProxyEndpoint,
    /// Destination proxy authentication, never a URL with embedded credentials.
    ProxyCredentials,
    /// One ordinary host file exported through the runtime filesystem share.
    FilesystemFile,
    /// A host directory tree exported through the runtime filesystem share.
    FilesystemDirectory,
    /// A destination named directory volume, without source-name fallback.
    NamedDirectory,
    /// A destination named disk volume.
    NamedDisk,
    /// An external disk-image file with separately validated format/layout.
    DiskImage,
    /// A destination stream socket or supported local pipe.
    StreamSocket,
    /// A destination datagram socket.
    DatagramSocket,
}

/// All consumers implied by the saved fields. These are not archive-selected activation timing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SavedBindingConsumer {
    /// Additional init inputs on a cold boot, not full resume of captured PID 1.
    BootInit,
    /// Defaults for a new command; immediate for run, potentially deferred for create.
    NewCommand,
    /// Files needed to materialize registered scripts; full captured handles need further proof.
    ScriptBacking,
    /// Host gateway policy before guest traffic, including captured secret placeholders.
    Gateway,
    /// Guest trust before cold boot; full resume must validate captured trust compatibility.
    GuestTrust,
    /// Destination host listener before guest activation.
    Listener,
    /// External guest mount backing before activation, with full-state identity checks.
    Mount,
    /// Guest-to-host IPC route before activation.
    Vsock,
}

/// One logical binding can have several consumers, but exactly one destination value shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedBindingUse {
    /// Expected shape derived from every referencing field.
    pub kind: SavedBindingKind,
    /// Union of consumers; a future-command use cannot weaken a gateway/init requirement.
    pub consumers: BTreeSet<SavedBindingConsumer>,
}

/// Requirements derived from the selected configuration, not a readiness authorization.
pub type SavedBindingUses = BTreeMap<String, SavedBindingUse>;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Validate a complete runtime/network binding inventory without loading destination values.
///
/// The resolver must call this again on its selected effective settings after mode,
/// clears and overrides. Import/inspect can call it on the recorded settings without
/// asking for credentials. Every used ID must be declared with a compatible shape;
/// unused inventory entries are rejected rather than becoming hidden requirements.
pub fn validate_binding_inventory(
    runtime: &SavedRuntimeConfig,
    network: &SavedNetworkConfig,
    inventory: &BTreeMap<String, SavedBindingKind>,
) -> SnapshotManifestResult<SavedBindingUses> {
    let uses = collect_binding_uses(runtime, network)?;
    validate_inventory_uses(&uses, inventory)?;
    Ok(uses)
}

/// Collect potential consumers; false/disabled saved settings do not silently erase references.
/// Whether a consumer runs is determined later by the selected operation and destination policy.
pub fn collect_binding_uses(
    runtime: &SavedRuntimeConfig,
    network: &SavedNetworkConfig,
) -> SnapshotManifestResult<SavedBindingUses> {
    let mut uses = BTreeMap::new();
    for (id, consumers) in runtime.binding_requirements()? {
        for consumer in consumers {
            let consumer = match consumer {
                RuntimeBindingConsumer::BootInit => SavedBindingConsumer::BootInit,
                RuntimeBindingConsumer::NewCommand => SavedBindingConsumer::NewCommand,
                RuntimeBindingConsumer::ScriptBacking => SavedBindingConsumer::ScriptBacking,
            };
            record(&mut uses, &id, SavedBindingKind::Text, consumer)?;
        }
    }
    network.validate()?;
    // Exhaustive destructuring makes every future network field an explicit
    // binding-policy decision, instead of silently omitting a new consumer.
    let SavedNetworkConfig {
        enabled: _,
        policy: _,
        strict: _,
        dns,
        tls,
        secrets,
        max_tcp_connections: _,
        max_inbound_tcp_connections: _,
        max_udp_connections: _,
        tcp_accept_queue_size: _,
        rate_limiter: _,
        nat64_prefixes: _,
        ports,
        guest_trust,
        http: _,
        outbound_proxy,
    } = network;
    if let Some(dns) = dns.as_ref().and_then(SavedValue::value) {
        for resolver in &dns.resolvers {
            record(
                &mut uses,
                &resolver.id,
                SavedBindingKind::DnsResolver,
                SavedBindingConsumer::Gateway,
            )?;
        }
    }
    if let Some(tls) = tls.as_ref().and_then(SavedValue::value) {
        for ca in tls
            .upstream_cas
            .iter()
            .chain(tls.scoped_upstream_cas.iter().map(|scoped| &scoped.binding))
        {
            record(
                &mut uses,
                &ca.id,
                SavedBindingKind::Certificate,
                SavedBindingConsumer::Gateway,
            )?;
        }
        if let Some(ca) = &tls.intercept_ca {
            record(
                &mut uses,
                &ca.id,
                SavedBindingKind::TlsIdentity,
                SavedBindingConsumer::Gateway,
            )?;
        }
    }
    if let Some(secrets) = secrets.as_ref().and_then(SavedValue::value) {
        for secret in &secrets.entries {
            record(
                &mut uses,
                &secret.binding.id,
                SavedBindingKind::Text,
                SavedBindingConsumer::Gateway,
            )?;
        }
    }
    if let Some(ports) = ports.as_ref().and_then(SavedValue::value) {
        for port in ports {
            record(
                &mut uses,
                &port.binding.id,
                SavedBindingKind::Listener,
                SavedBindingConsumer::Listener,
            )?;
        }
    }
    if let Some(trust) = guest_trust.as_ref().and_then(SavedValue::value) {
        for ca in trust {
            record(
                &mut uses,
                &ca.id,
                SavedBindingKind::Certificate,
                SavedBindingConsumer::GuestTrust,
            )?;
        }
    }
    if let Some(proxy) = outbound_proxy.as_ref().and_then(SavedValue::value) {
        record(
            &mut uses,
            &proxy.endpoint.id,
            SavedBindingKind::ProxyEndpoint,
            SavedBindingConsumer::Gateway,
        )?;
        if let Some(credentials) = &proxy.credentials {
            record(
                &mut uses,
                &credentials.id,
                SavedBindingKind::ProxyCredentials,
                SavedBindingConsumer::Gateway,
            )?;
        }
    }
    count(uses.len(), "bindings")?;
    Ok(uses)
}

pub(super) fn validate_inventory_uses(
    uses: &SavedBindingUses,
    inventory: &BTreeMap<String, SavedBindingKind>,
) -> SnapshotManifestResult<()> {
    count(inventory.len(), "bindings")?;
    for id in inventory.keys() {
        binding(id, "bindings")?;
    }
    for (id, usage) in uses {
        match inventory.get(id) {
            Some(kind) if *kind == usage.kind => {}
            Some(_) => {
                return invalid(
                    "SCFG_BINDING",
                    "bindings",
                    "declared binding kind conflicts with its use",
                );
            }
            None => {
                return invalid(
                    "SCFG_BINDING",
                    "bindings",
                    "referenced binding is not declared",
                );
            }
        }
    }
    if inventory.keys().any(|id| !uses.contains_key(id)) {
        return invalid(
            "SCFG_BINDING",
            "bindings",
            "inventory contains an unreferenced binding",
        );
    }
    Ok(())
}

pub(super) fn merge_binding_uses(
    into: &mut SavedBindingUses,
    from: SavedBindingUses,
) -> SnapshotManifestResult<()> {
    for (id, usage) in from {
        for consumer in usage.consumers {
            record(into, &id, usage.kind, consumer)?;
        }
    }
    Ok(())
}

pub(super) fn record(
    uses: &mut SavedBindingUses,
    id: &str,
    kind: SavedBindingKind,
    consumer: SavedBindingConsumer,
) -> SnapshotManifestResult<()> {
    let usage = uses
        .entry(id.to_owned())
        .or_insert_with(|| SavedBindingUse {
            kind,
            consumers: BTreeSet::new(),
        });
    if usage.kind != kind {
        return invalid(
            "SCFG_BINDING",
            "bindings",
            "one binding is used with incompatible destination kinds",
        );
    }
    usage.consumers.insert(consumer);
    Ok(())
}
