//! Select destination listeners without opening sockets or transferring source-host ownership.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::IpAddr;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedBindingReference, SavedBindingUses, SavedNetworkConfig,
    SavedPublishedPort, SavedRuntimeConfig, SavedValue, collect_binding_uses,
};
use microsandbox_types::{NetworkSpec, PortProtocol, PublishedPortSpec};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Destination-owned address for a logical listener. Transport and guest service come from
/// the selected requirement, so one binding can supply independent TCP and UDP listeners.
#[derive(Clone)]
pub struct ListenerBindingInput {
    /// Literal destination IP, with no hostname lookup or source-host fallback.
    pub host_bind: IpAddr,
    /// Destination port; zero retains the native ephemeral-allocation meaning.
    pub host_port: u16,
}

/// One saved requirement or explicit additional listener, still awaiting socket admission.
#[derive(Clone)]
pub struct ListenerInputSelection {
    /// Recorded logical identity and guest service, if known.
    pub saved: Option<SavedPublishedPort>,
    /// Explicit destination address, never copied to portable metadata.
    pub destination: Option<PublishedPortSpec>,
}

/// Keyed listener selection only. Bind success, destination policy and captured connections
/// must be checked before traffic or guest execution; this is not an activation permit.
pub struct ListenerInputPlan {
    /// Every surviving source listener and explicit additional destination listener.
    pub entries: Vec<ListenerInputSelection>,
    /// Logical requirements not supplied for every referencing listener/transport.
    pub remaining_bindings: SavedBindingUses,
    /// An omitted/unknown source list is not a checked empty captured inventory.
    pub source_unknown: bool,
    /// A recorded builtin default is distinct from unrecorded metadata.
    pub source_defaulted: bool,
    /// Full resume requires authoritative NIC/connection checks beyond port matching.
    pub requires_full_compatibility: bool,
}

/// Complete native listener inputs with immutable admission obligations. No sockets are opened.
pub struct ListenerConfigurationPlan {
    ports: Vec<PublishedPortSpec>,
    selection: ListenerInputPlan,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ListenerConfigurationPlan {
    /// Keep source completeness and full-state connection/NIC obligations.
    pub fn selection(&self) -> &ListenerInputPlan {
        &self.selection
    }

    /// Replace only the listener inventory. Unknown source observations refuse before
    /// mutation; socket allocation, mandatory policy and captured connections remain gates.
    pub fn apply_to(&self, network: &mut NetworkSpec) -> MicrosandboxResult<()> {
        if self.selection.source_unknown {
            return Err(error("SCFG_UNKNOWN", "listener inventory needs resolution"));
        }
        network.ports.clone_from(&self.ports);
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for ListenerBindingInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerBindingInput")
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ListenerInputSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerInputSelection")
            .field("has_saved", &self.saved.is_some())
            .field("has_destination", &self.destination.is_some())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ListenerInputPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerInputPlan")
            .field("entry_count", &self.entries.len())
            .field("binding_count", &self.remaining_bindings.len())
            .field("source_unknown", &self.source_unknown)
            .field("source_defaulted", &self.source_defaulted)
            .field(
                "requires_full_compatibility",
                &self.requires_full_compatibility,
            )
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for ListenerConfigurationPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListenerConfigurationPlan")
            .field("selection", &self.selection)
            .finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Prepare all selected listener bindings as immediate destination inputs. A missing saved
/// listener cannot silently disappear, and supplying an address does not prove bind success.
pub fn prepare_listener_configuration(
    saved: Option<&SavedValue<Vec<SavedPublishedPort>>>,
    explicit: &[PublishedPortSpec],
    bindings: &BTreeMap<String, ListenerBindingInput>,
    full_resume: bool,
) -> MicrosandboxResult<ListenerConfigurationPlan> {
    let selection = select_listener_inputs(saved, explicit, bindings, full_resume)?;
    if !selection.remaining_bindings.is_empty() {
        return Err(error(
            "SCFG_BINDING",
            "required listener inputs are missing",
        ));
    }
    let ports = selection
        .entries
        .iter()
        .map(|entry| {
            entry
                .destination
                .clone()
                .ok_or_else(|| error("SCFG_BINDING", "selected listener has no destination"))
        })
        .collect::<MicrosandboxResult<Vec<_>>>()?;
    Ok(ListenerConfigurationPlan { ports, selection })
}

/// Resolve selected listeners by logical identity, using a native port override only when
/// the remaining service/transport match is unambiguous in both inputs. Multiple listeners
/// may target one guest service, so matching only by guest port must never discard entries.
///
/// Optional mode/clear selection precedes this step. Independent captured requirements still
/// join binding demand afterward; empty native collections cannot erase selected listeners.
/// No socket is opened, no source configuration is consulted and no destination IP is saved.
pub fn select_listener_inputs(
    saved: Option<&SavedValue<Vec<SavedPublishedPort>>>,
    explicit: &[PublishedPortSpec],
    bindings: &BTreeMap<String, ListenerBindingInput>,
    full_resume: bool,
) -> MicrosandboxResult<ListenerInputPlan> {
    let mut source = SavedNetworkConfig {
        ports: saved.cloned(),
        ..Default::default()
    };
    source
        .validate()
        .map_err(|_| error("SCFG_VALUE", "invalid saved listener metadata"))?;
    if explicit.len() > MAX_SAVED_CONFIG_ENTRIES || bindings.len() > MAX_SAVED_CONFIG_ENTRIES {
        return Err(error("SCFG_LIMIT", "too many destination listeners"));
    }
    let mut entries: Vec<_> = saved
        .and_then(SavedValue::value)
        .into_iter()
        .flatten()
        .map(|saved| ListenerInputSelection {
            saved: Some(saved.clone()),
            destination: None,
        })
        .collect();
    for (id, input) in bindings {
        SavedBindingReference { id: id.clone() }
            .validate()
            .map_err(|_| error("SCFG_BINDING", "invalid destination listener binding"))?;
        let mut used = false;
        for entry in &mut entries {
            if let Some(saved) = &entry.saved
                && saved.binding.id == *id
            {
                entry.destination = Some(PublishedPortSpec {
                    host_bind: input.host_bind.to_string(),
                    host_port: input.host_port,
                    guest_port: saved.guest_port,
                    protocol: saved.protocol,
                });
                used = true;
            }
        }
        if !used {
            return Err(error(
                "SCFG_BINDING",
                "listener binding has no selected consumer",
            ));
        }
    }
    let mut explicit_services = BTreeMap::new();
    for input in explicit {
        *explicit_services
            .entry(service(input.guest_port, input.protocol))
            .or_insert(0usize) += 1;
    }
    for input in explicit {
        // Parse without resolving hostnames or touching the network. Keep the native input
        // itself unchanged; canonical IP identity is used only to detect exact collisions.
        destination_address(input)?;
        let identity = service(input.guest_port, input.protocol);
        let candidates: Vec<_> = entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| {
                entry
                    .saved
                    .as_ref()
                    .filter(|saved| {
                        entry.destination.is_none()
                            && service(saved.guest_port, saved.protocol) == identity
                    })
                    .map(|_| index)
            })
            .collect();
        if candidates.len() > 1 || (!candidates.is_empty() && explicit_services[&identity] > 1) {
            return Err(error(
                "SCFG_BINDING",
                "ambiguous listener mapping; supply logical listener bindings",
            ));
        }
        if let Some(index) = candidates.first() {
            entries[*index].destination = Some(input.clone());
        } else {
            entries.push(ListenerInputSelection {
                saved: None,
                destination: Some(input.clone()),
            });
        }
    }
    if entries.len() > MAX_SAVED_CONFIG_ENTRIES {
        return Err(error("SCFG_LIMIT", "too many combined listeners"));
    }
    let mut addresses = BTreeSet::new();
    for entry in &entries {
        if let Some(input) = &entry.destination {
            let address = destination_address(input)?;
            // Separate port-zero sockets receive separate allocations; equating zero to an
            // allocated port would incorrectly forbid multiple ephemeral listeners.
            if input.host_port != 0
                && !addresses.insert((address, input.host_port, service(0, input.protocol).1))
            {
                return Err(error(
                    "SCFG_IDENTITY",
                    "conflicting destination listener addresses",
                ));
            }
        }
    }
    if let Some(SavedValue::Value { value, .. }) = &mut source.ports {
        *value = entries
            .iter()
            .filter(|entry| entry.destination.is_none())
            .filter_map(|entry| entry.saved.clone())
            .collect();
    }
    let remaining_bindings = collect_binding_uses(&SavedRuntimeConfig::default(), &source)
        .map_err(|_| error("SCFG_BINDING", "invalid remaining listener requirements"))?;
    Ok(ListenerInputPlan {
        entries,
        remaining_bindings,
        source_unknown: saved.is_none() || matches!(saved, Some(SavedValue::Unknown { .. })),
        source_defaulted: matches!(saved, Some(SavedValue::Default {})),
        requires_full_compatibility: full_resume,
    })
}

fn service(guest_port: u16, protocol: PortProtocol) -> (u16, u8) {
    (
        guest_port,
        match protocol {
            PortProtocol::Tcp => 0,
            PortProtocol::Udp => 1,
        },
    )
}

fn destination_address(input: &PublishedPortSpec) -> MicrosandboxResult<IpAddr> {
    input.host_bind.parse().map_err(|_| {
        error(
            "SCFG_VALUE",
            "listener address must be a literal destination IP",
        )
    })
}

fn error(code: &str, reason: &str) -> MicrosandboxError {
    MicrosandboxError::InvalidConfig(format!("{code}: network.ports: {reason}"))
}
