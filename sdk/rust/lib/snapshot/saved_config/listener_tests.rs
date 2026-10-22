//! A guest service is not a unique host-listener identity.

use std::collections::BTreeMap;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedBindingReference, SavedOrigin, SavedPublishedPort,
    SavedUnknownReason, SavedValue,
};
use microsandbox_types::{NetworkSpec, PortProtocol, PublishedPortSpec};

use super::{
    BindingDemandContext, ListenerBindingInput, plan_binding_demand,
    prepare_listener_configuration, select_listener_inputs,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn saved(values: &[(&str, u16, PortProtocol)]) -> SavedValue<Vec<SavedPublishedPort>> {
    SavedValue::Value {
        value: values
            .iter()
            .map(|(id, port, protocol)| SavedPublishedPort {
                guest_port: *port,
                protocol: *protocol,
                binding: SavedBindingReference { id: (*id).into() },
            })
            .collect(),
        origin: SavedOrigin::Configured,
    }
}

fn port(host: u16, guest: u16, protocol: PortProtocol) -> PublishedPortSpec {
    PublishedPortSpec {
        host_bind: "127.0.0.1".into(),
        host_port: host,
        guest_port: guest,
        protocol,
    }
}

fn binding(host_port: u16) -> ListenerBindingInput {
    ListenerBindingInput {
        host_bind: "127.0.0.1".parse().unwrap(),
        host_port,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn preparation_preserves_shared_tcp_udp_ephemeral_listeners_and_full_obligations() {
    let source = saved(&[
        ("shared", 80, PortProtocol::Tcp),
        ("shared", 53, PortProtocol::Udp),
    ]);
    let before = serde_json::to_vec(&source).unwrap();
    let plan = prepare_listener_configuration(
        Some(&source),
        &[],
        &BTreeMap::from([("shared".into(), binding(0))]),
        true,
    )
    .unwrap();
    let mut network = NetworkSpec::default();
    network.strict = false;
    plan.apply_to(&mut network).unwrap();
    assert_eq!(network.ports.len(), 2);
    assert_eq!(network.ports[0].host_port, 0);
    assert_eq!(network.ports[1].host_port, 0);
    assert_eq!(network.ports[0].protocol, PortProtocol::Tcp);
    assert_eq!(network.ports[1].protocol, PortProtocol::Udp);
    assert!(!network.strict);
    assert!(plan.selection().requires_full_compatibility);
    assert_eq!(serde_json::to_vec(&source).unwrap(), before);
    assert!(!format!("{plan:?}").contains("127.0.0.1"));
}

#[test]
fn preparation_cannot_drop_an_unsupplied_shared_listener_consumer() {
    let source = saved(&[
        ("shared", 80, PortProtocol::Tcp),
        ("shared", 53, PortProtocol::Udp),
    ]);
    let error = prepare_listener_configuration(
        Some(&source),
        &[port(8080, 80, PortProtocol::Tcp)],
        &BTreeMap::new(),
        false,
    )
    .unwrap_err();
    assert!(error.to_string().contains("SCFG_BINDING"));
    assert!(!error.to_string().contains("shared"));
    assert!(prepare_listener_configuration(Some(&source), &[], &BTreeMap::new(), false).is_err());
}

#[test]
fn unknown_listener_inventory_cannot_partially_overwrite_network() {
    let source = SavedValue::Unknown {
        reason: SavedUnknownReason::NotObserved,
    };
    for saved in [None, Some(&source)] {
        let plan = prepare_listener_configuration(
            saved,
            &[port(8080, 80, PortProtocol::Tcp)],
            &BTreeMap::new(),
            false,
        )
        .unwrap();
        let mut network = NetworkSpec::default();
        network.ports.push(port(9090, 90, PortProtocol::Tcp));
        network.strict = false;
        let before = serde_json::to_vec(&network).unwrap();
        assert!(
            plan.apply_to(&mut network)
                .unwrap_err()
                .to_string()
                .contains("SCFG_UNKNOWN")
        );
        assert_eq!(serde_json::to_vec(&network).unwrap(), before);
    }
}

#[test]
fn known_empty_listener_inventory_replaces_lower_ports_without_changing_policy() {
    let source = SavedValue::Default {};
    let plan = prepare_listener_configuration(Some(&source), &[], &BTreeMap::new(), false).unwrap();
    let mut network = NetworkSpec::default();
    network.ports.push(port(9090, 90, PortProtocol::Tcp));
    network.strict = false;
    plan.apply_to(&mut network).unwrap();
    assert!(network.ports.is_empty());
    assert!(!network.strict);
    assert!(plan.selection().source_defaulted);
}

#[test]
fn one_native_mapping_preserves_other_services_and_shared_transport_requirements() {
    let source = saved(&[
        ("shared", 80, PortProtocol::Tcp),
        ("shared", 53, PortProtocol::Udp),
    ]);
    let before = serde_json::to_vec(&source).unwrap();
    let plan = select_listener_inputs(
        Some(&source),
        &[port(8080, 80, PortProtocol::Tcp)],
        &BTreeMap::new(),
        false,
    )
    .unwrap();
    assert!(plan.entries[0].destination.is_some());
    assert!(plan.entries[1].destination.is_none());
    assert!(plan.remaining_bindings.contains_key("shared"));
    assert_eq!(serde_json::to_vec(&source).unwrap(), before);
    let plan = select_listener_inputs(
        Some(&source),
        &[
            port(8080, 80, PortProtocol::Tcp),
            port(5353, 53, PortProtocol::Udp),
        ],
        &BTreeMap::new(),
        false,
    )
    .unwrap();
    assert!(plan.remaining_bindings.is_empty());
}

#[test]
fn logical_bindings_preserve_distinct_listeners_for_the_same_guest_service() {
    let source = saved(&[
        ("private", 80, PortProtocol::Tcp),
        ("public", 80, PortProtocol::Tcp),
    ]);
    let ambiguous = select_listener_inputs(
        Some(&source),
        &[port(8080, 80, PortProtocol::Tcp)],
        &BTreeMap::new(),
        false,
    )
    .unwrap_err();
    assert!(ambiguous.to_string().contains("SCFG_BINDING"));
    assert!(ambiguous.to_string().contains("logical listener bindings"));
    let plan = select_listener_inputs(
        Some(&source),
        &[],
        &BTreeMap::from([
            ("private".into(), binding(8080)),
            ("public".into(), binding(9090)),
        ]),
        false,
    )
    .unwrap();
    assert_eq!(plan.entries.len(), 2);
    assert!(plan.remaining_bindings.is_empty());
    assert_eq!(
        plan.entries
            .iter()
            .map(|e| e.destination.as_ref().unwrap().host_port)
            .collect::<Vec<_>>(),
        [8080, 9090]
    );
}

#[test]
fn partial_logical_mapping_leaves_one_unambiguous_native_match() {
    let source = saved(&[
        ("private", 80, PortProtocol::Tcp),
        ("public", 80, PortProtocol::Tcp),
    ]);
    let plan = select_listener_inputs(
        Some(&source),
        &[port(9090, 80, PortProtocol::Tcp)],
        &BTreeMap::from([("private".into(), binding(8080))]),
        false,
    )
    .unwrap();
    assert_eq!(plan.entries.len(), 2);
    assert!(plan.remaining_bindings.is_empty());
    assert_eq!(
        plan.entries[0].destination.as_ref().unwrap().host_port,
        8080
    );
    assert_eq!(
        plan.entries[1].destination.as_ref().unwrap().host_port,
        9090
    );
}

#[test]
fn multiple_native_candidates_cannot_choose_a_saved_binding_by_input_order() {
    let source = saved(&[("one", 80, PortProtocol::Tcp)]);
    for inputs in [
        vec![
            port(8080, 80, PortProtocol::Tcp),
            port(9090, 80, PortProtocol::Tcp),
        ],
        vec![
            port(9090, 80, PortProtocol::Tcp),
            port(8080, 80, PortProtocol::Tcp),
        ],
    ] {
        assert!(
            select_listener_inputs(Some(&source), &inputs, &BTreeMap::new(), false)
                .unwrap_err()
                .to_string()
                .contains("ambiguous")
        );
    }
    // Once the required identity is bound explicitly, extra listeners need no guessing.
    let plan = select_listener_inputs(
        Some(&source),
        &[port(9090, 80, PortProtocol::Tcp)],
        &BTreeMap::from([("one".into(), binding(8080))]),
        false,
    )
    .unwrap();
    assert_eq!(plan.entries.len(), 2);
    assert!(plan.entries[1].saved.is_none());
}

#[test]
fn one_binding_can_supply_independent_tcp_and_udp_namespaces() {
    let source = saved(&[
        ("shared", 53, PortProtocol::Tcp),
        ("shared", 53, PortProtocol::Udp),
    ]);
    let plan = select_listener_inputs(
        Some(&source),
        &[],
        &BTreeMap::from([("shared".into(), binding(5353))]),
        true,
    )
    .unwrap();
    assert_eq!(plan.entries.len(), 2);
    assert!(plan.remaining_bindings.is_empty());
    assert!(plan.requires_full_compatibility);
}

#[test]
fn empty_inputs_keep_requirements_and_unknown_or_default_states_stay_distinct() {
    let source = saved(&[("one", 80, PortProtocol::Tcp)]);
    let plan = select_listener_inputs(Some(&source), &[], &BTreeMap::new(), false).unwrap();
    assert_eq!(plan.entries.len(), 1);
    assert!(plan.remaining_bindings.contains_key("one"));
    let unknown = SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    };
    let default = SavedValue::Default {};
    let empty = saved(&[]);
    for (source, unknown, defaulted) in [
        (None, true, false),
        (Some(&unknown), true, false),
        (Some(&default), false, true),
        (Some(&empty), false, false),
    ] {
        let plan = select_listener_inputs(
            source,
            &[port(8080, 80, PortProtocol::Tcp)],
            &BTreeMap::new(),
            true,
        )
        .unwrap();
        assert_eq!(plan.source_unknown, unknown);
        assert_eq!(plan.source_defaulted, defaulted);
        assert!(plan.requires_full_compatibility);
    }
}

#[test]
fn destination_collisions_include_logical_and_native_inputs_and_normalized_ipv6() {
    let source = saved(&[("one", 80, PortProtocol::Tcp)]);
    let err = select_listener_inputs(
        Some(&source),
        &[port(8080, 81, PortProtocol::Tcp)],
        &BTreeMap::from([("one".into(), binding(8080))]),
        false,
    )
    .unwrap_err();
    assert!(err.to_string().contains("SCFG_IDENTITY"));
    let mut a = port(8080, 80, PortProtocol::Tcp);
    a.host_bind = "::1".into();
    let mut b = port(8080, 81, PortProtocol::Tcp);
    b.host_bind = "0:0:0:0:0:0:0:1".into();
    assert!(
        select_listener_inputs(None, &[a, b], &BTreeMap::new(), false)
            .unwrap_err()
            .to_string()
            .contains("SCFG_IDENTITY")
    );
    let plan = select_listener_inputs(
        None,
        &[
            port(0, 80, PortProtocol::Tcp),
            port(0, 81, PortProtocol::Tcp),
        ],
        &BTreeMap::new(),
        false,
    )
    .unwrap();
    assert_eq!(plan.entries.len(), 2);
}

#[test]
fn source_validation_precedes_overrides_and_unknown_binding_ids_refuse() {
    let malformed = saved(&[
        ("one", 80, PortProtocol::Tcp),
        ("one", 81, PortProtocol::Tcp),
    ]);
    assert!(
        select_listener_inputs(
            Some(&malformed),
            &[],
            &BTreeMap::from([("one".into(), binding(8080))]),
            false
        )
        .unwrap_err()
        .to_string()
        .contains("SCFG_VALUE")
    );
    for id in ["unknown", "invalid/id"] {
        let err = select_listener_inputs(
            None,
            &[],
            &BTreeMap::from([(id.into(), binding(8080))]),
            false,
        )
        .unwrap_err();
        assert!(err.to_string().contains("SCFG_BINDING"));
        assert!(!err.to_string().contains(id));
    }
}

#[test]
fn addresses_are_not_resolved_and_diagnostics_do_not_expose_bindings() {
    let mut input = port(8080, 80, PortProtocol::Tcp);
    input.host_bind = "PRIVATE_ENDPOINT_SENTINEL.invalid".into();
    let err = select_listener_inputs(None, &[input], &BTreeMap::new(), false).unwrap_err();
    assert!(!err.to_string().contains("SENTINEL"));
    let source = saved(&[("PRIVATE_ID_SENTINEL", 80, PortProtocol::Tcp)]);
    let input = binding(8080);
    let plan = select_listener_inputs(
        Some(&source),
        &[],
        &BTreeMap::from([("PRIVATE_ID_SENTINEL".into(), input.clone())]),
        false,
    )
    .unwrap();
    let text = format!("{plan:?} {:?} {input:?}", plan.entries);
    assert!(!text.contains("SENTINEL"));
    assert!(!text.contains("127.0.0.1"));
    assert!(!text.contains("8080"));
}

#[test]
fn supplying_selected_listener_defaults_does_not_erase_captured_requirements() {
    let source = saved(&[("one", 80, PortProtocol::Tcp)]);
    let captured = select_listener_inputs(Some(&source), &[], &BTreeMap::new(), true)
        .unwrap()
        .remaining_bindings;
    let selected = select_listener_inputs(
        Some(&source),
        &[port(8080, 80, PortProtocol::Tcp)],
        &BTreeMap::new(),
        true,
    )
    .unwrap();
    assert!(selected.remaining_bindings.is_empty());
    let demand = plan_binding_demand(
        &selected.remaining_bindings,
        Some(&captured),
        BindingDemandContext {
            full_resume: true,
            starts_command: false,
        },
    )
    .unwrap();
    assert!(demand.bindings()["one"].required_now);
    assert!(demand.bindings()["one"].captured_execution);
}

#[test]
fn oversized_destination_and_combined_listener_sets_refuse() {
    let source = saved(&[("one", 80, PortProtocol::Tcp)]);
    let inputs: Vec<_> = (0..=MAX_SAVED_CONFIG_ENTRIES)
        .map(|i| port(0, (1000 + i) as u16, PortProtocol::Tcp))
        .collect();
    for (source, inputs) in [
        (None, inputs.as_slice()),
        (Some(&source), &inputs[..MAX_SAVED_CONFIG_ENTRIES]),
    ] {
        assert!(
            select_listener_inputs(source, inputs, &BTreeMap::new(), false)
                .unwrap_err()
                .to_string()
                .contains("SCFG_LIMIT")
        );
    }
}
