//! Timing tests use both derived portable requirements and adversarial direct construction.

use std::collections::{BTreeMap, BTreeSet};

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedBindingConsumer as Consumer, SavedBindingKind as Kind,
    SavedBindingUse, SavedBindingUses, SavedNetworkConfig, SavedRuntimeConfig,
    collect_binding_uses,
};

use super::{BindingDemandContext, plan_binding_demand};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn uses(id: &str, kind: Kind, consumers: &[Consumer]) -> SavedBindingUses {
    BTreeMap::from([(
        id.to_owned(),
        SavedBindingUse {
            kind,
            consumers: consumers.iter().copied().collect(),
        },
    )])
}

fn context(full_resume: bool, starts_command: bool) -> BindingDemandContext {
    BindingDemandContext {
        full_resume,
        starts_command,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn every_consumer_has_explicit_disk_create_run_and_full_timing() {
    let cases = [
        (Consumer::BootInit, Kind::Text, true, true, false),
        (Consumer::NewCommand, Kind::Text, false, true, false),
        (Consumer::ScriptBacking, Kind::Text, true, true, true),
        (Consumer::Gateway, Kind::ProxyCredentials, true, true, true),
        (Consumer::GuestTrust, Kind::Certificate, true, true, true),
        (Consumer::Listener, Kind::Listener, true, true, true),
        (Consumer::Mount, Kind::NamedDisk, true, true, true),
        (Consumer::Vsock, Kind::StreamSocket, true, true, true),
    ];
    for (consumer, kind, create, run, full) in cases {
        let selected = uses("binding", kind, &[consumer]);
        let empty = BTreeMap::new();
        for (ctx, immediate) in [
            (context(false, false), create),
            (context(false, true), run),
            (context(true, false), full),
        ] {
            let plan =
                plan_binding_demand(&selected, ctx.full_resume.then_some(&empty), ctx).unwrap();
            assert_eq!(
                plan.bindings()["binding"].required_now,
                immediate,
                "{consumer:?} {ctx:?}"
            );
            let gaps = plan.supply_gaps(&BTreeMap::new()).unwrap();
            assert_eq!(gaps.immediate.contains("binding"), immediate);
            assert_eq!(
                gaps.before_new_command.contains("binding"),
                consumer == Consumer::NewCommand
            );
            assert_eq!(
                gaps.before_cold_boot.contains("binding"),
                consumer == Consumer::BootInit
            );
        }
    }
}

#[test]
fn derived_gateway_use_promotes_shared_future_command_secret() {
    let runtime = SavedRuntimeConfig::from_bytes(
        br#"{
        "env":{"state":"value","origin":"configured","value":{
            "TOKEN":{"kind":"binding","id":"shared"},
            "LATER":{"kind":"binding","id":"later"}
        }}
    }"#,
    )
    .unwrap();
    let network = SavedNetworkConfig::from_bytes(
        br#"{
        "outbound_proxy":{"state":"value","origin":"configured","value":{
            "protocol":"socks5","endpoint":{"id":"proxy"},"credentials":{"id":"auth"}
        }},
        "secrets":{"state":"value","origin":"configured","value":{
            "violation_action":"block-and-log", "entries":[{
                "env_var":"TOKEN", "binding":{"id":"shared"}, "placeholder":"$MSB_TOKEN",
                "allowed_hosts":[{"exact":"api.example.com"}],
                "substitution":{"headers":true,"header_fields":["Authorization"],"query":false,"body":false},
                "passthrough_hosts":[], "require_tls_identity":true
            }]
        }}
    }"#,
    )
    .unwrap();
    let selected = collect_binding_uses(&runtime, &network).unwrap();
    let plan = plan_binding_demand(&selected, None, context(false, false)).unwrap();
    let gaps = plan.supply_gaps(&BTreeMap::new()).unwrap();
    assert_eq!(
        gaps.immediate,
        BTreeSet::from(["shared".into(), "proxy".into(), "auth".into()])
    );
    assert_eq!(
        gaps.before_new_command,
        BTreeSet::from(["shared".into(), "later".into()])
    );
}

#[test]
fn captured_evidence_survives_cleared_or_fresh_command_defaults() {
    let captured = uses("captured", Kind::Text, &[Consumer::NewCommand]);
    let empty = BTreeMap::new();
    let plan = plan_binding_demand(&empty, Some(&captured), context(true, false)).unwrap();
    let demand = &plan.bindings()["captured"];
    assert!(demand.required_now && demand.captured_execution);
    assert!(
        plan.supply_gaps(&BTreeMap::new())
            .unwrap()
            .immediate
            .contains("captured")
    );
}

#[test]
fn matching_captured_and_selected_bindings_union_every_consumer() {
    let selected = uses(
        "shared",
        Kind::Text,
        &[Consumer::BootInit, Consumer::NewCommand],
    );
    let captured = uses("shared", Kind::Text, &[Consumer::ScriptBacking]);
    let plan = plan_binding_demand(&selected, Some(&captured), context(true, false)).unwrap();
    assert_eq!(plan.bindings().len(), 1);
    let demand = &plan.bindings()["shared"];
    assert!(demand.required_now && demand.captured_execution);
    assert_eq!(
        demand.consumers,
        BTreeSet::from([
            Consumer::BootInit,
            Consumer::NewCommand,
            Consumer::ScriptBacking
        ])
    );
}

#[test]
fn unknown_captured_inventory_is_not_an_empty_inventory() {
    let empty = BTreeMap::new();
    assert!(plan_binding_demand(&empty, None, context(true, false)).is_err());
    assert!(plan_binding_demand(&empty, Some(&empty), context(true, false)).is_ok());
    assert!(plan_binding_demand(&empty, Some(&empty), context(false, false)).is_err());
    assert!(plan_binding_demand(&empty, Some(&empty), context(true, true)).is_err());
}

#[test]
fn captured_and_selected_kind_collision_is_refused_before_supply() {
    let selected = uses("shared", Kind::Text, &[Consumer::NewCommand]);
    let captured = uses("shared", Kind::ProxyCredentials, &[Consumer::Gateway]);
    assert!(
        plan_binding_demand(&selected, Some(&captured), context(true, false))
            .unwrap_err()
            .to_string()
            .contains("kinds conflict")
    );
}

#[test]
fn supplied_values_do_not_erase_future_requirements_or_resolve_sibling_ids() {
    let mut selected = uses(
        "shared",
        Kind::Text,
        &[Consumer::BootInit, Consumer::NewCommand],
    );
    selected.extend(uses("other", Kind::Text, &[Consumer::NewCommand]));
    let plan = plan_binding_demand(&selected, None, context(false, false)).unwrap();
    let before = plan.clone();
    let supplied = BTreeMap::from([("shared".into(), Kind::Text)]);
    let gaps = plan.supply_gaps(&supplied).unwrap();
    assert!(gaps.immediate.is_empty());
    assert_eq!(gaps.before_new_command, BTreeSet::from(["other".into()]));
    assert_eq!(plan, before);
    assert!(
        plan.supply_gaps(&BTreeMap::new())
            .unwrap()
            .immediate
            .contains("shared")
    );
}

#[test]
fn missing_or_wrong_destination_shapes_remain_actionable_and_redacted() {
    let selected = uses("SENTINEL", Kind::Certificate, &[Consumer::GuestTrust]);
    let plan = plan_binding_demand(&selected, None, context(false, false)).unwrap();
    for supplied in [
        BTreeMap::from([("SENTINEL".into(), Kind::Text)]),
        BTreeMap::from([("SENTINEL_WRONG_ID".into(), Kind::Certificate)]),
    ] {
        let message = plan.supply_gaps(&supplied).unwrap_err().to_string();
        assert!(message.contains("SCFG_BINDING"));
        assert!(!message.contains("SENTINEL"));
    }
    let gaps = plan.supply_gaps(&BTreeMap::new()).unwrap();
    assert!(gaps.immediate.contains("SENTINEL"));
    assert!(!format!("{plan:?} {gaps:?}").contains("SENTINEL"));
}

#[test]
fn direct_maps_cannot_bypass_logical_id_and_consumer_validation() {
    for id in ["", "SENTINEL/host/path", "SENTINEL\0", &"x".repeat(129)] {
        let selected = uses(id, Kind::Text, &[Consumer::NewCommand]);
        let message = plan_binding_demand(&selected, None, context(false, false))
            .unwrap_err()
            .to_string();
        assert!(message.contains("SCFG_BINDING"));
        assert!(!message.contains("SENTINEL"));
    }
    for selected in [
        uses("binding", Kind::Text, &[]),
        uses("binding", Kind::Text, &[Consumer::Mount]),
        uses("binding", Kind::Listener, &[Consumer::NewCommand]),
    ] {
        assert!(plan_binding_demand(&selected, None, context(false, false)).is_err());
    }
}

#[test]
fn combined_inventory_and_supply_are_bounded() {
    let selected = (0..MAX_SAVED_CONFIG_ENTRIES)
        .map(|i| {
            (
                format!("binding-{i}"),
                SavedBindingUse {
                    kind: Kind::Text,
                    consumers: BTreeSet::from([Consumer::NewCommand]),
                },
            )
        })
        .collect();
    let plan = plan_binding_demand(&selected, None, context(false, false)).unwrap();
    assert_eq!(plan.bindings().len(), MAX_SAVED_CONFIG_ENTRIES);
    let captured = uses("one-more", Kind::Text, &[Consumer::BootInit]);
    assert!(plan_binding_demand(&selected, Some(&captured), context(true, false)).is_err());
    let supplied = (0..=MAX_SAVED_CONFIG_ENTRIES)
        .map(|i| (format!("binding-{i}"), Kind::Text))
        .collect();
    assert!(
        plan.supply_gaps(&supplied)
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
}
