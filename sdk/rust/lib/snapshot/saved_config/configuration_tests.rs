//! Combined preparation checks cross-family invariants that isolated selectors cannot prove.

use std::{collections::BTreeMap, path::PathBuf};

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_BYTES, SavedBindingConsumer, SavedBindingKind, SavedBindingUse,
    SavedBindingUses, SavedSandboxConfig,
};
use microsandbox_types::{
    DnsConfig, DnsConfigPatch, EnvVar, InterfaceOverrides, InterfaceOverridesPatch,
    NetworkSpecPatch, PortProtocol, PublishedPortSpec, SandboxResources, SandboxResourcesPatch,
    SandboxRuntimeOptionsPatch, SandboxSpec, SandboxSpecPatch, SecretSource, SecretsConfig,
    SecretsConfigPatch, SecurityProfile, TlsConfig, TlsConfigPatch,
};
use serde_json::{Value, json};
use zeroize::Zeroizing;

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn known(value: Value) -> Value {
    json!({"state":"value","origin":"configured","value":value})
}

pub(super) fn document(active: Value, bindings: Value) -> SavedSandboxConfig {
    SavedSandboxConfig::from_bytes(
        &serde_json::to_vec(&json!({
            "schema_version": 1, "active": active, "bindings": bindings,
            "provenance": {"producer_version":"0.8.0",
                "active_generation":{"state":"unknown","reason":"not_observed"}}
        }))
        .unwrap(),
    )
    .unwrap()
}

fn shared() -> SavedSandboxConfig {
    document(
        json!({
            "runtime": {"env": known(json!({"TOKEN":{"kind":"binding","id":"shared"}}))},
            "network": {"secrets": known(json!({
                "entries": [{
                    "env_var":"TOKEN", "binding":{"id":"shared"}, "placeholder":"PLACEHOLDER",
                    "allowed_hosts":["any"],
                "passthrough_hosts":[],
                    "substitution":{"headers":true,"header_fields":["Authorization"],"query":false,"body":false},
                    "require_tls_identity":true
                }],
                "violation_action":"block"
            }))}
        }),
        json!({"shared":"text"}),
    )
}

fn text(value: &str) -> ConfigurationBindingInput {
    ConfigurationBindingInput::Text(RuntimeBindingInput {
        text: Zeroizing::new(value.into()),
        script_mode: None,
    })
}

pub(super) fn prepare(
    saved: &SavedSandboxConfig,
    explicit: &SandboxSpecPatch,
    mode: SnapshotConfigMode,
    context: SavedConfigurationContext<'_>,
    bindings: BTreeMap<String, ConfigurationBindingInput>,
) -> crate::MicrosandboxResult<SavedConfigurationPlan> {
    let full = matches!(context, SavedConfigurationContext::Full { .. });
    let mut lower = SandboxSpec::default();
    lower.env = vec![EnvVar {
        key: "TOKEN".into(),
        value: "LOWER_SENTINEL".into(),
    }];
    let baseline = DestinationNetworkBaseline {
        strict: false,
        tls_enabled: false,
        intercepted_ports: vec![],
    };
    prepare_saved_configuration(
        SavedConfigurationRequest {
            saved,
            manifest: &storage_tests::manifest(full),
            lower: &lower,
            lower_resources: &SandboxResourcesPatch::new(),
            explicit,
            clears: &SavedConfigurationClears::default(),
            mode,
            context,
            guest_security: DestinationGuestSecurity {
                baseline: SecurityProfile::default(),
                minimum: SecurityProfile::default(),
            },
            network_baseline: &baseline,
        },
        bindings,
    )
}

pub(super) fn disk() -> SavedConfigurationContext<'static> {
    SavedConfigurationContext::Disk {
        starts_command: false,
    }
}

fn fails(result: crate::MicrosandboxResult<SavedConfigurationPlan>, code: &str) {
    let error = result.unwrap_err().to_string();
    assert!(error.contains(code), "{error}");
    assert!(!error.contains("SENTINEL"), "{error}");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn one_binding_supplies_identical_command_and_substitution_values_without_mutating_source() {
    let saved = shared();
    let original = serde_json::to_vec(&saved).unwrap();
    let plan = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::from([("shared".into(), text("DESTINATION_SENTINEL"))]),
    )
    .unwrap();
    let command = plan.runtime().command_defaults().unwrap();
    assert_eq!(command.env.len(), 1);
    assert_eq!(command.env[0].value, "DESTINATION_SENTINEL");
    let mut secrets = SecretsConfig::default();
    plan.secrets().apply_to(&mut secrets).unwrap();
    assert_eq!(&*secrets.secrets[0].value, &command.env[0].value);
    let demand = &plan.demand().bindings()["shared"];
    assert!(demand.required_now);
    assert!(demand.consumers.contains(&SavedBindingConsumer::Gateway));
    assert!(demand.consumers.contains(&SavedBindingConsumer::NewCommand));
    assert!(plan.supply_gaps().before_new_command.is_empty());
    assert!(plan.supply_gaps().immediate.is_empty());
    assert_eq!(serde_json::to_vec(&saved).unwrap(), original);
    assert!(!format!("{plan:?} {:?}", plan.bindings()).contains("SENTINEL"));
}

#[test]
fn unresolved_secret_source_cannot_be_used_as_command_text_or_lower_default() {
    let saved = shared();
    let inputs = || {
        BTreeMap::from([(
            "shared".into(),
            ConfigurationBindingInput::TextSource(SecretSource::env("UNAVAILABLE_SENTINEL")),
        )])
    };
    let plan = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        disk(),
        inputs(),
    )
    .unwrap();
    assert!(plan.runtime().command_defaults().is_err());
    assert!(plan.supply_gaps().before_new_command.contains("shared"));
    assert!(plan.unresolved_text_sources().contains("shared"));
    let mut secrets = SecretsConfig::default();
    plan.secrets().apply_to(&mut secrets).unwrap();
    assert!(secrets.secrets[0].value.is_empty());
    assert_eq!(
        secrets.secrets[0].source,
        Some(SecretSource::env("UNAVAILABLE_SENTINEL"))
    );
    fails(
        prepare(
            &saved,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            SavedConfigurationContext::Disk {
                starts_command: true,
            },
            inputs(),
        ),
        "SCFG_BINDING",
    );
    assert!(!format!("{plan:?} {:?}", plan.bindings()).contains("SENTINEL"));
}

#[test]
fn shared_gateway_use_cannot_be_deferred_with_future_command() {
    fails(
        prepare(
            &shared(),
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::new(),
        ),
        "SCFG_BINDING",
    );
    let command_only = document(
        json!({"runtime":{"env":known(json!({"TOKEN":{"kind":"binding","id":"later"}}))}}),
        json!({"later":"text"}),
    );
    let plan = prepare(
        &command_only,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::new(),
    )
    .unwrap();
    assert!(plan.supply_gaps().immediate.is_empty());
    assert!(plan.supply_gaps().before_new_command.contains("later"));
    assert!(plan.runtime().command_defaults().is_err());
}

#[test]
fn explicit_runtime_override_does_not_erase_shared_substitution_requirement() {
    let patch = SandboxSpecPatch::new().env(vec![EnvVar {
        key: "TOKEN".into(),
        value: "EXPLICIT_SENTINEL".into(),
    }]);
    fails(
        prepare(
            &shared(),
            &patch,
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::new(),
        ),
        "SCFG_BINDING",
    );
    let plan = prepare(
        &shared(),
        &patch,
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::from([("shared".into(), text("BOUND_SENTINEL"))]),
    )
    .unwrap();
    assert_eq!(
        plan.runtime().command_defaults().unwrap().env[0].value,
        "EXPLICIT_SENTINEL"
    );
    assert!(
        !plan.demand().bindings()["shared"]
            .consumers
            .contains(&SavedBindingConsumer::NewCommand)
    );
    let mut secrets = SecretsConfig::default();
    plan.secrets().apply_to(&mut secrets).unwrap();
    assert_eq!(&*secrets.secrets[0].value, "BOUND_SENTINEL");
}

#[test]
fn wrong_unused_and_pending_only_bindings_are_rejected_without_disclosing_values() {
    let saved = shared();
    fails(
        prepare(
            &saved,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::from([(
                "shared".into(),
                ConfigurationBindingInput::Gateway(GatewayBindingInput::DnsResolver(
                    "SECRET_SENTINEL".into(),
                )),
            )]),
        ),
        "SCFG_BINDING",
    );
    let mut value = serde_json::to_value(&saved).unwrap();
    value["pending"] = json!({"runtime":{"cmd":known(json!([{"kind":"binding","id":"pending"}]))}});
    value["bindings"]["pending"] = json!("text");
    let saved = SavedSandboxConfig::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
    let plan = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::from([("shared".into(), text("BOUND_SENTINEL"))]),
    )
    .unwrap();
    assert!(!plan.demand().bindings().contains_key("pending"));
    fails(
        prepare(
            &saved,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::from([
                ("shared".into(), text("BOUND_SENTINEL")),
                ("pending".into(), text("PENDING_SENTINEL")),
            ]),
        ),
        "SCFG_BINDING",
    );
}

#[test]
fn malformed_original_document_is_rejected_before_fresh_or_explicit_masking() {
    let mut saved = shared();
    saved
        .bindings
        .insert("shared".into(), SavedBindingKind::DnsResolver);
    fails(
        prepare(
            &saved,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Fresh,
            disk(),
            BTreeMap::new(),
        ),
        "SCFG_SCHEMA",
    );
}

#[test]
fn fresh_discards_optional_command_defaults_but_retains_gateway_requirements() {
    let plan = prepare(
        &shared(),
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Fresh,
        disk(),
        BTreeMap::from([("shared".into(), text("BOUND_SENTINEL"))]),
    )
    .unwrap();
    assert_eq!(
        plan.runtime().command_defaults().unwrap().env[0].value,
        "LOWER_SENTINEL"
    );
    assert!(plan.demand().bindings()["shared"].required_now);
    assert!(
        !plan.demand().bindings()["shared"]
            .consumers
            .contains(&SavedBindingConsumer::NewCommand)
    );
}

#[test]
fn full_fresh_preserves_independent_captured_only_bindings_and_geometry() {
    let saved = document(json!({}), json!({}));
    let captured = SavedBindingUses::from([(
        "captured".into(),
        SavedBindingUse {
            kind: SavedBindingKind::Text,
            consumers: [SavedBindingConsumer::NewCommand].into(),
        },
    )]);
    let geometry = SandboxResources {
        cpus: 4,
        max_cpus: 8,
        memory_mib: 1024,
        max_memory_mib: 2048,
        ..Default::default()
    };
    let context = || SavedConfigurationContext::Full {
        resources: &geometry,
        security: SecurityProfile::default(),
        bindings: &captured,
    };
    fails(
        prepare(
            &saved,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Fresh,
            context(),
            BTreeMap::new(),
        ),
        "SCFG_BINDING",
    );
    let plan = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Fresh,
        context(),
        BTreeMap::from([("captured".into(), text("CAPTURED_SENTINEL"))]),
    )
    .unwrap();
    assert!(plan.demand().bindings()["captured"].required_now);
    assert!(plan.demand().bindings()["captured"].captured_execution);
    assert!(plan.bindings().contains_key("captured"));
    assert!(plan.resources().requires_full_compatibility());
    assert_eq!(plan.resources().resources().unwrap().memory_mib, 1024);
    assert!(plan.runtime().inputs().requires_full_identity);
    assert!(plan.storage().selection().requires_full_identity);
    assert!(plan.gateway().selection().requires_full_compatibility);
}

#[test]
fn listener_bindings_disambiguate_before_explicit_matching_and_retain_demand() {
    let port = |id: &str| json!({"binding":{"id":id},"guest_port":80,"protocol":"tcp"});
    let saved = document(
        json!({"network":{"ports":known(json!([port("one"),port("two")]))}}),
        json!({"one":"listener","two":"listener"}),
    );
    let patch =
        SandboxSpecPatch::new().network(NetworkSpecPatch::new().ports(vec![PublishedPortSpec {
            host_bind: "127.0.0.1".into(),
            host_port: 8082,
            guest_port: 80,
            protocol: PortProtocol::Tcp,
        }]));
    let plan = prepare(
        &saved,
        &patch,
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::from([(
            "one".into(),
            ConfigurationBindingInput::Listener(ListenerBindingInput {
                host_bind: "127.0.0.1".parse().unwrap(),
                host_port: 8081,
            }),
        )]),
    )
    .unwrap();
    assert!(plan.demand().bindings().contains_key("one"));
    assert!(!plan.demand().bindings().contains_key("two"));
    let mut native = microsandbox_types::NetworkSpec::default();
    plan.listeners().apply_to(&mut native).unwrap();
    assert_eq!(
        native.ports.iter().map(|p| p.host_port).collect::<Vec<_>>(),
        [8081, 8082]
    );
}

#[test]
fn registry_is_bounded_before_cloning_shared_values() {
    fails(
        prepare(
            &shared(),
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::from([(
                "shared".into(),
                text(&"x".repeat(MAX_SAVED_CONFIG_BYTES + 1)),
            )]),
        ),
        "SCFG_LIMIT",
    );
}

#[test]
fn late_preparation_failure_cannot_modify_explicit_destination_or_source() {
    let saved = shared();
    let patch = SandboxSpecPatch::new()
        .runtime(SandboxRuntimeOptionsPatch::new().entrypoint(vec!["EXPLICIT_SENTINEL".into()]))
        .resources(SandboxResourcesPatch::new().cpus(4).max_cpus(2));
    let source_bytes = serde_json::to_vec(&saved).unwrap();
    let explicit_before = format!("{patch:?}");
    fails(
        prepare(
            &saved,
            &patch,
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::from([("shared".into(), text("BOUND_SENTINEL"))]),
        ),
        "SCFG_VALUE",
    );
    assert_eq!(serde_json::to_vec(&saved).unwrap(), source_bytes);
    assert_eq!(format!("{patch:?}"), explicit_before);
}

#[test]
fn network_assembly_preserves_absent_and_explicit_empty_containers() {
    let saved = document(
        json!({"network":{
            "dns":{"state":"default"}, "tls":{"state":"default"},
            "secrets":{"state":"default"}, "ports":{"state":"default"},
            "guest_trust":{"state":"default"}, "outbound_proxy":{"state":"default"}
        }}),
        json!({}),
    );
    for explicit_containers in [false, true] {
        let network = if explicit_containers {
            NetworkSpecPatch::new()
                .dns(DnsConfigPatch::new())
                .tls(TlsConfigPatch::new())
                .secrets(SecretsConfigPatch::new())
        } else {
            NetworkSpecPatch::new()
        };
        let plan = prepare(
            &saved,
            &SandboxSpecPatch::new().network(network),
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::new(),
        )
        .unwrap();
        let native = plan.network_inputs().unwrap();
        assert_eq!(native.dns.is_some(), explicit_containers);
        assert_eq!(native.tls.is_some(), explicit_containers);
        assert_eq!(native.secrets.is_some(), explicit_containers);
        assert!(native.ports.is_empty());
        assert!(native.outbound_proxy.is_none());
    }
}

#[test]
fn network_assembly_keeps_policy_resources_and_all_admission_obligations_together() {
    let saved = document(
        json!({"network":{
            "dns":known(json!({"rebind_protection":false,"query_timeout_ms":17,
                "resolvers":[{"id":"resolver"}]})),
            "tls":known(json!({"enabled":true,"intercepted_ports":[443],"bypass":[],
                "verify_upstream":true,"block_quic_on_intercept":true,
                "upstream_cas":[{"id":"ca"}],"scoped_upstream_cas":[],
                "scoped_verify_upstream":[]})),
            "secrets":{"state":"default"},
            "ports":known(json!([{"guest_port":80,"protocol":"tcp","binding":{"id":"listener"}}])),
            "guest_trust":known(json!([{"id":"ca"}])),
            "outbound_proxy":known(json!({"protocol":"http_connect","endpoint":{"id":"proxy"}}))
        }}),
        json!({"resolver":"dns_resolver","ca":"certificate","listener":"listener","proxy":"proxy_endpoint"}),
    );
    let before = serde_json::to_vec(&saved).unwrap();
    let bindings = BTreeMap::from([
        (
            "resolver".into(),
            ConfigurationBindingInput::Gateway(GatewayBindingInput::DnsResolver(
                "DNS_SENTINEL.invalid:5353".into(),
            )),
        ),
        (
            "ca".into(),
            ConfigurationBindingInput::Gateway(GatewayBindingInput::Certificate(
                "/missing/CA_SENTINEL.pem".into(),
            )),
        ),
        (
            "proxy".into(),
            ConfigurationBindingInput::Gateway(GatewayBindingInput::ProxyEndpoint(
                "PROXY_SENTINEL.invalid:3128".into(),
            )),
        ),
        (
            "listener".into(),
            ConfigurationBindingInput::Listener(ListenerBindingInput {
                host_bind: "127.0.0.1".parse().unwrap(),
                host_port: 0,
            }),
        ),
    ]);
    let plan = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        disk(),
        bindings,
    )
    .unwrap();
    let approvals = format!("{:?}", plan.network_policy().selection().required_approvals);
    assert!(
        !plan
            .network_policy()
            .selection()
            .required_approvals
            .is_empty()
    );
    let native = plan.network_inputs().unwrap();
    let dns = native.dns.as_ref().unwrap();
    assert!(!dns.rebind_protection);
    assert_eq!(dns.query_timeout_ms, 17);
    assert_eq!(dns.nameservers, ["DNS_SENTINEL.invalid:5353"]);
    let tls = native.tls.as_ref().unwrap();
    assert!(tls.enabled);
    assert_eq!(
        tls.upstream_ca_cert,
        [PathBuf::from("/missing/CA_SENTINEL.pem")]
    );
    assert_eq!(native.ports.len(), 1);
    assert_eq!(native.ports[0].host_port, 0);
    assert_eq!(native.ports[0].guest_port, 80);
    assert!(native.outbound_proxy.is_some());
    assert_eq!(
        plan.gateway().guest_trust_certificates().unwrap(),
        [PathBuf::from("/missing/CA_SENTINEL.pem")]
    );
    // No filesystem, DNS or credential lookup was needed, and composition grants no consent.
    assert_eq!(
        format!("{:?}", plan.network_policy().selection().required_approvals),
        approvals
    );
    assert_eq!(
        serde_json::to_value(plan.network_inputs().unwrap()).unwrap(),
        serde_json::to_value(native).unwrap()
    );
    assert_eq!(serde_json::to_vec(&saved).unwrap(), before);
    assert!(!format!("{plan:?}").contains("SENTINEL"));
}

#[test]
fn network_assembly_refuses_each_unknown_inventory_instead_of_returning_partial_inputs() {
    for field in [
        "dns",
        "tls",
        "secrets",
        "ports",
        "guest_trust",
        "outbound_proxy",
    ] {
        let mut network = json!({
            "dns":{"state":"default"}, "tls":{"state":"default"},
            "secrets":{"state":"default"}, "ports":{"state":"default"},
            "guest_trust":{"state":"default"}, "outbound_proxy":{"state":"default"}
        });
        network[field] = json!({"state":"unknown","reason":"not_recorded"});
        let saved = document(json!({"network":network}), json!({}));
        let before = serde_json::to_vec(&saved).unwrap();
        let plan = prepare(
            &saved,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::new(),
        )
        .unwrap();
        let error = plan.network_inputs().unwrap_err().to_string();
        assert!(error.contains("SCFG_UNKNOWN"), "{field}: {error}");
        assert_eq!(serde_json::to_vec(&saved).unwrap(), before);
    }
}

#[test]
fn network_assembly_does_not_resolve_secret_sources_or_make_future_commands_ready() {
    let mut saved = shared();
    let defaults = document(
        json!({"network":{
            "dns":{"state":"default"}, "tls":{"state":"default"},
            "ports":{"state":"default"}, "guest_trust":{"state":"default"},
            "outbound_proxy":{"state":"default"}
        }}),
        json!({}),
    );
    saved.active.network.dns = defaults.active.network.dns;
    saved.active.network.tls = defaults.active.network.tls;
    saved.active.network.ports = defaults.active.network.ports;
    saved.active.network.guest_trust = defaults.active.network.guest_trust;
    saved.active.network.outbound_proxy = defaults.active.network.outbound_proxy;
    let plan = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::from([(
            "shared".into(),
            ConfigurationBindingInput::TextSource(SecretSource::env("UNAVAILABLE_SENTINEL")),
        )]),
    )
    .unwrap();
    let native = plan.network_inputs().unwrap();
    let secrets = native.secrets.unwrap();
    assert_eq!(secrets.secrets.len(), 1);
    assert!(secrets.secrets[0].value.is_empty());
    assert_eq!(
        secrets.secrets[0].source,
        Some(SecretSource::env("UNAVAILABLE_SENTINEL"))
    );
    assert!(plan.runtime().command_defaults().is_err());
    assert!(plan.unresolved_text_sources().contains("shared"));
    assert!(plan.supply_gaps().before_new_command.contains("shared"));
    assert!(!format!("{plan:?}").contains("SENTINEL"));
}

#[test]
fn network_assembly_keeps_destination_interface_and_caps_without_claiming_full_compatibility() {
    let saved = document(
        json!({"network":{
            "dns":{"state":"default"}, "tls":{"state":"default"},
            "secrets":{"state":"default"}, "ports":{"state":"default"},
            "guest_trust":{"state":"default"}, "outbound_proxy":{"state":"default"}
        }}),
        json!({}),
    );
    let explicit = SandboxSpecPatch::new().network(
        NetworkSpecPatch::new()
            .interface(InterfaceOverridesPatch::new().mtu(1400))
            .max_udp_connections(0)
            .tcp_accept_queue_size(23),
    );
    let resources = SandboxResources::default();
    let captured = SavedBindingUses::new();
    let plan = prepare(
        &saved,
        &explicit,
        SnapshotConfigMode::Fresh,
        SavedConfigurationContext::Full {
            resources: &resources,
            security: SecurityProfile::default(),
            bindings: &captured,
        },
        BTreeMap::new(),
    )
    .unwrap();
    let native = plan.network_inputs().unwrap();
    assert_eq!(native.interface.unwrap().mtu, Some(1400));
    assert_eq!(native.max_udp_connections, Some(0));
    assert_eq!(native.tcp_accept_queue_size, Some(23));
    assert!(native.dns.is_none());
    assert!(native.tls.is_none());
    assert!(native.secrets.is_none());
    assert!(
        plan.network_policy()
            .selection()
            .requires_full_compatibility
    );
    assert!(plan.gateway().selection().requires_full_compatibility);
    assert!(plan.listeners().selection().requires_full_compatibility);
    assert!(plan.secrets().selection().requires_full_identity);
}

#[test]
fn network_assembly_keeps_recorded_empty_substitution_container_present() {
    let saved = document(
        json!({"network":{
            "dns":{"state":"default"}, "tls":{"state":"default"},
            "secrets":known(json!({"entries":[],"violation_action":"block","passthrough_hosts":[]})),
            "ports":{"state":"default"}, "guest_trust":{"state":"default"},
            "outbound_proxy":{"state":"default"}
        }}),
        json!({}),
    );
    let plan = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::new(),
    )
    .unwrap();
    let native = plan.network_inputs().unwrap();
    let secrets = native.secrets.unwrap();
    assert!(secrets.secrets.is_empty());
    assert_eq!(secrets.passthrough_hosts, Some(vec![]));
}

#[test]
fn network_assembly_fresh_mode_keeps_destination_policy_container_presence() {
    let saved = document(
        json!({"network":{
            "dns":{"state":"default"}, "tls":{"state":"default"},
            "secrets":{"state":"default"}, "ports":{"state":"default"},
            "guest_trust":{"state":"default"}, "outbound_proxy":{"state":"default"}
        }}),
        json!({}),
    );
    let mut lower = SandboxSpec::default();
    lower.network.dns = Some(DnsConfig {
        query_timeout_ms: 12345,
        ..Default::default()
    });
    lower.network.tls = Some(TlsConfig {
        enabled: true,
        intercepted_ports: vec![443, 8443],
        ..Default::default()
    });
    lower.network.interface = Some(InterfaceOverrides {
        mtu: Some(1337),
        mac: Some([2, 0, 0, 0, 0, 7]),
        ..Default::default()
    });
    let explicit = SandboxSpecPatch::new()
        .network(NetworkSpecPatch::new().interface(InterfaceOverridesPatch::new().mtu(1400)));
    let baseline = DestinationNetworkBaseline {
        strict: true,
        tls_enabled: true,
        intercepted_ports: vec![443, 8443],
    };
    let plan = prepare_saved_configuration(
        SavedConfigurationRequest {
            saved: &saved,
            manifest: &storage_tests::manifest(false),
            lower: &lower,
            lower_resources: &SandboxResourcesPatch::new(),
            explicit: &explicit,
            clears: &SavedConfigurationClears::default(),
            mode: SnapshotConfigMode::Fresh,
            context: disk(),
            guest_security: DestinationGuestSecurity {
                baseline: SecurityProfile::default(),
                minimum: SecurityProfile::default(),
            },
            network_baseline: &baseline,
        },
        BTreeMap::new(),
    )
    .unwrap();
    let native = plan.network_inputs().unwrap();
    let interface = native.interface.as_ref().unwrap();
    assert_eq!(interface.mtu, Some(1400));
    assert_eq!(interface.mac, Some([2, 0, 0, 0, 0, 7]));
    assert_eq!(
        native
            .dns
            .expect("destination DNS policy must remain present")
            .query_timeout_ms,
        12345
    );
    let tls = native
        .tls
        .expect("destination TLS policy must remain present");
    assert!(tls.enabled);
    assert_eq!(tls.intercepted_ports, [443, 8443]);
}
