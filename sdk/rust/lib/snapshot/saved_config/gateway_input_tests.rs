//! Resource replacement cannot silently erase a different consumer or imply captured identity.

use std::path::PathBuf;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedBindingConsumer, SavedNetworkConfig, SavedUnknownReason,
    SavedValue,
};
use microsandbox_types::{
    DnsConfigPatch, InterceptCaConfig, NetworkSpecPatch, OutboundProxy, SecretSource,
    Socks5Credentials, TlsConfigPatch,
};
use serde_json::{Value, json};

use super::{BindingDemandContext, plan_binding_demand, select_gateway_inputs};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn record(value: Value) -> Value {
    json!({"state":"value", "origin":"configured", "value":value})
}

fn source() -> SavedNetworkConfig {
    SavedNetworkConfig::from_bytes(&serde_json::to_vec(&json!({
        "dns":record(json!({"rebind_protection":true,"query_timeout_ms":5000,"resolvers":[{"id":"resolver"}]})),
        "tls":record(json!({"enabled":true,"intercepted_ports":[443],"bypass":[],"verify_upstream":true,
            "block_quic_on_intercept":true,"upstream_cas":[{"id":"shared-ca"}],
            "scoped_upstream_cas":[{"pattern":"*.example","binding":{"id":"shared-ca"}}],
            "scoped_verify_upstream":[],"intercept_ca":{"id":"identity"}})),
        "guest_trust":record(json!([{"id":"shared-ca"}])),
        "outbound_proxy":record(json!({"protocol":"socks5","endpoint":{"id":"proxy"},"credentials":{"id":"auth"}})),
        "ports":record(json!([{"guest_port":80,"protocol":"tcp","binding":{"id":"listener"}}])),
        "secrets":record(json!({"passthrough_hosts":[],"entries":[],"violation_action":"block"}))
    })).unwrap()).unwrap()
}

fn proxy() -> OutboundProxy {
    OutboundProxy::Socks5 {
        address: "PRIVATE_PROXY_SENTINEL.invalid:1080".into(),
        credentials: Some(Socks5Credentials {
            username: "PRIVATE_USER_SENTINEL".into(),
            password: SecretSource::env("MSB_TEST_UNRESOLVED_PASSWORD_SENTINEL"),
        }),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn policy_only_overrides_do_not_supply_resource_bindings_or_enter_destination_projection() {
    let mut explicit = NetworkSpecPatch::new();
    explicit.enabled = Some(false);
    explicit.strict = Some(false);
    explicit.dns = Some(DnsConfigPatch::new().rebind_protection(false));
    explicit.tls = Some(TlsConfigPatch::new().verify_upstream(false));
    let plan = select_gateway_inputs(&source(), &explicit, false).unwrap();
    assert_eq!(plan.remaining_bindings.len(), 5);
    assert!(plan.remaining_bindings.contains_key("resolver"));
    assert!(!plan.remaining_bindings.contains_key("listener"));
    assert!(plan.requirements.ports.is_none());
    assert!(plan.requirements.secrets.is_none());
    assert!(plan.destination.enabled.is_none());
    assert!(plan.destination.strict.is_none());
    assert!(plan.destination.dns.is_none());
    assert!(plan.destination.tls.is_none());
}

#[test]
fn resolver_replacement_preserves_order_empty_and_other_requirements_without_lookup() {
    let saved = source();
    let bytes = serde_json::to_vec(&saved).unwrap();
    for values in [
        vec![
            "PRIVATE_DNS_B_SENTINEL.invalid".into(),
            "PRIVATE_DNS_A_SENTINEL.invalid".into(),
        ],
        vec![],
    ] {
        let mut explicit = NetworkSpecPatch::new();
        explicit.dns = Some(DnsConfigPatch::new().nameservers(values.clone()));
        let plan = select_gateway_inputs(&saved, &explicit, false).unwrap();
        assert_eq!(
            plan.destination.dns.as_ref().unwrap().nameservers.as_ref(),
            Some(&values)
        );
        assert!(!plan.remaining_bindings.contains_key("resolver"));
        assert_eq!(plan.remaining_bindings.len(), 4);
        assert!(!format!("{plan:?}").contains("SENTINEL"));
        assert_eq!(serde_json::to_vec(&saved).unwrap(), bytes);
    }
}

#[test]
fn replacing_one_trust_list_retains_shared_scoped_and_guest_consumers() {
    let mut explicit = NetworkSpecPatch::new();
    explicit.tls = Some(TlsConfigPatch::new().upstream_ca_cert(vec![]));
    let plan = select_gateway_inputs(&source(), &explicit, false).unwrap();
    let shared = &plan.remaining_bindings["shared-ca"];
    assert!(shared.consumers.contains(&SavedBindingConsumer::Gateway));
    assert!(shared.consumers.contains(&SavedBindingConsumer::GuestTrust));
    explicit.tls.as_mut().unwrap().scoped_upstream_ca_cert = Some(vec![]);
    for trust in [false, true] {
        explicit.trust_host_cas = Some(trust);
        let plan = select_gateway_inputs(&source(), &explicit, false).unwrap();
        let shared = &plan.remaining_bindings["shared-ca"];
        assert!(!shared.consumers.contains(&SavedBindingConsumer::Gateway));
        assert!(shared.consumers.contains(&SavedBindingConsumer::GuestTrust));
        assert_eq!(plan.destination.trust_host_cas, Some(trust));
    }
}

#[test]
fn explicit_interception_identity_preserves_path_policy_and_rejects_partial_pairs() {
    let cert = PathBuf::from("../PRIVATE_CERT_SENTINEL.pem");
    let key = PathBuf::from("./symlink/../PRIVATE_KEY_SENTINEL.pem");
    for identity in [
        InterceptCaConfig {
            cert_path: Some(cert.clone()),
            key_path: Some(key.clone()),
        },
        InterceptCaConfig::default(),
    ] {
        let mut explicit = NetworkSpecPatch::new();
        explicit.tls = Some(TlsConfigPatch::new().intercept_ca(identity.clone()));
        let plan = select_gateway_inputs(&source(), &explicit, true).unwrap();
        let selected = plan
            .destination
            .tls
            .as_ref()
            .unwrap()
            .intercept_ca
            .as_ref()
            .unwrap();
        assert_eq!(selected.cert_path, identity.cert_path);
        assert_eq!(selected.key_path, identity.key_path);
        assert!(!plan.remaining_bindings.contains_key("identity"));
        assert!(plan.requires_full_compatibility);
        assert!(!format!("{plan:?}").contains("SENTINEL"));
    }
    for identity in [
        InterceptCaConfig {
            cert_path: Some(cert),
            key_path: None,
        },
        InterceptCaConfig {
            cert_path: None,
            key_path: Some(key),
        },
    ] {
        let mut explicit = NetworkSpecPatch::new();
        explicit.tls = Some(TlsConfigPatch::new().intercept_ca(identity));
        let err = select_gateway_inputs(&source(), &explicit, false).unwrap_err();
        assert!(err.to_string().contains("SCFG_BINDING"));
        assert!(!err.to_string().contains("SENTINEL"));
    }
}

#[test]
fn proxy_omission_clear_and_replacement_are_distinct_and_credentials_stay_unresolved() {
    let saved = source();
    let before = serde_json::to_vec(&saved).unwrap();
    let mut explicit = NetworkSpecPatch::new();
    let plan = select_gateway_inputs(&saved, &explicit, false).unwrap();
    assert!(plan.remaining_bindings.contains_key("proxy"));
    assert!(plan.remaining_bindings.contains_key("auth"));
    for input in [None, Some(proxy())] {
        explicit.outbound_proxy = Some(input.clone());
        let plan = select_gateway_inputs(&saved, &explicit, false).unwrap();
        assert_eq!(plan.destination.outbound_proxy, Some(input));
        assert!(!plan.remaining_bindings.contains_key("proxy"));
        assert!(!plan.remaining_bindings.contains_key("auth"));
        assert!(plan.requirements.outbound_proxy.is_none());
        assert!(!format!("{plan:?}").contains("SENTINEL"));
        assert_eq!(serde_json::to_vec(&saved).unwrap(), before);
    }
}

#[test]
fn full_captured_requirements_survive_selected_proxy_and_identity_replacement() {
    let saved = source();
    let captured = select_gateway_inputs(&saved, &NetworkSpecPatch::new(), true)
        .unwrap()
        .remaining_bindings;
    let mut explicit = NetworkSpecPatch::new();
    explicit.outbound_proxy = Some(None);
    explicit.tls = Some(TlsConfigPatch::new().intercept_ca(InterceptCaConfig::default()));
    let selected = select_gateway_inputs(&saved, &explicit, true).unwrap();
    let demand = plan_binding_demand(
        &selected.remaining_bindings,
        Some(&captured),
        BindingDemandContext {
            full_resume: true,
            starts_command: false,
        },
    )
    .unwrap();
    for id in ["proxy", "auth", "identity"] {
        assert!(demand.bindings()[id].required_now);
        assert!(demand.bindings()[id].captured_execution);
    }
}

#[test]
fn unknown_default_and_omitted_resource_fields_are_masked_independently() {
    let mut saved = SavedNetworkConfig::default();
    saved.tls = Some(SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    });
    saved.outbound_proxy = Some(SavedValue::Default {});
    let mut explicit = NetworkSpecPatch::new();
    explicit.tls = Some(TlsConfigPatch::new().upstream_ca_cert(vec![]));
    let plan = select_gateway_inputs(&saved, &explicit, true).unwrap();
    assert!(!plan.unknown_fields.contains("network.tls.upstream_ca_cert"));
    assert!(
        plan.unknown_fields
            .contains("network.tls.scoped_upstream_ca_cert")
    );
    assert!(plan.unknown_fields.contains("network.tls.intercept_ca"));
    assert!(plan.unknown_fields.contains("network.dns.nameservers"));
    assert!(plan.unknown_fields.contains("network.guest_trust"));
    assert!(plan.defaulted_fields.contains("network.outbound_proxy"));
    explicit.outbound_proxy = Some(None);
    let plan = select_gateway_inputs(&saved, &explicit, true).unwrap();
    assert!(!plan.defaulted_fields.contains("network.outbound_proxy"));
    assert!(plan.requires_full_compatibility);
}

#[test]
fn invalid_original_shared_kind_cannot_be_hidden_by_an_explicit_override() {
    let mut saved = source();
    if let Some(SavedValue::Value { value, .. }) = &mut saved.outbound_proxy {
        value.endpoint.id = "shared-ca".into();
    }
    let mut explicit = NetworkSpecPatch::new();
    explicit.outbound_proxy = Some(None);
    let err = select_gateway_inputs(&saved, &explicit, false).unwrap_err();
    assert!(err.to_string().contains("SCFG_BINDING"));
    assert!(!err.to_string().contains("shared-ca"));
}

#[test]
fn source_secret_shape_errors_stay_redacted_and_destination_lists_are_bounded() {
    let mut saved = source();
    if let Some(SavedValue::Value { value, .. }) = &mut saved.tls {
        value.scoped_upstream_cas[0].pattern = "PRIVATE_PATTERN_SENTINEL\n".into();
    }
    let err = select_gateway_inputs(&saved, &NetworkSpecPatch::new(), false).unwrap_err();
    assert!(!err.to_string().contains("SENTINEL"));
    let mut explicit = NetworkSpecPatch::new();
    explicit.dns = Some(
        DnsConfigPatch::new().nameservers(vec!["127.0.0.1".into(); MAX_SAVED_CONFIG_ENTRIES + 1]),
    );
    assert!(
        select_gateway_inputs(&source(), &explicit, false)
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
}
