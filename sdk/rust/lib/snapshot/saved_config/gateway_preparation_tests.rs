//! Preparation must preserve destination provenance and never turn missing bindings into defaults.

use std::collections::BTreeMap;
use std::path::PathBuf;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_TEXT_BYTES, SavedNetworkConfig, SavedProxyProtocol, SavedScopedTrust, SavedValue,
};
use microsandbox_types::{
    DnsConfig, DnsConfigPatch, InterceptCaConfig, NetworkSpec, NetworkSpecPatch, OutboundProxy,
    SecretSource, Socks5Credentials, TlsConfig, TlsConfigPatch,
};
use serde_json::{Value, json};

use super::{GatewayBindingInput, prepare_gateway_configuration};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn record(value: Value) -> Value {
    json!({"state":"value", "origin":"configured", "value":value})
}

fn source() -> SavedNetworkConfig {
    SavedNetworkConfig::from_bytes(&serde_json::to_vec(&json!({
        "dns":record(json!({"rebind_protection":true,"query_timeout_ms":5000,
            "resolvers":[{"id":"resolver-b"},{"id":"resolver-a"}]})),
        "tls":record(json!({"enabled":true,"intercepted_ports":[443],"bypass":[],"verify_upstream":true,
            "block_quic_on_intercept":true,"upstream_cas":[{"id":"ca"}],
            "scoped_upstream_cas":[{"pattern":"*.example","binding":{"id":"ca"}}],
            "scoped_verify_upstream":[],"intercept_ca":{"id":"identity"}})),
        "guest_trust":record(json!([{"id":"ca"}])),
        "outbound_proxy":record(json!({"protocol":"socks5","endpoint":{"id":"proxy"},"credentials":{"id":"auth"}}))
    })).unwrap()).unwrap()
}

fn inputs() -> BTreeMap<String, GatewayBindingInput> {
    BTreeMap::from([
        (
            "resolver-a".into(),
            GatewayBindingInput::DnsResolver("DNS_A_SENTINEL.invalid:53".into()),
        ),
        (
            "resolver-b".into(),
            GatewayBindingInput::DnsResolver("DNS_B_SENTINEL.invalid:53".into()),
        ),
        (
            "ca".into(),
            GatewayBindingInput::Certificate(PathBuf::from("./symlink/../CA_SENTINEL.pem")),
        ),
        (
            "identity".into(),
            GatewayBindingInput::TlsIdentity(InterceptCaConfig {
                cert_path: Some("../CERT_SENTINEL.pem".into()),
                key_path: Some("../KEY_SENTINEL.pem".into()),
            }),
        ),
        (
            "proxy".into(),
            GatewayBindingInput::ProxyEndpoint("PROXY_SENTINEL.invalid:1080".into()),
        ),
        (
            "auth".into(),
            GatewayBindingInput::Socks5Credentials(Socks5Credentials {
                username: "USER_SENTINEL".into(),
                password: SecretSource::env("MISSING_PASSWORD_SENTINEL"),
            }),
        ),
    ])
}

fn assert_redacted(error: &crate::MicrosandboxError, code: &str) {
    assert!(error.to_string().contains(code), "{error}");
    assert!(!error.to_string().contains("SENTINEL"));
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn prepares_ordered_shared_material_without_reading_files_or_credential_sources() {
    let saved = source();
    let original = serde_json::to_vec(&saved).unwrap();
    let input = inputs();
    let plan =
        prepare_gateway_configuration(&saved, &NetworkSpecPatch::new(), &input, true).unwrap();
    let mut network = NetworkSpec::default();
    network.strict = false;
    network.dns = Some(DnsConfig {
        rebind_protection: false,
        query_timeout_ms: 17,
        ..Default::default()
    });
    network.tls = Some(TlsConfig {
        verify_upstream: false,
        intercepted_ports: vec![8443],
        ..Default::default()
    });
    plan.apply_inputs_to(&mut network).unwrap();
    let dns = network.dns.unwrap();
    assert_eq!(
        dns.nameservers,
        ["DNS_B_SENTINEL.invalid:53", "DNS_A_SENTINEL.invalid:53"]
    );
    assert!(!dns.rebind_protection);
    assert_eq!(dns.query_timeout_ms, 17);
    let tls = network.tls.unwrap();
    assert!(!tls.verify_upstream);
    assert_eq!(tls.intercepted_ports, [8443]);
    let path = PathBuf::from("./symlink/../CA_SENTINEL.pem");
    assert_eq!(tls.upstream_ca_cert, [path.clone()]);
    assert_eq!(tls.scoped_upstream_ca_cert[0].path, path);
    assert_eq!(tls.scoped_upstream_ca_cert[0].pattern, "*.example");
    assert_eq!(plan.guest_trust_certificates().unwrap(), [path]);
    assert_eq!(
        tls.intercept_ca.key_path,
        Some("../KEY_SENTINEL.pem".into())
    );
    let Some(OutboundProxy::Socks5 {
        credentials: Some(auth),
        ..
    }) = network.outbound_proxy
    else {
        panic!("missing proxy")
    };
    assert_eq!(
        auth.password,
        SecretSource::env("MISSING_PASSWORD_SENTINEL")
    );
    assert!(plan.selection().requires_full_compatibility);
    assert_eq!(plan.selection().remaining_bindings.len(), 6);
    assert_eq!(serde_json::to_vec(&saved).unwrap(), original);
    assert!(!format!("{plan:?} {input:?}").contains("SENTINEL"));
}

#[test]
fn every_missing_immediate_binding_refuses_instead_of_falling_back() {
    for id in inputs().keys() {
        let mut input = inputs();
        input.remove(id);
        let error =
            prepare_gateway_configuration(&source(), &NetworkSpecPatch::new(), &input, false)
                .unwrap_err();
        assert_redacted(&error, "SCFG_BINDING");
    }
}

#[test]
fn explicit_empty_overrides_discard_only_their_consumers() {
    let mut explicit = NetworkSpecPatch::new();
    explicit.dns = Some(DnsConfigPatch::new().nameservers(vec![]));
    explicit.tls = Some(
        TlsConfigPatch::new()
            .upstream_ca_cert(vec![])
            .scoped_upstream_ca_cert(vec![])
            .intercept_ca(InterceptCaConfig::default()),
    );
    explicit.outbound_proxy = Some(None);
    explicit.trust_host_cas = Some(false);
    let input = BTreeMap::from([(
        "ca".into(),
        GatewayBindingInput::Certificate("NEW_GUEST_CA_SENTINEL.pem".into()),
    )]);
    let plan = prepare_gateway_configuration(&source(), &explicit, &input, true).unwrap();
    let mut destination = NetworkSpec::default();
    plan.apply_inputs_to(&mut destination).unwrap();
    assert!(destination.dns.unwrap().nameservers.is_empty());
    let tls = destination.tls.unwrap();
    assert!(tls.upstream_ca_cert.is_empty());
    assert!(tls.scoped_upstream_ca_cert.is_empty());
    assert!(tls.intercept_ca.cert_path.is_none());
    assert!(destination.outbound_proxy.is_none());
    assert!(!destination.trust_host_cas);
    assert_eq!(
        plan.guest_trust_certificates().unwrap(),
        [PathBuf::from("NEW_GUEST_CA_SENTINEL.pem")]
    );
    assert!(plan.selection().requires_full_compatibility);
}

#[test]
fn builtin_defaults_clear_lower_gateway_resources_without_changing_policy() {
    let saved = SavedNetworkConfig {
        dns: Some(SavedValue::Default {}),
        tls: Some(SavedValue::Default {}),
        guest_trust: Some(SavedValue::Default {}),
        outbound_proxy: Some(SavedValue::Default {}),
        ..Default::default()
    };
    let plan =
        prepare_gateway_configuration(&saved, &NetworkSpecPatch::new(), &BTreeMap::new(), false)
            .unwrap();
    let mut destination = NetworkSpec::default();
    destination.dns = Some(DnsConfig {
        nameservers: vec!["OLD_RESOLVER".into()],
        query_timeout_ms: 27,
        ..Default::default()
    });
    destination.tls = Some(TlsConfig {
        enabled: true,
        upstream_ca_cert: vec!["OLD_CA".into()],
        ..Default::default()
    });
    destination.outbound_proxy = Some(OutboundProxy::HttpConnect {
        address: "OLD_PROXY:80".into(),
    });
    plan.apply_inputs_to(&mut destination).unwrap();
    let dns = destination.dns.unwrap();
    assert!(dns.nameservers.is_empty());
    assert_eq!(dns.query_timeout_ms, 27);
    let tls = destination.tls.unwrap();
    assert!(tls.enabled);
    assert!(tls.upstream_ca_cert.is_empty());
    assert!(destination.outbound_proxy.is_none());
    assert!(plan.guest_trust_certificates().unwrap().is_empty());
}

#[test]
fn unknown_gateway_source_cannot_borrow_lower_inputs_or_partially_apply() {
    let mut saved = source();
    saved.guest_trust = None;
    let mut input = inputs();
    // ca is still required by both upstream trust uses.
    let plan =
        prepare_gateway_configuration(&saved, &NetworkSpecPatch::new(), &input, false).unwrap();
    let mut destination = NetworkSpec::default();
    let before = serde_json::to_vec(&destination).unwrap();
    assert_redacted(
        &plan.apply_inputs_to(&mut destination).unwrap_err(),
        "SCFG_UNKNOWN",
    );
    assert_eq!(serde_json::to_vec(&destination).unwrap(), before);
    assert_redacted(
        &plan.guest_trust_certificates().unwrap_err(),
        "SCFG_UNKNOWN",
    );
    input.insert(
        "UNUSED_SENTINEL".into(),
        GatewayBindingInput::DnsResolver("1.1.1.1".into()),
    );
    assert_redacted(
        &prepare_gateway_configuration(&source(), &NetworkSpecPatch::new(), &input, false)
            .unwrap_err(),
        "SCFG_BINDING",
    );
}

#[test]
fn wrong_kind_partial_identity_and_protocol_mismatch_are_redacted() {
    for replacement in [
        GatewayBindingInput::DnsResolver("WRONG_SENTINEL".into()),
        GatewayBindingInput::TlsIdentity(InterceptCaConfig::default()),
        GatewayBindingInput::TlsIdentity(InterceptCaConfig {
            cert_path: Some("ONLY_CERT_SENTINEL".into()),
            key_path: None,
        }),
    ] {
        let mut input = inputs();
        input.insert("identity".into(), replacement);
        assert_redacted(
            &prepare_gateway_configuration(&source(), &NetworkSpecPatch::new(), &input, false)
                .unwrap_err(),
            "SCFG_BINDING",
        );
    }
    let mut input = inputs();
    input.insert(
        "auth".into(),
        GatewayBindingInput::Socks4User("USER_SENTINEL".into()),
    );
    assert_redacted(
        &prepare_gateway_configuration(&source(), &NetworkSpecPatch::new(), &input, false)
            .unwrap_err(),
        "SCFG_BINDING",
    );
}

#[test]
fn socks4_and_unauthenticated_protocols_preserve_exact_selected_protocol() {
    for protocol in ["http_connect", "socks4", "socks5"] {
        let mut saved = source();
        let proxy = json!({"protocol":protocol,"endpoint":{"id":"proxy"}});
        saved.outbound_proxy = serde_json::from_value(record(proxy)).unwrap();
        let mut input = inputs();
        input.remove("auth");
        let plan =
            prepare_gateway_configuration(&saved, &NetworkSpecPatch::new(), &input, false).unwrap();
        let mut destination = NetworkSpec::default();
        plan.apply_inputs_to(&mut destination).unwrap();
        assert_eq!(
            serde_json::to_value(destination.outbound_proxy).unwrap()["protocol"],
            protocol
        );
    }
    let mut saved = source();
    if let Some(SavedValue::Value { value, .. }) = &mut saved.outbound_proxy {
        value.protocol = SavedProxyProtocol::Socks4;
    }
    let mut input = inputs();
    input.insert(
        "auth".into(),
        GatewayBindingInput::Socks4User("EXACT_USER_SENTINEL".into()),
    );
    let plan =
        prepare_gateway_configuration(&saved, &NetworkSpecPatch::new(), &input, false).unwrap();
    let mut destination = NetworkSpec::default();
    plan.apply_inputs_to(&mut destination).unwrap();
    let Some(OutboundProxy::Socks4 { user_id, .. }) = destination.outbound_proxy else {
        panic!("wrong protocol")
    };
    assert_eq!(user_id.as_deref(), Some("EXACT_USER_SENTINEL"));
}

#[test]
fn oversized_or_nul_binding_values_fail_without_echoing_values() {
    for value in [
        "X".repeat(MAX_SAVED_TEXT_BYTES + 1),
        "SENTINEL\0value".into(),
        String::new(),
    ] {
        let mut input = inputs();
        input.insert("resolver-a".into(), GatewayBindingInput::DnsResolver(value));
        assert_redacted(
            &prepare_gateway_configuration(&source(), &NetworkSpecPatch::new(), &input, false)
                .unwrap_err(),
            "SCFG_VALUE",
        );
    }
}

#[test]
fn shared_certificate_expansion_is_bounded_per_consumer_not_just_per_binding() {
    let mut saved = source();
    if let Some(SavedValue::Value { value, .. }) = &mut saved.tls {
        let binding = value.scoped_upstream_cas[0].binding.clone();
        value.scoped_upstream_cas = (0..9)
            .map(|n| SavedScopedTrust {
                pattern: format!("host{n}.example"),
                binding: binding.clone(),
            })
            .collect();
    }
    let mut input = inputs();
    input.insert(
        "ca".into(),
        GatewayBindingInput::Certificate("X".repeat(MAX_SAVED_TEXT_BYTES).into()),
    );
    assert_redacted(
        &prepare_gateway_configuration(&saved, &NetworkSpecPatch::new(), &input, false)
            .unwrap_err(),
        "SCFG_LIMIT",
    );
}

#[test]
fn malformed_source_cannot_be_hidden_by_explicit_proxy_clear() {
    let mut saved = source();
    if let Some(SavedValue::Value { value, .. }) = &mut saved.outbound_proxy {
        value.protocol = SavedProxyProtocol::HttpConnect;
    }
    let mut explicit = NetworkSpecPatch::new();
    explicit.outbound_proxy = Some(None);
    assert_redacted(
        &prepare_gateway_configuration(&saved, &explicit, &BTreeMap::new(), false).unwrap_err(),
        "SCFG_VALUE",
    );
}

#[test]
fn empty_socks4_user_is_preserved_without_becoming_an_omitted_credential() {
    let mut saved = source();
    if let Some(SavedValue::Value { value, .. }) = &mut saved.outbound_proxy {
        value.protocol = SavedProxyProtocol::Socks4;
    }
    let mut input = inputs();
    input.insert(
        "auth".into(),
        GatewayBindingInput::Socks4User(String::new()),
    );
    let plan =
        prepare_gateway_configuration(&saved, &NetworkSpecPatch::new(), &input, false).unwrap();
    let mut destination = NetworkSpec::default();
    plan.apply_inputs_to(&mut destination).unwrap();
    let Some(OutboundProxy::Socks4 { user_id, .. }) = destination.outbound_proxy else {
        panic!("wrong protocol")
    };
    assert_eq!(user_id, Some(String::new()));
}
