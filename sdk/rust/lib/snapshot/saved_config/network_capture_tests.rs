//! Network capture must preserve gaps and order without serializing private source resources.

use microsandbox_types::snapshot::saved_config::{
    SavedBindingReference, SavedNetworkConfig, SavedTlsCaptureBindings, SavedUnknownReason,
    SavedValue,
};
use serde_json::{Value, json};

use super::{
    NetworkCaptureBindings, NetworkCaptureControls, NetworkCaptureSection, ProxyCaptureBindings,
    RuntimeCaptureSource,
};
use crate::sandbox::SandboxBuilder;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn reference(id: &str) -> SavedBindingReference {
    SavedBindingReference { id: id.into() }
}

fn source() -> Value {
    let config = SandboxBuilder::new("source")
        .image("alpine")
        .finish(None, None)
        .unwrap();
    let mut raw = serde_json::to_value(config.clone_for_persistence()).unwrap();
    raw["network"] = json!({
        "enabled": false, "strict": true,
        "interface": {"mac": [2, 99, 99, 99, 99, 99], "ipv4_address": "192.0.2.91"},
        "ports": [], "policy": null, "dns": null, "tls": null, "secrets": null,
        "max_connections": 0, "max_inbound_tcp_connections": 0, "max_udp_connections": 0,
        "tcp_accept_queue_size": 1024, "rate_limiter": null,
        "nat64_prefixes": [], "trust_host_cas": false,
        "http": {"deny_response": false, "deny_response_format": "text", "deny_message": "", "network_deny_message": null, "secret_deny_message": null},
        "outbound_proxy": null
    });
    raw
}

fn capture(
    raw: &Value,
    bindings: NetworkCaptureBindings,
) -> crate::MicrosandboxResult<SavedNetworkConfig> {
    RuntimeCaptureSource::from_recorded(raw, None, None)?
        .project_network(bindings, &NetworkCaptureControls::default())
}

fn is_unknown<T>(value: &Option<SavedValue<T>>) -> bool {
    matches!(
        value,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    )
}

fn gateway_source() -> Value {
    let mut raw = source();
    raw["network"]["dns"] = json!({"rebind_protection": true, "nameservers": ["PRIVATE_RESOLVER:5300"], "query_timeout_ms": 70});
    raw["network"]["tls"] = json!({
        "enabled": true, "intercepted_ports": [8443, 443], "bypass": ["example.com"],
        "verify_upstream": true, "block_quic_on_intercept": true,
        "upstream_ca_cert": ["/PRIVATE_UPSTREAM_CA"],
        "scoped_upstream_ca_cert": [{"pattern": "*.example.org", "path": "/PRIVATE_SCOPED_CA"}],
        "scoped_verify_upstream": [{"pattern": "example.net", "verify": false}],
        "intercept_ca": {"cert_path": "/PRIVATE_CA_CERT", "key_path": "/PRIVATE_CA_KEY"}
    });
    raw["network"]["ports"] = json!([{"guest_port": 8080, "host_port": 59999, "host_bind": "PRIVATE_LISTENER", "protocol": "tcp"}]);
    raw["network"]["outbound_proxy"] =
        json!({"protocol": "socks4", "address": "PRIVATE_PROXY:1080", "user_id": "PRIVATE_USER"});
    raw["network"]["trust_host_cas"] = json!(true);
    raw
}

fn gateway_bindings() -> NetworkCaptureBindings {
    NetworkCaptureBindings {
        resolvers: vec![reference("resolver")],
        tls: Some(SavedTlsCaptureBindings {
            upstream_cas: vec![reference("upstream")],
            scoped_upstream_cas: vec![reference("scoped")],
            intercept_ca: Some(reference("interception")),
        }),
        listeners: vec![reference("listener")],
        guest_trust: vec![reference("guest-trust")],
        proxy: Some(ProxyCaptureBindings {
            endpoint: reference("proxy"),
            credentials: Some(reference("proxy-auth")),
        }),
        ..Default::default()
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn generated_network_requirements_project_without_copying_source_authority() {
    let raw = gateway_source();
    let source = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    for (section, prefix) in [
        (NetworkCaptureSection::Active, "active.network"),
        (NetworkCaptureSection::Pending, "pending.network"),
    ] {
        let bindings = source
            .network_requirements(section, vec![reference("observed-trust")])
            .unwrap();
        let saved = source
            .project_network(bindings, &NetworkCaptureControls::default())
            .unwrap();
        let encoded = serde_json::to_string(&saved).unwrap();
        assert!(!encoded.contains("PRIVATE_"));
        assert!(!encoded.contains("59999"));
        for field in [
            "dns.resolvers.0",
            "tls.upstream_cas.0",
            "tls.scoped_upstream_cas.0",
            "tls.intercept_ca",
            "listeners.0",
            "proxy.endpoint",
            "proxy.credentials",
        ] {
            assert!(encoded.contains(&format!("{prefix}.{field}")), "{field}");
        }
    }
}

#[test]
fn generated_requirements_do_not_promote_incomplete_sections() {
    let mut raw = gateway_source();
    for (section, field) in [
        ("dns", "query_timeout_ms"),
        ("tls", "intercept_ca"),
        ("outbound_proxy", "user_id"),
    ] {
        raw["network"][section]
            .as_object_mut()
            .unwrap()
            .remove(field);
    }
    raw["network"]["ports"][0]
        .as_object_mut()
        .unwrap()
        .remove("protocol");
    let source = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let bindings = source
        .network_requirements(
            NetworkCaptureSection::Active,
            vec![reference("observed-trust")],
        )
        .unwrap();
    assert!(bindings.resolvers.is_empty());
    assert!(bindings.tls.is_none());
    assert!(bindings.listeners.is_empty());
    assert!(bindings.proxy.is_none());
    let saved = source
        .project_network(bindings, &NetworkCaptureControls::default())
        .unwrap();
    assert!(is_unknown(&saved.dns));
    assert!(is_unknown(&saved.tls));
    assert!(is_unknown(&saved.ports));
    assert!(is_unknown(&saved.outbound_proxy));
}

#[test]
fn generated_proxy_requirements_preserve_empty_authentication_and_automatic_ca() {
    for (proxy, authenticated) in [
        (
            json!({"protocol":"http_connect", "address":"PRIVATE_PROXY"}),
            false,
        ),
        (
            json!({"protocol":"socks4", "address":"PRIVATE_PROXY", "user_id":null}),
            false,
        ),
        (
            json!({"protocol":"socks4", "address":"PRIVATE_PROXY", "user_id":""}),
            true,
        ),
        (
            json!({"protocol":"socks5", "address":"PRIVATE_PROXY", "credentials":null}),
            false,
        ),
        (
            json!({"protocol":"socks5", "address":"PRIVATE_PROXY", "credentials":{"username":"", "password":{"kind":"env","var":"PRIVATE_PASSWORD"}}}),
            true,
        ),
    ] {
        let mut raw = gateway_source();
        raw["network"]["outbound_proxy"] = proxy;
        raw["network"]["tls"]["intercept_ca"] = json!({"cert_path":null,"key_path":null});
        let source = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
        let bindings = source
            .network_requirements(
                NetworkCaptureSection::Active,
                vec![reference("observed-trust")],
            )
            .unwrap();
        assert_eq!(
            bindings.proxy.as_ref().unwrap().credentials.is_some(),
            authenticated
        );
        assert!(bindings.tls.as_ref().unwrap().intercept_ca.is_some());
        source
            .project_network(bindings, &NetworkCaptureControls::default())
            .unwrap();
    }
}

#[test]
fn generated_requirements_cannot_invent_host_trust_observations() {
    let raw = gateway_source();
    let source = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let bindings = source
        .network_requirements(NetworkCaptureSection::Active, vec![])
        .unwrap();
    let error = source
        .project_network(bindings, &NetworkCaptureControls::default())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("guest_trust"));
    assert!(!error.contains("PRIVATE_"));
}

#[test]
fn generated_secret_ids_are_ordinal_and_duplicate_source_keys_refuse() {
    let mut raw = source();
    let secret = json!({
        "env_var":"TOKEN", "value":"PRIVATE_SECRET", "placeholder":"token",
        "allowed_hosts":[{"exact":"example.com"}], "passthrough_hosts":[],
        "violation_action":null,"require_tls_identity":true,
        "substitution":{"headers":true,"header_fields":[],"query":false,"body":false}
    });
    let mut sourced = secret.clone();
    sourced["env_var"] = "SECOND_TOKEN".into();
    sourced["placeholder"] = "second-placeholder".into();
    sourced["value"] = "".into();
    sourced["source"] = json!({"kind":"env","var":"PRIVATE_HOST_ENV"});
    raw["network"]["secrets"] = json!({
        "passthrough_hosts":null,"violation_action":"block","secrets":[secret.clone(), sourced]
    });
    let source = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let bindings = source
        .network_requirements(NetworkCaptureSection::Active, vec![])
        .unwrap();
    assert_eq!(bindings.secrets["TOKEN"].id, "active.network.secrets.0");
    assert_eq!(
        bindings.secrets["SECOND_TOKEN"].id,
        "active.network.secrets.1"
    );
    let saved = source
        .project_network(bindings, &NetworkCaptureControls::default())
        .unwrap();
    assert!(!serde_json::to_string(&saved).unwrap().contains("PRIVATE_"));
    let entries = &saved.secrets.as_ref().unwrap().value().unwrap().entries;
    assert_eq!(entries[0].env_var, "TOKEN");
    assert_eq!(entries[1].env_var, "SECOND_TOKEN");

    raw["network"]["secrets"]["secrets"]
        .as_array_mut()
        .unwrap()
        .push(secret);
    let source = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let error = source
        .network_requirements(NetworkCaptureSection::Active, vec![])
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("duplicate source secret key"));
    assert!(!error.contains("PRIVATE_"));
}

#[test]
fn generated_requirements_bound_ordinal_allocation() {
    let mut raw = gateway_source();
    raw["network"]["dns"]["nameservers"] = json!(vec![
        "PRIVATE_RESOLVER";
        microsandbox_types::snapshot::saved_config::MAX_SAVED_CONFIG_ENTRIES
            + 1
    ]);
    let source = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let error = source
        .network_requirements(NetworkCaptureSection::Active, vec![])
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("SCFG_LIMIT"));
    assert!(!error.contains("PRIVATE_"));
}

#[test]
fn network_capture_preserves_explicit_zero_false_empty_and_default() {
    let saved = capture(&source(), NetworkCaptureBindings::default()).unwrap();
    assert_eq!(
        saved.enabled.as_ref().and_then(SavedValue::value),
        Some(&false)
    );
    assert_eq!(
        saved
            .max_tcp_connections
            .as_ref()
            .and_then(SavedValue::value),
        Some(&0)
    );
    assert!(matches!(saved.policy, Some(SavedValue::Default {})));
    assert!(
        saved
            .ports
            .as_ref()
            .and_then(SavedValue::value)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        saved
            .http
            .as_ref()
            .and_then(SavedValue::value)
            .unwrap()
            .deny_message
            .as_deref(),
        Some("")
    );
    let encoded = serde_json::to_string(&saved).unwrap();
    assert!(!encoded.contains("192.0.2.91"));
    assert!(!encoded.contains("interface"));
}

#[test]
fn network_capture_missing_sections_are_not_current_defaults() {
    let mut raw = source();
    raw.as_object_mut().unwrap().remove("network");
    let saved = capture(&raw, NetworkCaptureBindings::default()).unwrap();
    let encoded = serde_json::to_value(&saved).unwrap();
    for field in encoded.as_object().unwrap().values() {
        assert_eq!(
            field,
            &json!({"state": "unknown", "reason": "not_recorded"})
        );
    }
}

#[test]
fn network_capture_gateway_bindings_exclude_source_authority() {
    let saved = capture(&gateway_source(), gateway_bindings()).unwrap();
    let encoded = serde_json::to_string(&saved).unwrap();
    assert!(!encoded.contains("PRIVATE_"));
    assert!(!encoded.contains("59999"));
    assert_eq!(
        saved
            .dns
            .as_ref()
            .and_then(SavedValue::value)
            .unwrap()
            .resolvers[0]
            .id,
        "resolver"
    );
    assert_eq!(
        saved
            .tls
            .as_ref()
            .and_then(SavedValue::value)
            .unwrap()
            .intercepted_ports,
        [8443, 443]
    );
    assert_eq!(
        saved.ports.as_ref().and_then(SavedValue::value).unwrap()[0].guest_port,
        8080
    );
}

#[test]
fn network_capture_requires_exact_gateway_bindings_and_safe_errors() {
    let raw = gateway_source();
    for index in 0..7 {
        let mut bindings = gateway_bindings();
        match index {
            0 => bindings.resolvers.clear(),
            1 => bindings.resolvers.push(reference("extra")),
            2 => bindings.tls.as_mut().unwrap().upstream_cas.clear(),
            3 => bindings.tls.as_mut().unwrap().intercept_ca = None,
            4 => bindings.listeners.clear(),
            5 => bindings.proxy.as_mut().unwrap().credentials = None,
            _ => bindings.guest_trust.clear(),
        }
        let error = capture(&raw, bindings).unwrap_err().to_string();
        assert!(error.contains("SCFG_BINDING"), "{error}");
        assert!(!error.contains("PRIVATE_"));
    }
}

#[test]
fn network_capture_partial_policy_is_unknown_not_weakened() {
    for (section, value) in [
        ("dns", json!({"nameservers": []})),
        ("tls", json!({"enabled": true})),
        ("policy", json!({"rules": []})),
        ("http", json!({"deny_response": true})),
        ("rate_limiter", json!({"egress": null})),
        ("secrets", json!({"secrets": []})),
        (
            "outbound_proxy",
            json!({"protocol": "socks4", "address": "PRIVATE_PROXY"}),
        ),
    ] {
        let mut raw = source();
        raw["network"][section] = value;
        let saved = serde_json::to_value(capture(&raw, NetworkCaptureBindings::default()).unwrap())
            .unwrap();
        assert_eq!(saved[section]["state"], "unknown", "{section}");
    }
}

#[test]
fn network_capture_rejects_unused_bindings_for_absent_null_or_incomplete_source() {
    for value in [None, Some(Value::Null), Some(json!({"nameservers": []}))] {
        let mut raw = source();
        match value {
            None => {
                raw["network"].as_object_mut().unwrap().remove("dns");
            }
            Some(value) => raw["network"]["dns"] = value,
        }
        let error = capture(
            &raw,
            NetworkCaptureBindings {
                resolvers: vec![reference("unused")],
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("SCFG_BINDING"));
    }
    let mut raw = source();
    raw["network"]["tls"] = gateway_source()["network"]["tls"].clone();
    raw["network"]["tls"]["enabled"] = json!(false);
    raw["network"]["tls"]["upstream_ca_cert"] = json!([]);
    raw["network"]["tls"]["scoped_upstream_ca_cert"] = json!([]);
    raw["network"]["tls"]["intercept_ca"] = json!({"cert_path": null, "key_path": null});
    assert!(
        capture(
            &raw,
            NetworkCaptureBindings {
                tls: Some(SavedTlsCaptureBindings {
                    intercept_ca: Some(reference("unused")),
                    ..Default::default()
                }),
                ..Default::default()
            }
        )
        .is_err()
    );
}

#[test]
fn network_capture_preserves_policy_order_and_rate_parameters_without_counters() {
    let mut raw = source();
    raw["network"]["policy"] = json!({"default_egress": "deny", "default_ingress": "deny", "rules": [
        {"direction": "egress", "destination": "any", "protocols": ["tcp"], "ports": [{"start": 443, "end": 443}], "action": "allow"},
        {"direction": "egress", "destination": "any", "protocols": [], "ports": [], "action": "deny"}
    ]});
    raw["network"]["rate_limiter"] = json!({"egress": {"bandwidth": {"size": 4096, "refill_time_ms": 100, "one_time_burst": 0}, "ops": null}, "ingress": null});
    let saved = capture(&raw, NetworkCaptureBindings::default()).unwrap();
    let rules = &saved
        .policy
        .as_ref()
        .and_then(SavedValue::value)
        .unwrap()
        .rules;
    assert_eq!(rules[0].action, microsandbox_types::Action::Allow);
    assert_eq!(rules[1].action, microsandbox_types::Action::Deny);
    let rates = saved
        .rate_limiter
        .as_ref()
        .and_then(SavedValue::value)
        .unwrap();
    assert_eq!(
        rates
            .egress
            .as_ref()
            .unwrap()
            .bandwidth
            .as_ref()
            .unwrap()
            .size,
        4096
    );
    assert!(rates.ingress.is_none());
    raw["network"]["rate_limiter"]["egress"]["bandwidth"]
        .as_object_mut()
        .unwrap()
        .remove("one_time_burst");
    assert!(is_unknown(
        &capture(&raw, NetworkCaptureBindings::default())
            .unwrap()
            .rate_limiter
    ));
    raw["network"]["policy"]["rules"][0]
        .as_object_mut()
        .unwrap()
        .remove("protocols");
    assert!(is_unknown(
        &capture(&raw, NetworkCaptureBindings::default())
            .unwrap()
            .policy
    ));
}

#[test]
fn network_capture_secrets_retain_requirements_without_material_or_source() {
    let mut raw = source();
    raw["network"]["secrets"] = json!({
        "passthrough_hosts": null, "violation_action": "block", "secrets": [{
            "env_var": "TOKEN", "value": "PRIVATE_SECRET", "placeholder": "placeholder-token",
            "allowed_hosts": [{"exact": "example.com"}], "passthrough_hosts": [], "violation_action": null,
            "require_tls_identity": true,
            "substitution": {"headers": true, "header_fields": ["Authorization"], "query": false, "body": false}
        }]
    });
    let bindings = NetworkCaptureBindings {
        secrets: [("TOKEN".into(), reference("token"))].into(),
        ..Default::default()
    };
    let saved = capture(&raw, bindings).unwrap();
    let text = serde_json::to_string(&saved).unwrap();
    assert!(!text.contains("PRIVATE_SECRET"));
    assert!(text.contains("placeholder-token"));
    assert_eq!(
        saved
            .secrets
            .as_ref()
            .and_then(SavedValue::value)
            .unwrap()
            .entries[0]
            .binding
            .id,
        "token"
    );
    let error = capture(&raw, NetworkCaptureBindings::default())
        .unwrap_err()
        .to_string();
    assert!(error.contains("SCFG_BINDING"));
    assert!(!error.contains("PRIVATE_SECRET"));
}

#[test]
fn network_capture_http_omission_precedes_literal_validation() {
    let mut raw = source();
    raw["network"]["http"]["deny_message"] = json!("PRIVATE_RESPONSE".repeat(100_000));
    assert!(capture(&raw, NetworkCaptureBindings::default()).is_err());
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let saved = adapter
        .project_network(
            NetworkCaptureBindings::default(),
            &NetworkCaptureControls { omit_http: true },
        )
        .unwrap();
    assert!(saved.http.is_none());
    assert!(
        !serde_json::to_string(&saved)
            .unwrap()
            .contains("PRIVATE_RESPONSE")
    );
}

#[test]
fn network_capture_supports_recorded_aliases_without_guessing() {
    let mut raw = gateway_source();
    let net = raw["network"].as_object_mut().unwrap();
    let count = net.remove("max_connections").unwrap();
    net.insert("max_tcp_connections".into(), count);
    let tls = net["tls"].as_object_mut().unwrap();
    let ca = tls.remove("intercept_ca").unwrap();
    tls.insert("ca".into(), ca);
    let scoped = tls.remove("scoped_upstream_ca_cert").unwrap();
    tls.insert("scoped_upstream_ca_certs".into(), scoped);
    let saved = capture(&raw, gateway_bindings()).unwrap();
    assert_eq!(
        saved
            .max_tcp_connections
            .as_ref()
            .and_then(SavedValue::value),
        Some(&0)
    );
    assert!(saved.tls.as_ref().and_then(SavedValue::value).is_some());
}

#[test]
fn network_capture_proxy_authentication_is_explicit_for_every_protocol() {
    for (proxy, credentials) in [
        (
            json!({"protocol": "http_connect", "address": "PRIVATE_PROXY"}),
            false,
        ),
        (
            json!({"protocol": "socks4", "address": "PRIVATE_PROXY", "user_id": null}),
            false,
        ),
        (
            json!({"protocol": "socks4", "address": "PRIVATE_PROXY", "user_id": ""}),
            true,
        ),
        (
            json!({"protocol": "socks5", "address": "PRIVATE_PROXY", "credentials": null}),
            false,
        ),
        (
            json!({"protocol": "socks5", "address": "PRIVATE_PROXY", "credentials": {"username": "PRIVATE_USER", "password": {"kind": "env", "var": "PRIVATE_PASSWORD_SOURCE"}}}),
            true,
        ),
    ] {
        let mut raw = source();
        raw["network"]["outbound_proxy"] = proxy;
        let bindings = |authenticated: bool| NetworkCaptureBindings {
            proxy: Some(ProxyCaptureBindings {
                endpoint: reference("proxy"),
                credentials: authenticated.then(|| reference("auth")),
            }),
            ..Default::default()
        };
        let saved = capture(&raw, bindings(credentials)).unwrap();
        assert!(!serde_json::to_string(&saved).unwrap().contains("PRIVATE_"));
        assert!(capture(&raw, bindings(!credentials)).is_err());
    }
}

#[test]
fn network_capture_generated_interception_still_requires_identity() {
    let mut raw = gateway_source();
    raw["network"]["tls"]["intercept_ca"] = json!({"cert_path": null, "key_path": null});
    capture(&raw, gateway_bindings()).unwrap();
    let mut bindings = gateway_bindings();
    bindings.tls.as_mut().unwrap().intercept_ca = None;
    assert!(
        capture(&raw, bindings)
            .unwrap_err()
            .to_string()
            .contains("SCFG_BINDING")
    );
    raw["network"]["tls"]["intercept_ca"]
        .as_object_mut()
        .unwrap()
        .remove("key_path");
    let mut bindings = gateway_bindings();
    bindings.tls = None;
    assert!(is_unknown(&capture(&raw, bindings).unwrap().tls));
}

#[test]
fn network_capture_nested_missing_fields_cannot_gain_implicit_authority() {
    let mut raw = source();
    // Historical omission has no private evidence distinguishing a known default.
    raw.as_object_mut().unwrap().remove("field_presence");
    raw["network"]["ports"] =
        json!([{"guest_port": 80, "host_port": 59999, "host_bind": "PRIVATE_LISTENER"}]);
    assert!(is_unknown(
        &capture(&raw, NetworkCaptureBindings::default())
            .unwrap()
            .ports
    ));
    let error = capture(
        &raw,
        NetworkCaptureBindings {
            listeners: vec![reference("listener")],
            ..Default::default()
        },
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("SCFG_BINDING"));
    assert!(!error.contains("PRIVATE_LISTENER"));
    raw["network"]["max_connections"] = Value::Null;
    assert!(matches!(
        capture(&raw, NetworkCaptureBindings::default())
            .unwrap()
            .max_tcp_connections,
        Some(SavedValue::Default {})
    ));
    raw["network"]
        .as_object_mut()
        .unwrap()
        .remove("max_connections");
    assert!(is_unknown(
        &capture(&raw, NetworkCaptureBindings::default())
            .unwrap()
            .max_tcp_connections
    ));
}
