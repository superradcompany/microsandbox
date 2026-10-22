//! Policy preservation and credential-exclusion checks for the portable network section.

use std::collections::BTreeMap;

use serde_json::{Value, json};

use crate::{
    HostPattern, SecretEntry, SecretSource, SecretSubstitution, SecretViolationAction,
    SecretsConfig,
};

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn policy_order_and_disabled_safeguards_are_recorded_not_silently_repaired() {
    let mut value = network();
    value["strict"] = recorded(json!(false));
    value["dns"]["value"]["rebind_protection"] = json!(false);
    value["tls"]["value"]["verify_upstream"] = json!(false);
    value["tls"]["value"]["block_quic_on_intercept"] = json!(false);
    value["tls"]["value"]["bypass"] = json!(["*.example.com"]);
    value["policy"] = recorded(json!({
        "default_egress":"deny", "default_ingress":"deny", "rules":[
            {"direction":"egress", "destination":{"domain":"allowed.example.com"}, "protocols":["tcp"], "ports":[{"start":443,"end":443}], "action":"allow"},
            {"direction":"egress", "destination":"any", "protocols":[], "ports":[], "action":"deny"}
        ]
    }));
    let parsed = parse(&value);
    assert_eq!(serde_json::to_value(parsed).unwrap(), value);
    // Parsing is not authorization. The resolver must require explicit consent
    // for applicable relaxations and enforce mandatory destination constraints.
}

#[test]
fn unknown_network_fields_never_admit_host_paths_or_credentials() {
    let base = network();
    for path in [
        "/outbound_proxy/value/address",
        "/outbound_proxy/value/password",
        "/outbound_proxy/value/credentials/value",
        "/outbound_proxy/value/endpoint/source",
        "/tls/value/key_path",
        "/tls/value/intercept_ca/cert_path",
        "/tls/value/upstream_ca_cert",
        "/dns/value/nameservers",
        "/ports/value/0/host_port",
        "/ports/value/0/host_bind",
        "/secrets/value/entries/0/value",
        "/secrets/value/entries/0/source",
        "/secrets/value/entries/0/substitution/authorization_header",
        "/secrets/value/entries/0/binding/value",
        "/tls/value/scoped_upstream_cas/0/path",
        "/tls/value/scoped_verify_upstream/0/approved",
    ] {
        let mut value = base.clone();
        let (parent, key) = path.rsplit_once('/').unwrap();
        value
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert(key.into(), json!("SENTINEL_PRIVATE_MATERIAL"));
        let error = reject(&value, "SCFG_SCHEMA");
        assert!(!error.contains("SENTINEL"));
    }
    for key in [
        "interface",
        "source_config",
        "trust_host_cas",
        "safe_to_apply",
        "profile",
    ] {
        let mut value = base.clone();
        value[key] = json!("SENTINEL");
        reject(&value, "SCFG_SCHEMA");
    }
}

#[test]
fn all_nested_operational_records_reject_extra_fields() {
    let mut base = network();
    base["policy"] = recorded(
        json!({"default_egress":"deny", "default_ingress":"deny", "rules":[
            {"direction":"egress", "destination":{"domain":"example.com"}, "protocols":["tcp"], "ports":[{"start":80,"end":443}], "action":"allow"}
        ]}),
    );
    for path in [
        "/policy/value",
        "/policy/value/rules/0",
        "/policy/value/rules/0/ports/0",
        "/rate_limiter/value",
        "/rate_limiter/value/egress",
        "/rate_limiter/value/egress/bandwidth",
        "/http/value",
        "/guest_trust/value/0",
    ] {
        let mut value = base.clone();
        value
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("SENTINEL_FIELD".into(), json!(true));
        let error = reject(&value, "SCFG_SCHEMA");
        assert!(!error.contains("SENTINEL"));
    }
    let mut value = base;
    value["policy"]["value"]["rules"][0]["destination"] =
        json!({"domain":"example.com", "safe_to_apply":true});
    reject(&value, "SCFG_SCHEMA");
}

#[test]
fn zero_unlimited_and_explicit_empty_values_remain_distinct() {
    let value = json!({
        "max_tcp_connections":recorded(json!(0)), "max_inbound_tcp_connections":recorded(json!(0)),
        "max_udp_connections":recorded(json!(0)), "nat64_prefixes":recorded(json!([])),
        "enabled":recorded(json!(false)), "ports":recorded(json!([])),
        "http":recorded(json!({"deny_response":true,"deny_response_format":"json","network_deny_message":""}))
    });
    assert_eq!(serde_json::to_value(parse(&value)).unwrap(), value);
    for field in [
        "enabled",
        "policy",
        "strict",
        "dns",
        "tls",
        "secrets",
        "max_tcp_connections",
        "max_inbound_tcp_connections",
        "max_udp_connections",
        "tcp_accept_queue_size",
        "rate_limiter",
        "nat64_prefixes",
        "ports",
        "guest_trust",
        "http",
        "outbound_proxy",
    ] {
        reject(&json!({field:null}), "SCFG_SCHEMA");
    }
}

#[test]
fn malformed_network_numbers_and_limits_fail_before_activation() {
    for limit in [json!(1.5), json!(9_007_199_254_740_992_u64), json!(-1)] {
        reject(&json!({"max_tcp_connections":recorded(limit)}), "SCFG_");
    }
    for queue in [0_u32, 2_147_483_648] {
        reject(
            &json!({"tcp_accept_queue_size":recorded(json!(queue))}),
            "active.network.tcp_accept_queue_size",
        );
    }
    reject(
        &json!({"nat64_prefixes":recorded(json!(["64:ff9b::/64"]))}),
        "active.network.nat64_prefixes",
    );
    for path in ["size", "refill_time_ms"] {
        let mut value = network();
        value["rate_limiter"]["value"]["egress"]["bandwidth"][path] = json!(0);
        reject(&value, "active.network.rate_limiter");
    }
    reject(
        &json!({"rate_limiter":recorded(json!({"egress":{}}))}),
        "active.network.rate_limiter",
    );
    let mut typed = parse(&network());
    typed.max_udp_connections = Some(SavedValue::Value {
        value: u64::MAX,
        origin: SavedOrigin::Configured,
    });
    assert!(
        typed
            .validate()
            .unwrap_err()
            .to_string()
            .contains("JSON-safe")
    );
}

#[test]
fn listener_identity_allows_multiple_bindings_for_the_same_guest_service() {
    let mut value = network();
    value["ports"] = recorded(json!([
        {"guest_port":80,"protocol":"tcp","binding":{"id":"listener.first"}},
        {"guest_port":80,"protocol":"tcp","binding":{"id":"listener.second"}},
        {"guest_port":80,"protocol":"udp","binding":{"id":"listener.first"}}
    ]));
    parse(&value);
    value["ports"]["value"][1]["binding"]["id"] = json!("listener.first");
    reject(&value, "SCFG_IDENTITY");
}

#[test]
fn duplicate_binding_and_secret_identities_are_rejected() {
    let mut value = network();
    value["dns"]["value"]["resolvers"] = json!([{"id":"dns"},{"id":"dns"}]);
    reject(&value, "SCFG_IDENTITY");

    let mut value = network();
    let secret = value["secrets"]["value"]["entries"][0].clone();
    value["secrets"]["value"]["entries"]
        .as_array_mut()
        .unwrap()
        .push(secret);
    reject(&value, "SCFG_IDENTITY");
    value["secrets"]["value"]["entries"][1]["env_var"] = json!("OTHER");
    reject(&value, "SCFG_IDENTITY");
}

#[test]
fn secret_projection_excludes_resolved_material_and_host_source_names() {
    let source = source_secrets();
    let portable = SavedSecretsConfig::from_source(&source, &bindings()).unwrap();
    let bytes = serde_json::to_vec(&portable).unwrap();
    let text = String::from_utf8(bytes.clone()).unwrap();
    assert!(!text.contains("SENTINEL_RESOLVED"));
    assert!(!text.contains("SENTINEL_HOST_SOURCE"));
    assert!(!text.contains("\"source\""));
    assert!(!text.contains("\"value\""));
    let actual: Value = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(actual["entries"][0]["placeholder"], "$MSB_TOKEN");
    assert_eq!(actual["entries"][0]["binding"]["id"], "secret.token");
    assert_eq!(
        actual["entries"][0]["substitution"]["header_fields"],
        json!(["Authorization"])
    );
    assert_eq!(
        actual["entries"][0]["allowed_hosts"],
        json!([{"exact":"api.example.com"}])
    );
    assert_eq!(
        source.secrets[0].value.as_str(),
        "SENTINEL_RESOLVED_CREDENTIAL"
    );
    parse(&json!({"secrets":recorded(actual)}));
}

#[test]
fn missing_or_misspelled_secret_bindings_never_fall_back_to_source() {
    let source = source_secrets();
    for mappings in [
        BTreeMap::new(),
        BTreeMap::from([(
            "TYPO".into(),
            SavedBindingReference {
                id: "secret.token".into(),
            },
        )]),
    ] {
        let error = SavedSecretsConfig::from_source(&source, &mappings)
            .err()
            .expect("missing binding must fail")
            .to_string();
        assert!(error.contains("SCFG_BINDING"));
        assert!(!error.contains("SENTINEL"));
    }
}

#[test]
fn secret_projection_uses_the_existing_substitution_validity_rules() {
    let mut source = source_secrets();
    source.secrets[0].substitution.headers = false;
    let error = SavedSecretsConfig::from_source(&source, &bindings())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("invalid placeholder or substitution policy"));
    assert!(!error.contains("SENTINEL"));
}

#[test]
fn network_duplicate_keys_and_secret_values_are_redacted_on_errors() {
    for bytes in [
        br#"{"SENTINEL":0,"SENTINEL":1}"#.as_slice(),
        br#"{"tls":{"state":"SENTINEL"}}"#.as_slice(),
        br#"{"outbound_proxy":{"state":"value","origin":"configured","value":{"protocol":"SENTINEL","endpoint":{"id":"proxy"}}}}"#.as_slice(),
    ] {
        let error = SavedNetworkConfig::from_bytes(bytes).unwrap_err().to_string();
        assert!(!error.contains("SENTINEL"));
        assert!(error.contains("active.network"));
    }
    assert!(!format!("{:?}", parse(&network())).contains("api.example.com"));
}

pub(super) fn network() -> Value {
    json!({
        "enabled":recorded(json!(true)),
        "dns":recorded(json!({"rebind_protection":true,"query_timeout_ms":5000,"resolvers":[{"id":"dns.primary"}]})),
        "tls":recorded(json!({
            "enabled":true,"intercepted_ports":[443],"bypass":[],"verify_upstream":true,"block_quic_on_intercept":true,
            "upstream_cas":[{"id":"tls.upstream"}],"intercept_ca":{"id":"tls.intercept"},
            "scoped_upstream_cas":[{"pattern":"*.example.com","binding":{"id":"tls.scoped"}}],
            "scoped_verify_upstream":[{"pattern":"verified.example.com","verify":true}]
        })),
        "rate_limiter":recorded(json!({"egress":{"bandwidth":{"size":1024,"refill_time_ms":1000,"one_time_burst":0}}})),
        "ports":recorded(json!([{"guest_port":80,"protocol":"tcp","binding":{"id":"http.listener"}}])),
        "guest_trust":recorded(json!([{"id":"trust.corporate"}])),
        "http":recorded(json!({"deny_response":true,"deny_response_format":"json"})),
        "outbound_proxy":recorded(json!({"protocol":"socks5","endpoint":{"id":"proxy.endpoint"},"credentials":{"id":"proxy.auth"}})),
        "secrets":recorded(serde_json::to_value(SavedSecretsConfig::from_source(&source_secrets(), &bindings()).unwrap()).unwrap())
    })
}

fn source_secrets() -> SecretsConfig {
    SecretsConfig {
        passthrough_hosts: Some(vec![]),
        violation_action: SecretViolationAction::BlockAndLog,
        secrets: vec![SecretEntry {
            env_var: "TOKEN".into(),
            value: "SENTINEL_RESOLVED_CREDENTIAL".to_owned().into(),
            source: Some(SecretSource::env("SENTINEL_HOST_SOURCE")),
            placeholder: "$MSB_TOKEN".into(),
            allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
            substitution: SecretSubstitution {
                headers: true,
                header_fields: vec!["Authorization".into()],
                query: false,
                body: false,
            },
            passthrough_hosts: vec![],
            violation_action: None,
            require_tls_identity: true,
        }],
    }
}

fn bindings() -> BTreeMap<String, SavedBindingReference> {
    BTreeMap::from([(
        "TOKEN".into(),
        SavedBindingReference {
            id: "secret.token".into(),
        },
    )])
}

fn recorded(value: Value) -> Value {
    json!({"state":"value","value":value,"origin":"configured"})
}

fn parse(value: &Value) -> SavedNetworkConfig {
    SavedNetworkConfig::from_bytes(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn reject(value: &Value, expected: &str) -> String {
    let error = SavedNetworkConfig::from_bytes(&serde_json::to_vec(value).unwrap())
        .unwrap_err()
        .to_string();
    assert!(
        error.contains(expected),
        "expected {expected}; received {error}"
    );
    error
}
