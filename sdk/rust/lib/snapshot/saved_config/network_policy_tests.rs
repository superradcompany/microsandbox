//! Gateway policy selection is independent of credentials, binding preparation and activation.

use std::collections::BTreeSet;

use microsandbox_types::snapshot::saved_config::*;
use microsandbox_types::{
    DnsConfigPatch, HttpConfigPatch, NetworkPolicy, NetworkRateLimiterConfigPatch, NetworkSpec,
    NetworkSpecPatch, TlsConfigPatch,
};
use serde_json::{Value, json};

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn record(value: Value) -> Value {
    json!({"state":"value", "value":value, "origin":"configured"})
}

fn source() -> SavedNetworkConfig {
    let value = json!({
        "enabled": record(json!(true)),
        "strict": record(json!(true)),
        "policy": record(json!({"default_egress":"deny","default_ingress":"deny","rules":[
            {"direction":"egress","destination":{"domain":"SENTINEL.example"},"protocols":["tcp"],"ports":[{"start":443,"end":443}],"action":"allow"},
            {"direction":"egress","destination":"any","protocols":[],"ports":[],"action":"deny"}
        ]})),
        "dns": record(json!({"rebind_protection":true,"query_timeout_ms":0,"resolvers":[{"id":"dns"}]})),
        "tls": record(json!({"enabled":true,"intercepted_ports":[443,8443],"bypass":[],"verify_upstream":true,"block_quic_on_intercept":true,
            "upstream_cas":[{"id":"ca"}],"scoped_upstream_cas":[],"scoped_verify_upstream":[],"intercept_ca":{"id":"identity"}})),
        "max_tcp_connections": record(json!(0)),
        "max_inbound_tcp_connections": record(json!(12)),
        "max_udp_connections": record(json!(0)),
        "tcp_accept_queue_size": record(json!(128)),
        "nat64_prefixes": record(json!([])),
        "rate_limiter": record(json!({"egress":{"bandwidth":{"size":8192,"refill_time_ms":1000,"one_time_burst":0}},"ingress":{"ops":{"size":5,"refill_time_ms":1,"one_time_burst":2}}})),
        "http": record(json!({"deny_response":false,"deny_response_format":"json","deny_message":"SENTINEL_MESSAGE","network_deny_message":"","secret_deny_message":""})),
        "ports": record(json!([{"guest_port":8080,"protocol":"tcp","binding":{"id":"listener"}}])),
        "guest_trust": record(json!([{"id":"ca"}])),
        "outbound_proxy": record(json!({"protocol":"socks5","endpoint":{"id":"proxy"},"credentials":{"id":"auth"}}))
    });
    // Use the strict reader too: tests must exercise representable portable metadata.
    SavedNetworkConfig::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn baseline() -> DestinationNetworkBaseline {
    DestinationNetworkBaseline {
        strict: true,
        tls_enabled: true,
        intercepted_ports: vec![443],
    }
}

fn select(saved: &SavedNetworkConfig, patch: &NetworkSpecPatch) -> NetworkPolicySelection {
    select_network_policy_defaults(
        saved,
        patch,
        &[],
        SnapshotConfigMode::Saved,
        false,
        &baseline(),
    )
    .unwrap()
}

fn concrete_mut<T>(field: &mut Option<SavedValue<T>>) -> &mut T {
    match field.as_mut().unwrap() {
        SavedValue::Value { value, .. } => value,
        _ => panic!("concrete fixture"),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn literals_keep_policy_order_false_zero_empty_and_independent_limits() {
    let saved = source();
    let before = serde_json::to_vec(&saved).unwrap();
    let selected = select(&saved, &NetworkSpecPatch::new());
    assert!(selected.required_approvals.is_empty());
    assert!(selected.unknown_fields.is_empty());
    assert!(selected.defaulted_fields.is_empty());
    assert!(selected.absent_fields.is_empty());
    assert!(!format!("{selected:?}").contains("SENTINEL"));
    let mut actual = NetworkSpec::default();
    selected.defaults.apply_to(&mut actual);
    let policy = actual.policy.unwrap();
    assert_eq!(policy.rules.len(), 2);
    assert_eq!(policy.rules[0].action, microsandbox_types::Action::Allow);
    assert_eq!(policy.rules[1].action, microsandbox_types::Action::Deny);
    assert_eq!(actual.max_tcp_connections, Some(0));
    assert_eq!(actual.max_inbound_tcp_connections, Some(12));
    assert_eq!(actual.max_udp_connections, Some(0));
    assert_eq!(actual.tcp_accept_queue_size, Some(128));
    assert!(actual.nat64_prefixes.is_empty());
    assert!(!actual.http.deny_response);
    assert_eq!(actual.http.network_deny_message.as_deref(), Some(""));
    assert_eq!(actual.dns.unwrap().query_timeout_ms, 0);
    let rate = actual.rate_limiter.unwrap();
    assert_eq!(rate.egress.unwrap().bandwidth.unwrap().one_time_burst, 0);
    assert_eq!(rate.ingress.unwrap().ops.unwrap().size, 5);
    assert_eq!(serde_json::to_vec(&saved).unwrap(), before);
}

#[test]
fn sparse_dns_and_tls_overrides_do_not_erase_sibling_policy_or_copy_endpoints() {
    let saved = source();
    let patch = NetworkSpecPatch::new()
        .dns(
            DnsConfigPatch::new()
                .query_timeout_ms(25)
                .nameservers(vec!["SENTINEL_DNS".into()]),
        )
        .tls(
            TlsConfigPatch::new()
                .bypass(vec![])
                .upstream_ca_cert(vec!["SENTINEL_CA".into()]),
        );
    let selected = select(&saved, &patch);
    let dns = selected.defaults.dns.as_ref().unwrap();
    assert_eq!(dns.rebind_protection, Some(true));
    assert!(dns.query_timeout_ms.is_none());
    assert!(dns.nameservers.is_none());
    let tls = selected.defaults.tls.as_ref().unwrap();
    assert!(tls.bypass.is_none());
    assert_eq!(tls.enabled, Some(true));
    assert_eq!(tls.verify_upstream, Some(true));
    assert!(tls.upstream_ca_cert.is_none());
    assert!(tls.intercept_ca.is_none());
    assert!(tls.cache.is_none());
    let mut final_config = NetworkSpec::default();
    selected.defaults.apply_to(&mut final_config);
    patch.apply_to(&mut final_config);
    assert_eq!(final_config.dns.unwrap().query_timeout_ms, 25);
    let tls = final_config.tls.unwrap();
    assert!(tls.bypass.is_empty());
    assert!(tls.enabled && tls.verify_upstream);
    assert_eq!(tls.upstream_ca_cert[0].to_str(), Some("SENTINEL_CA"));
}

#[test]
fn ordered_lists_replace_whole_lists_and_never_concatenate_saved_rules() {
    let saved = source();
    let replacement: NetworkPolicy = serde_json::from_value(
        json!({"default_egress":"allow","default_ingress":"deny","rules":[]}),
    )
    .unwrap();
    let patch = NetworkSpecPatch::new()
        .policy(replacement.clone())
        .tls(
            TlsConfigPatch::new()
                .intercepted_ports(vec![9443])
                .scoped_verify_upstream(vec![]),
        )
        .nat64_prefixes(vec![]);
    let selected = select(&saved, &patch);
    assert!(selected.defaults.policy.is_none());
    assert!(
        selected
            .defaults
            .tls
            .as_ref()
            .unwrap()
            .intercepted_ports
            .is_none()
    );
    assert!(selected.defaults.nat64_prefixes.is_none());
    let mut actual = NetworkSpec::default();
    selected.defaults.apply_to(&mut actual);
    patch.apply_to(&mut actual);
    assert_eq!(actual.policy.unwrap(), replacement);
    assert_eq!(actual.tls.unwrap().intercepted_ports, vec![9443]);
}

#[test]
fn saved_relaxations_need_each_field_approval_and_explicit_choices_only_mask_their_fields() {
    let mut saved = source();
    *concrete_mut(&mut saved.strict) = false;
    concrete_mut(&mut saved.dns).rebind_protection = false;
    let tls = concrete_mut(&mut saved.tls);
    tls.enabled = false;
    tls.intercepted_ports = vec![];
    tls.bypass = vec!["SENTINEL.example".into()];
    tls.verify_upstream = false;
    tls.block_quic_on_intercept = false;
    tls.scoped_verify_upstream = vec![SavedScopedVerification {
        pattern: "SENTINEL.example".into(),
        verify: false,
    }];
    let selected = select(&saved, &NetworkSpecPatch::new());
    assert_eq!(selected.required_approvals.len(), 8);
    let patch = NetworkSpecPatch::new()
        .strict(false)
        .dns(DnsConfigPatch::new().rebind_protection(true))
        .tls(TlsConfigPatch::new().verify_upstream(false).bypass(vec![]));
    let selected = select(&saved, &patch);
    assert_eq!(selected.required_approvals.len(), 4);
    assert!(
        !selected
            .required_approvals
            .contains(&NetworkPolicyApproval::RelaxedAuthority)
    );
    assert!(
        !selected
            .required_approvals
            .contains(&NetworkPolicyApproval::DisabledDnsRebindProtection)
    );
    assert!(
        !selected
            .required_approvals
            .contains(&NetworkPolicyApproval::DisabledUpstreamVerification)
    );
    assert!(
        !selected
            .required_approvals
            .contains(&NetworkPolicyApproval::TlsBypass)
    );
    // Explicit false is intent, not an exemption from the later mandatory-policy check.
    assert!(selected.defaults.strict.is_none());
    assert!(!format!("{selected:?}").contains("SENTINEL"));
}

#[test]
fn inspection_approval_uses_destination_baseline_not_an_artifact_claim() {
    let mut saved = source();
    *concrete_mut(&mut saved.strict) = false;
    concrete_mut(&mut saved.tls).enabled = false;
    concrete_mut(&mut saved.tls).intercepted_ports = vec![];
    let relaxed = DestinationNetworkBaseline {
        strict: false,
        tls_enabled: false,
        intercepted_ports: vec![],
    };
    assert!(
        select_network_policy_defaults(
            &saved,
            &NetworkSpecPatch::new(),
            &[],
            SnapshotConfigMode::Saved,
            false,
            &relaxed
        )
        .unwrap()
        .required_approvals
        .is_empty()
    );
    assert_eq!(
        select(&saved, &NetworkSpecPatch::new())
            .required_approvals
            .len(),
        3
    );
}

#[test]
fn fresh_mode_drops_optional_policy_but_full_nic_and_compatibility_remain() {
    let saved = source();
    for full in [false, true] {
        let selected = select_network_policy_defaults(
            &saved,
            &NetworkSpecPatch::new(),
            &[],
            SnapshotConfigMode::Fresh,
            full,
            &baseline(),
        )
        .unwrap();
        assert_eq!(selected.defaults.enabled, full.then_some(true));
        assert!(selected.defaults.policy.is_none());
        assert!(selected.defaults.dns.is_none());
        assert!(selected.defaults.tls.is_none());
        assert!(selected.defaults.http.deny_message.is_none());
        assert!(selected.required_approvals.is_empty());
        assert_eq!(selected.requires_full_compatibility, full);
    }
    for mode in [SnapshotConfigMode::Fresh, SnapshotConfigMode::Saved] {
        assert!(
            select_network_policy_defaults(
                &saved,
                &NetworkSpecPatch::new().enabled(false),
                &[],
                mode,
                true,
                &baseline()
            )
            .unwrap_err()
            .to_string()
            .contains("SCFG_FULL_STATE")
        );
        assert!(
            select_network_policy_defaults(
                &saved,
                &NetworkSpecPatch::new(),
                &[NetworkPolicyClear::Enabled],
                mode,
                true,
                &baseline()
            )
            .is_err()
        );
        assert!(
            select_network_policy_defaults(
                &saved,
                &NetworkSpecPatch::new().enabled(true),
                &[],
                mode,
                true,
                &baseline()
            )
            .unwrap()
            .requires_full_compatibility
        );
    }
}

#[test]
fn unknown_nested_fields_survive_partial_override_and_clear_individually() {
    let mut saved = source();
    saved.dns = Some(SavedValue::Unknown {
        reason: SavedUnknownReason::NotObserved,
    });
    saved.tls = Some(SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    });
    saved.enabled = Some(SavedValue::Unknown {
        reason: SavedUnknownReason::NotObserved,
    });
    let patch = NetworkSpecPatch::new()
        .dns(DnsConfigPatch::new().query_timeout_ms(1))
        .tls(TlsConfigPatch::new().verify_upstream(true));
    let selected = select_network_policy_defaults(
        &saved,
        &patch,
        &[NetworkPolicyClear::TlsBypass],
        SnapshotConfigMode::Saved,
        true,
        &baseline(),
    )
    .unwrap();
    assert!(selected.unknown_fields.contains("network.enabled"));
    assert!(
        selected
            .unknown_fields
            .contains("network.dns.rebind_protection")
    );
    assert!(
        !selected
            .unknown_fields
            .contains("network.dns.query_timeout_ms")
    );
    assert!(
        !selected
            .unknown_fields
            .contains("network.tls.verify_upstream")
    );
    assert!(!selected.unknown_fields.contains("network.tls.bypass"));
    assert!(selected.unknown_fields.contains("network.tls.enabled"));
    assert!(selected.requires_full_compatibility);
}

#[test]
fn known_absence_default_and_omission_remain_distinct_for_final_assembly() {
    let mut saved = source();
    concrete_mut(&mut saved.rate_limiter).egress = None;
    concrete_mut(&mut saved.http).deny_message = None;
    saved.strict = Some(SavedValue::Default {});
    saved.max_tcp_connections = None;
    let selected = select(&saved, &NetworkSpecPatch::new());
    assert_eq!(
        selected.absent_fields,
        BTreeSet::from(["network.rate_limiter.egress", "network.http.deny_message"])
    );
    assert_eq!(
        selected.defaulted_fields,
        BTreeSet::from(["network.strict"])
    );
    assert!(
        selected
            .defaults
            .rate_limiter
            .as_ref()
            .unwrap()
            .egress
            .is_none()
    );
    assert!(
        selected
            .defaults
            .rate_limiter
            .as_ref()
            .unwrap()
            .ingress
            .is_some()
    );
    let explicit = NetworkSpecPatch::new()
        .rate_limiter(NetworkRateLimiterConfigPatch::new().egress(
            microsandbox_types::RateLimiterConfig {
                ops: Some(microsandbox_types::TokenBucketConfig {
                    size: 1,
                    refill_time_ms: 1,
                    one_time_burst: 0,
                }),
                bandwidth: None,
            },
        ))
        .http(HttpConfigPatch::new().deny_message("explicit".into()));
    assert!(select(&saved, &explicit).absent_fields.is_empty());
}

#[test]
fn scoped_clears_preserve_other_fields_and_do_not_rewrite_binding_requirements() {
    let saved = source();
    let original = collect_binding_uses(&SavedRuntimeConfig::default(), &saved).unwrap();
    let clears = [
        NetworkPolicyClear::DnsQueryTimeout,
        NetworkPolicyClear::TlsBypass,
        NetworkPolicyClear::EgressRateLimit,
        NetworkPolicyClear::HttpDenyMessage,
        NetworkPolicyClear::Policy,
    ];
    let mut reverse = clears.to_vec();
    reverse.reverse();
    reverse.push(NetworkPolicyClear::Policy);
    for clears in [&clears[..], reverse.as_slice()] {
        let selected = select_network_policy_defaults(
            &saved,
            &NetworkSpecPatch::new(),
            clears,
            SnapshotConfigMode::Saved,
            false,
            &baseline(),
        )
        .unwrap();
        assert_eq!(selected.cleared_fields.len(), 5);
        assert!(selected.defaults.policy.is_none());
        assert_eq!(
            selected.defaults.dns.as_ref().unwrap().rebind_protection,
            Some(true)
        );
        assert!(
            selected
                .defaults
                .dns
                .as_ref()
                .unwrap()
                .query_timeout_ms
                .is_none()
        );
        assert!(
            selected
                .defaults
                .rate_limiter
                .as_ref()
                .unwrap()
                .egress
                .is_none()
        );
        assert!(
            selected
                .defaults
                .rate_limiter
                .as_ref()
                .unwrap()
                .ingress
                .is_some()
        );
        assert!(selected.defaults.http.deny_message.is_none());
        assert_eq!(
            selected.defaults.http.secret_deny_message.as_deref(),
            Some("")
        );
        // This stage cannot fulfill, waive or copy a path/secret/listener binding.
        assert!(selected.defaults.ports.is_none());
        assert!(selected.defaults.outbound_proxy.is_none());
        assert!(selected.defaults.trust_host_cas.is_none());
        assert!(selected.defaults.secrets.is_none());
        assert!(selected.defaults.interface.is_none());
        assert_eq!(
            collect_binding_uses(&SavedRuntimeConfig::default(), &saved).unwrap(),
            original
        );
    }
}

#[test]
fn invalid_source_is_rejected_even_when_fresh_or_overridden_and_errors_do_not_leak() {
    let mut saved = source();
    concrete_mut(&mut saved.policy).rules[0].ports[0] = SavedPortRange { start: 5, end: 1 };
    for mode in [SnapshotConfigMode::Saved, SnapshotConfigMode::Fresh] {
        let error = select_network_policy_defaults(
            &saved,
            &NetworkSpecPatch::new().policy(NetworkPolicy {
                default_egress: microsandbox_types::Action::Deny,
                default_ingress: microsandbox_types::Action::Deny,
                rules: vec![],
            }),
            &[],
            mode,
            false,
            &baseline(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("SCFG_VALUE"));
        assert!(!error.contains("SENTINEL"));
    }
    let error = select_network_policy_defaults(
        &source(),
        &NetworkSpecPatch::new(),
        &vec![NetworkPolicyClear::Policy; MAX_SAVED_CONFIG_ENTRIES + 1],
        SnapshotConfigMode::Saved,
        false,
        &baseline(),
    )
    .unwrap_err()
    .to_string();
    assert!(error.contains("SCFG_LIMIT"));
}
