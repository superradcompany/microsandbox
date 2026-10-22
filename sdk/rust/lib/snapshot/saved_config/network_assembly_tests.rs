//! Native policy must not revive cleared fallback or consume destination resource inputs.

use microsandbox_types::snapshot::saved_config::SavedNetworkConfig;
use microsandbox_types::{
    DnsConfig, DnsConfigPatch, HttpConfigPatch, NetworkRateLimiterConfig,
    NetworkRateLimiterConfigPatch, NetworkSpec, NetworkSpecPatch, OutboundProxy, RateLimiterConfig,
    TlsConfig, TlsConfigPatch,
};
use serde_json::{Value, json};

use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn value(value: Value) -> Value {
    json!({"state":"value", "origin":"configured", "value":value})
}

fn saved(value: Value) -> SavedNetworkConfig {
    SavedNetworkConfig::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap()
}

fn baseline() -> DestinationNetworkBaseline {
    DestinationNetworkBaseline {
        strict: true,
        tls_enabled: true,
        intercepted_ports: vec![443, 8443],
    }
}

fn plan(
    saved: &SavedNetworkConfig,
    lower: &NetworkSpec,
    explicit: &NetworkSpecPatch,
    clears: &[NetworkPolicyClear],
) -> NetworkPolicyConfigurationPlan {
    prepare_network_policy_configuration(
        saved,
        lower,
        explicit,
        clears,
        SnapshotConfigMode::Saved,
        false,
        &baseline(),
    )
    .unwrap()
}

fn native(plan: &NetworkPolicyConfigurationPlan) -> NetworkSpec {
    let mut result = NetworkSpec::default();
    plan.apply_policy_to(&mut result).unwrap();
    result
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn absent_saved_values_remove_fallback_without_losing_other_directions() {
    let source = saved(json!({
        "rate_limiter":value(json!({})),
        "http":value(json!({"deny_response":true,"deny_response_format":"json"}))
    }));
    let mut lower = NetworkSpec::default();
    lower.http.deny_message = Some("old".into());
    lower.http.network_deny_message = Some("old".into());
    lower.http.secret_deny_message = Some("old".into());
    lower.rate_limiter = Some(NetworkRateLimiterConfig {
        egress: Some(RateLimiterConfig::default()),
        ingress: Some(RateLimiterConfig::default()),
    });
    let explicit = NetworkSpecPatch::new()
        .rate_limiter(NetworkRateLimiterConfigPatch::new().ingress(RateLimiterConfig::default()));
    let result = native(&plan(&source, &lower, &explicit, &[]));
    let limits = result.rate_limiter.unwrap();
    assert!(limits.egress.is_none());
    assert!(limits.ingress.is_some());
    assert!(result.http.deny_message.is_none());
    assert!(result.http.network_deny_message.is_none());
    assert!(result.http.secret_deny_message.is_none());
}

#[test]
fn explicit_clear_precedes_explicit_override_and_keeps_siblings() {
    let mut lower = NetworkSpec::default();
    lower.http.network_deny_message = Some("older".into());
    lower.http.secret_deny_message = Some("keep".into());
    lower.dns = Some(DnsConfig {
        query_timeout_ms: 7,
        ..Default::default()
    });
    let source = saved(json!({"max_tcp_connections":value(json!(55))}));
    let explicit = NetworkSpecPatch::new()
        .max_tcp_connections(0)
        .http(HttpConfigPatch::new().network_deny_message(String::new()));
    let result = native(&plan(
        &source,
        &lower,
        &explicit,
        &[
            NetworkPolicyClear::MaxTcpConnections,
            NetworkPolicyClear::HttpNetworkDenyMessage,
            NetworkPolicyClear::DnsQueryTimeout,
        ],
    ));
    assert_eq!(result.max_tcp_connections, Some(0));
    assert_eq!(result.http.network_deny_message.as_deref(), Some(""));
    assert_eq!(result.http.secret_deny_message.as_deref(), Some("keep"));
    assert_eq!(result.dns.unwrap().query_timeout_ms, 5000);
}

#[test]
fn builtin_tls_default_retains_relaxation_approvals() {
    let source = saved(json!({"tls":{"state":"default"}}));
    let lower = NetworkSpec {
        tls: Some(TlsConfig {
            enabled: true,
            intercepted_ports: vec![443, 8443],
            ..Default::default()
        }),
        ..Default::default()
    };
    let plan = plan(&source, &lower, &NetworkSpecPatch::new(), &[]);
    let result = native(&plan);
    assert!(!result.tls.unwrap().enabled);
    assert!(
        plan.selection()
            .required_approvals
            .contains(&NetworkPolicyApproval::DisabledTlsInterception)
    );
    assert!(
        plan.selection()
            .required_approvals
            .contains(&NetworkPolicyApproval::ReducedTlsInterception)
    );
    let explicit = NetworkSpecPatch::new().tls(
        TlsConfigPatch::new()
            .enabled(true)
            .intercepted_ports(vec![443, 8443]),
    );
    let overridden = prepare_network_policy_configuration(
        &source,
        &lower,
        &explicit,
        &[],
        SnapshotConfigMode::Saved,
        false,
        &baseline(),
    )
    .unwrap();
    assert!(overridden.selection().required_approvals.is_empty());
    assert!(native(&overridden).tls.unwrap().enabled);
}

#[test]
fn unknown_policy_cannot_return_an_apparently_valid_lower_fallback() {
    let source = saved(json!({"strict":{"state":"unknown","reason":"not_recorded"}}));
    let plan = plan(
        &source,
        &NetworkSpec::default(),
        &NetworkSpecPatch::new(),
        &[],
    );
    let mut target = NetworkSpec::default();
    target.http.network_deny_message = Some("SENTINEL_TARGET".into());
    let before = serde_json::to_value(&target).unwrap();
    let error = plan.apply_policy_to(&mut target).unwrap_err().to_string();
    assert!(error.contains("SCFG_UNKNOWN"));
    assert!(!error.contains("SENTINEL"));
    assert_eq!(serde_json::to_value(&target).unwrap(), before);
}

#[test]
fn policy_assembly_neither_copies_inputs_nor_erases_prepared_resources() {
    let source = SavedNetworkConfig::default();
    let lower = NetworkSpec {
        outbound_proxy: Some(OutboundProxy::HttpConnect {
            address: "LOWER_SENTINEL:3128".into(),
        }),
        dns: Some(DnsConfig {
            nameservers: vec!["LOWER_SENTINEL".into()],
            ..Default::default()
        }),
        ..Default::default()
    };
    let explicit = NetworkSpecPatch::new()
        .outbound_proxy(OutboundProxy::HttpConnect {
            address: "EXPLICIT_SENTINEL:3128".into(),
        })
        .dns(
            DnsConfigPatch::new()
                .nameservers(vec!["EXPLICIT_SENTINEL".into()])
                .query_timeout_ms(17),
        )
        .tls(
            TlsConfigPatch::new()
                .upstream_ca_cert(vec!["/missing/EXPLICIT_SENTINEL".into()])
                .enabled(true),
        );
    let plan = plan(&source, &lower, &explicit, &[]);
    assert!(!format!("{plan:?}").contains("SENTINEL"));
    let empty = native(&plan);
    assert!(!serde_json::to_string(&empty).unwrap().contains("SENTINEL"));
    let mut target = lower.clone();
    target.tls = Some(TlsConfig {
        upstream_ca_cert: vec!["/prepared/destination.pem".into()],
        ..Default::default()
    });
    let before_proxy = serde_json::to_value(&target.outbound_proxy).unwrap();
    plan.apply_policy_to(&mut target).unwrap();
    assert_eq!(
        serde_json::to_value(&target.outbound_proxy).unwrap(),
        before_proxy
    );
    assert_eq!(target.dns.as_ref().unwrap().nameservers, ["LOWER_SENTINEL"]);
    assert_eq!(target.dns.as_ref().unwrap().query_timeout_ms, 17);
    assert_eq!(
        target.tls.as_ref().unwrap().upstream_ca_cert,
        [std::path::PathBuf::from("/prepared/destination.pem")]
    );
    assert!(target.tls.unwrap().enabled);
}

#[test]
fn full_fresh_keeps_nic_evidence_and_refuses_conflicting_presence() {
    let source = saved(json!({"enabled":value(json!(false)),"strict":value(json!(false))}));
    let lower = NetworkSpec::default();
    let plan = prepare_network_policy_configuration(
        &source,
        &lower,
        &NetworkSpecPatch::new(),
        &[],
        SnapshotConfigMode::Fresh,
        true,
        &baseline(),
    )
    .unwrap();
    let result = native(&plan);
    assert!(!result.enabled);
    assert_eq!(result.strict, lower.strict);
    assert!(plan.selection().requires_full_compatibility);
    for (patch, clears) in [
        (NetworkSpecPatch::new().enabled(true), vec![]),
        (NetworkSpecPatch::new(), vec![NetworkPolicyClear::Enabled]),
    ] {
        assert!(
            prepare_network_policy_configuration(
                &source,
                &lower,
                &patch,
                &clears,
                SnapshotConfigMode::Fresh,
                true,
                &baseline()
            )
            .is_err()
        );
    }
}

#[test]
fn all_recorded_builtin_policy_fields_replace_prior_values() {
    let source = saved(json!({
        "enabled":{"state":"default"},"strict":{"state":"default"},
        "policy":{"state":"default"},"dns":{"state":"default"},
        "tls":{"state":"default"},"max_tcp_connections":{"state":"default"},
        "max_inbound_tcp_connections":{"state":"default"},"max_udp_connections":{"state":"default"},
        "tcp_accept_queue_size":{"state":"default"},"nat64_prefixes":{"state":"default"},
        "rate_limiter":{"state":"default"},"http":{"state":"default"}
    }));
    let mut lower = NetworkSpec {
        enabled: false,
        max_tcp_connections: Some(9),
        max_inbound_tcp_connections: Some(8),
        max_udp_connections: Some(7),
        tcp_accept_queue_size: Some(6),
        nat64_prefixes: vec![],
        ..Default::default()
    };
    lower.http.deny_response = false;
    lower.http.network_deny_message = Some("old".into());
    let result = native(&plan(&source, &lower, &NetworkSpecPatch::new(), &[]));
    let defaults = NetworkSpec::default();
    assert_eq!(result.enabled, defaults.enabled);
    assert_eq!(result.strict, defaults.strict);
    assert!(result.policy.is_none());
    assert_eq!(result.max_tcp_connections, defaults.max_tcp_connections);
    assert_eq!(
        result.max_inbound_tcp_connections,
        defaults.max_inbound_tcp_connections
    );
    assert_eq!(result.max_udp_connections, defaults.max_udp_connections);
    assert_eq!(result.tcp_accept_queue_size, defaults.tcp_accept_queue_size);
    assert_eq!(result.nat64_prefixes, defaults.nat64_prefixes);
    assert_eq!(
        serde_json::to_value(&result.http).unwrap(),
        serde_json::to_value(&defaults.http).unwrap()
    );
    assert_eq!(
        result.rate_limiter.unwrap(),
        NetworkRateLimiterConfig::default()
    );
    assert_eq!(
        serde_json::to_value(result.dns).unwrap(),
        serde_json::to_value(Some(DnsConfig::default())).unwrap()
    );
    assert_eq!(
        serde_json::to_value(result.tls).unwrap(),
        serde_json::to_value(Some(TlsConfig::default())).unwrap()
    );
}

#[test]
fn ordered_policy_and_explicit_empty_lists_survive_composition() {
    let source = saved(json!({
        "policy":value(json!({"default_egress":"deny","default_ingress":"deny","rules":[
            {"direction":"egress","destination":"any","protocols":["tcp"],"ports":[],"action":"allow"},
            {"direction":"egress","destination":"any","protocols":[],"ports":[],"action":"deny"}
        ]})),
        "tls":value(json!({"enabled":true,"intercepted_ports":[443],"bypass":["SENTINEL.example"],"verify_upstream":false,"block_quic_on_intercept":false,"upstream_cas":[],"scoped_upstream_cas":[],"scoped_verify_upstream":[]}))
    }));
    let before = serde_json::to_value(&source).unwrap();
    let explicit = NetworkSpecPatch::new().tls(TlsConfigPatch::new().bypass(vec![]));
    let plan = plan(&source, &NetworkSpec::default(), &explicit, &[]);
    assert!(!format!("{plan:?}").contains("SENTINEL"));
    let result = native(&plan);
    let rules = result.policy.unwrap().rules;
    assert_eq!(rules[0].action, microsandbox_types::Action::Allow);
    assert_eq!(rules[1].action, microsandbox_types::Action::Deny);
    assert!(result.tls.unwrap().bypass.is_empty());
    assert!(
        !plan
            .selection()
            .required_approvals
            .contains(&NetworkPolicyApproval::TlsBypass)
    );
    assert!(
        plan.selection()
            .required_approvals
            .contains(&NetworkPolicyApproval::DisabledUpstreamVerification)
    );
    assert_eq!(serde_json::to_value(&source).unwrap(), before);
}
