//! Real serializer shapes must retain declared omissions without inventing old intent.

use microsandbox_types::snapshot::saved_config::{SavedNetworkConfig, SavedValue};
use microsandbox_types::{NetworkSpec, OutboundProxy, TlsConfigPatch};
use serde_json::{Value, json};

use super::{SandboxBuilder, SandboxConfig, SandboxConfigPatch};
use crate::snapshot::saved_config::{
    NetworkCaptureControls, NetworkCaptureSection, RuntimeCaptureSource,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn declared() -> SandboxConfig {
    let mut patch = SandboxConfigPatch::new();
    patch.spec.network = serde_json::from_value::<NetworkSpec>(json!({
        "trust_host_cas": false,
        "outbound_proxy": {"protocol":"socks5", "address":"127.0.0.1:1080"},
        "tls": {"enabled":true},
        "secrets": {"secrets":[{
            "env_var":"TOKEN", "source":{"kind":"env","var":"PRIVATE_HOST_ENV"},
            "placeholder":"token-placeholder", "allowed_hosts":[{"exact":"example.com"}]
        }]},
        "rate_limiter":{"egress":{"bandwidth":{"size":4096,"refill_time_ms":100}}}
    }))
    .unwrap()
    .into();
    SandboxBuilder::new("network-presence")
        .image("alpine")
        .overlay(patch)
        .finish(None, None)
        .unwrap()
}

fn raw(config: &SandboxConfig) -> Value {
    serde_json::to_value(config.clone_for_persistence()).unwrap()
}

// Fully explicit entries need no omission hints, so this isolates the missing parent.
fn explicit_entries_without_policy() -> Value {
    let mut record = raw(&declared());
    record["network"]["secrets"]["passthrough_hosts"] = json!([]);
    record["network"]["secrets"]["secrets"][0]["violation_action"] = json!("block");
    record["network"]["secrets"]["secrets"][0]["substitution"]["header_fields"] =
        json!(["Authorization"]);
    record["network"]["secrets"]
        .as_object_mut()
        .unwrap()
        .remove("violation_action");
    record
}

fn project(raw: &Value) -> SavedNetworkConfig {
    let source = RuntimeCaptureSource::from_recorded(raw, None, None).unwrap();
    let bindings = source
        .network_requirements(NetworkCaptureSection::Active, vec![])
        .unwrap();
    source
        .project_network(bindings, &NetworkCaptureControls::default())
        .unwrap()
}

fn unknown<T>(value: &Option<SavedValue<T>>) -> bool {
    matches!(value, Some(SavedValue::Unknown { .. }))
}

fn assert_known(saved: &SavedNetworkConfig) {
    assert!(saved.http.as_ref().unwrap().value().is_some());
    assert!(saved.secrets.as_ref().unwrap().value().is_some());
    assert!(saved.rate_limiter.as_ref().unwrap().value().is_some());
    assert!(saved.outbound_proxy.as_ref().unwrap().value().is_some());
}

fn assert_unknown(saved: &SavedNetworkConfig) {
    assert!(unknown(&saved.http));
    assert!(unknown(&saved.secrets));
    assert!(unknown(&saved.rate_limiter));
    assert!(unknown(&saved.outbound_proxy));
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn declared_nested_defaults_survive_the_actual_serializer_without_private_values() {
    let record = raw(&declared());
    for path in [
        "/network/http/deny_message",
        "/network/outbound_proxy/credentials",
        "/network/secrets/passthrough_hosts",
        "/network/secrets/secrets/0/violation_action",
        "/network/secrets/secrets/0/substitution/header_fields",
        "/network/rate_limiter/ingress",
        "/network/rate_limiter/egress/ops",
    ] {
        assert!(record.pointer(path).is_none(), "{path}");
    }
    let hint = record["field_presence"].to_string();
    assert!(!hint.contains("PRIVATE_"));
    assert!(!hint.contains("127.0.0.1"));
    assert!(!hint.contains("token-placeholder"));
    assert!(!hint.contains("example.com"));
    let saved = project(&record);
    assert_known(&saved);
    assert!(
        saved
            .outbound_proxy
            .as_ref()
            .unwrap()
            .value()
            .unwrap()
            .credentials
            .is_none()
    );
    let secrets = saved.secrets.as_ref().unwrap().value().unwrap();
    assert_eq!(secrets.entries[0].env_var, "TOKEN");
    assert!(secrets.entries[0].substitution.header_fields.is_empty());
    let encoded = serde_json::to_string(&saved).unwrap();
    assert!(!encoded.contains("PRIVATE_"));
    assert!(!encoded.contains("field_presence"));
    let decoded: SandboxConfig = serde_json::from_value(record).unwrap();
    assert_known(&project(&raw(&SandboxBuilder::from(decoded)
        .finish(None, None)
        .unwrap())));
}

#[test]
fn old_records_and_historical_replacements_cannot_borrow_new_presence() {
    let mut record = raw(&declared());
    record.as_object_mut().unwrap().remove("field_presence");
    assert_unknown(&project(&record));
    let mut old: SandboxConfig = serde_json::from_value(record).unwrap();
    for _ in 0..2 {
        old = SandboxBuilder::from(old).finish(None, None).unwrap();
        assert_unknown(&project(&raw(&old)));
    }
    let replaced = SandboxBuilder::from(declared())
        .overlay(SandboxConfigPatch::from(old))
        .finish(None, None)
        .unwrap();
    assert_unknown(&project(&raw(&replaced)));
}

#[test]
fn missing_recorded_parents_retire_nested_evidence_before_reconstruction() {
    for (parent, field, family) in [
        ("/network", "http", "http"),
        ("/network", "outbound_proxy", "proxy"),
        ("/network", "secrets", "secrets"),
        ("/network/rate_limiter", "egress", "rates"),
        ("/network/secrets/secrets/0", "substitution", "secrets"),
    ] {
        let mut record = raw(&declared());
        record
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        let decoded: SandboxConfig = serde_json::from_value(record.clone()).unwrap();
        let rebuilt = raw(&SandboxBuilder::from(decoded).finish(None, None).unwrap());
        for input in [&record, &rebuilt] {
            let saved = project(input);
            let missing = match family {
                "http" => unknown(&saved.http),
                "proxy" => unknown(&saved.outbound_proxy),
                "secrets" => unknown(&saved.secrets),
                _ => unknown(&saved.rate_limiter),
            };
            assert!(missing, "{parent}/{field}");
        }
    }
}

#[test]
fn missing_enclosing_secret_policy_stays_unknown_after_repeated_saves() {
    for explicit_passthrough in [false, true] {
        let mut record = raw(&declared());
        if explicit_passthrough {
            // An explicit empty list no longer needs its own omission hint. Per-entry
            // hints must not certify the parent policy that serde supplies on decode.
            record["network"]["secrets"]["passthrough_hosts"] = json!([]);
        }
        record["network"]["secrets"]
            .as_object_mut()
            .unwrap()
            .remove("violation_action");
        for rewrite in 0..3 {
            assert!(
                unknown(&project(&record).secrets),
                "explicit passthrough: {explicit_passthrough}, rewrite: {rewrite}"
            );
            let decoded: SandboxConfig = serde_json::from_value(record).unwrap();
            record = raw(&SandboxBuilder::from(decoded).finish(None, None).unwrap());
        }
    }
}

#[test]
fn missing_secret_policy_with_explicit_entries_stays_unknown_after_rewrite() {
    let record = explicit_entries_without_policy();
    assert!(unknown(&project(&record).secrets));
    // Fully explicit entries need no omission hints. The enclosing default must
    // still not become recorded intent merely because configuration was rewritten.
    for supplied_presence in [true, false] {
        let mut rewritten = record.clone();
        if !supplied_presence {
            rewritten.as_object_mut().unwrap().remove("field_presence");
        }
        for _ in 0..3 {
            let decoded: SandboxConfig = serde_json::from_value(rewritten).unwrap();
            let before = serde_json::to_value(&decoded.spec).unwrap();
            let rebuilt = SandboxBuilder::from(decoded).finish(None, None).unwrap();
            assert_eq!(serde_json::to_value(&rebuilt.spec).unwrap(), before);
            rewritten = raw(&rebuilt);
            assert!(unknown(&project(&rewritten).secrets));
        }
    }
}

#[test]
fn malformed_negative_policy_evidence_cannot_certify_synthesized_defaults() {
    let decoded: SandboxConfig = serde_json::from_value(explicit_entries_without_policy()).unwrap();
    let expected_spec = serde_json::to_value(&decoded.spec).unwrap();
    let rewritten = raw(&decoded);
    for marker in [
        json!(true),
        json!(null),
        json!("future"),
        json!({"unknown": true}),
    ] {
        let mut input = rewritten.clone();
        input["field_presence"]["secret_policy_unrecorded"] = marker;
        // An unrelated future field also makes the current evidence decoder refuse
        // the document. Its negative information must still survive that refusal.
        input["field_presence"]["future_field"] = json!(true);
        let decoded: SandboxConfig = serde_json::from_value(input).unwrap();
        assert_eq!(serde_json::to_value(&decoded.spec).unwrap(), expected_spec);
        assert!(unknown(&project(&raw(&decoded)).secrets));
    }
}

#[test]
fn unrecorded_secret_policy_requires_an_explicit_policy_replacement() {
    let record = explicit_entries_without_policy();
    let historical: SandboxConfig = serde_json::from_value(record).unwrap();
    let rebuilt = SandboxBuilder::from(historical.clone())
        .label("team", "example")
        .finish(None, None)
        .unwrap();
    assert!(unknown(&project(&raw(&rebuilt)).secrets));
    let mut sparse = SandboxConfigPatch::new();
    sparse.spec.network.secrets = Some(Default::default());
    let rebuilt = SandboxBuilder::from(historical.clone())
        .overlay(sparse)
        .finish(None, None)
        .unwrap();
    assert!(unknown(&project(&raw(&rebuilt)).secrets));

    // Explicit policy declaration is distinct from an identical historical overlay.
    let inherited = SandboxBuilder::from(declared())
        .overlay(SandboxConfigPatch::from(historical.clone()))
        .finish(None, None)
        .unwrap();
    assert!(unknown(&project(&raw(&inherited)).secrets));
    let mut replacement = SandboxConfigPatch::new();
    replacement.spec.network.secrets =
        Some(historical.spec.network.secrets.clone().unwrap().into());
    let explicit = SandboxBuilder::from(historical)
        .overlay(replacement)
        .finish(None, None)
        .unwrap();
    assert!(project(&raw(&explicit)).secrets.unwrap().value().is_some());
}

#[cfg(feature = "net")]
#[test]
fn fluent_policy_selection_clears_uncertainty_but_other_network_edits_do_not() {
    let record = explicit_entries_without_policy();
    let historical: SandboxConfig = serde_json::from_value(record).unwrap();
    let action = historical
        .spec
        .network
        .secrets
        .as_ref()
        .unwrap()
        .violation_action
        .clone();
    let unrelated = SandboxBuilder::from(historical.clone())
        .network(|network| network.max_tcp_connections(123))
        .finish(None, None)
        .unwrap();
    assert!(unknown(&project(&raw(&unrelated)).secrets));
    for explicit in [
        SandboxBuilder::from(historical.clone()).secret_violation_action(action.clone()),
        SandboxBuilder::from(historical).network(|network| network.secret_violation_action(action)),
    ] {
        let config = explicit.finish(None, None).unwrap();
        assert!(project(&raw(&config)).secrets.unwrap().value().is_some());
    }
}

#[test]
fn historical_policy_replacement_does_not_inherit_destination_uncertainty() {
    let known: SandboxConfig = serde_json::from_value(raw(&declared())).unwrap();
    let mut partial = raw(&known);
    partial["network"]["secrets"]
        .as_object_mut()
        .unwrap()
        .remove("violation_action");
    let unknown_config: SandboxConfig = serde_json::from_value(partial).unwrap();
    let replaced = SandboxBuilder::from(unknown_config)
        .overlay(SandboxConfigPatch::from(known))
        .finish(None, None)
        .unwrap();
    assert!(project(&raw(&replaced)).secrets.unwrap().value().is_some());
}

#[test]
fn changed_values_retire_evidence_and_cannot_revive_it_after_omission() {
    for (parent, field, replacement, family) in [
        (
            "/network/http",
            "deny_message",
            json!("PRIVATE_MESSAGE"),
            "http",
        ),
        (
            "/network/outbound_proxy",
            "credentials",
            json!({"username":"PRIVATE_USER", "password":{"kind":"env","var":"PRIVATE_PASSWORD"}}),
            "proxy",
        ),
        (
            "/network/secrets/secrets/0/substitution",
            "header_fields",
            json!(["Authorization"]),
            "secrets",
        ),
        (
            "/network/rate_limiter/egress",
            "ops",
            json!({"size":100,"refill_time_ms":100,"one_time_burst":0}),
            "rates",
        ),
    ] {
        let mut record = raw(&declared());
        record.pointer_mut(parent).unwrap()[field] = replacement;
        let changed: SandboxConfig = serde_json::from_value(record).unwrap();
        let mut rewritten = raw(&changed);
        rewritten
            .pointer_mut(parent)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .remove(field);
        let saved = project(&rewritten);
        assert!(
            match family {
                "http" => unknown(&saved.http),
                "proxy" => unknown(&saved.outbound_proxy),
                "secrets" => unknown(&saved.secrets),
                _ => unknown(&saved.rate_limiter),
            },
            "{parent}/{field}"
        );
    }
}

#[test]
fn unknown_nested_hint_is_ignored_without_breaking_config_decode() {
    let mut record = raw(&declared());
    let original = record["network"].clone();
    record["field_presence"]["nested_network"] = json!([{"kind":"future_default"}]);
    let decoded: SandboxConfig = serde_json::from_value(record.clone()).unwrap();
    // Unknown positive hints are discarded, but missing policy fields still retain
    // negative evidence so a later save cannot certify decoder-supplied defaults.
    assert_eq!(raw(&decoded)["network"], original);
    assert_unknown(&project(&record));
    assert_unknown(&project(&raw(&decoded)));
}

#[test]
fn explicit_no_auth_proxy_establishes_only_that_nested_default() {
    let mut record = raw(&declared());
    record.as_object_mut().unwrap().remove("field_presence");
    let old: SandboxConfig = serde_json::from_value(record).unwrap();
    let mut patch = SandboxConfigPatch::new();
    patch.spec.network.outbound_proxy = Some(Some(OutboundProxy::Socks4 {
        address: "127.0.0.1:1080".into(),
        user_id: None,
    }));
    let config = SandboxBuilder::from(old)
        .overlay(patch)
        .finish(None, None)
        .unwrap();
    let saved = project(&raw(&config));
    assert!(saved.outbound_proxy.as_ref().unwrap().value().is_some());
    assert!(unknown(&saved.http));
    assert!(unknown(&saved.secrets));
    assert!(unknown(&saved.rate_limiter));
}

#[test]
fn omitted_required_rate_bucket_fields_cannot_be_reconstructed_as_evidence() {
    let mut record = raw(&declared());
    record
        .pointer_mut("/network/rate_limiter/egress/bandwidth")
        .unwrap()
        .as_object_mut()
        .unwrap()
        .remove("one_time_burst");
    assert!(unknown(&project(&record).rate_limiter));
    let decoded: SandboxConfig = serde_json::from_value(record).unwrap();
    let rebuilt = SandboxBuilder::from(decoded).finish(None, None).unwrap();
    assert!(unknown(&project(&raw(&rebuilt)).rate_limiter));
}

#[test]
fn omitted_network_policy_fields_remain_unknown_across_rewrites() {
    let mut invented = Vec::new();
    for (family, field) in [
        ("tls", "enabled"),
        ("tls", "intercepted_ports"),
        ("tls", "bypass"),
        ("tls", "verify_upstream"),
        ("tls", "block_quic_on_intercept"),
        ("tls", "upstream_ca_cert"),
        ("tls", "scoped_upstream_ca_cert"),
        ("tls", "scoped_verify_upstream"),
        ("tls", "intercept_ca"),
        ("dns", "rebind_protection"),
        ("dns", "nameservers"),
        ("dns", "query_timeout_ms"),
    ] {
        let mut record = raw(&declared());
        record["network"]["dns"] = json!({
            "rebind_protection": true,
            "query_timeout_ms": 5000,
            "nameservers": []
        });
        assert!(project(&record).tls.unwrap().value().is_some());
        assert!(project(&record).dns.unwrap().value().is_some());
        record["network"][family]
            .as_object_mut()
            .unwrap()
            .remove(field);
        let is_unknown = |saved: &SavedNetworkConfig| match family {
            "tls" => unknown(&saved.tls),
            _ => unknown(&saved.dns),
        };
        assert!(is_unknown(&project(&record)), "{family}.{field}");
        // A label-only edit must not certify a policy supplied by typed decoding.
        for supplied_presence in [true, false] {
            let mut rewritten = record.clone();
            if !supplied_presence {
                rewritten.as_object_mut().unwrap().remove("field_presence");
            }
            for _ in 0..3 {
                let decoded: SandboxConfig = serde_json::from_value(rewritten).unwrap();
                let spec = serde_json::to_value(&decoded.spec).unwrap();
                let rebuilt = SandboxBuilder::from(decoded)
                    .label("team", "example")
                    .finish(None, None)
                    .unwrap();
                // The only operational edit is the deliberately changed label.
                let mut changed_spec = serde_json::to_value(&rebuilt.spec).unwrap();
                changed_spec["labels"] = spec["labels"].clone();
                assert_eq!(changed_spec, spec);
                rewritten = raw(&rebuilt);
                if !is_unknown(&project(&rewritten)) {
                    invented.push(format!("{family}.{field}"));
                }
            }
        }
    }
    assert!(
        invented.is_empty(),
        "synthesized policy became known: {invented:?}"
    );
}

#[test]
fn policy_negative_evidence_survives_malformed_hints_and_unknown_fields() {
    for marker in [
        json!(null),
        json!(["future"]),
        json!({}),
        json!(["tls_verify_upstream"]),
    ] {
        let mut record = raw(&declared());
        record["field_presence"]["unrecorded_network_policy"] = marker;
        record["field_presence"]["future"] = json!(true);
        let expected = record["network"].clone();
        let decoded: SandboxConfig = serde_json::from_value(record).unwrap();
        assert_eq!(raw(&decoded)["network"], expected);
        assert!(unknown(&project(&raw(&decoded)).tls));
        let text = raw(&decoded)["field_presence"].to_string();
        assert!(!text.contains("PRIVATE_") && !text.contains("127.0.0.1"));
    }
}

#[test]
fn explicit_policy_patch_repairs_only_the_fields_it_supplies() {
    let mut record = raw(&declared());
    for field in ["enabled", "verify_upstream"] {
        record["network"]["tls"]
            .as_object_mut()
            .unwrap()
            .remove(field);
    }
    let historical: SandboxConfig = serde_json::from_value(record).unwrap();
    let mut patch = SandboxConfigPatch::new();
    patch.spec.network.tls = Some(TlsConfigPatch {
        enabled: Some(true),
        ..Default::default()
    });
    let partial = SandboxBuilder::from(historical.clone())
        .overlay(patch)
        .finish(None, None)
        .unwrap();
    assert!(unknown(&project(&raw(&partial)).tls));
    let mut patch = SandboxConfigPatch::new();
    patch.spec.network.tls = Some(TlsConfigPatch {
        verify_upstream: Some(true),
        ..Default::default()
    });
    let explicit = SandboxBuilder::from(partial)
        .overlay(patch)
        .finish(None, None)
        .unwrap();
    assert!(project(&raw(&explicit)).tls.unwrap().value().is_some());
    let known: SandboxConfig = serde_json::from_value(raw(&declared())).unwrap();
    let replaced = SandboxBuilder::from(historical)
        .overlay(SandboxConfigPatch::from(known))
        .finish(None, None)
        .unwrap();
    assert!(project(&raw(&replaced)).tls.unwrap().value().is_some());
}

#[cfg(feature = "net")]
#[test]
fn fluent_policy_edits_do_not_certify_untouched_fields_or_unknown_list_prefixes() {
    let mut record = raw(&declared());
    for field in ["enabled", "verify_upstream", "bypass"] {
        record["network"]["tls"]
            .as_object_mut()
            .unwrap()
            .remove(field);
    }
    let historical: SandboxConfig = serde_json::from_value(record).unwrap();
    let partial = SandboxBuilder::from(historical.clone())
        .intercept_tls()
        .network(|n| n.tls_overlay(|t| t.verify_upstream(true).bypass("example.invalid")))
        .finish(None, None)
        .unwrap();
    assert!(unknown(&project(&raw(&partial)).tls));
    let replaced = SandboxBuilder::from(partial)
        .network(|n| n.tls(|t| t.verify_upstream(true)))
        .finish(None, None)
        .unwrap();
    assert!(project(&raw(&replaced)).tls.unwrap().value().is_some());

    let mut record = raw(&historical);
    record["network"].as_object_mut().unwrap().remove("tls");
    record.as_object_mut().unwrap().remove("field_presence");
    let absent: SandboxConfig = serde_json::from_value(record).unwrap();
    let unrelated = SandboxBuilder::from(absent)
        .network(|n| n.max_tcp_connections(123))
        .finish(None, None)
        .unwrap();
    assert!(unknown(&project(&raw(&unrelated)).tls));
}

#[test]
#[ignore = "requires actual old/new runtime records from saved-presence-evidence.py"]
fn live_network_default_evidence_projects_without_reinventing_old_intent() {
    let root = std::path::PathBuf::from(std::env::var_os("MSB_NESTED_PRESENCE_FIXTURES").unwrap());
    let require_unrecorded_policy =
        std::env::var_os("MSB_REQUIRE_UNRECORDED_SECRET_POLICY").is_some();
    for (name, known) in [
        ("current-source.json", true),
        ("runtime-modified-source.json", true),
        ("old-modified-config.json", false),
        ("new-after-old-source.json", false),
    ] {
        let recorded: Value =
            serde_json::from_slice(&std::fs::read(root.join(name)).unwrap()).unwrap();
        let saved = project(&recorded);
        assert_eq!(
            saved.http.as_ref().unwrap().value().is_some(),
            known,
            "{name}"
        );
        assert_eq!(unknown(&saved.http), !known, "{name}");
        if require_unrecorded_policy && known {
            assert_eq!(
                recorded.pointer("/field_presence/secret_policy_unrecorded"),
                Some(&Value::Bool(true)),
                "{name}"
            );
            assert!(unknown(&saved.secrets), "{name}");
        }
        let config: SandboxConfig = serde_json::from_value(recorded).unwrap();
        let rebuilt = SandboxBuilder::from(config).finish(None, None).unwrap();
        assert_eq!(unknown(&project(&raw(&rebuilt)).http), !known, "{name}");
        if require_unrecorded_policy && known {
            assert!(unknown(&project(&raw(&rebuilt)).secrets), "{name}");
        }
    }
}

#[test]
fn tls_aliases_preserve_evidence_but_missing_ca_children_do_not() {
    for ca in ["intercept_ca", "ca"] {
        let mut record = raw(&declared());
        let tls = record["network"]["tls"].as_object_mut().unwrap();
        let certs = tls.remove("scoped_upstream_ca_cert").unwrap();
        tls.insert("scoped_upstream_ca_certs".into(), certs);
        if ca == "ca" {
            let value = tls.remove("intercept_ca").unwrap();
            tls.insert(ca.into(), value);
        }
        assert!(project(&record).tls.unwrap().value().is_some());
        for child in ["cert_path", "key_path"] {
            let mut missing = record.clone();
            missing["network"]["tls"][ca]
                .as_object_mut()
                .unwrap()
                .remove(child);
            for _ in 0..3 {
                let decoded: SandboxConfig = serde_json::from_value(missing).unwrap();
                missing = raw(&SandboxBuilder::from(decoded)
                    .label("note", "checked")
                    .finish(None, None)
                    .unwrap());
                assert!(unknown(&project(&missing).tls), "{ca}.{child}");
            }
        }
    }
}

#[cfg(feature = "net")]
#[test]
fn fluent_scalar_and_list_replacements_establish_only_selected_policy() {
    let mut record = raw(&declared());
    record["network"]["dns"] = json!({});
    let tls = record["network"]["tls"].as_object_mut().unwrap();
    tls.remove("intercepted_ports");
    tls.remove("block_quic_on_intercept");
    let old: SandboxConfig = serde_json::from_value(record).unwrap();
    let partial = SandboxBuilder::from(old)
        .network(|n| {
            n.tls_overlay(|t| t.intercepted_ports(vec![443]))
                .dns_overlay(|d| d.rebind_protection(true).query_timeout_ms(5000))
        })
        .finish(None, None)
        .unwrap();
    let saved = project(&raw(&partial));
    assert!(unknown(&saved.tls));
    assert!(unknown(&saved.dns));
    // Selecting a value equal to the decoder default still establishes intent.
    let explicit = SandboxBuilder::from(partial)
        .network(|n| {
            n.tls_overlay(|t| t.block_quic(true))
                .dns_overlay(|d| d.nameservers(Vec::<std::net::IpAddr>::new()))
        })
        .finish(None, None)
        .unwrap();
    let saved = project(&raw(&explicit));
    assert!(saved.tls.unwrap().value().is_some());
    assert!(saved.dns.unwrap().value().is_some());
}

#[test]
#[ignore = "requires real runtime records from saved-presence-evidence.py"]
fn live_missing_policy_remains_unknown_when_projected_and_rewritten() {
    let root = std::path::PathBuf::from(std::env::var_os("MSB_POLICY_PRESENCE_FIXTURES").unwrap());
    for version in ["current", "v0.6.0", "v0.6.6", "v0.6.7", "v0.6.18", "v0.7.8"] {
        let mut files = vec!["historical-network-rewritten-config.json"];
        if version == "current" {
            files.extend(["current-source.json", "runtime-modified-source.json"]);
        }
        for file in files {
            let mut record: Value =
                serde_json::from_slice(&std::fs::read(root.join(version).join(file)).unwrap())
                    .unwrap();
            for _ in 0..3 {
                let saved = project(&record);
                assert!(unknown(&saved.tls), "{version}/{file}");
                assert!(unknown(&saved.dns), "{version}/{file}");
                let config: SandboxConfig = serde_json::from_value(record).unwrap();
                record = raw(&SandboxBuilder::from(config)
                    .label("projection", "checked")
                    .finish(None, None)
                    .unwrap());
            }
        }
    }
}
