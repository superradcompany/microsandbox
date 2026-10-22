//! Cross-section invariants, full-range quantities, and hostile document boundaries.

use std::collections::{BTreeMap, BTreeSet};

use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use crate::GuestClockPolicy;
use crate::snapshot::{Manifest, RestoreDefaults};
use crate::{Rlimit, RlimitResource, SandboxPolicy};

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn allocations_reject_zero_and_conflicting_maxima_without_inventing_unknown_values() {
    for (current, maximum) in [("cpus", "max_cpus"), ("memory_mib", "max_memory_mib")] {
        for value in [
            json!({current: saved(json!(0))}),
            json!({maximum:saved(json!(0))}),
            json!({current:saved(json!(4)), maximum:saved(json!(2))}),
        ] {
            assert!(
                SavedResourcesConfig::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err()
            );
        }
        for value in [
            json!({current:{"state":"unknown","reason":"converging"},maximum:saved(json!(8))}),
            json!({current:saved(json!(4)),maximum:{"state":"default"}}),
            json!({current:saved(json!(4))}),
            json!({current:saved(json!(4)),maximum:saved(json!(4))}),
        ] {
            let config =
                SavedResourcesConfig::from_bytes(&serde_json::to_vec(&value).unwrap()).unwrap();
            assert_eq!(serde_json::to_value(config).unwrap(), value);
        }
    }
}

#[test]
fn active_capacity_cannot_be_a_requested_target_but_pending_intent_can() {
    for field in ["cpus", "memory_mib"] {
        let mut doc = document();
        doc["active"]["resources"][field] = saved(json!(4));
        reject(&doc, "active allocation requires an observed value");
        doc["active"]["resources"][field]["origin"] = json!("observed");
        parse(&doc);
        doc["active"]["resources"][field] = json!({"state":"unknown", "reason":"converging"});
        doc["pending"] = json!({"resources":{field:saved(json!(8))}});
        let config = parse(&doc);
        let encoded = serde_json::to_value(config).unwrap();
        assert_eq!(encoded["active"]["resources"][field]["state"], "unknown");
        assert_eq!(encoded["pending"]["resources"][field]["value"], 8);
    }
}

#[test]
fn new_sections_reject_null_unknown_and_host_operational_fields() {
    for field in ["cpus", "memory_mib", "max_cpus", "max_memory_mib", "thp"] {
        assert!(
            SavedResourcesConfig::from_bytes(&serde_json::to_vec(&json!({field:null})).unwrap())
                .is_err()
        );
    }
    for field in ["labels", "security_profile", "rlimits", "lifecycle"] {
        assert!(
            SavedExecutionConfig::from_bytes(&serde_json::to_vec(&json!({field:null})).unwrap())
                .is_err()
        );
    }
    for field in [
        "host_cpu_ids",
        "cpu_placement",
        "placement_profile",
        "observed_at_host_path",
    ] {
        assert!(
            SavedResourcesConfig::from_bytes(
                &serde_json::to_vec(&json!({field:"SENTINEL"})).unwrap()
            )
            .is_err()
        );
    }
    for field in [
        "ephemeral",
        "replace",
        "source_config",
        "argv",
        "elapsed_secs",
        "deployment_profile",
    ] {
        assert!(
            SavedExecutionConfig::from_bytes(
                &serde_json::to_vec(&json!({field:"SENTINEL"})).unwrap()
            )
            .is_err()
        );
    }
    for field in ["ephemeral", "elapsed_secs", "safe_to_apply"] {
        let value = json!({"lifecycle":saved(json!({field:true}))});
        assert!(SavedExecutionConfig::from_bytes(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn every_rlimit_retains_exact_full_u64_range_through_descriptor_canonicalization() {
    use RlimitResource::*;
    let resources = [
        Cpu, Fsize, Data, Stack, Core, Rss, Nproc, Nofile, Memlock, As, Locks, Sigpending,
        Msgqueue, Nice, Rtprio, Rttime,
    ];
    let quantities = [
        0,
        1,
        9_007_199_254_740_991,
        9_007_199_254_740_992,
        u64::MAX - 1,
        u64::MAX,
    ];
    for resource in resources {
        for value in quantities {
            let original = Rlimit {
                resource,
                soft: value,
                hard: u64::MAX,
            };
            let saved_limit = SavedRlimit::from(&original);
            let config = SavedExecutionConfig {
                rlimits: Some(SavedValue::Value {
                    value: vec![saved_limit],
                    origin: SavedOrigin::Configured,
                }),
                ..Default::default()
            };
            config.validate().unwrap();
            let json = serde_json::to_value(&config).unwrap();
            let mut canonical = Vec::new();
            crate::snapshot::manifest::write_canonical_json(&json, &mut canonical).unwrap();
            let decoded = SavedExecutionConfig::from_bytes(&canonical).unwrap();
            let actual: Rlimit = decoded.rlimits.unwrap().value().unwrap()[0].clone().into();
            assert_eq!(
                (actual.resource, actual.soft, actual.hard),
                (resource, value, u64::MAX)
            );
            assert_eq!(
                json["rlimits"]["value"][0]["soft"],
                json!(value.to_string())
            );
        }
    }
}

#[test]
fn unsigned_quantities_reject_ambiguous_or_out_of_range_representations() {
    for value in [
        json!(0),
        json!(-1),
        json!(1.0),
        json!(null),
        json!(""),
        json!("00"),
        json!("01"),
        json!("+1"),
        json!("-1"),
        json!("1.0"),
        json!("1e3"),
        json!(" 1"),
        json!("1\n"),
        json!("18446744073709551616"),
    ] {
        let config = json!({"rlimits":saved(json!([{"resource":"Nofile","soft":value,"hard":"18446744073709551615"}]))});
        assert!(
            SavedExecutionConfig::from_bytes(&serde_json::to_vec(&config).unwrap()).is_err(),
            "accepted {value}"
        );
    }
}

#[test]
fn rlimit_duplicates_and_inverted_ranges_fail_on_decode_and_typed_input() {
    let limit = SavedRlimit {
        resource: RlimitResource::Nofile,
        soft: SavedU64::new(128),
        hard: SavedU64::new(64),
    };
    let mut config = SavedExecutionConfig {
        rlimits: Some(SavedValue::Value {
            value: vec![limit.clone()],
            origin: SavedOrigin::Configured,
        }),
        ..Default::default()
    };
    assert!(config.validate().is_err());
    let limit = SavedRlimit {
        soft: SavedU64::new(0),
        ..limit
    };
    config.rlimits = Some(SavedValue::Value {
        value: vec![limit.clone(), limit],
        origin: SavedOrigin::Configured,
    });
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("duplicate resource limit")
    );
    assert!(SavedExecutionConfig::from_bytes(&serde_json::to_vec(&config).unwrap()).is_err());
}

#[test]
fn lifetime_projection_omits_ownership_and_preserves_disabled_zero_and_full_range() {
    let source = SandboxPolicy {
        ephemeral: true,
        max_duration_secs: Some(u64::MAX),
        idle_timeout_secs: Some(0),
    };
    let saved_policy = SavedLifetimePolicy::from_source(&source);
    assert_eq!(
        serde_json::to_value(saved_policy).unwrap(),
        json!({"max_duration_secs":"18446744073709551615","idle_timeout_secs":"0"})
    );
    assert_eq!(
        serde_json::to_value(SavedLifetimePolicy::from_source(&SandboxPolicy::default())).unwrap(),
        json!({})
    );
    assert!(
        serde_json::from_value::<SavedLifetimePolicy>(json!({"max_duration_secs":null})).is_err()
    );
    assert!(source.ephemeral);
}

#[test]
fn user_label_empty_values_are_preserved_and_diagnostics_do_not_echo_invalid_keys() {
    let good = json!({"labels":saved(json!({"team":"","literal.with.dots":"build"})),"security_profile":saved(json!("default"))});
    let parsed = SavedExecutionConfig::from_bytes(&serde_json::to_vec(&good).unwrap()).unwrap();
    assert_eq!(serde_json::to_value(parsed).unwrap(), good);
    for labels in [
        json!({"":"value"}),
        json!({"SENTINEL\0":"value"}),
        json!({"key":"SENTINEL\0"}),
    ] {
        let error = SavedExecutionConfig::from_bytes(
            &serde_json::to_vec(&json!({"labels":saved(labels)})).unwrap(),
        )
        .unwrap_err()
        .to_string();
        assert!(error.contains("active.execution.labels"));
        assert!(!error.contains("SENTINEL"));
    }
}

#[test]
fn schema_version_required_fields_and_unknown_operational_fields_fail_closed() {
    for version in [json!(0), json!(2), json!(null), json!("1"), json!(1.5)] {
        let mut value = document();
        value["schema_version"] = version;
        reject(&value, "SCFG_");
    }
    for field in ["schema_version", "active", "bindings", "provenance"] {
        let mut value = document();
        value.as_object_mut().unwrap().remove(field);
        reject(&value, "SCFG_SCHEMA");
    }
    for path in [
        "",
        "/active",
        "/provenance",
        "/active/resources",
        "/active/execution",
    ] {
        let mut value = document();
        value
            .pointer_mut(path)
            .unwrap()
            .as_object_mut()
            .unwrap()
            .insert("SENTINEL_UNKNOWN".into(), json!("SENTINEL_VALUE"));
        assert!(!reject(&value, "SCFG_SCHEMA").contains("SENTINEL"));
    }
    let mut value = document();
    value["pending"] = Value::Null;
    reject(&value, "SCFG_SCHEMA");
}

#[test]
fn document_rejects_duplicate_keys_before_typed_conversion() {
    let bytes = serde_json::to_string(&document()).unwrap().replacen(
        "\"schema_version\":1",
        "\"schema_version\":1,\"schema_version\":2",
        1,
    );
    assert!(
        SavedSandboxConfig::from_bytes(bytes.as_bytes())
            .err()
            .unwrap()
            .to_string()
            .contains("SCFG_JSON")
    );
}

#[test]
fn capture_generation_is_observed_or_unknown_never_requested_default() {
    for value in [
        json!({"state":"unknown","reason":"not_observed"}),
        json!({"state":"value","origin":"observed","value":"runtime-generation-42"}),
    ] {
        let mut doc = document();
        doc["provenance"]["active_generation"] = value;
        parse(&doc);
    }
    for value in [
        json!({"state":"default"}),
        saved(json!("requested-42")),
        json!({"state":"value","origin":"observed","value":"SENTINEL\n"}),
    ] {
        let mut doc = document();
        doc["provenance"]["active_generation"] = value;
        assert!(!reject(&doc, "provenance.active_generation").contains("SENTINEL"));
    }
}

#[test]
fn inventory_covers_all_runtime_and_network_consumers_and_shared_strict_use() {
    let mut doc = document();
    doc["active"]["network"] = super::network_tests::network();
    doc["active"]["runtime"] = json!({
        "env":saved(json!({"TOKEN":{"kind":"binding","id":"secret.token"}})),
        "init":saved(json!({"kind":"handoff","selection":"path","resolved_path":"/sbin/init","args":[{"kind":"binding","id":"boot"}],"env":{}})),
        "scripts":saved(json!({"health":{"kind":"binding","id":"script"}}))
    });
    doc["bindings"] = json!({"secret.token":"text","boot":"text","script":"text","dns.primary":"dns_resolver",
        "tls.upstream":"certificate","tls.intercept":"tls_identity","tls.scoped":"certificate",
        "trust.corporate":"certificate","http.listener":"listener","proxy.endpoint":"proxy_endpoint","proxy.auth":"proxy_credentials"});
    let config = parse(&doc);
    let uses = config.active_binding_uses().unwrap();
    use SavedBindingConsumer::*;
    let expected = BTreeMap::from([
        ("secret.token", BTreeSet::from([Gateway, NewCommand])),
        ("boot", BTreeSet::from([BootInit])),
        ("script", BTreeSet::from([ScriptBacking])),
        ("dns.primary", BTreeSet::from([Gateway])),
        ("tls.upstream", BTreeSet::from([Gateway])),
        ("tls.intercept", BTreeSet::from([Gateway])),
        ("tls.scoped", BTreeSet::from([Gateway])),
        ("trust.corporate", BTreeSet::from([GuestTrust])),
        ("http.listener", BTreeSet::from([Listener])),
        ("proxy.endpoint", BTreeSet::from([Gateway])),
        ("proxy.auth", BTreeSet::from([Gateway])),
    ]);
    assert_eq!(uses.len(), expected.len());
    for (id, consumers) in expected {
        assert_eq!(uses[id].consumers, consumers);
    }
    for id in config.bindings.keys() {
        let mut invalid = doc.clone();
        invalid["bindings"].as_object_mut().unwrap().remove(id);
        reject(&invalid, "referenced binding is not declared");
    }
}

#[test]
fn same_ca_can_serve_gateway_and_guest_but_cannot_be_a_private_identity() {
    let mut doc = document();
    doc["active"]["network"] = super::network_tests::network();
    let network =
        SavedNetworkConfig::from_bytes(&serde_json::to_vec(&doc["active"]["network"]).unwrap())
            .unwrap();
    let uses = collect_binding_uses(&SavedRuntimeConfig::default(), &network).unwrap();
    doc["bindings"] = serde_json::to_value(
        uses.iter()
            .map(|(id, use_)| (id.clone(), use_.kind))
            .collect::<BTreeMap<_, _>>(),
    )
    .unwrap();
    doc["active"]["network"]["guest_trust"]["value"][0]["id"] = json!("tls.upstream");
    doc["bindings"]
        .as_object_mut()
        .unwrap()
        .remove("trust.corporate");
    let uses = parse(&doc).active_binding_uses().unwrap();
    assert_eq!(
        uses["tls.upstream"].consumers,
        BTreeSet::from([
            SavedBindingConsumer::Gateway,
            SavedBindingConsumer::GuestTrust
        ])
    );
    doc["active"]["network"]["tls"]["value"]["intercept_ca"]["id"] = json!("tls.upstream");
    reject(&doc, "incompatible destination kinds");
}

#[test]
fn missing_wrong_unused_or_forged_inventory_entries_fail_without_values() {
    let mut doc = document();
    doc["active"]["runtime"]["env"] =
        saved(json!({"TOKEN":{"kind":"binding","id":"SENTINEL_BINDING"}}));
    assert!(!reject(&doc, "SCFG_BINDING").contains("SENTINEL"));
    doc["bindings"] = json!({"SENTINEL_BINDING":"listener"});
    reject(&doc, "conflicts with its use");
    doc["bindings"] =
        json!({"SENTINEL_BINDING":{"kind":"text","consumers":["new_command"],"value":"SENTINEL"}});
    reject(&doc, "SCFG_SCHEMA");
    doc["bindings"] = json!({"SENTINEL_BINDING":"text","unused":"text"});
    reject(&doc, "unreferenced binding");
}

#[test]
fn pending_bindings_are_validated_but_never_added_to_active_consumers() {
    let mut doc = document();
    doc["active"]["runtime"]["cmd"] = saved(json!([{ "kind":"binding","id":"active.command"}]));
    doc["pending"] = json!({"runtime":{"init":saved(json!({"kind":"handoff","selection":"path","resolved_path":"/new/init","args":[{"kind":"binding","id":"pending.boot"}],"env":{}}))}});
    doc["bindings"] = json!({"active.command":"text","pending.boot":"text"});
    let config = parse(&doc);
    let uses = config.active_binding_uses().unwrap();
    assert_eq!(uses.len(), 1);
    assert_eq!(
        uses["active.command"].consumers,
        BTreeSet::from([SavedBindingConsumer::NewCommand])
    );
    doc["bindings"]
        .as_object_mut()
        .unwrap()
        .remove("pending.boot");
    reject(&doc, "referenced binding is not declared");
    doc["bindings"]["pending.boot"] = json!("text");
    doc["pending"]["runtime"]["init"]["value"]["resolved_path"] = json!("relative");
    reject(&doc, "pending.runtime.init");
}

#[test]
fn pending_and_active_cannot_give_one_binding_incompatible_shapes() {
    let mut doc = document();
    doc["active"]["runtime"]["cmd"] = saved(json!([{ "kind":"binding","id":"shared"}]));
    doc["pending"] = json!({"network":{"dns":saved(json!({"rebind_protection":true,"query_timeout_ms":1000,"resolvers":[{"id":"shared"}]}))}});
    doc["bindings"] = json!({"shared":"text"});
    reject(&doc, "incompatible destination kinds");
}

#[test]
fn document_enforces_aggregate_script_budget_across_active_and_pending() {
    let body = "x".repeat(MAX_SAVED_SCRIPT_BYTES);
    let script = json!({"kind":"inline","content":body,"mode":493,"digest":format!("sha256:{}",hex::encode(Sha256::digest(body.as_bytes())))});
    let mut doc = document();
    doc["active"]["runtime"]["scripts"] = saved(json!({"a":script,"b":script,"c":script}));
    doc["pending"] = json!({"runtime":{"scripts":saved(json!({"d":script}))}});
    parse(&doc);
    doc["pending"]["runtime"]["scripts"]["value"]["e"] = script;
    reject(&doc, "combined active and pending script payload");
}

#[test]
fn whole_document_size_and_inventory_count_are_bounded_for_typed_callers_too() {
    let mut config = parse(&document());
    config.bindings = (0..=MAX_SAVED_CONFIG_ENTRIES)
        .map(|i| (format!("b{i}"), SavedBindingKind::Text))
        .collect();
    assert!(
        config
            .validate()
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
    let mut doc = document();
    doc["provenance"]["source_name"] = json!("x".repeat(MAX_SAVED_CONFIG_BYTES));
    reject(&doc, "SCFG_LIMIT");
}

#[test]
fn legacy_user_and_clock_must_agree_without_changing_legacy_encoding() {
    let mut manifest = descriptor();
    manifest
        .set_restore_defaults(RestoreDefaults {
            user: Some("1000:1000".into()),
        })
        .unwrap();
    manifest.set_guest_clock(GuestClockPolicy::Off).unwrap();
    let before = manifest.to_canonical_bytes().unwrap();
    let mut doc = document();
    doc["active"]["runtime"]["user"] = saved(json!("1000:1000"));
    doc["active"]["runtime"]["guest_clock"] = saved(json!("off"));
    parse(&doc).validate_legacy_projections(&manifest).unwrap();
    assert_eq!(manifest.to_canonical_bytes().unwrap(), before);
    for (field, value) in [
        ("user", saved(json!("0"))),
        ("guest_clock", saved(json!("sync"))),
        ("user", json!({"state":"default"})),
        (
            "guest_clock",
            json!({"state":"unknown","reason":"not_recorded"}),
        ),
    ] {
        let mut invalid = doc.clone();
        invalid["active"]["runtime"][field] = value;
        assert!(
            parse(&invalid)
                .validate_legacy_projections(&manifest)
                .unwrap_err()
                .to_string()
                .contains("SCFG_IDENTITY")
        );
    }
    // A historical-only field is not a conflicting duplicate.
    parse(&document())
        .validate_legacy_projections(&manifest)
        .unwrap();
}

#[test]
fn absent_legacy_clock_still_means_sync_for_saved_projection() {
    let manifest = descriptor();
    assert_eq!(manifest.guest_clock().unwrap(), GuestClockPolicy::Sync);
    let before = manifest.to_canonical_bytes().unwrap();
    for clock in [
        saved(json!("sync")),
        json!({"state":"default"}),
        json!({"state":"unknown","reason":"not_recorded"}),
    ] {
        let mut doc = document();
        doc["active"]["runtime"]["guest_clock"] = clock;
        parse(&doc).validate_legacy_projections(&manifest).unwrap();
    }
    let mut doc = document();
    doc["active"]["runtime"]["guest_clock"] = saved(json!("off"));
    let error = parse(&doc)
        .validate_legacy_projections(&manifest)
        .unwrap_err();
    assert!(error.to_string().contains("SCFG_IDENTITY"));
    assert!(error.to_string().contains("active.runtime.guest_clock"));
    assert_eq!(manifest.to_canonical_bytes().unwrap(), before);
}

#[test]
fn schema_document_is_still_not_advertised_as_a_supported_extension() {
    assert!(
        !crate::snapshot::manifest::SUPPORTED_REQUIRES.contains(&"microsandbox.sandbox-config")
    );
}

#[test]
fn script_backing_requires_observed_matching_inventory_and_never_pending_intent() {
    let mut doc = document();
    doc["active"]["storage"] = json!({});
    let content = "PRIVATE_SCRIPT_BODY";
    doc["active"]["runtime"]["scripts"] = json!({"state":"value","origin":"observed","value":{"task":{"kind":"inline","content":content,"mode":416,"digest":format!("sha256:{}",hex::encode(Sha256::digest(content)))}}});
    doc["active"]["script_backing"] = json!({"state":"value","origin":"observed","value":{
        "runtime_directory":{"uid":0,"gid":0,"mode":493},
        "scripts_directory":{"uid":41,"gid":42,"mode":448},
        "files":{"task":{"uid":43,"gid":44,"mode":416}}
    }});
    let parsed = parse(&doc);
    assert_eq!(serde_json::to_value(parsed).unwrap(), doc);
    for (path, value) in [
        ("/active/script_backing/origin", json!("configured")),
        ("/active/script_backing/value/files/task/mode", json!(493)),
        (
            "/active/script_backing/value/runtime_directory/mode",
            json!(4095),
        ),
        ("/active/script_backing/value/files", json!({})),
        ("/active/runtime/scripts/origin", json!("configured")),
    ] {
        let mut bad = doc.clone();
        *bad.pointer_mut(path).unwrap() = value;
        let error = SavedSandboxConfig::from_bytes(&serde_json::to_vec(&bad).unwrap())
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains(content));
    }
    let mut bad = doc.clone();
    bad["pending"] = json!({"script_backing":{"state":"unknown","reason":"not_recorded"}});
    reject(&bad, "pending intent cannot contain observed backing");
    for value in [json!(null), json!({"state":"default"})] {
        let mut bad = doc.clone();
        bad["active"]["script_backing"] = value;
        assert!(SavedSandboxConfig::from_bytes(&serde_json::to_vec(&bad).unwrap()).is_err());
    }
    doc["active"]["script_backing"] = json!({"state":"unknown","reason":"not_recorded"});
    parse(&doc);
    doc["active"]
        .as_object_mut()
        .unwrap()
        .remove("script_backing");
    parse(&doc);
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn document() -> Value {
    json!({"schema_version":1,"active":{"resources":{},"runtime":{},"network":{},"execution":{}},"bindings":{},
        "provenance":{"producer_version":"0.8.0","active_generation":{"state":"unknown","reason":"not_observed"}}})
}

fn saved(value: Value) -> Value {
    json!({"state":"value","origin":"configured","value":value})
}

fn parse(value: &Value) -> SavedSandboxConfig {
    SavedSandboxConfig::from_bytes(&serde_json::to_vec(value).unwrap()).unwrap()
}

fn reject(value: &Value, expected: &str) -> String {
    let error = SavedSandboxConfig::from_bytes(&serde_json::to_vec(value).unwrap())
        .err()
        .expect("must reject document")
        .to_string();
    assert!(error.contains(expected), "expected {expected}; got {error}");
    error
}

pub(super) fn descriptor() -> Manifest {
    serde_json::from_value(json!({
        "schema":crate::snapshot::manifest::SCHEMA, "snapshot_id":"snap_0123456789abcdef0123456789abcdef", "scope":"file",
        "state":{"kind":"file","disk_format":"raw","filesystem":"ext4","virtual_size":4,"head":"layer_0123456789abcdef0123456789abcdef",
            "layers":[{"layer_id":"layer_0123456789abcdef0123456789abcdef","format":"raw","virtual_size":4,"backing":null,"payload":{"file_kind":"regular","integrity":null}}]},
        "capture":{"created_at":"2026-08-29T00:00:00Z","source_lineage":null,"source_checkpoint":null,"consistency":"crash-consistent"},
        "image":{"reference":"docker.io/library/alpine:latest","manifest_digest":format!("sha256:{}","a".repeat(64))},
        "parent":null,"requires":[],"extensions":{}
    })).unwrap()
}
