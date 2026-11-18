//! Whole-document capture keeps active evidence, pending intent and binding kinds distinct.

use std::collections::BTreeMap;

use microsandbox_runtime::retention::{
    CapturedScriptBacking, CapturedScriptDirectory, ScriptBackingEvidence,
};
use microsandbox_types::snapshot::Manifest;
use microsandbox_types::snapshot::saved_config::{
    RuntimeCaptureAction, RuntimeCaptureTarget, SavedBindingKind, SavedBindingReference,
    SavedOrigin, SavedText, SavedUnknownReason, SavedValue,
};
use microsandbox_types::{
    GuestClockPolicy, HostPermissions, MountOptions, OwnedVolumeStorage, StatVirtualization,
    VolumeMount,
};
use serde_json::{Value, json};
use sha2::Digest;

use super::storage_tests::manifest;
use super::{
    CaptureDocumentRequest, ExecutionCaptureControls, NetworkCaptureBindings,
    NetworkCaptureControls, PendingCaptureSource, ResourceCaptureObservation, RuntimeCaptureSource,
    StorageCaptureBindings,
};
use crate::sandbox::SandboxBuilder;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Default)]
struct Controls {
    runtime: BTreeMap<RuntimeCaptureTarget, RuntimeCaptureAction>,
    execution: ExecutionCaptureControls,
    network: NetworkCaptureControls,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn source() -> Value {
    let mut config = SandboxBuilder::new("PRIVATE_SOURCE_NAME")
        .image("alpine")
        .cmd(["active-default"])
        .background_command(["PRIVATE_INVOCATION"])
        .env("TOKEN", "ordinary")
        .finish(None, None)
        .unwrap();
    config.spec.resources.cpus = 4;
    config.spec.resources.max_cpus = 8;
    config.spec.resources.memory_mib = 1024;
    config.spec.resources.max_memory_mib = 2048;
    config.spec.network.trust_host_cas = false;
    config.spec.labels.insert("team".into(), "work".into());
    serde_json::to_value(config.clone_for_persistence()).unwrap()
}

fn known<T>(value: T, origin: SavedOrigin) -> SavedValue<T> {
    SavedValue::Value { value, origin }
}

fn generation() -> SavedValue<String> {
    known("17".into(), SavedOrigin::Observed)
}

fn request<'a>(descriptor: &'a Manifest, controls: &'a Controls) -> CaptureDocumentRequest<'a> {
    CaptureDocumentRequest {
        manifest: descriptor,
        resources: ResourceCaptureObservation {
            cpus: known(2, SavedOrigin::Observed),
            memory_mib: known(512, SavedOrigin::Observed),
        },
        network: NetworkCaptureBindings::default(),
        storage: StorageCaptureBindings::default(),
        runtime_controls: &controls.runtime,
        execution_controls: &controls.execution,
        network_controls: &controls.network,
        pending: None,
        include_source_name: false,
        construction_resources: None,
    }
}

fn pending_record(configure: impl FnOnce(SandboxBuilder) -> SandboxBuilder) -> Value {
    let mut config = configure(
        SandboxBuilder::new("pending-source")
            .image("alpine")
            .cpus(8),
    )
    .finish(None, None)
    .unwrap();
    config.spec.network.trust_host_cas = false;
    serde_json::to_value(config.clone_for_persistence()).unwrap()
}

fn pending(raw: &Value) -> PendingCaptureSource<'_> {
    PendingCaptureSource::from_recorded(raw, Default::default(), Default::default()).unwrap()
}

// Source-name provenance is optional, but the captured guest hostname is a separate
// intentional field. Check exact value paths so an excluded invocation/env value cannot
// be hidden by a broad allowance for the source name anywhere in the document.
fn assert_only_guest_hostname_has_private_marker(
    document: &microsandbox_types::snapshot::saved_config::SavedSandboxConfig,
) {
    fn visit(value: &Value, path: String, found: &mut Vec<String>) {
        match value {
            Value::String(text) if text.contains("PRIVATE_") => found.push(path),
            Value::Object(fields) => {
                for (key, value) in fields {
                    visit(value, format!("{path}/{key}"), found);
                }
            }
            Value::Array(values) => {
                for (index, value) in values.iter().enumerate() {
                    visit(value, format!("{path}/{index}"), found);
                }
            }
            _ => {}
        }
    }
    let mut found = Vec::new();
    visit(
        &serde_json::to_value(document).unwrap(),
        String::new(),
        &mut found,
    );
    assert_eq!(found, ["/active/runtime/hostname/value/value"]);
    assert!(document.provenance.source_name.is_none());
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn capture_document_projects_all_active_sections_without_raw_source_leaks() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let before = descriptor.to_canonical_bytes().unwrap();
    let controls = Controls::default();
    let document = adapter
        .project_document(request(&descriptor, &controls), generation())
        .unwrap();
    assert_eq!(
        document
            .active
            .resources
            .cpus
            .as_ref()
            .and_then(SavedValue::value),
        Some(&2)
    );
    assert_eq!(
        document
            .active
            .resources
            .memory_mib
            .as_ref()
            .and_then(SavedValue::value),
        Some(&512)
    );
    assert_eq!(
        document
            .active
            .execution
            .labels
            .as_ref()
            .and_then(SavedValue::value)
            .unwrap()["team"],
        "work"
    );
    assert!(
        document
            .active
            .storage
            .mounts
            .as_ref()
            .and_then(SavedValue::value)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        document
            .provenance
            .active_generation
            .value()
            .map(String::as_str),
        Some("17")
    );
    assert!(document.bindings.is_empty());
    assert!(document.pending.is_none());
    let encoded = serde_json::to_vec(&document).unwrap();
    let text = std::str::from_utf8(&encoded).unwrap();
    assert_only_guest_hostname_has_private_marker(&document);
    assert!(!text.contains("environment_provenance"));
    assert!(!text.contains("command_provenance"));
    assert!(
        microsandbox_types::snapshot::saved_config::SavedSandboxConfig::from_bytes(&encoded)
            .unwrap()
            == document
    );
    assert_eq!(descriptor.to_canonical_bytes().unwrap(), before);
}

#[test]
fn capture_document_pending_targets_and_bindings_never_supply_active_defaults() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let mut controls = Controls::default();
    controls.runtime.insert(
        RuntimeCaptureTarget::EnvKey("FUTURE".into()),
        RuntimeCaptureAction::Bind("future".into()),
    );
    let mut pending_raw = pending_record(|builder| {
        builder
            .cmd(["pending-default"])
            .env("FUTURE", "PRIVATE_FUTURE_CREDENTIAL")
    });
    pending_raw
        .as_object_mut()
        .unwrap()
        .remove("environment_provenance");
    let mut input = request(&descriptor, &controls);
    input.pending = Some(pending(&pending_raw));
    let document = adapter.project_document(input, generation()).unwrap();
    assert_eq!(
        document
            .active
            .resources
            .cpus
            .as_ref()
            .and_then(SavedValue::value),
        Some(&2)
    );
    let pending = document.pending.as_ref().unwrap();
    assert_eq!(
        pending.resources.cpus.as_ref().and_then(SavedValue::value),
        Some(&8)
    );
    assert!(
        matches!(&document.active.runtime.cmd.as_ref().and_then(SavedValue::value).unwrap()[0], SavedText::Literal { value } if value == "active-default")
    );
    assert!(
        matches!(&pending.runtime.cmd.as_ref().and_then(SavedValue::value).unwrap()[0], SavedText::Literal { value } if value == "pending-default")
    );
    assert_eq!(document.bindings["future"], SavedBindingKind::Text);
    assert!(
        !document
            .active_binding_uses()
            .unwrap()
            .contains_key("future")
    );
}

#[test]
fn capture_document_unknown_active_setting_stays_unknown_despite_pending_value() {
    let mut raw = source();
    raw["runtime"].as_object_mut().unwrap().remove("workdir");
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let controls = Controls::default();
    let pending_raw = pending_record(|builder| builder.workdir("/future"));
    let mut input = request(&descriptor, &controls);
    input.pending = Some(pending(&pending_raw));
    let document = adapter.project_document(input, generation()).unwrap();
    assert!(matches!(
        document.active.runtime.workdir,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded
        })
    ));
    assert_eq!(
        document
            .pending
            .as_ref()
            .unwrap()
            .runtime
            .workdir
            .as_ref()
            .and_then(SavedValue::value)
            .map(String::as_str),
        Some("/future")
    );
}

#[test]
fn capture_document_rejects_cross_family_binding_conflicts_without_echoing_ids() {
    let mut raw = source();
    raw["network"]["dns"] = json!({"rebind_protection": true, "nameservers": ["PRIVATE_RESOLVER"], "query_timeout_ms": 100});
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let mut controls = Controls::default();
    controls.runtime.insert(
        RuntimeCaptureTarget::EnvKey("TOKEN".into()),
        RuntimeCaptureAction::Bind("shared".into()),
    );
    let mut input = request(&descriptor, &controls);
    input.network.resolvers = vec![SavedBindingReference {
        id: "shared".into(),
    }];
    let error = adapter
        .project_document(input, generation())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("SCFG_BINDING"), "{error}");
    assert!(!error.contains("PRIVATE_"));
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let mut input = request(&descriptor, &controls);
    let mut pending_raw = pending_record(|builder| builder);
    pending_raw["vsock"]["routes"] =
        json!([{"port":456,"socket_type":"stream","host_socket":"/PRIVATE_SOCKET"}]);
    input.pending = Some(
        PendingCaptureSource::from_recorded(
            &pending_raw,
            Default::default(),
            StorageCaptureBindings {
                routes: vec![SavedBindingReference {
                    id: "shared".into(),
                }],
                ..Default::default()
            },
        )
        .unwrap(),
    );
    assert!(
        adapter
            .project_document(input, generation())
            .err()
            .unwrap()
            .to_string()
            .contains("SCFG_BINDING")
    );
}

#[test]
fn capture_document_shared_text_inventory_is_derived_and_pending_exclusions_apply() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let mut controls = Controls::default();
    controls.runtime.insert(
        RuntimeCaptureTarget::EnvKey("TOKEN".into()),
        RuntimeCaptureAction::Bind("shared".into()),
    );
    controls.runtime.insert(
        RuntimeCaptureTarget::EnvKey("FUTURE".into()),
        RuntimeCaptureAction::Bind("shared".into()),
    );
    controls.runtime.insert(
        RuntimeCaptureTarget::EnvKey("EXCLUDED".into()),
        RuntimeCaptureAction::Omit,
    );
    let mut pending_raw = pending_record(|builder| {
        builder
            .env("FUTURE", "PRIVATE_CREDENTIAL")
            .env("EXCLUDED", "PRIVATE_EXCLUDED")
    });
    pending_raw
        .as_object_mut()
        .unwrap()
        .remove("environment_provenance");
    let mut input = request(&descriptor, &controls);
    input.pending = Some(pending(&pending_raw));
    let document = adapter.project_document(input, generation()).unwrap();
    assert_eq!(document.bindings.len(), 1);
    assert_eq!(document.bindings["shared"], SavedBindingKind::Text);
    assert_only_guest_hostname_has_private_marker(&document);
}

#[test]
fn capture_document_generation_and_source_provenance_remain_explicit() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let controls = Controls::default();
    for invalid in [
        SavedValue::Default {},
        known(
            "PRIVATE_REQUESTED_GENERATION".into(),
            SavedOrigin::Configured,
        ),
    ] {
        let error = adapter
            .project_document(request(&descriptor, &controls), invalid)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("SCFG_VALUE"));
        assert!(!error.contains("PRIVATE_"));
    }
    let mut input = request(&descriptor, &controls);
    input.include_source_name = true;
    let document = adapter
        .project_document(
            input,
            SavedValue::Unknown {
                reason: SavedUnknownReason::NotObserved,
            },
        )
        .unwrap();
    assert_eq!(
        document.provenance.source_name.as_deref(),
        Some("PRIVATE_SOURCE_NAME")
    );
    assert!(matches!(
        document.provenance.active_generation,
        SavedValue::Unknown { .. }
    ));
}

#[test]
fn full_script_metadata_survives_projection_without_retaining_excluded_body_hashes() {
    let mut raw = source();
    raw["runtime"]["scripts"] = json!({"task":"STALE_DECLARATION"});
    let evidence = ScriptBackingEvidence::Observed {
        runtime_directory: CapturedScriptDirectory {
            uid: 0,
            gid: 0,
            mode: 0o755,
        },
        scripts_directory: CapturedScriptDirectory {
            uid: 44,
            gid: 45,
            mode: 0o710,
        },
        files: BTreeMap::from([(
            "task".into(),
            CapturedScriptBacking {
                content: "PRIVATE_OBSERVED_BODY".into(),
                uid: 42,
                gid: 43,
                mode: 0o640,
            },
        )]),
    };
    let source = RuntimeCaptureSource::from_recorded(&raw, None, Some(&evidence)).unwrap();
    let descriptor = manifest(true);
    let mut controls = Controls::default();
    let doc = source
        .project_document(request(&descriptor, &controls), generation())
        .unwrap();
    let metadata = doc
        .active
        .script_backing
        .as_ref()
        .and_then(SavedValue::value)
        .unwrap();
    assert_eq!(
        (
            metadata.files["task"].uid,
            metadata.files["task"].gid,
            metadata.files["task"].mode
        ),
        (42, 43, 0o640)
    );
    assert_eq!(metadata.scripts_directory.mode, 0o710);
    controls.runtime.insert(
        RuntimeCaptureTarget::ScriptKey("task".into()),
        RuntimeCaptureAction::Bind("body".into()),
    );
    let bound = source
        .project_document(request(&descriptor, &controls), generation())
        .unwrap();
    let encoded = serde_json::to_string(&bound).unwrap();
    assert!(!encoded.contains("PRIVATE_OBSERVED_BODY"));
    assert!(!encoded.contains(&hex::encode(sha2::Sha256::digest(b"PRIVATE_OBSERVED_BODY"))));
    assert!(bound.active.script_backing.is_some());
    assert!(
        source
            .project_document(
                request(&manifest(false), &Controls::default()),
                generation()
            )
            .unwrap()
            .active
            .script_backing
            .is_none()
    );
}

#[test]
fn capture_document_full_state_exclusions_follow_the_descriptor_scope() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let mut controls = Controls::default();
    controls
        .runtime
        .insert(RuntimeCaptureTarget::Scripts, RuntimeCaptureAction::Omit);
    let descriptor = manifest(true);
    let error = adapter
        .project_document(request(&descriptor, &controls), generation())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("SCFG_IDENTITY"));
    let descriptor = manifest(false);
    let document = adapter
        .project_document(request(&descriptor, &controls), generation())
        .unwrap();
    assert!(document.active.runtime.scripts.is_none());
}

#[test]
fn capture_document_detects_legacy_projection_contradiction_without_mutation() {
    let raw = source();
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let mut descriptor = manifest(false);
    descriptor.set_guest_clock(GuestClockPolicy::Off).unwrap();
    let before = descriptor.to_canonical_bytes().unwrap();
    let controls = Controls::default();
    assert!(
        adapter
            .project_document(request(&descriptor, &controls), generation())
            .is_err()
    );
    assert_eq!(descriptor.to_canonical_bytes().unwrap(), before);
}

#[test]
fn capture_document_enforces_combined_active_and_pending_script_budget() {
    let content = "x".repeat(63 * 1024);
    let mut raw = source();
    raw["runtime"]["scripts"] = json!({"a": "registered", "b": "registered", "c": "registered"});
    let backing = ScriptBackingEvidence::Observed {
        runtime_directory: CapturedScriptDirectory {
            uid: 0,
            gid: 0,
            mode: 0o755,
        },
        scripts_directory: CapturedScriptDirectory {
            uid: 0,
            gid: 0,
            mode: 0o755,
        },
        files: ["a", "b", "c"]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    CapturedScriptBacking {
                        content: content.clone(),
                        uid: 0,
                        gid: 0,
                        mode: 0o644,
                    },
                )
            })
            .collect(),
    };
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, Some(&backing)).unwrap();
    let descriptor = manifest(false);
    let controls = Controls::default();
    let pending_raw = pending_record(|builder| builder.script("d", &content).script("e", &content));
    let mut input = request(&descriptor, &controls);
    input.pending = Some(pending(&pending_raw));
    let error = adapter
        .project_document(input, generation())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("SCFG_LIMIT"));
    let mut controls = Controls::default();
    controls
        .runtime
        .insert(RuntimeCaptureTarget::Scripts, RuntimeCaptureAction::Omit);
    let mut input = request(&descriptor, &controls);
    input.pending = Some(pending(&pending_raw));
    let document = adapter.project_document(input, generation()).unwrap();
    assert!(document.active.runtime.scripts.is_none());
    assert!(document.pending.as_ref().unwrap().runtime.scripts.is_none());
}

#[test]
fn capture_document_assembles_raw_pending_intent_without_active_fallback() {
    let active_raw = source();
    let active = RuntimeCaptureSource::from_recorded(&active_raw, None, None).unwrap();
    let mut config = SandboxBuilder::new("next-start")
        .image("alpine")
        .cmd(["next-default"])
        .init("auto")
        .script("next-task", "echo next-start")
        .finish(None, None)
        .unwrap();
    config.spec.mounts.push(VolumeMount::Owned {
        guest: "/future".into(),
        storage: OwnedVolumeStorage::Disk { capacity_mib: 64 },
        options: MountOptions::default(),
        stat_virtualization: StatVirtualization::Strict,
        host_permissions: HostPermissions::Private,
    });
    let mut pending_raw = serde_json::to_value(config.clone_for_persistence()).unwrap();
    // Explicitly recorded absence: a historical serializer omission is still unknown.
    pending_raw["mounts"][0]["options"]["override_uid"] = Value::Null;
    pending_raw["mounts"][0]["options"]["override_gid"] = Value::Null;
    let descriptor = manifest(false);
    let controls = Controls::default();
    let mut request = request(&descriptor, &controls);
    // This pending source requests no external host trust inventory.
    pending_raw["network"]["trust_host_cas"] = Value::Bool(false);
    pending_raw["network"]["enabled"] = Value::Bool(false);
    pending_raw["labels"] = json!({"future":"intent"});
    request.pending = Some(pending(&pending_raw));
    let document = active.project_document(request, generation()).unwrap();
    let encoded = serde_json::to_value(&document).unwrap();
    assert_eq!(
        encoded["pending"]["runtime"]["init"]["value"]["cmd"],
        "auto"
    );
    assert_eq!(
        encoded["pending"]["runtime"]["scripts"]["value"]["next-task"]["kind"],
        "declaration"
    );
    assert_eq!(
        encoded["pending"]["resources"]["cpus"]["origin"],
        "configured"
    );
    assert_eq!(encoded["active"]["resources"]["cpus"]["origin"], "observed");
    assert_eq!(encoded["active"]["runtime"]["init"]["state"], "unknown");
    assert_eq!(
        encoded["pending"]["storage"]["mounts"]["value"][0]["kind"],
        "requested_owned"
    );
    assert_eq!(encoded["active"]["storage"]["mounts"]["value"], json!([]));
    assert_eq!(encoded["pending"]["network"]["enabled"]["value"], false);
    assert_eq!(
        encoded["pending"]["execution"]["labels"]["value"],
        json!({"future":"intent"})
    );
    assert_eq!(
        encoded["active"]["execution"]["labels"]["value"],
        json!({"team":"work"})
    );
    assert!(document.active_binding_uses().unwrap().is_empty());
    assert!(document.active.runtime.validate_active().is_ok());
    assert!(document.pending.unwrap().runtime.validate_active().is_err());
}

#[test]
fn capture_document_excludes_labels_and_http_across_both_recorded_sources_before_validation() {
    let mut raw = source();
    let mut future = pending_record(|builder| builder);
    let excluded = "PRIVATE_EXCLUDED".repeat(10_000);
    raw["labels"] = json!({"shared": excluded, "active-only": excluded, "keep":"active"});
    future["labels"] = json!({"shared": excluded, "pending-only": excluded, "keep":"pending"});
    for record in [&mut raw, &mut future] {
        record["network"]["http"]["deny_message"] = json!(excluded);
    }
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let no_controls = Controls::default();
    let mut input = request(&descriptor, &no_controls);
    input.pending = Some(pending(&future));
    assert!(adapter.project_document(input, generation()).is_err());

    for whole in [false, true] {
        let mut controls = Controls::default();
        controls.network.omit_http = true;
        controls.execution.omit_labels = whole;
        if !whole {
            controls.execution.omit_label_keys = ["shared", "active-only", "pending-only"]
                .into_iter()
                .map(str::to_owned)
                .collect();
        }
        let mut input = request(&descriptor, &controls);
        input.pending = Some(pending(&future));
        let document = adapter.project_document(input, generation()).unwrap();
        let pending = document.pending.as_ref().unwrap();
        assert!(document.active.network.http.is_none());
        assert!(pending.network.http.is_none());
        if whole {
            assert!(document.active.execution.labels.is_none());
            assert!(pending.execution.labels.is_none());
        } else {
            assert_eq!(
                document
                    .active
                    .execution
                    .labels
                    .as_ref()
                    .unwrap()
                    .value()
                    .unwrap(),
                &BTreeMap::from([("keep".into(), "active".into())])
            );
            assert_eq!(
                pending.execution.labels.as_ref().unwrap().value().unwrap(),
                &BTreeMap::from([("keep".into(), "pending".into())])
            );
        }
        assert_only_guest_hostname_has_private_marker(&document);
    }
}

#[test]
fn capture_document_label_selectors_reject_unmatched_reserved_and_overlapping_controls() {
    let raw = source();
    let mut future = pending_record(|builder| builder);
    future["labels"] = json!({"future":"visible", "microsandbox.PRIVATE_SYSTEM":"hidden"});
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    for (key, whole) in [
        ("PRIVATE_TYPO", false),
        ("microsandbox.PRIVATE_SYSTEM", false),
        ("future", true),
    ] {
        let mut controls = Controls::default();
        controls.execution.omit_labels = whole;
        controls.execution.omit_label_keys.insert(key.into());
        let mut input = request(&descriptor, &controls);
        input.pending = Some(pending(&future));
        let error = adapter
            .project_document(input, generation())
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("SCFG_VALUE"), "{error}");
        assert!(!error.contains("PRIVATE"), "{error}");
    }
}

#[test]
fn capture_document_missing_pending_sections_stay_unknown_without_active_fallback() {
    let raw = source();
    let mut future = pending_record(|builder| builder);
    for key in [
        "network",
        "resources",
        "runtime",
        "labels",
        "mounts",
        "vsock",
        "security_profile",
        "rlimits",
        "lifecycle",
        "command_provenance",
        "environment_provenance",
    ] {
        future.as_object_mut().unwrap().remove(key);
    }
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let controls = Controls::default();
    let mut input = request(&descriptor, &controls);
    input.pending = Some(pending(&future));
    let document = adapter.project_document(input, generation()).unwrap();
    let encoded = serde_json::to_value(document).unwrap();
    for path in [
        "/pending/resources/cpus",
        "/pending/runtime/workdir",
        "/pending/network/enabled",
        "/pending/execution/labels",
        "/pending/execution/security_profile",
        "/pending/execution/lifecycle",
        "/pending/storage/mounts",
        "/pending/storage/vsock",
    ] {
        assert_eq!(encoded.pointer(path).unwrap()["state"], "unknown", "{path}");
    }
    assert_eq!(encoded["active"]["resources"]["cpus"]["value"], 2);
}

#[test]
fn capture_document_pending_bindings_must_match_the_pending_source() {
    let mut raw = source();
    raw["network"]["dns"] = json!({"rebind_protection":true,"nameservers":["PRIVATE_ACTIVE_ENDPOINT"],"query_timeout_ms":100});
    let future = pending_record(|builder| builder);
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let controls = Controls::default();
    let mut input = request(&descriptor, &controls);
    input.network.resolvers = vec![SavedBindingReference {
        id: "active-dns".into(),
    }];
    input.pending = Some(
        PendingCaptureSource::from_recorded(
            &future,
            NetworkCaptureBindings {
                resolvers: vec![SavedBindingReference {
                    id: "PRIVATE_UNUSED".into(),
                }],
                ..Default::default()
            },
            Default::default(),
        )
        .unwrap(),
    );
    let error = adapter
        .project_document(input, generation())
        .err()
        .unwrap()
        .to_string();
    assert!(error.contains("SCFG_BINDING"), "{error}");
    assert!(!error.contains("PRIVATE"), "{error}");
}

#[test]
fn capture_document_pending_network_and_socket_requirements_never_become_active_demand() {
    let raw = source();
    let mut future = pending_record(|builder| builder);
    future["network"]["dns"] = json!({"rebind_protection":true,"nameservers":["PRIVATE_PENDING_ENDPOINT"],"query_timeout_ms":100});
    future["vsock"]["routes"] =
        json!([{"port":456,"socket_type":"stream","host_socket":"/PRIVATE_PENDING_SOCKET"}]);
    let adapter = RuntimeCaptureSource::from_recorded(&raw, None, None).unwrap();
    let descriptor = manifest(false);
    let controls = Controls::default();
    let mut input = request(&descriptor, &controls);
    input.pending = Some(
        PendingCaptureSource::from_recorded(
            &future,
            NetworkCaptureBindings {
                resolvers: vec![SavedBindingReference {
                    id: "future-dns".into(),
                }],
                ..Default::default()
            },
            StorageCaptureBindings {
                routes: vec![SavedBindingReference {
                    id: "future-socket".into(),
                }],
                ..Default::default()
            },
        )
        .unwrap(),
    );
    let document = adapter.project_document(input, generation()).unwrap();
    assert_eq!(document.bindings.len(), 2);
    assert!(document.bindings.contains_key("future-dns"));
    assert!(document.bindings.contains_key("future-socket"));
    assert!(document.active_binding_uses().unwrap().is_empty());
    assert_only_guest_hostname_has_private_marker(&document);
}

#[test]
#[ignore = "requires MSB_PRESENCE_CAPTURE_FIXTURES from saved-presence-evidence.py"]
fn runtime_capture_document_preserves_old_writer_unknowns() {
    let directory = std::path::PathBuf::from(
        std::env::var_os("MSB_PRESENCE_CAPTURE_FIXTURES").expect("live fixture directory"),
    );
    let active_raw: Value = serde_json::from_slice(
        &std::fs::read(directory.join("current/current-source.json")).unwrap(),
    )
    .unwrap();
    let active = RuntimeCaptureSource::from_recorded(&active_raw, None, None).unwrap();
    let descriptor = manifest(false);
    let mut controls = Controls::default();
    // These fixtures include environment values without portable literal provenance.
    // Explicitly omit that optional default; never relax the binding requirement just
    // to exercise ownership evidence from real old/new producer records.
    controls
        .runtime
        .insert(RuntimeCaptureTarget::Env, RuntimeCaptureAction::Omit);
    for (name, mounts_known) in [
        ("current-source", true),
        ("runtime-modified-source", true),
        ("old-modified-config", false),
        ("new-after-old-source", false),
    ] {
        let future: Value = serde_json::from_slice(
            &std::fs::read(directory.join("current").join(format!("{name}.json"))).unwrap(),
        )
        .unwrap();
        let mut input = request(&descriptor, &controls);
        // These saved records do not attest a new capture cut or guest allocation.
        // Exercise their real producer shapes without manufacturing either observation.
        input.resources = ResourceCaptureObservation::default();
        input.pending = Some(pending(&future));
        let document = active
            .project_document(
                input,
                SavedValue::Unknown {
                    reason: SavedUnknownReason::NotObserved,
                },
            )
            .unwrap();
        assert!(matches!(
            document.active.resources.cpus,
            Some(SavedValue::Unknown { .. })
        ));
        let pending = document.pending.unwrap();
        assert_eq!(
            pending.storage.mounts.unwrap().value().is_some(),
            mounts_known,
            "{name}"
        );
        assert!(matches!(
            pending.resources.cpus,
            Some(SavedValue::Value {
                origin: SavedOrigin::Configured,
                ..
            })
        ));
    }
}
