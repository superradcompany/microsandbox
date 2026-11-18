//! Whole-input composition must retain requirements as well as selected native values.

use std::collections::BTreeMap;

use microsandbox_types::{
    HostPermissions, MountOptions, NetworkSpecPatch, SandboxPolicyPatch, SandboxResources,
    SandboxResourcesPatch, SandboxRuntimeOptionsPatch, SandboxSpec, SandboxSpecPatch,
    SecurityProfile, StatVirtualization, VolumeMount,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::configuration_tests::{disk, document, known, prepare};
use super::*;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn active() -> Value {
    json!({"network":{
        "dns":{"state":"default"}, "tls":{"state":"default"},
        "secrets":{"state":"default"}, "ports":{"state":"default"},
        "guest_trust":{"state":"default"}, "outbound_proxy":{"state":"default"}
    }})
}

fn literal(value: &str) -> Value {
    json!({"kind":"literal","value":value})
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn destination_inputs_compose_families_without_reapplying_the_raw_patch() {
    let content = "#!/bin/sh\nprintf '%s' SCRIPT_SENTINEL\n";
    let mut source = active();
    source["runtime"] = json!({
        "entrypoint":known(json!([literal("/saved")])),
        "cmd":known(json!([literal("old-cmd")])),
        "env":known(json!({"KEEP":literal("ENV_SENTINEL")})),
        "scripts":known(json!({"job":{"kind":"inline","content":content,"mode":448,
            "digest":format!("sha256:{}",hex::encode(Sha256::digest(content.as_bytes())))}}))
    });
    source["resources"] = json!({"cpus":known(json!(2)), "max_cpus":known(json!(4))});
    source["resources"]["cpus"]["origin"] = json!("observed");
    source["execution"] = json!({"labels":known(json!({"team":"saved"}))});
    let saved = document(source, json!({}));
    let before = serde_json::to_vec(&saved).unwrap();
    let explicit = SandboxSpecPatch::new()
        .name("destination".into())
        .runtime(SandboxRuntimeOptionsPatch::new().entrypoint(vec!["/explicit".into()]))
        .resources(SandboxResourcesPatch::new().cpus(3))
        .lifecycle(SandboxPolicyPatch::new().ephemeral(true))
        .network(NetworkSpecPatch::new().max_udp_connections(0))
        .mounts(vec![VolumeMount::Bind {
            host: "/missing/MOUNT_SENTINEL".into(),
            guest: "/data".into(),
            options: MountOptions::default(),
            stat_virtualization: StatVirtualization::Strict,
            host_permissions: HostPermissions::Private,
            follow_root_symlinks: false,
            quota_mib: Some(7),
        }]);
    let inputs = prepare(
        &saved,
        &explicit,
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::new(),
    )
    .unwrap()
    .into_destination_inputs()
    .unwrap();
    let spec = inputs.spec_inputs();
    assert_eq!(spec.name, "destination");
    assert!(spec.lifecycle.ephemeral);
    assert_eq!((spec.resources.cpus, spec.resources.max_cpus), (3, 4));
    assert_eq!(spec.labels.get("team").map(String::as_str), Some("saved"));
    assert_eq!(spec.runtime.entrypoint, Some(vec!["/explicit".into()]));
    assert_eq!(spec.runtime.cmd, Some(vec![]));
    assert_eq!(spec.env[0].value, "ENV_SENTINEL");
    assert_eq!(spec.network.max_udp_connections, Some(0));
    assert_eq!(spec.mounts[0].guest(), "/data");
    // Exact scripts must never flow through the ordinary script-string writer.
    assert!(spec.runtime.scripts.is_empty());
    let script = &inputs.plan().runtime().scripts()["job"];
    assert_eq!(script.content.as_str(), content);
    assert_eq!(script.mode, 0o700);
    assert!(!format!("{inputs:?}").contains("SENTINEL"));
    assert_eq!(serde_json::to_vec(&saved).unwrap(), before);
}

#[test]
fn destination_inputs_keep_deferred_command_bindings_without_claiming_readiness() {
    let mut source = active();
    source["runtime"] = json!({"env":known(json!({"TOKEN":{"kind":"binding","id":"token"}}))});
    let saved = document(source, json!({"token":"text"}));
    let inputs = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        disk(),
        BTreeMap::new(),
    )
    .unwrap()
    .into_destination_inputs()
    .unwrap();
    assert!(
        inputs
            .plan()
            .supply_gaps()
            .before_new_command
            .contains("token")
    );
    assert!(inputs.plan().runtime().command_defaults().is_err());
    assert!(inputs.spec_inputs().env.is_empty());
    // Starting that command now must still refuse, rather than using the empty native field.
    let error = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        SavedConfigurationContext::Disk {
            starts_command: true,
        },
        BTreeMap::new(),
    )
    .and_then(SavedConfigurationPlan::into_destination_inputs)
    .unwrap_err()
    .to_string();
    assert!(error.contains("SCFG_BINDING"), "{error}");
}

#[test]
fn destination_inputs_unknown_command_fields_are_guarded_at_the_actual_consumer() {
    for field in ["env", "cmd", "entrypoint", "workdir", "shell", "user"] {
        let mut source = active();
        source["runtime"] = json!({});
        source["runtime"][field] = json!({"state":"unknown","reason":"not_observed"});
        let saved = document(source, json!({}));
        for starts_command in [false, true] {
            let result = prepare(
                &saved,
                &SandboxSpecPatch::new(),
                SnapshotConfigMode::Saved,
                SavedConfigurationContext::Disk { starts_command },
                BTreeMap::new(),
            )
            .and_then(SavedConfigurationPlan::into_destination_inputs);
            if starts_command {
                let error = result.unwrap_err().to_string();
                assert!(error.contains("SCFG_UNKNOWN"), "{field}: {error}");
            } else {
                let inputs = result.unwrap();
                assert!(!inputs.plan().context().starts_command);
                assert!(
                    inputs.plan().runtime().command_defaults().is_err(),
                    "{field}"
                );
            }
        }
    }
}

#[test]
fn destination_inputs_refuse_each_unknown_immediate_family_without_mutating_source() {
    for (section, field) in [
        ("runtime", "hostname"),
        ("runtime", "guest_clock"),
        ("runtime", "scripts"),
        ("runtime", "init"),
        ("resources", "cpus"),
        ("execution", "rlimits"),
        ("network", "dns"),
        ("storage", "mounts"),
    ] {
        let mut source = active();
        if source.get(section).is_none() {
            source[section] = json!({});
        }
        source[section][field] = json!({"state":"unknown","reason":"not_observed"});
        let saved = document(source, json!({}));
        let before = serde_json::to_vec(&saved).unwrap();
        let error = prepare(
            &saved,
            &SandboxSpecPatch::new(),
            SnapshotConfigMode::Saved,
            disk(),
            BTreeMap::new(),
        )
        .and_then(SavedConfigurationPlan::into_destination_inputs)
        .unwrap_err()
        .to_string();
        assert!(error.contains("SCFG_UNKNOWN"), "{section}.{field}: {error}");
        assert_eq!(serde_json::to_vec(&saved).unwrap(), before);
    }
}

#[test]
fn destination_inputs_full_resume_preserves_cold_boot_init_without_replaying_it() {
    let mut source = active();
    source["runtime"] = json!({"init":known(json!({
        "kind":"handoff", "selection":"path", "resolved_path":"/sbin/saved-init",
        "args":[literal("--init")], "env":{}
    }))});
    let saved = document(source, json!({}));
    let resources = SandboxResources::default();
    let captured = Default::default();
    let inputs = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        SavedConfigurationContext::Full {
            resources: &resources,
            security: SecurityProfile::default(),
            bindings: &captured,
        },
        BTreeMap::new(),
    )
    .unwrap()
    .into_destination_inputs()
    .unwrap();
    assert!(inputs.spec_inputs().init.is_none());
    assert!(inputs.plan().context().full_resume);
    assert_eq!(
        inputs
            .plan()
            .runtime()
            .cold_boot_init()
            .unwrap()
            .unwrap()
            .cmd,
        "/sbin/saved-init"
    );
    assert!(inputs.plan().runtime().inputs().requires_full_identity);
    assert!(inputs.plan().resources().requires_full_compatibility());
    assert!(
        inputs
            .plan()
            .network_policy()
            .selection()
            .requires_full_compatibility
    );
}

#[test]
fn destination_inputs_full_resume_retains_unavailable_future_init() {
    let mut source = active();
    source["runtime"] = json!({"init":{"state":"unknown","reason":"not_observed"}});
    let saved = document(source, json!({}));
    let resources = SandboxResources::default();
    let captured = Default::default();
    let inputs = prepare(
        &saved,
        &SandboxSpecPatch::new(),
        SnapshotConfigMode::Saved,
        SavedConfigurationContext::Full {
            resources: &resources,
            security: SecurityProfile::default(),
            bindings: &captured,
        },
        BTreeMap::new(),
    )
    .unwrap()
    .into_destination_inputs()
    .unwrap();
    assert!(inputs.spec_inputs().init.is_none());
    assert!(inputs.plan().runtime().cold_boot_init().is_err());
}

#[test]
fn destination_inputs_pin_destination_identity_and_ownership_at_preparation() {
    let saved = document(active(), json!({}));
    let mut lower = SandboxSpec::default();
    lower.name = "destination".into();
    lower
        .labels
        .insert("sandbox.id".into(), "DESTINATION_ID".into());
    lower.labels.insert("team".into(), "lower-team".into());
    lower.lifecycle.ephemeral = true;
    let explicit =
        SandboxSpecPatch::new().labels(BTreeMap::from([("team".into(), "explicit".into())]));
    let baseline = DestinationNetworkBaseline {
        strict: false,
        tls_enabled: false,
        intercepted_ports: vec![],
    };
    let plan = prepare_saved_configuration(
        SavedConfigurationRequest {
            saved: &saved,
            manifest: &storage_tests::manifest(false),
            lower: &lower,
            lower_resources: &SandboxResourcesPatch::new(),
            explicit: &explicit,
            clears: &SavedConfigurationClears::default(),
            mode: SnapshotConfigMode::Saved,
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
    lower.name = "changed-after-preparation".into();
    lower.labels.clear();
    lower.lifecycle.ephemeral = false;
    let inputs = plan.into_destination_inputs().unwrap();
    assert_eq!(inputs.spec_inputs().name, "destination");
    assert_eq!(inputs.spec_inputs().labels["sandbox.id"], "DESTINATION_ID");
    assert_eq!(inputs.spec_inputs().labels["team"], "explicit");
    assert!(inputs.spec_inputs().lifecycle.ephemeral);
}
