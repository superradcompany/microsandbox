//! Cold-boot materialization from portable bytes, independent of a surviving source.

use std::{
    collections::BTreeMap,
    fs::{self, File},
};

use microsandbox_filesystem::PassthroughFs;
use microsandbox_types::snapshot::saved_config::{
    SavedBindingKind, SavedOrigin, SavedRuntimeConfig, SavedSandboxConfig, SavedScript,
    SavedUnknownReason, SavedValue,
};
use microsandbox_types::{
    SandboxResources, SandboxRuntimeOptionsPatch, SandboxSpec, SandboxSpecPatch,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{
    ConfigurationBindingInput, RuntimeBindingInput, RuntimeConfigurationPlan, RuntimeDefaultClear,
    RuntimeSelectionContext, SavedConfigurationContext, SavedConfigurationPlan, SnapshotConfigMode,
    prepare_runtime_configuration,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn saved_scripts(scripts: Value) -> SavedRuntimeConfig {
    SavedRuntimeConfig::from_bytes(
        &serde_json::to_vec(&json!({
            "scripts": {"state":"value", "origin":"observed", "value":scripts}
        }))
        .unwrap(),
    )
    .unwrap()
}

fn inline(content: &str, mode: u16) -> Value {
    json!({
        "kind":"inline", "content":content, "mode":mode,
        "digest":format!("sha256:{}", hex::encode(Sha256::digest(content.as_bytes())))
    })
}

fn prepare(
    saved: &SavedRuntimeConfig,
    full: bool,
    patch: &SandboxSpecPatch,
    clears: &[RuntimeDefaultClear],
    bindings: &BTreeMap<String, RuntimeBindingInput>,
) -> RuntimeConfigurationPlan {
    prepare_runtime_configuration(
        saved,
        &SandboxSpec::default(),
        patch,
        clears,
        RuntimeSelectionContext {
            config_mode: SnapshotConfigMode::Saved,
            full_resume: full,
            starts_command: false,
        },
        bindings,
    )
    .unwrap()
}

fn portable_full_scripts() -> SavedSandboxConfig {
    super::configuration_tests::document(
        json!({
            "runtime":{"scripts":{"state":"value","origin":"observed","value":{"task":inline("CAPTURED_BODY",0o640)}}},
            "script_backing":{"state":"value","origin":"observed","value":{
                "runtime_directory":{"uid":40,"gid":41,"mode":488},
                "scripts_directory":{"uid":44,"gid":45,"mode":456},
                "files":{"task":{"uid":42,"gid":43,"mode":416}}
            }}
        }),
        json!({}),
    )
}

fn prepare_full_scripts(
    saved: &SavedSandboxConfig,
    patch: &SandboxSpecPatch,
    bindings: BTreeMap<String, ConfigurationBindingInput>,
) -> SavedConfigurationPlan {
    let resources = SandboxResources::default();
    let captured = Default::default();
    super::configuration_tests::prepare(
        saved,
        patch,
        SnapshotConfigMode::Fresh,
        SavedConfigurationContext::Full {
            resources: &resources,
            security: Default::default(),
            bindings: &captured,
        },
        bindings,
    )
    .unwrap()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn disk_script_materialization_survives_source_deletion_without_rewrapping() {
    let source = tempfile::tempdir().unwrap();
    let body = "#!/bin/custom-shell\r\nprintf 'literal λ'\r\n";
    fs::write(source.path().join("registered"), body).unwrap();
    let saved = saved_scripts(json!({"task":inline(body, 0o640)}));
    let serialized = serde_json::to_vec(&saved).unwrap();
    drop(saved);
    source.close().unwrap();
    let portable = SavedRuntimeConfig::from_bytes(&serialized).unwrap();
    let plan = prepare(
        &portable,
        false,
        &SandboxSpecPatch::new(),
        &[],
        &BTreeMap::new(),
    );
    let parent = tempfile::tempdir().unwrap();
    let staged = plan.stage_disk_scripts(parent.path()).unwrap();
    let file = staged.path().join("scripts/task");
    assert_eq!(fs::read(&file).unwrap(), body.as_bytes());
    let stat = PassthroughFs::runtime_backing_stat(&File::open(&file).unwrap()).unwrap();
    assert_eq!(
        (stat.st_uid, stat.st_gid, stat.st_mode & 0o7777),
        (0, 0, 0o640)
    );
    assert!(plan.command_defaults().unwrap().runtime.scripts.is_empty());
    drop(staged);
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn disk_script_bindings_materialize_destination_values_without_rewriting_portable_metadata() {
    let saved = saved_scripts(json!({"task":{"kind":"binding","id":"script-input"}}));
    let original = serde_json::to_vec(&saved).unwrap();
    let bindings = BTreeMap::from([(
        "script-input".into(),
        RuntimeBindingInput {
            text: Zeroizing::new("DESTINATION_SCRIPT_SENTINEL".into()),
            script_mode: Some(0),
        },
    )]);
    let plan = prepare(&saved, false, &SandboxSpecPatch::new(), &[], &bindings);
    let parent = tempfile::tempdir().unwrap();
    let staged = plan.stage_disk_scripts(parent.path()).unwrap();
    let file = staged.path().join("scripts/task");
    assert_eq!(
        fs::read_to_string(&file).unwrap(),
        "DESTINATION_SCRIPT_SENTINEL"
    );
    let stat = PassthroughFs::runtime_backing_stat(&File::open(file).unwrap()).unwrap();
    assert_eq!(stat.st_mode & 0o7777, 0);
    assert_eq!(serde_json::to_vec(&saved).unwrap(), original);
    assert!(!format!("{plan:?}").contains("DESTINATION_SCRIPT_SENTINEL"));
}

#[test]
fn disk_script_staging_applies_selected_clears_and_explicit_replacements() {
    let saved = saved_scripts(json!({
        "keep":inline("saved", 0o640),
        "replace":inline("old", 0o700),
        "clear":inline("removed", 0o755)
    }));
    let patch = SandboxSpecPatch::new().runtime(
        SandboxRuntimeOptionsPatch::new()
            .scripts(BTreeMap::from([("replace".into(), "new".into())])),
    );
    let plan = prepare(
        &saved,
        false,
        &patch,
        &[RuntimeDefaultClear::ScriptKey("clear".into())],
        &BTreeMap::new(),
    );
    let parent = tempfile::tempdir().unwrap();
    let staged = plan.stage_disk_scripts(parent.path()).unwrap();
    assert!(!staged.path().join("scripts/clear").exists());
    assert_eq!(
        fs::read_to_string(staged.path().join("scripts/keep")).unwrap(),
        "saved"
    );
    let replaced = staged.path().join("scripts/replace");
    assert_eq!(fs::read_to_string(&replaced).unwrap(), "new");
    let stat = PassthroughFs::runtime_backing_stat(&File::open(replaced).unwrap()).unwrap();
    assert_eq!(stat.st_mode & 0o7777, 0o755);
}

#[test]
fn full_resume_cannot_use_cold_boot_staging_even_with_equal_or_empty_scripts() {
    let parent = tempfile::tempdir().unwrap();
    for saved in [
        saved_scripts(json!({})),
        saved_scripts(json!({"task":inline("body", 0o755)})),
    ] {
        let plan = prepare(
            &saved,
            true,
            &SandboxSpecPatch::new(),
            &[],
            &BTreeMap::new(),
        );
        let error = plan
            .stage_disk_scripts(parent.path())
            .unwrap_err()
            .to_string();
        assert!(error.contains("SCFG_IDENTITY"));
        assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
    }
}

#[test]
fn full_script_materialization_keeps_serialized_guest_metadata_after_source_deletion() {
    let source = tempfile::tempdir().unwrap();
    fs::write(source.path().join("source"), "CAPTURED_BODY").unwrap();
    let document = portable_full_scripts();
    let bytes = serde_json::to_vec(&document).unwrap();
    drop(document);
    source.close().unwrap();
    let saved = SavedSandboxConfig::from_bytes(&bytes).unwrap();
    let plan = prepare_full_scripts(&saved, &SandboxSpecPatch::new(), BTreeMap::new());
    let parent = tempfile::tempdir().unwrap();
    let staged = plan.stage_full_scripts(parent.path()).unwrap();
    assert_eq!(
        fs::read_to_string(staged.path().join("scripts/task")).unwrap(),
        "CAPTURED_BODY"
    );
    for (path, expected) in [
        (staged.path().to_path_buf(), (40, 41, 0o750)),
        (staged.path().join("scripts"), (44, 45, 0o710)),
        (staged.path().join("scripts/task"), (42, 43, 0o640)),
    ] {
        let stat = PassthroughFs::runtime_backing_stat(&File::open(path).unwrap()).unwrap();
        assert_eq!((stat.st_uid, stat.st_gid, stat.st_mode & 0o7777), expected);
    }
    assert!(plan.runtime().inputs().requires_full_identity);
    drop(staged);
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[test]
fn full_script_staging_never_invents_metadata_or_certifies_changed_or_bound_bytes() {
    let parent = tempfile::tempdir().unwrap();
    for state in [
        None,
        Some(SavedValue::Unknown {
            reason: SavedUnknownReason::NotRecorded,
        }),
    ] {
        let mut saved = portable_full_scripts();
        saved.active.script_backing = state;
        let plan = prepare_full_scripts(&saved, &SandboxSpecPatch::new(), BTreeMap::new());
        assert!(plan.stage_full_scripts(parent.path()).is_err());
    }
    let saved = portable_full_scripts();
    let patch = SandboxSpecPatch::new().runtime(
        SandboxRuntimeOptionsPatch::new()
            .scripts(BTreeMap::from([("task".into(), "CHANGED_BODY".into())])),
    );
    let plan = prepare_full_scripts(&saved, &patch, BTreeMap::new());
    assert!(plan.stage_full_scripts(parent.path()).is_err());
    let mut bound = saved.clone();
    *bound.active.runtime.scripts.as_mut().unwrap() = SavedValue::Value {
        origin: SavedOrigin::Observed,
        value: BTreeMap::from([("task".into(), SavedScript::Binding { id: "body".into() })]),
    };
    bound.bindings.insert("body".into(), SavedBindingKind::Text);
    let plan = prepare_full_scripts(
        &bound,
        &SandboxSpecPatch::new(),
        BTreeMap::from([(
            "body".into(),
            ConfigurationBindingInput::Text(RuntimeBindingInput {
                text: Zeroizing::new("CAPTURED_BODY".into()),
                script_mode: Some(0o640),
            }),
        )]),
    );
    assert!(plan.stage_full_scripts(parent.path()).is_err());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}
