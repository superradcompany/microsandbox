//! Substitution preparation preserves identity and policy while keeping credentials local.

use std::collections::BTreeMap;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_BYTES, MAX_SAVED_TEXT_BYTES, SavedBindingReference, SavedOrigin,
    SavedSecretsConfig, SavedUnknownReason, SavedValue,
};
use microsandbox_types::{
    SecretEntry, SecretSource, SecretViolationAction, SecretsConfig, SecretsConfigPatch,
};
use serde_json::json;
use zeroize::Zeroizing;

use super::{SecretBindingInput, prepare_secret_configuration};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn entry(index: usize) -> SecretEntry {
    serde_json::from_value(json!({
        "env_var": format!("TOKEN_{index}"),
        "placeholder": format!("PLACEHOLDER_{index}"),
        "value": "SOURCE_SECRET_SENTINEL",
        "allowed_hosts": ["any"],
        "substitution": {"headers": true, "header_fields": ["Authorization"], "query": false, "body": false},
        "require_tls_identity": true
    })).unwrap()
}

fn source(count: usize) -> SavedValue<SavedSecretsConfig> {
    let entries: Vec<_> = (0..count).map(entry).collect();
    let bindings = entries
        .iter()
        .map(|entry| {
            (
                entry.env_var.clone(),
                SavedBindingReference {
                    id: "shared".into(),
                },
            )
        })
        .collect();
    SavedValue::Value {
        value: SavedSecretsConfig::from_source(
            &SecretsConfig {
                secrets: entries,
                ..Default::default()
            },
            &bindings,
        )
        .unwrap(),
        origin: SavedOrigin::Configured,
    }
}

fn supplied() -> BTreeMap<String, SecretBindingInput> {
    BTreeMap::from([(
        "shared".into(),
        SecretBindingInput::Value(Zeroizing::new("DESTINATION_SECRET_SENTINEL".into())),
    )])
}

fn assert_error(error: crate::MicrosandboxError, code: &str) {
    assert!(error.to_string().contains(code), "{error}");
    assert!(!error.to_string().contains("SENTINEL"));
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn shared_material_preserves_each_policy_and_never_changes_portable_source() {
    let mut saved = source(2);
    let SavedValue::Value { value, .. } = &mut saved else {
        unreachable!()
    };
    value.entries[1].substitution.body = true;
    value.entries[1].require_tls_identity = false;
    value.entries[1].violation_action = Some(SecretViolationAction::BlockAndTerminate);
    value.violation_action = SecretViolationAction::Block;
    let original = serde_json::to_vec(&saved).unwrap();
    let inputs = supplied();
    let plan = prepare_secret_configuration(Some(&saved), None, &inputs, true).unwrap();
    let mut native = SecretsConfig::default();
    plan.apply_to(&mut native).unwrap();
    assert_eq!(native.secrets.len(), 2);
    for (index, secret) in native.secrets.iter().enumerate() {
        assert_eq!(secret.env_var, format!("TOKEN_{index}"));
        assert_eq!(secret.placeholder, format!("PLACEHOLDER_{index}"));
        assert_eq!(&*secret.value, "DESTINATION_SECRET_SENTINEL");
        assert_eq!(secret.substitution.header_fields, ["Authorization"]);
        assert!(secret.source.is_none());
    }
    assert!(!native.secrets[0].substitution.body);
    assert!(native.secrets[1].substitution.body);
    assert!(plan.selection().tls_identity_approvals.contains("TOKEN_1"));
    assert!(plan.selection().requires_full_identity);
    assert!(plan.selection().remaining_bindings.contains_key("shared"));
    let bindings = native
        .secrets
        .iter()
        .map(|entry| {
            (
                entry.env_var.clone(),
                SavedBindingReference {
                    id: "shared".into(),
                },
            )
        })
        .collect();
    // Projecting the composed destination must preserve every policy field while
    // substituting logical references for the newly supplied credentials again.
    assert!(
        SavedSecretsConfig::from_source(&native, &bindings).unwrap() == *saved.value().unwrap()
    );
    assert_eq!(serde_json::to_vec(&saved).unwrap(), original);
    assert!(
        !String::from_utf8(original)
            .unwrap()
            .contains("SECRET_SENTINEL")
    );
    assert!(!format!("{plan:?} {inputs:?}").contains("SENTINEL"));
}

#[test]
fn keyed_override_keeps_other_shared_consumer_and_does_not_resolve_sources() {
    let saved = source(2);
    let mut explicit_entry = entry(0);
    explicit_entry.value.clear();
    explicit_entry.source = Some(SecretSource::env("MISSING_EXPLICIT_SENTINEL"));
    let explicit = SecretsConfigPatch::new().secrets(vec![explicit_entry]);
    let reference = SecretSource::Store {
        reference: "test-unavailable://BINDING_SENTINEL".into(),
    };
    let input = BTreeMap::from([(
        "shared".into(),
        SecretBindingInput::Source(reference.clone()),
    )]);
    let plan = prepare_secret_configuration(Some(&saved), Some(&explicit), &input, true).unwrap();
    let mut native = SecretsConfig::default();
    plan.apply_to(&mut native).unwrap();
    assert_eq!(
        native.secrets[0].source,
        Some(SecretSource::env("MISSING_EXPLICIT_SENTINEL"))
    );
    assert_eq!(native.secrets[1].source, Some(reference));
    assert!(native.secrets.iter().all(|entry| entry.value.is_empty()));
    assert!(!format!("{plan:?} {input:?}").contains("SENTINEL"));
}

#[test]
fn missing_or_extra_inputs_refuse_instead_of_using_source_credentials() {
    let saved = source(2);
    assert_error(
        prepare_secret_configuration(Some(&saved), None, &BTreeMap::new(), false).unwrap_err(),
        "SCFG_BINDING",
    );
    let mut input = supplied();
    input.insert(
        "UNUSED_SENTINEL".into(),
        SecretBindingInput::Value(Zeroizing::new("SECRET_SENTINEL".into())),
    );
    assert_error(
        prepare_secret_configuration(Some(&saved), None, &input, false).unwrap_err(),
        "SCFG_BINDING",
    );
}

#[test]
fn complete_selection_replaces_lower_entries_and_respects_explicit_global_policy() {
    let empty = SavedValue::Default {};
    let plan = prepare_secret_configuration(Some(&empty), None, &BTreeMap::new(), false).unwrap();
    let mut native = SecretsConfig {
        secrets: vec![entry(99)],
        ..Default::default()
    };
    plan.apply_to(&mut native).unwrap();
    assert!(native.secrets.is_empty());
    assert!(native.passthrough_hosts.is_none());

    let explicit = SecretsConfigPatch::new()
        .replace_secrets(vec![])
        .passthrough_hosts(vec![]);
    let saved = source(2);
    let plan =
        prepare_secret_configuration(Some(&saved), Some(&explicit), &supplied(), false).unwrap();
    plan.apply_to(&mut native).unwrap();
    assert_eq!(
        native.secrets.len(),
        2,
        "empty native input cannot drop required saved identities"
    );
    assert_eq!(native.passthrough_hosts, Some(vec![]));
}

#[test]
fn unknown_inventory_cannot_partially_mutate_destination() {
    let saved = SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    };
    let explicit = SecretsConfigPatch::new().secrets(vec![entry(0)]);
    let plan = prepare_secret_configuration(Some(&saved), Some(&explicit), &BTreeMap::new(), true)
        .unwrap();
    let mut native = SecretsConfig {
        secrets: vec![entry(99)],
        ..Default::default()
    };
    let before = serde_json::to_vec(&native).unwrap();
    assert_error(plan.apply_to(&mut native).unwrap_err(), "SCFG_UNKNOWN");
    assert_eq!(serde_json::to_vec(&native).unwrap(), before);
}

#[test]
fn invalid_or_ambiguous_credential_sources_have_redacted_errors() {
    let saved = source(1);
    for reference in ["", "NUL\0SOURCE_SENTINEL"] {
        let inputs = BTreeMap::from([(
            "shared".into(),
            SecretBindingInput::Source(SecretSource::env(reference)),
        )]);
        assert_error(
            prepare_secret_configuration(Some(&saved), None, &inputs, false).unwrap_err(),
            "SCFG_VALUE",
        );
    }
    let mut ambiguous = entry(0);
    ambiguous.source = Some(SecretSource::env("SOURCE_SENTINEL"));
    let explicit = SecretsConfigPatch::new().secrets(vec![ambiguous]);
    assert_error(
        prepare_secret_configuration(Some(&saved), Some(&explicit), &BTreeMap::new(), false)
            .unwrap_err(),
        "SCFG_VALUE",
    );
}

#[test]
fn repeated_shared_material_is_bounded_after_expansion() {
    let count = MAX_SAVED_CONFIG_BYTES / MAX_SAVED_TEXT_BYTES + 1;
    let saved = source(count);
    let inputs = BTreeMap::from([(
        "shared".into(),
        SecretBindingInput::Value(Zeroizing::new("s".repeat(MAX_SAVED_TEXT_BYTES))),
    )]);
    assert_error(
        prepare_secret_configuration(Some(&saved), None, &inputs, false).unwrap_err(),
        "SCFG_LIMIT",
    );
}

#[test]
fn explicit_empty_material_remains_distinct_from_an_unresolved_source() {
    let saved = source(1);
    let inputs = BTreeMap::from([(
        "shared".into(),
        SecretBindingInput::Value(Zeroizing::new(String::new())),
    )]);
    let plan = prepare_secret_configuration(Some(&saved), None, &inputs, false).unwrap();
    let mut native = SecretsConfig::default();
    plan.apply_to(&mut native).unwrap();
    assert!(native.secrets[0].value.is_empty());
    assert!(native.secrets[0].source.is_none());
}
