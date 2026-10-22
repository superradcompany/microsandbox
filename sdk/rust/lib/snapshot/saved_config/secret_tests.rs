//! Selection must never erase another consumer or transfer authority through saved policy.

use std::collections::BTreeMap;

use microsandbox_types::snapshot::saved_config::{
    MAX_SAVED_CONFIG_ENTRIES, SavedBindingReference, SavedOrigin, SavedSecretsConfig,
    SavedUnknownReason, SavedValue,
};
use microsandbox_types::{
    HostPattern, SecretEntry, SecretSource, SecretsConfig, SecretsConfigPatch,
};
use serde_json::json;

use super::{
    BindingDemandContext, plan_binding_demand, prepare_secret_configuration, select_secret_inputs,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn secret(name: &str, placeholder: &str) -> SecretEntry {
    serde_json::from_value(json!({
        "env_var": name, "placeholder": placeholder, "value": "DESTINATION_SECRET_SENTINEL",
        "allowed_hosts": ["any"], "require_tls_identity": true
    }))
    .unwrap()
}

fn source() -> SavedValue<SavedSecretsConfig> {
    let config = SecretsConfig {
        secrets: vec![
            secret("TOKEN.A", "PLACEHOLDER_A"),
            secret("TOKEN.B", "PLACEHOLDER_B"),
        ],
        ..Default::default()
    };
    let bindings = BTreeMap::from([
        (
            "TOKEN.A".into(),
            SavedBindingReference {
                id: "shared".into(),
            },
        ),
        (
            "TOKEN.B".into(),
            SavedBindingReference {
                id: "shared".into(),
            },
        ),
    ]);
    SavedValue::Value {
        value: SavedSecretsConfig::from_source(&config, &bindings).unwrap(),
        origin: SavedOrigin::Configured,
    }
}

fn patch(entries: Vec<SecretEntry>) -> SecretsConfigPatch {
    SecretsConfigPatch::new().secrets(entries)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn keyed_selection_preserves_saved_positions_and_appends_new_destination_order() {
    let mut saved = source();
    let SavedValue::Value { value, .. } = &mut saved else {
        unreachable!()
    };
    value.entries.reverse();
    let before = serde_json::to_vec(&saved).unwrap();
    let input = patch(vec![
        secret("TOKEN.Z", "NEW_Z"),
        secret("TOKEN.A", "PLACEHOLDER_A"),
        secret("TOKEN.C", "NEW_C"),
        secret("TOKEN.B", "PLACEHOLDER_B"),
    ]);
    for full_resume in [false, true] {
        let selected = select_secret_inputs(Some(&saved), Some(&input), full_resume).unwrap();
        let names: Vec<_> = selected
            .entries
            .iter()
            .map(|entry| entry.env_var.as_str())
            .collect();
        assert_eq!(names, ["TOKEN.B", "TOKEN.A", "TOKEN.Z", "TOKEN.C"]);
        assert!(
            selected
                .entries
                .iter()
                .all(|entry| entry.destination.is_some())
        );
        assert!(
            selected.entries[..2]
                .iter()
                .all(|entry| entry.saved.is_some())
        );
        assert!(
            selected.entries[2..]
                .iter()
                .all(|entry| entry.saved.is_none())
        );
        let plan =
            prepare_secret_configuration(Some(&saved), Some(&input), &BTreeMap::new(), full_resume)
                .unwrap();
        let mut native = SecretsConfig::default();
        plan.apply_to(&mut native).unwrap();
        let names: Vec<_> = native
            .secrets
            .iter()
            .map(|entry| entry.env_var.as_str())
            .collect();
        assert_eq!(names, ["TOKEN.B", "TOKEN.A", "TOKEN.Z", "TOKEN.C"]);
    }
    assert_eq!(serde_json::to_vec(&saved).unwrap(), before);
    let inherited = select_secret_inputs(Some(&saved), None, false).unwrap();
    assert_eq!(inherited.entries[0].env_var, "TOKEN.B");
    let fresh = select_secret_inputs(None, Some(&input), false).unwrap();
    let names: Vec<_> = fresh
        .entries
        .iter()
        .map(|entry| entry.env_var.as_str())
        .collect();
    assert_eq!(names, ["TOKEN.Z", "TOKEN.A", "TOKEN.C", "TOKEN.B"]);
}

#[test]
fn keyed_override_retains_other_shared_consumers_without_exporting_credentials() {
    let saved = source();
    let bytes = serde_json::to_vec(&saved).unwrap();
    let input = patch(vec![secret("TOKEN.A", "NEW_PLACEHOLDER")]);
    let selected = select_secret_inputs(Some(&saved), Some(&input), false).unwrap();
    assert_eq!(selected.entries.len(), 2);
    assert!(selected.entries[0].destination.is_some());
    assert!(selected.entries[1].destination.is_none());
    assert!(selected.remaining_bindings.contains_key("shared"));
    assert!(selected.global_defaults.get_secrets().is_none());
    assert!(selected.tls_identity_approvals.is_empty());
    assert_eq!(serde_json::to_vec(&saved).unwrap(), bytes);
    for text in [format!("{selected:?}"), format!("{:?}", selected.entries)] {
        assert!(!text.contains("SENTINEL"));
        assert!(!text.contains("PLACEHOLDER"));
        assert!(!text.contains("TOKEN"));
    }
    assert!(!String::from_utf8(bytes).unwrap().contains("SENTINEL"));
}

#[test]
fn only_the_final_shared_override_releases_selected_binding_demand() {
    let input = patch(vec![secret("TOKEN.A", "NEW_A"), secret("TOKEN.B", "NEW_B")]);
    let selected = select_secret_inputs(Some(&source()), Some(&input), false).unwrap();
    assert!(selected.remaining_bindings.is_empty());
    assert_eq!(selected.entries.len(), 2);
}

#[test]
fn empty_destination_list_is_not_a_clear_of_selected_requirements() {
    for input in [
        patch(vec![]),
        SecretsConfigPatch::new().replace_secrets(vec![]),
    ] {
        let selected = select_secret_inputs(Some(&source()), Some(&input), false).unwrap();
        assert_eq!(selected.entries.len(), 2);
        assert_eq!(selected.remaining_bindings.len(), 1);
    }
}

#[test]
fn destination_credential_sources_stay_unresolved_and_out_of_diagnostics() {
    for credential_source in [
        SecretSource::env("MSB_SAVED_CONFIG_TEST_UNRESOLVED_SOURCE_SENTINEL"),
        SecretSource::Store {
            reference: "unsupported-test-store://SOURCE_SENTINEL".into(),
        },
    ] {
        let mut entry = secret("TOKEN.A", "PLACEHOLDER_A");
        entry.value.clear();
        entry.source = Some(credential_source.clone());
        let selected =
            select_secret_inputs(Some(&source()), Some(&patch(vec![entry])), false).unwrap();
        let destination = selected.entries[0].destination.as_ref().unwrap();
        assert_eq!(destination.source.as_ref(), Some(&credential_source));
        assert!(destination.value.is_empty());
        assert!(selected.remaining_bindings.contains_key("shared"));
        assert!(!format!("{selected:?} {:?}", selected.entries).contains("SENTINEL"));
    }
}

#[test]
fn collisions_are_checked_across_saved_and_destination_entries() {
    for input in [
        patch(vec![secret("TOKEN.A", "A"), secret("TOKEN.A", "B")]),
        patch(vec![secret("TOKEN.C", "PLACEHOLDER_B")]),
        patch(vec![secret("TOKEN.A", "PLACEHOLDER_B")]),
        patch(vec![secret("TOKEN.C", "SAME"), secret("TOKEN.D", "SAME")]),
    ] {
        let err = select_secret_inputs(Some(&source()), Some(&input), false).unwrap_err();
        assert!(err.to_string().contains("SCFG_IDENTITY"));
        assert!(!err.to_string().contains("TOKEN"));
        assert!(!err.to_string().contains("SENTINEL"));
    }
}

#[test]
fn full_resume_keeps_recorded_placeholder_identity_and_requires_further_evidence() {
    let changed = patch(vec![secret("TOKEN.A", "REPLACEMENT")]);
    assert!(
        select_secret_inputs(Some(&source()), Some(&changed), true)
            .unwrap_err()
            .to_string()
            .contains("SCFG_FULL_STATE")
    );
    let matching = patch(vec![secret("TOKEN.A", "PLACEHOLDER_A")]);
    let selected = select_secret_inputs(Some(&source()), Some(&matching), true).unwrap();
    assert!(selected.requires_full_identity);
    assert!(selected.remaining_bindings.contains_key("shared"));
}

#[test]
fn captured_requirements_survive_complete_explicit_default_replacement() {
    let saved = source();
    let captured = select_secret_inputs(Some(&saved), None, true)
        .unwrap()
        .remaining_bindings;
    let replacements = patch(vec![
        secret("TOKEN.A", "PLACEHOLDER_A"),
        secret("TOKEN.B", "PLACEHOLDER_B"),
    ]);
    let selected = select_secret_inputs(Some(&saved), Some(&replacements), true).unwrap();
    assert!(selected.remaining_bindings.is_empty());
    let demand = plan_binding_demand(
        &selected.remaining_bindings,
        Some(&captured),
        BindingDemandContext {
            full_resume: true,
            starts_command: false,
        },
    )
    .unwrap();
    assert!(demand.bindings()["shared"].required_now);
    assert!(demand.bindings()["shared"].captured_execution);
}

#[test]
fn saved_relaxation_is_an_obligation_while_explicit_input_still_needs_policy_admission() {
    let mut saved = source();
    if let SavedValue::Value { value, .. } = &mut saved {
        value.entries[0].require_tls_identity = false;
    }
    let selected = select_secret_inputs(Some(&saved), None, false).unwrap();
    assert_eq!(
        selected
            .tls_identity_approvals
            .iter()
            .cloned()
            .collect::<Vec<_>>(),
        ["TOKEN.A"]
    );
    let mut explicit = secret("TOKEN.A", "PLACEHOLDER_A");
    explicit.require_tls_identity = false;
    let selected = select_secret_inputs(Some(&saved), Some(&patch(vec![explicit])), false).unwrap();
    assert!(selected.tls_identity_approvals.is_empty());
    assert!(
        !selected.entries[0]
            .destination
            .as_ref()
            .unwrap()
            .require_tls_identity
    );
}

#[test]
fn global_policy_preserves_absence_empty_and_independent_explicit_fields() {
    let saved = source();
    let selected = select_secret_inputs(Some(&saved), None, false).unwrap();
    assert!(selected.global_passthrough_absent);
    assert!(selected.global_defaults.violation_action.is_some());
    let mut input = SecretsConfigPatch::new();
    input.passthrough_hosts = Some(vec![]);
    let selected = select_secret_inputs(Some(&saved), Some(&input), false).unwrap();
    assert!(!selected.global_passthrough_absent);
    assert!(selected.global_defaults.passthrough_hosts.is_none());
    assert!(selected.global_defaults.violation_action.is_some());
    let mut saved = saved;
    if let SavedValue::Value { value, .. } = &mut saved {
        value.passthrough_hosts = Some(vec![HostPattern::Exact("allowed.example".into())]);
    }
    let selected = select_secret_inputs(Some(&saved), None, false).unwrap();
    assert_eq!(selected.global_defaults.passthrough_hosts.unwrap().len(), 1);
    assert!(!selected.global_passthrough_absent);
}

#[test]
fn absent_unknown_and_builtin_are_distinct_even_with_explicit_inputs() {
    let unknown = SavedValue::Unknown {
        reason: SavedUnknownReason::NotRecorded,
    };
    let default = SavedValue::Default {};
    let input = patch(vec![secret("TOKEN.C", "C")]);
    for (source, unknown, defaulted) in [
        (None, true, false),
        (Some(&unknown), true, false),
        (Some(&default), false, true),
    ] {
        let selected = select_secret_inputs(source, Some(&input), true).unwrap();
        assert_eq!(selected.source_unknown, unknown);
        assert_eq!(selected.source_defaulted, defaulted);
        assert!(selected.requires_full_identity);
        assert_eq!(selected.entries.len(), 1);
    }
}

#[test]
fn malformed_source_cannot_be_hidden_by_overrides_and_errors_do_not_echo_values() {
    let mut saved = source();
    if let SavedValue::Value { value, .. } = &mut saved {
        value.entries[1].placeholder = value.entries[0].placeholder.clone();
    }
    let input = patch(vec![secret("TOKEN.A", "A"), secret("TOKEN.B", "B")]);
    let err = select_secret_inputs(Some(&saved), Some(&input), false).unwrap_err();
    assert!(err.to_string().contains("SCFG_VALUE"));
    assert!(!err.to_string().contains("PLACEHOLDER"));
    let mut malformed = secret("TOKEN.C", "C");
    malformed.env_var = "C=SENTINEL".into();
    let err = select_secret_inputs(None, Some(&patch(vec![malformed])), false).unwrap_err();
    assert!(!err.to_string().contains("SENTINEL"));
}

#[test]
fn destination_and_combined_entry_counts_are_bounded() {
    let many = (0..=MAX_SAVED_CONFIG_ENTRIES)
        .map(|i| secret(&format!("KEY_{i}"), &format!("PLACEHOLDER_{i}")))
        .collect();
    assert!(
        select_secret_inputs(None, Some(&patch(many)), false)
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
    let many = (0..MAX_SAVED_CONFIG_ENTRIES - 1)
        .map(|i| secret(&format!("KEY_{i}"), &format!("PLACEHOLDER_{i}")))
        .collect();
    assert!(
        select_secret_inputs(Some(&source()), Some(&patch(many)), false)
            .unwrap_err()
            .to_string()
            .contains("SCFG_LIMIT")
    );
}
