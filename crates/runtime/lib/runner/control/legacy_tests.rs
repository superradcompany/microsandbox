//! Existing JSON control contracts remain valid alongside framed control.

use crate::control::*;

#[test]
fn secret_value_debug_is_redacted() {
    let request = ControlRequest::SecretsUpdate {
        changes: vec![SecretLiveChange::Rotate {
            name: "API_KEY".into(),
            value: SecretValue("sentinel-secret-value".into()),
        }],
    };

    let debug = format!("{request:?}");
    assert!(!debug.contains("sentinel-secret-value"));
    assert!(debug.contains("[redacted]"));
    assert!(debug.contains("API_KEY"));
}

#[test]
fn secrets_update_round_trips_through_json() {
    let request = ControlRequest::SecretsUpdate {
        changes: vec![
            SecretLiveChange::Rotate {
                name: "API_KEY".into(),
                value: SecretValue("new-material".into()),
            },
            SecretLiveChange::Remove {
                name: "OLD_KEY".into(),
            },
            SecretLiveChange::SetAllowedHosts {
                name: "API_KEY".into(),
                hosts: vec!["api.example.com".into(), "*".into()],
            },
        ],
    };

    let json = serde_json::to_string(&request).unwrap();
    let parsed: ControlRequest = serde_json::from_str(&json).unwrap();
    let ControlRequest::SecretsUpdate { changes } = parsed else {
        panic!("expected secrets_update");
    };
    assert_eq!(changes.len(), 3);
    let SecretLiveChange::Rotate { name, value } = &changes[0] else {
        panic!("expected rotate");
    };
    assert_eq!(name, "API_KEY");
    assert_eq!(value.0, "new-material");
}

#[test]
fn checkpoint_request_round_trips_through_json() {
    let request = ControlRequest::CheckpointCreate {
        guest_flush: None,
        record_integrity: false,
        checkpoint_id: "checkpoint_0123456789abcdef".into(),
        intent: CheckpointCaptureIntent::FullSnapshot,
    };

    let json = serde_json::to_string(&request).unwrap();
    assert!(
        !json.contains("guest_flush"),
        "legacy clients retain their request shape"
    );
    let parsed: ControlRequest = serde_json::from_str(&json).unwrap();

    assert!(matches!(
        parsed,
        ControlRequest::CheckpointCreate {
            guest_flush: None,
            record_integrity: false,
            checkpoint_id,
            intent: CheckpointCaptureIntent::FullSnapshot,
        } if checkpoint_id == "checkpoint_0123456789abcdef"
    ));
}

#[test]
fn disk_only_capture_has_a_distinct_wire_operation() {
    let request = ControlRequest::DiskCheckpointCreate {
        guest_flush: None,
        checkpoint_id: "disk_test".into(),
    };
    let json = serde_json::to_string(&request).unwrap();
    assert_eq!(
        serde_json::from_str::<serde_json::Value>(&json).unwrap()["op"],
        "disk_checkpoint_create"
    );
    assert!(
        matches!(serde_json::from_str::<ControlRequest>(&json).unwrap(), ControlRequest::DiskCheckpointCreate { checkpoint_id, guest_flush: None } if checkpoint_id == "disk_test")
    );
    // An older runtime's capability response cannot accidentally opt into this operation.
    let old: ControlCapabilities = serde_json::from_str(r#"{"cpu_resize":false,"memory_resize":false,"secrets_update":false,"checkpoint_create":true}"#).unwrap();
    assert!(!old.disk_checkpoint_create);
    assert!(!old.guest_flush_policy);
}

#[test]
fn explicit_flush_uses_validated_values_and_a_distinct_pause_operation() {
    let old: ControlRequest =
        serde_json::from_str(r#"{"op":"disk_checkpoint_create","checkpoint_id":"old"}"#).unwrap();
    assert!(matches!(
        old,
        ControlRequest::DiskCheckpointCreate {
            guest_flush: None,
            ..
        }
    ));
    for policy in ["auto", "required", "skip"] {
        let request: ControlRequest = serde_json::from_value(serde_json::json!({
            "op":"pause_with_guest_flush", "guest_flush":policy,
        }))
        .unwrap();
        assert!(matches!(
            request,
            ControlRequest::PauseWithGuestFlush { .. }
        ));
    }
    assert!(
        serde_json::from_str::<ControlRequest>(
            r#"{"op":"pause_with_guest_flush","guest_flush":"best-effort"}"#
        )
        .is_err()
    );
}

#[test]
fn capabilities_response_serializes_flags() {
    let response = ControlResponse {
        ok: true,
        capabilities: Some(ControlCapabilities {
            guest_flush_policy: true,
            optional_disk_integrity: true,
            branch_memfd: false,
            disk_compact_owned: true,
            branch_create: true,
            pause_resume: true,
            root_disk_grow: true,
            disk_compact: true,
            cpu_resize: true,
            memory_resize: false,
            secrets_update: true,
            checkpoint_create: true,
            disk_checkpoint_create: true,
        }),
        ..Default::default()
    };

    let json = serde_json::to_string(&response).unwrap();
    assert!(json.contains("\"secrets_update\":true"));
    assert!(json.contains("\"memory_resize\":false"));

    let parsed: ControlResponse = serde_json::from_str(&json).unwrap();
    assert!(parsed.capabilities.unwrap().secrets_update);
}

#[test]
fn legacy_responses_without_capabilities_still_parse() {
    let parsed: ControlResponse = serde_json::from_str(r#"{"ok":true}"#).unwrap();
    assert!(parsed.ok);
    assert!(parsed.capabilities.is_none());
}
