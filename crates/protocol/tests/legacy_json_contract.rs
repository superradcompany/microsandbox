//! Exercise the actual historical JSON type definitions, not a new imitation.

use microsandbox_protocol::control::{
    Capabilities, ControlRequest, CpuState, JsonControlResponse, MemoryState, SecretChange,
    SecretValue,
};

#[allow(dead_code)]
#[rustfmt::skip]
#[path = "fixtures/legacy_control_records.rs"]
mod historical;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn historical_consumer_accepts_additive_discovery() {
    let response = JsonControlResponse {
        ok: true,
        capabilities: Some(Capabilities {
            root_disk_grow: false,
            cpu_resize: true,
            memory_resize: false,
            secrets_update: true,
        }),
        control_protocols: Some(vec!["json".into(), "cbor".into()]),
        ..Default::default()
    };
    let wire = serde_json::to_vec(&response).unwrap();
    let old: historical::ControlResponse = serde_json::from_slice(&wire).unwrap();
    assert!(old.ok);
    let capabilities = old.capabilities.unwrap();
    assert!(capabilities.cpu_resize);
    assert!(!capabilities.memory_resize);
    assert!(capabilities.secrets_update);
}

#[test]
fn old_and_new_request_serializers_agree_for_every_operation() {
    let requests = [
        ControlRequest::Capabilities,
        ControlRequest::MemoryState,
        ControlRequest::MemoryTarget {
            total_mib: u64::MAX,
        },
        ControlRequest::CpuState,
        ControlRequest::CpuTarget { online: u32::MAX },
        ControlRequest::SecretsUpdate {
            changes: vec![
                SecretChange::Rotate {
                    name: "FIXTURE_TOKEN".into(),
                    value: SecretValue("artificial-test-value".into()),
                },
                SecretChange::Remove {
                    name: "ABSENT".into(),
                },
                SecretChange::SetAllowedHosts {
                    name: "FIXTURE_TOKEN".into(),
                    hosts: vec!["example.invalid".into()],
                },
            ],
        },
    ];
    for request in requests {
        let new_wire = serde_json::to_vec(&request).unwrap();
        let old: historical::ControlRequest = serde_json::from_slice(&new_wire).unwrap();
        let old_wire = serde_json::to_vec(&old).unwrap();
        assert_eq!(old_wire, new_wire);
        let new: ControlRequest = serde_json::from_slice(&old_wire).unwrap();
        assert_eq!(serde_json::to_vec(&new).unwrap(), old_wire);
    }
}

#[test]
fn old_and_new_result_serializers_preserve_errors_and_full_width_values() {
    let responses = [
        JsonControlResponse {
            ok: true,
            ..Default::default()
        },
        JsonControlResponse {
            ok: false,
            error: Some("artificial fixture failure".into()),
            ..Default::default()
        },
        JsonControlResponse {
            ok: true,
            memory: Some(MemoryState {
                boot_mib: 256,
                target_mib: u64::MAX,
                current_mib: 9007199254740993,
                max_mib: u64::MAX,
            }),
            ..Default::default()
        },
        JsonControlResponse {
            ok: true,
            cpu: Some(CpuState {
                possible: 4,
                requested_online: 3,
                actual_online: 2,
                enforced: 3,
            }),
            ..Default::default()
        },
    ];
    for response in responses {
        let new_wire = serde_json::to_vec(&response).unwrap();
        let old: historical::ControlResponse = serde_json::from_slice(&new_wire).unwrap();
        let old_wire = serde_json::to_vec(&old).unwrap();
        assert_eq!(old_wire, new_wire);
        let new: JsonControlResponse = serde_json::from_slice(&old_wire).unwrap();
        assert!(new.control_protocols.is_none());
        assert_eq!(serde_json::to_vec(&new).unwrap(), old_wire);
    }
}
