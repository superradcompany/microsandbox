//! Control conformance fixtures and adversarial checked-decoder boundaries.

use std::path::PathBuf;

use ciborium::Value;
use microsandbox_protocol::{
    codec::{self, MAX_FRAME_SIZE},
    control::*,
    message::{self, Message, MessageType},
    wire::{self, Envelope, WireError},
};
use serde_json::{Value as JsonValue, json};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn bytes(value: &Value) -> Vec<u8> {
    wire::encode(value).unwrap()
}

fn field(name: &str, value: Value) -> (Value, Value) {
    (Value::Text(name.into()), value)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn case(name: &str, envelope: Envelope, id: u32, flags: u8) -> JsonValue {
    raw_case(name, envelope.frame(id, flags).unwrap())
}

fn raw_case(name: &str, raw: codec::RawFrame) -> JsonValue {
    let envelope = Envelope::decode(&raw.body).unwrap();
    let mut frame = Vec::new();
    codec::encode_raw_to_buf(&raw, &mut frame).unwrap();
    json!({
        "name": name, "generation": envelope.v, "type": envelope.t,
        "id": raw.id, "flags": raw.flags, "payload_hex": hex(&envelope.p),
        "envelope_hex": hex(&raw.body), "frame_hex": hex(&frame),
    })
}

fn fixtures() -> JsonValue {
    let hello = ControlHello::default();
    let welcome = ControlWelcome::negotiate(&hello, DEFAULT_MAX_IN_FLIGHT).unwrap();
    let mut cases = vec![
        case(
            "hello",
            Envelope::new(1, "control.hello", &hello).unwrap(),
            0,
            0,
        ),
        case(
            "welcome",
            Envelope::new(1, "control.welcome", &welcome).unwrap(),
            0,
            1,
        ),
    ];
    for (name, request) in [
        ("capabilities", ControlRequest::Capabilities),
        ("memory_query", ControlRequest::MemoryState),
        ("cpu_query", ControlRequest::CpuState),
        (
            "memory_target",
            ControlRequest::MemoryTarget { total_mib: 2048 },
        ),
        (
            "memory_target_u64",
            ControlRequest::MemoryTarget {
                total_mib: u64::MAX,
            },
        ),
        ("cpu_target", ControlRequest::CpuTarget { online: 2 }),
        (
            "secrets_update",
            ControlRequest::SecretsUpdate {
                changes: vec![
                    SecretChange::Rotate {
                        name: "TEST_KEY".into(),
                        value: SecretValue("fixture-only".into()),
                    },
                    SecretChange::Remove {
                        name: "OLD_KEY".into(),
                    },
                    SecretChange::SetAllowedHosts {
                        name: "TEST_KEY".into(),
                        hosts: vec!["example.test".into()],
                    },
                ],
            },
        ),
    ] {
        cases.push(case(name, request.envelope(1).unwrap(), 17, 0));
    }
    cases.push(case(
        "capabilities_result",
        Envelope::new(
            1,
            "control.capabilities.result",
            &Capabilities {
                root_disk_grow: false,
                cpu_resize: true,
                memory_resize: true,
                secrets_update: false,
            },
        )
        .unwrap(),
        17,
        1,
    ));
    cases.push(case(
        "memory_state",
        Envelope::new(
            1,
            "control.memory.state",
            &MemoryState {
                boot_mib: 512,
                target_mib: 2048,
                current_mib: 1024,
                max_mib: 4096,
            },
        )
        .unwrap(),
        17,
        1,
    ));
    cases.push(case(
        "memory_state_u64",
        Envelope::new(
            1,
            "control.memory.state",
            &MemoryState {
                boot_mib: 1,
                target_mib: (1u64 << 53) + 1,
                current_mib: 0,
                max_mib: u64::MAX,
            },
        )
        .unwrap(),
        17,
        1,
    ));
    cases.push(case(
        "cpu_state",
        Envelope::new(
            1,
            "control.cpu.state",
            &CpuState {
                possible: 4,
                requested_online: 2,
                actual_online: 1,
                enforced: 2,
            },
        )
        .unwrap(),
        17,
        1,
    ));
    cases.push(case(
        "secrets_complete",
        Envelope::new(
            1,
            "control.secrets.result",
            &SecretsResult::Complete { applied_count: 3 },
        )
        .unwrap(),
        17,
        1,
    ));
    cases.push(case(
        "secrets_failed",
        Envelope::new(
            1,
            "control.secrets.result",
            &SecretsResult::Failed {
                applied_count: 1,
                failed_index: 1,
                error: ControlError::rejected("unknown_secret", "unknown secret"),
            },
        )
        .unwrap(),
        17,
        1,
    ));
    for code in [
        "invalid_handshake",
        "unsupported_generation",
        "invalid_request",
        "unsupported_operation",
        "busy",
        "unknown_secret",
        "invalid_secret_hosts",
        "internal",
    ] {
        let id = if matches!(code, "invalid_handshake" | "unsupported_generation") {
            0
        } else {
            17
        };
        cases.push(case(
            code,
            Envelope::new(
                1,
                "control.error",
                &ControlError::rejected(code, "operation rejected"),
            )
            .unwrap(),
            id,
            1,
        ));
    }
    cases.push(case(
        "unknown_error_effect",
        Envelope::new(
            1,
            "control.error",
            &ControlError {
                code: "future_error".into(),
                message: "result unavailable".into(),
                effect: ErrorEffect::Unknown,
            },
        )
        .unwrap(),
        17,
        1,
    ));
    let future_memory = Value::Map(vec![
        field("boot_mib", 512u64.into()),
        field("target_mib", 2048u64.into()),
        field("current_mib", 1024u64.into()),
        field("max_mib", 4096u64.into()),
        field(
            "future",
            Value::Map(vec![field("opaque", Value::Bytes(vec![0, 255]))]),
        ),
    ]);
    let envelope = Envelope::new(1, "control.memory.state", &future_memory).unwrap();
    cases.push(case(
        "memory_state_future_payload_field",
        envelope.clone(),
        17,
        1,
    ));
    // A checked envelope view drops extension fields. Pin the original body
    // separately so cross-language raw forwarding must preserve both layers.
    cases.push(raw_case(
        "memory_state_future_envelope_field",
        codec::RawFrame {
            id: 17,
            flags: 1,
            body: bytes(&Value::Map(vec![
                field("v", 1u64.into()),
                field("t", envelope.t.into()),
                field("p", Value::Bytes(envelope.p)),
                field("future", Value::Bytes(vec![1, 0, 255])),
            ])),
        },
    ));
    json!({"protocol": "msb.control", "generation": 1, "cases": cases})
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn generation_one_bytes_match_cross_language_fixtures() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/control-v1.json");
    let actual = fixtures();
    if std::env::var_os("UPDATE_CONTROL_FIXTURES").is_some() {
        // Only a source checkout can update the shared corpus. Packaged tests
        // read their exact local copy and must not create files outside the crate.
        let shared = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../packages/protocol-fixtures/control-v1.json");
        assert!(shared.is_file(), "update fixtures from a source checkout");
        let encoded = format!("{}\n", serde_json::to_string_pretty(&actual).unwrap());
        std::fs::write(&shared, &encoded).unwrap();
        std::fs::write(&path, &encoded).unwrap();
    }
    let expected: JsonValue = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    assert_eq!(
        actual, expected,
        "control wire bytes changed; review compatibility before updating fixtures"
    );
}

#[test]
fn neutral_envelope_preserves_existing_agent_encoding() {
    let original = Message::with_payload(
        MessageType::ExecStdin,
        42,
        &microsandbox_protocol::exec::ExecStdin {
            data: b"input\0\xff".to_vec(),
        },
    )
    .unwrap();
    let neutral = Envelope {
        v: original.v,
        t: original.t.as_str().into(),
        p: original.p.clone(),
    };
    let mut agent_bytes = Vec::new();
    codec::encode_to_buf(&original, &mut agent_bytes).unwrap();
    let mut neutral_bytes = Vec::new();
    codec::encode_raw_to_buf(
        &neutral.frame(original.id, original.flags).unwrap(),
        &mut neutral_bytes,
    )
    .unwrap();
    assert_eq!(agent_bytes, neutral_bytes);
    assert_eq!(
        message::PROTOCOL_VERSION,
        9,
        "control must not bump the agent generation"
    );
}

#[test]
fn checked_decoder_rejects_trailing_and_duplicate_keys() {
    let duplicate = bytes(&Value::Map(vec![
        field("total_mib", 1u64.into()),
        field("total_mib", 2u64.into()),
    ]));
    assert_eq!(
        wire::decode_record::<MemoryTarget>(&duplicate),
        Err(WireError::DuplicateKey)
    );
    let mut trailing = wire::encode(&MemoryTarget { total_mib: 1 }).unwrap();
    trailing.push(0);
    assert_eq!(
        wire::decode_record::<MemoryTarget>(&trailing),
        Err(WireError::InvalidCbor)
    );
}

#[test]
fn checked_decoder_ignores_future_fields_but_rejects_duplicate_unknown_keys() {
    let future = field(
        "future",
        Value::Map(vec![(Value::Integer(1.into()), Value::Bytes(vec![0, 255]))]),
    );
    let valid = bytes(&Value::Map(vec![
        field("total_mib", 2048u64.into()),
        future.clone(),
    ]));
    assert_eq!(
        wire::decode_record::<MemoryTarget>(&valid)
            .unwrap()
            .total_mib,
        2048
    );
    let duplicate = bytes(&Value::Map(vec![
        field("total_mib", 1u64.into()),
        future.clone(),
        future,
    ]));
    assert_eq!(
        wire::decode_record::<MemoryTarget>(&duplicate),
        Err(WireError::DuplicateKey)
    );
}

#[test]
fn pinned_future_fields_decode_as_checked_memory_and_survive_raw_forwarding() {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/control-v1.json");
    let fixtures: JsonValue = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    for name in [
        "memory_state_future_payload_field",
        "memory_state_future_envelope_field",
    ] {
        let fixture = fixtures["cases"]
            .as_array()
            .unwrap()
            .iter()
            .find(|fixture| fixture["name"] == name)
            .expect("the future-field case must be pinned");
        let packet = fixture["frame_hex"].as_str().unwrap();
        let mut input = (0..packet.len())
            .step_by(2)
            .map(|index| u8::from_str_radix(&packet[index..index + 2], 16).unwrap())
            .collect();
        let frame = codec::try_decode_raw_from_buf(&mut input).unwrap().unwrap();
        assert!(input.is_empty());
        let envelope = Envelope::decode(&frame.body).unwrap();
        assert_eq!(
            envelope.payload::<MemoryState>().unwrap(),
            MemoryState {
                boot_mib: 512,
                target_mib: 2048,
                current_mib: 1024,
                max_mib: 4096,
            }
        );
        let mut forwarded = Vec::new();
        codec::encode_raw_to_buf(&frame, &mut forwarded).unwrap();
        assert_eq!(hex(&forwarded), packet);
        if name == "memory_state_future_envelope_field" {
            assert_ne!(envelope.encode().unwrap(), frame.body);
        }
    }
}

#[test]
fn unsigned_fields_reject_negative_floats_strings_and_overflow() {
    for value in [
        Value::Integer((-1).into()),
        Value::Float(1.0),
        Value::Text("1".into()),
        Value::Bool(true),
    ] {
        let encoded = bytes(&Value::Map(vec![field("total_mib", value)]));
        assert!(wire::decode_record::<MemoryTarget>(&encoded).is_err());
    }
    let encoded = bytes(&Value::Map(vec![field(
        "online",
        (u32::MAX as u64 + 1).into(),
    )]));
    assert!(wire::decode_record::<CpuTarget>(&encoded).is_err());
    let encoded = wire::encode(&MemoryTarget {
        total_mib: u64::MAX,
    })
    .unwrap();
    assert_eq!(
        wire::decode_record::<MemoryTarget>(&encoded)
            .unwrap()
            .total_mib,
        u64::MAX
    );
}

#[test]
fn handshake_limits_and_generation_are_validated_in_both_directions() {
    let mut hello = ControlHello {
        max_generation: 7,
        max_frame_size: 8192,
        max_in_flight: 8,
        ..Default::default()
    };
    let welcome = ControlWelcome::negotiate(&hello, 4).unwrap();
    assert_eq!(
        (
            welcome.generation,
            welcome.max_frame_size,
            welcome.max_in_flight
        ),
        (1, 8192, 4)
    );
    welcome.validate_for(&hello).unwrap();
    let mut bad = welcome.clone();
    bad.max_frame_size = 16384;
    assert!(bad.validate_for(&hello).is_err());
    bad = welcome.clone();
    bad.max_in_flight = 9;
    assert!(bad.validate_for(&hello).is_err());
    bad = welcome;
    bad.generation = 8;
    assert!(bad.validate_for(&hello).is_err());
    hello.min_generation = 2;
    assert_eq!(
        ControlWelcome::negotiate(&hello, 64).unwrap_err().code,
        "unsupported_generation"
    );
    for maximum in [0, 4095, MAX_FRAME_SIZE + 1] {
        let offer = ControlHello {
            max_frame_size: maximum,
            ..Default::default()
        };
        assert_eq!(offer.validate().unwrap_err().code, "invalid_handshake");
    }
}

#[test]
fn hello_keeps_the_unambiguous_zero_prefix() {
    let envelope = Envelope::new(1, "control.hello", &ControlHello::default()).unwrap();
    let mut encoded = Vec::new();
    codec::encode_raw_to_buf(&envelope.frame(0, 0).unwrap(), &mut encoded).unwrap();
    assert_eq!(encoded[0], 0);
    assert!(encoded.len() - 4 <= MAX_HANDSHAKE_FRAME_SIZE as usize);
    assert_eq!(Envelope::decode(&encoded[9..]).unwrap().t, "control.hello");
}

#[test]
fn duplicate_secret_entry_is_rejected_before_dispatch() {
    let change = Value::Map(vec![
        field("change", "rotate".into()),
        field("name", "KEY".into()),
        field("value", "first".into()),
        field("value", "second".into()),
    ]);
    let envelope = Envelope {
        v: 1,
        t: "control.secrets.update".into(),
        p: bytes(&Value::Map(vec![field(
            "changes",
            Value::Array(vec![change]),
        )])),
    };
    assert!(matches!(
        ControlRequest::from_envelope(&envelope),
        Err(WireError::DuplicateKey)
    ));
}

#[test]
fn error_diagnostics_do_not_contain_secret_payloads() {
    let secret = "fixture-sensitive-value";
    let request = ControlRequest::SecretsUpdate {
        changes: vec![SecretChange::Rotate {
            name: "TEST_KEY".into(),
            value: SecretValue(secret.into()),
        }],
    };
    assert!(!format!("{request:?}").contains(secret));
    let envelope = request.envelope(1).unwrap();
    assert!(!format!("{envelope:?}").contains(secret));
    let invalid = bytes(&Value::Map(vec![field(
        "online",
        Value::Text(secret.into()),
    )]));
    assert!(
        !format!(
            "{}",
            wire::decode_record::<CpuTarget>(&invalid).unwrap_err()
        )
        .contains(secret)
    );
}

#[test]
fn legacy_json_spelling_and_optional_discovery_are_preserved() {
    assert_eq!(
        serde_json::to_string(&ControlRequest::MemoryTarget { total_mib: 2048 }).unwrap(),
        r#"{"op":"memory_target","total_mib":2048}"#
    );
    let old: JsonControlResponse = serde_json::from_str(r#"{"ok":true,"capabilities":{"cpu_resize":true,"memory_resize":false,"secrets_update":false}}"#).unwrap();
    assert!(old.control_protocols.is_none());
    let new = JsonControlResponse {
        control_protocols: Some(vec!["json".into(), "cbor".into()]),
        ..old
    };
    let encoded = serde_json::to_value(new).unwrap();
    assert_eq!(encoded["control_protocols"], json!(["json", "cbor"]));
    assert!(encoded.get("memory").is_none());
}

#[test]
fn envelope_requires_a_byte_string_and_preserves_unknown_names() {
    let invalid = bytes(&Value::Map(vec![
        field("v", 1u64.into()),
        field("t", "future.message".into()),
        field("p", Value::Array(vec![0u64.into()])),
    ]));
    assert!(matches!(
        Envelope::decode(&invalid),
        Err(WireError::InvalidRecord)
    ));
    let valid = bytes(&Value::Map(vec![
        field("v", 1u64.into()),
        field("t", "future.message".into()),
        field("p", Value::Bytes(vec![0xff, 0, 0x7f])),
        field("future", "untouched".into()),
    ]));
    let decoded = Envelope::decode(&valid).unwrap();
    assert_eq!(decoded.t, "future.message");
    assert_eq!(decoded.p, vec![0xff, 0, 0x7f]);
}
