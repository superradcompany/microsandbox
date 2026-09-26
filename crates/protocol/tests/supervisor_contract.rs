//! Cross-language supervisor generation-one fixtures and wire invariants.

use microsandbox_protocol::{
    codec::{self, RawFrame},
    supervisor::*,
    wire::Envelope,
};
use serde_json::{Value as JsonValue, json};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn case(name: &str, envelope: Envelope, id: u32, flags: u8) -> JsonValue {
    let raw = envelope.frame(id, flags).unwrap();
    let envelope = Envelope::decode(&raw.body).unwrap();
    let mut frame = Vec::new();
    codec::encode_raw_to_buf(&raw, &mut frame).unwrap();
    json!({
        "name": name, "generation": envelope.v, "type": envelope.t,
        "id": raw.id, "flags": raw.flags, "frame_hex": hex(&frame),
    })
}

fn fixtures() -> JsonValue {
    let request_id = SupervisorRequestId([
        0x01, 0x89, 0xab, 0xcd, 0xef, 0x70, 0x70, 0x01, 0x80, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08,
    ]);
    let operation_id = OperationId([0x22; 16]);
    let lineage_id = SandboxLineageId([0x33; 16]);
    let hello = SupervisorHello {
        protocol: SUPERVISOR_PROTOCOL.into(),
        min_generation: 1,
        max_generation: 1,
        implementation_version: "0.7.4".into(),
        client_instance_id: ClientInstanceId([0x11; 16]),
        canonical_home_digest: HomeDigest([0x44; 32]),
        requested_limits: SupervisorLimits::default(),
        resume_catalog_revision: Some(41),
    };
    let welcome = SupervisorWelcome {
        protocol: SUPERVISOR_PROTOCOL.into(),
        generation: 1,
        implementation_version: "0.7.4".into(),
        supervisor_instance_id: SupervisorInstanceId([0x55; 16]),
        canonical_home_digest: hello.canonical_home_digest,
        effective_limits: SupervisorLimits::default(),
        current_catalog_revision: 42,
        oldest_catalog_revision: 7,
        launch_profile: LaunchProfile::JailedLinuxV1,
    };
    let create = Mutation {
        supervisor_request_id: request_id,
        expected_catalog_revision: Some(42),
        intent: CreateSandboxIntent {
            name: "demo".into(),
            spec: VersionedDocument {
                schema_generation: 1,
                cbor: vec![0xa0],
            },
            isolation_profile: "linux-v1".into(),
        },
    };
    let accepted = OperationAccepted {
        operation_id,
        supervisor_request_id: request_id,
        catalog_revision: 43,
        replayed: false,
    };
    let event = CatalogEvent {
        catalog_revision: 44,
        sandbox: Some(SandboxRecord {
            lineage_id,
            name: "demo".into(),
            desired_state: DesiredSandboxState::Running,
            observed_state: ObservedSandboxState::Starting,
            runtime_boot_id: None,
            catalog_revision: 44,
        }),
        operation: None,
    };
    json!({
        "protocol": SUPERVISOR_PROTOCOL,
        "generation": 1,
        "preamble_hex": hex(SUPERVISOR_MAGIC),
        "cases": [
            case("hello", Envelope::new(1, "supervisor.hello", &hello).unwrap(), 0, 0),
            case("welcome", Envelope::new(1, "supervisor.welcome", &welcome).unwrap(), 0, 1),
            case("sandbox_create", Envelope::new(1, "sandbox.create", &create).unwrap(), 17, 0),
            case("operation_accepted", Envelope::new(1, "operation.accepted", &accepted).unwrap(), 17, 1),
            case("catalog_event", Envelope::new(1, "supervisor.event", &event).unwrap(), 19, 0),
        ],
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn supervisor_generation_one_fixture_is_pinned() {
    let expected: JsonValue = serde_json::from_str(include_str!("fixtures/supervisor-v1.json"))
        .expect("valid fixture JSON");
    let actual = fixtures();
    if actual != expected {
        eprintln!("{}", serde_json::to_string_pretty(&actual).unwrap());
    }
    assert_eq!(
        actual, expected,
        "review and update the shared fixture intentionally"
    );
}

#[test]
fn identities_are_byte_strings_and_locators_are_unambiguous() {
    let encoded = microsandbox_protocol::wire::encode(&OperationId([7; 16])).unwrap();
    assert_eq!(encoded[0], 0x50, "a 16-byte ID must use a CBOR byte string");
    let locator = SandboxLocator::Lineage {
        lineage_id: SandboxLineageId([1; 16]),
    };
    let encoded = microsandbox_protocol::wire::encode(&locator).unwrap();
    let value: SandboxLocator = microsandbox_protocol::wire::decode_record(&encoded).unwrap();
    assert_eq!(value, locator);
    assert!(
        SupervisorRequestId([0, 0, 0, 0, 0, 0, 0x70, 0, 0x80, 0, 0, 0, 0, 0, 0, 0,]).is_uuid_v7()
    );
}

#[test]
fn welcome_cannot_cross_home_or_expand_the_offer() {
    let hello = SupervisorHello {
        protocol: SUPERVISOR_PROTOCOL.into(),
        min_generation: 1,
        max_generation: 1,
        implementation_version: "test".into(),
        client_instance_id: ClientInstanceId([1; 16]),
        canonical_home_digest: HomeDigest([2; 32]),
        requested_limits: SupervisorLimits::default(),
        resume_catalog_revision: None,
    };
    let mut welcome = SupervisorWelcome {
        protocol: SUPERVISOR_PROTOCOL.into(),
        generation: 1,
        implementation_version: "test".into(),
        supervisor_instance_id: SupervisorInstanceId([3; 16]),
        canonical_home_digest: hello.canonical_home_digest,
        effective_limits: hello.requested_limits,
        current_catalog_revision: 1,
        oldest_catalog_revision: 0,
        launch_profile: LaunchProfile::Supervised,
    };
    assert!(welcome.validate_for(&hello).is_ok());
    welcome.canonical_home_digest = HomeDigest([9; 32]);
    assert!(welcome.validate_for(&hello).is_err());
}

#[test]
fn negotiation_accepts_future_maximums_but_requires_overlap() {
    let mut hello = SupervisorHello {
        protocol: SUPERVISOR_PROTOCOL.into(),
        min_generation: 1,
        max_generation: 9,
        implementation_version: "future".into(),
        client_instance_id: ClientInstanceId([1; 16]),
        canonical_home_digest: HomeDigest([2; 32]),
        requested_limits: SupervisorLimits::default(),
        resume_catalog_revision: None,
    };
    assert_eq!(select_supervisor_generation(&hello), Ok(1));
    hello.min_generation = 2;
    assert_eq!(
        select_supervisor_generation(&hello),
        Err(InvalidSupervisorHandshake)
    );
}

#[test]
fn every_known_message_is_generation_one() {
    for name in [
        "supervisor.status",
        "supervisor.capabilities",
        "supervisor.watch",
        "request.get",
        "sandbox.create",
        "sandbox.start",
        "sandbox.stop",
        "sandbox.kill",
        "sandbox.restart",
        "sandbox.remove",
        "sandbox.modify",
        "sandbox.inspect",
        "sandbox.list",
        "operation.get",
        "operation.watch",
        "operation.cancel",
        "operation.retry",
    ] {
        assert_eq!(supervisor_message_min_generation(name), Some(1));
    }
    assert_eq!(supervisor_message_min_generation("future.extension"), None);
    let _ = RawFrame {
        id: 1,
        flags: 0,
        body: Vec::new(),
    };
}
