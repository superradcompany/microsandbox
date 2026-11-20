//! Query-bound observation framing, availability and bounded identity contracts.

use microsandbox_protocol::{
    core::Ready,
    message::{FLAG_TERMINAL, Message, MessageType},
    resources::{
        ObservationUnavailable, ObserveResources, ObservedResources, ResourceObservation,
        ResourceRelayAdvertisement, ResourceRelayDiscovery,
    },
};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn host_advertisement_preserves_ready_and_is_not_inferred_from_guest_fields() {
    let ready = Ready {
        agent_version: "guest-version-is-not-relay-support".into(),
        ..Default::default()
    };
    let message = Message::with_payload(
        MessageType::Ready,
        0,
        &ResourceRelayAdvertisement {
            ready: &ready,
            relay_resource_observation: 1,
        },
    )
    .unwrap();
    // The released Ready shape ignores the optional host field.
    let decoded = message.payload::<Ready>().unwrap();
    assert_eq!(decoded.agent_version, ready.agent_version);
    assert_eq!(
        message
            .payload::<ResourceRelayDiscovery>()
            .unwrap()
            .relay_resource_observation,
        Some(1)
    );
    // A relay reserializes the guest through Ready before adding host metadata.
    // Guest-supplied fields therefore cannot forge support on an older relay.
    let old_relay = Message::with_payload(MessageType::Ready, 0, &decoded).unwrap();
    assert!(
        old_relay
            .payload::<ResourceRelayDiscovery>()
            .unwrap()
            .relay_resource_observation
            .is_none()
    );
}

#[test]
fn observations_are_generation_eleven_without_changing_existing_operations() {
    for generation in 1..=10 {
        assert!(!MessageType::ObserveResources.is_available_at(generation));
        assert!(!MessageType::ObservedResources.is_available_at(generation));
        assert!(MessageType::ExecRequest.is_available_at(generation));
    }
    assert!(MessageType::ObserveResources.is_available_at(11));
    assert!(MessageType::ObservedResources.is_available_at(11));
    // Generation 10 already owns execution acknowledgements, independently of observation.
    assert!(MessageType::ExecStdinAck.is_available_at(10));
    assert!(MessageType::ExecOutputAck.is_available_at(10));
    assert_eq!(MessageType::ObserveResources.flags(), 0);
    assert_eq!(MessageType::ObservedResources.flags(), FLAG_TERMINAL);
}

#[test]
fn query_identity_round_trips_and_missing_identity_is_not_invented() {
    let request = ObserveResources {
        query_id: [0xab; 16],
    };
    let encoded = Message::with_payload(MessageType::ObserveResources, 17, &request).unwrap();
    assert_eq!(encoded.payload::<ObserveResources>().unwrap(), request);
    for value in [
        serde_json::json!({}),
        serde_json::json!({"query_id": [1, 2]}),
    ] {
        assert!(serde_json::from_value::<ObserveResources>(value).is_err());
    }
    let response = ObservedResources {
        query_id: request.query_id,
        cpu: ResourceObservation::Unavailable {
            reason: ObservationUnavailable::Busy,
        },
        memory: ResourceObservation::Unavailable {
            reason: ObservationUnavailable::Unsupported,
        },
    };
    let encoded = Message::with_payload(MessageType::ObservedResources, 17, &response).unwrap();
    assert_eq!(encoded.payload::<ObservedResources>().unwrap(), response);
}
