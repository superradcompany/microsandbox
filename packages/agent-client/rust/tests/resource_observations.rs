//! Real framed-client admission and response validation for resource observations.

use std::time::Duration;

use microsandbox_agent_client::{
    AgentClient, Delivery, ErrorKind, TypedMessage, resources::observe_resources,
};
use microsandbox_protocol::{
    codec,
    core::{Ping, Pong, Ready},
    message::{Message, MessageType, PROTOCOL_VERSION},
    resources::{
        CpuReadiness, ObservationUnavailable, ObserveResources, ObservedResources,
        RESOURCE_OBSERVATION_RELAY_VERSION, ResourceObservation, ResourceRelayAdvertisement,
    },
};
use tokio::io::{AsyncWriteExt, DuplexStream};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn peer(generation: u8, relay: Option<u8>) -> (AgentClient, DuplexStream) {
    let (host, mut guest) = tokio::io::duplex(16384);
    guest.write_all(&1u32.to_be_bytes()).await.unwrap();
    guest.write_all(&32u32.to_be_bytes()).await.unwrap();
    let guest_ready = Ready::default();
    let mut ready = if let Some(version) = relay {
        Message::with_payload(
            MessageType::Ready,
            0,
            &ResourceRelayAdvertisement {
                ready: &guest_ready,
                relay_resource_observation: version,
            },
        )
        .unwrap()
    } else {
        Message::with_payload(MessageType::Ready, 0, &guest_ready).unwrap()
    };
    ready.v = generation;
    codec::write_message(&mut guest, &ready).await.unwrap();
    (AgentClient::connect_stream(host).await.unwrap(), guest)
}

fn unavailable(query_id: [u8; 16]) -> ObservedResources {
    ObservedResources {
        query_id,
        cpu: ResourceObservation::Unavailable {
            reason: ObservationUnavailable::Busy,
        },
        memory: ResourceObservation::Unavailable {
            reason: ObservationUnavailable::Unsupported,
        },
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn older_peer_gets_no_observation_request_and_remains_usable() {
    for (generation, relay) in [
        (9, None),
        (9, Some(1)),
        (10, None),
        (10, Some(1)),
        (10, Some(2)),
        (11, None),
        (11, Some(2)),
    ] {
        let (client, mut guest) = peer(generation, relay).await;
        let error = observe_resources(&client, [1; 16], Duration::from_secs(1))
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::UnsupportedOperation);
        assert_eq!(error.delivery, Delivery::NotSent);
        // The ordinary typed API must enforce the same pre-dispatch gate.
        let error = client
            .request(TypedMessage::new(
                MessageType::ObserveResources,
                &ObserveResources { query_id: [2; 16] },
            ))
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::UnsupportedOperation);
        assert_eq!(error.delivery, Delivery::NotSent);
        let server = tokio::spawn(async move {
            // The first frame must still be the ordinary ping, never the unsupported query.
            let request = codec::read_message(&mut guest).await.unwrap();
            assert_eq!(request.t, MessageType::Ping);
            codec::write_message(
                &mut guest,
                &Message::with_payload(MessageType::Pong, request.id, &Pong {}).unwrap(),
            )
            .await
            .unwrap();
        });
        let reply = client
            .request(TypedMessage::new(MessageType::Ping, &Ping {}))
            .await
            .unwrap();
        assert_eq!(reply.t, MessageType::Pong.as_str());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn query_echo_terminal_generation_and_scalar_invariants_are_checked() {
    for case in 0..6 {
        let (client, mut guest) =
            peer(PROTOCOL_VERSION, Some(RESOURCE_OBSERVATION_RELAY_VERSION)).await;
        let server = tokio::spawn(async move {
            let request = codec::read_message(&mut guest).await.unwrap();
            let payload = request.payload::<ObserveResources>().unwrap();
            let mut observation = unavailable(payload.query_id);
            if case == 1 {
                observation.query_id = [9; 16];
            }
            if case == 5 {
                observation.cpu = ResourceObservation::Available {
                    value: CpuReadiness {
                        possible: 1,
                        requested_online: 2,
                        actual_online: 2,
                        exact: true,
                    },
                };
            }
            let mut reply =
                Message::with_payload(MessageType::ObservedResources, request.id, &observation)
                    .unwrap();
            if case == 2 {
                reply.flags = 0;
            }
            if case == 3 {
                reply.v = 10;
            }
            if case == 4 {
                reply.t = MessageType::Pong;
            }
            codec::write_message(&mut guest, &reply).await.unwrap();
        });
        let reply = observe_resources(&client, [4; 16], Duration::from_secs(1)).await;
        if case == 0 {
            assert_eq!(reply.unwrap(), unavailable([4; 16]));
        } else {
            assert_eq!(
                reply.unwrap_err().kind,
                ErrorKind::InvalidData,
                "case {case}"
            );
        }
        server.await.unwrap();
    }
}

#[tokio::test]
async fn timeout_does_not_send_another_operation() {
    let (client, mut guest) =
        peer(PROTOCOL_VERSION, Some(RESOURCE_OBSERVATION_RELAY_VERSION)).await;
    let server = tokio::spawn(async move {
        let first = codec::read_message(&mut guest).await.unwrap();
        assert_eq!(first.t, MessageType::ObserveResources);
        assert!(
            tokio::time::timeout(Duration::from_millis(100), codec::read_message(&mut guest))
                .await
                .is_err()
        );
    });
    let error = observe_resources(&client, [3; 16], Duration::from_millis(20))
        .await
        .unwrap_err();
    assert_eq!(error.kind, ErrorKind::Timeout);
    server.await.unwrap();
}

#[cfg(all(feature = "uds", unix))]
#[tokio::test]
#[ignore = "requires a disposable live VM, MSB_RESOURCE_SOCKET and MSB_EXPECT_OBSERVATION"]
async fn live_resource_capability_safety() {
    let path = std::env::var("MSB_RESOURCE_SOCKET").unwrap();
    let supported = std::env::var("MSB_EXPECT_OBSERVATION").unwrap() == "1";
    let client = AgentClient::connect(path).await.unwrap();
    let result = observe_resources(&client, [8; 16], Duration::from_secs(3)).await;
    if supported {
        let observation = result.unwrap();
        println!("fresh observation (not resize completion): {observation:?}");
    } else {
        let error = result.unwrap_err();
        assert_eq!(error.kind, ErrorKind::UnsupportedOperation);
        assert_eq!(error.delivery, Delivery::NotSent);
    }
    // Keep the same connection open: refusal must not poison its routing or VM.
    let reply = client
        .request(TypedMessage::new(MessageType::Ping, &Ping {}))
        .await
        .unwrap();
    assert_eq!(reply.t, MessageType::Pong.as_str());
}

#[cfg(all(feature = "uds", unix))]
#[tokio::test]
#[ignore = "requires a disposable live VM and MSB_RESOURCE_SOCKET"]
async fn live_resource_observation() {
    let path = std::env::var("MSB_RESOURCE_SOCKET").unwrap();
    let client = AgentClient::connect(path).await.unwrap();
    let result = observe_resources(&client, [7; 16], Duration::from_secs(3))
        .await
        .unwrap();
    println!("{result:?}");
    if let Ok(expected) = std::env::var("MSB_EXPECT_MEMORY_ONLINE") {
        let ResourceObservation::Available { value } = result.memory else {
            panic!("memory observation unavailable")
        };
        assert_eq!(value.all_online, expected == "1");
    }
    if let Ok(expected) = std::env::var("MSB_EXPECT_CPU_EXACT") {
        let ResourceObservation::Available { value } = result.cpu else {
            panic!("CPU observation unavailable")
        };
        assert_eq!(value.exact, expected == "1");
    }
}
