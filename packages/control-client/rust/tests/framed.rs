//! Public control specialization and checked-operation contracts.

use std::time::Duration;

use ciborium::Value;
use microsandbox_control_client::{size::SizeExt, *};
use microsandbox_protocol::{
    codec,
    wire::{self, Envelope},
};
use microsandbox_protocol_client::{CborEnvelopeCodec, EnvelopeCodec};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn hello(server: &mut DuplexStream) -> ControlHello {
    let frame = codec::read_raw_frame(server).await.unwrap();
    assert_eq!((frame.id, frame.flags), (0, 0));
    let envelope = Envelope::decode(&frame.body).unwrap();
    assert_eq!((envelope.v, envelope.t.as_str()), (1, "control.hello"));
    envelope.payload().unwrap()
}

async fn welcome(server: &mut DuplexStream, max_in_flight: u32) {
    let offer = hello(server).await;
    let selected = ControlWelcome::negotiate(&offer, max_in_flight).unwrap();
    let frame = Envelope::new(1, "control.welcome", &selected)
        .unwrap()
        .frame(0, 1)
        .unwrap();
    codec::write_raw_frame(server, &frame).await.unwrap();
}

fn message(name: &str, payload: &impl serde::Serialize) -> Message {
    let frame = Envelope::new(1, name, payload)
        .unwrap()
        .frame(17, 1)
        .unwrap();
    CborEnvelopeCodec.decode(frame).unwrap()
}

fn memory() -> MemoryState {
    MemoryState {
        boot_mib: 512,
        target_mib: u64::MAX,
        current_mib: 1024,
        max_mib: u64::MAX,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn framed_setup_is_direct_and_multiple_operations_share_one_connection() {
    let (stream, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        // A JSON probe would start with '{', so this proves the explicit path.
        assert_eq!(server.read_u8().await.unwrap(), 0);
        let mut prefix = [0; 3];
        server.read_exact(&mut prefix).await.unwrap();
        let length = u32::from_be_bytes([0, prefix[0], prefix[1], prefix[2]]);
        assert!(length <= MAX_HANDSHAKE_FRAME_SIZE);
        let mut packet = vec![0; length as usize + 4];
        packet[..4].copy_from_slice(&length.to_be_bytes());
        server.read_exact(&mut packet[4..]).await.unwrap();
        let frame = codec::try_decode_raw_from_buf(&mut packet)
            .unwrap()
            .unwrap();
        let offer: ControlHello = Envelope::decode(&frame.body).unwrap().payload().unwrap();
        assert_eq!(offer.max_in_flight, 64);
        let selected = ControlWelcome::negotiate(&offer, 2).unwrap();
        codec::write_raw_frame(
            &mut server,
            &Envelope::new(1, "control.welcome", &selected)
                .unwrap()
                .frame(0, 1)
                .unwrap(),
        )
        .await
        .unwrap();
        for expected in ["control.memory.state", "control.memory.target"] {
            let request = codec::read_raw_frame(&mut server).await.unwrap();
            assert_ne!(request.id, 0);
            assert_eq!(request.flags, 0);
            let envelope = Envelope::decode(&request.body).unwrap();
            assert_eq!(envelope.t, expected);
            if expected == "control.memory.target" {
                assert_eq!(envelope.payload::<MemoryTarget>().unwrap().total_mib, 2048);
            }
            codec::write_raw_frame(
                &mut server,
                &Envelope::new(1, "control.memory.state", &memory())
                    .unwrap()
                    .frame(request.id, 1)
                    .unwrap(),
            )
            .await
            .unwrap();
        }
    });
    let client = ControlClient::connect_stream(stream).await.unwrap();
    assert_eq!(client.ready().welcome.max_in_flight, 2);
    assert_eq!(
        client
            .request_typed(&GetMemoryState)
            .await
            .unwrap()
            .target_mib,
        u64::MAX
    );
    assert_eq!(
        client
            .request_typed(&SetMemoryTarget::new(2048.mib()))
            .await
            .unwrap()
            .max_mib,
        u64::MAX
    );
    client.close().await;
    peer.await.unwrap();
}

#[tokio::test]
async fn invalid_welcome_never_admits_an_application_request() {
    for case in 0..8 {
        let (stream, mut server) = tokio::io::duplex(8192);
        let peer = tokio::spawn(async move {
            let offer = hello(&mut server).await;
            let mut selected = ControlWelcome::negotiate(&offer, 64).unwrap();
            let mut id = 0;
            let mut flags = 1;
            let mut generation = 1;
            match case {
                0 => selected.protocol = "other".into(),
                1 => selected.generation = 2,
                2 => selected.max_frame_size = 4095,
                3 => selected.max_frame_size = 4 * 1024 * 1024 + 1,
                4 => selected.max_in_flight = 65,
                5 => id = 1,
                6 => flags = 0,
                _ => generation = 2,
            }
            let frame = Envelope::new(generation, "control.welcome", &selected)
                .unwrap()
                .frame(id, flags)
                .unwrap();
            codec::write_raw_frame(&mut server, &frame).await.unwrap();
            let mut byte = [0];
            assert_eq!(server.read(&mut byte).await.unwrap(), 0);
        });
        let result = ControlClient::connect_stream(stream).await;
        let error = result.err().expect("invalid welcome must fail");
        assert_eq!(error.kind, ErrorKind::InvalidData);
        assert_eq!(error.delivery, Delivery::NotSent);
        peer.await.unwrap();
    }
}

#[tokio::test]
async fn oversized_opening_prefix_is_rejected_without_waiting_for_its_body() {
    let (stream, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        hello(&mut server).await;
        server.write_all(&8192u32.to_be_bytes()).await.unwrap();
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    });
    let result = ControlClient::connect_stream(stream).await;
    assert_eq!(result.err().unwrap().kind, ErrorKind::InvalidData);
    peer.await.unwrap();
}

#[tokio::test]
async fn setup_deadline_is_absolute_and_a_refusal_does_not_downgrade() {
    let (stream, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        hello(&mut server).await;
        server.write_all(&[0]).await.unwrap();
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    });
    let result =
        ControlClient::connect_stream_with(stream, |o| o.setup_timeout(Duration::from_millis(20)))
            .await;
    assert_eq!(result.err().unwrap().kind, ErrorKind::Timeout);
    peer.await.unwrap();

    let (stream, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        hello(&mut server).await;
        let refusal = ControlError::rejected("unsupported_generation", "upgrade required");
        codec::write_raw_frame(
            &mut server,
            &Envelope::new(1, "control.error", &refusal)
                .unwrap()
                .frame(0, 1)
                .unwrap(),
        )
        .await
        .unwrap();
        let mut byte = [0];
        assert_eq!(server.read(&mut byte).await.unwrap(), 0);
    });
    let result = ControlClient::connect_stream(stream).await;
    assert_eq!(result.err().unwrap().kind, ErrorKind::UnsupportedOperation);
    peer.await.unwrap();
}

#[tokio::test]
async fn generic_native_unknown_and_opaque_paths_remain_available() {
    let (stream, mut server) = tokio::io::duplex(8192);
    let peer = tokio::spawn(async move {
        welcome(&mut server, 64).await;
        let native = codec::read_raw_frame(&mut server).await.unwrap();
        assert_eq!(
            Envelope::decode(&native.body).unwrap().t,
            "extension.control"
        );
        codec::write_raw_frame(&mut server, &RawFrame { flags: 1, ..native })
            .await
            .unwrap();
        let raw = codec::read_raw_frame(&mut server).await.unwrap();
        assert_eq!(raw.body, [0xff, 1, 2]);
        codec::write_raw_frame(&mut server, &RawFrame { flags: 1, ..raw })
            .await
            .unwrap();
    });
    let client = ControlClient::connect_stream(stream).await.unwrap();
    let message = client
        .request(TypedMessage::new("extension.control", Empty {}))
        .await
        .unwrap();
    assert_eq!(message.t, "extension.control");
    let frame = client.request_raw(0, vec![0xff, 1, 2]).await.unwrap();
    assert_eq!(frame.body, [0xff, 1, 2]);
    client.close().await;
    peer.await.unwrap();
}

#[test]
fn all_checked_operations_use_shared_records_and_full_width_values() {
    assert_eq!(GetCapabilities.message().unwrap().payload, [0xa0]);
    assert_eq!(
        GetCpuState.message().unwrap().message_type,
        "control.cpu.state"
    );
    assert_eq!(SetMemoryTarget::new(2.gib()).total_mib, 2048);
    let target = SetMemoryTarget {
        total_mib: u64::MAX,
    }
    .message()
    .unwrap();
    assert_eq!(
        wire::decode_record::<MemoryTarget>(&target.payload)
            .unwrap()
            .total_mib,
        u64::MAX
    );
    let cpu = CpuState {
        possible: 4,
        requested_online: 2,
        actual_online: 3,
        enforced: 2,
    };
    assert_eq!(
        SetCpuTarget::new(2)
            .decode(message("control.cpu.state", &cpu))
            .unwrap(),
        cpu
    );
    let caps = Capabilities {
        root_disk_grow: false,
        cpu_resize: true,
        memory_resize: true,
        secrets_update: false,
    };
    assert_eq!(
        GetCapabilities
            .decode(message("control.capabilities.result", &caps))
            .unwrap(),
        caps
    );
    assert_eq!(
        GetMemoryState
            .decode(message("control.memory.state", &memory()))
            .unwrap(),
        memory()
    );
}

#[test]
fn checked_failures_retain_original_frames_and_future_error_codes() {
    let peer = ControlError::rejected("future_refusal", "safe diagnostic");
    let response = message("control.error", &peer);
    let original = response.raw().body.clone();
    match GetMemoryState.decode(response).unwrap_err() {
        ControlClientError::Peer { error, response } => {
            assert_eq!(error, peer);
            assert_eq!(response.raw().body, original);
        }
        error => panic!("wrong failure: {error}"),
    }
    for response in [
        message("other", &memory()),
        message("control.memory.state", &CpuTarget { online: 1 }),
    ] {
        assert!(matches!(
            GetMemoryState.decode(response),
            Err(ControlClientError::InvalidResponse { .. })
        ));
    }
}

#[test]
fn partial_secret_progress_is_preserved_and_inconsistent_or_duplicate_records_rejected() {
    let request = UpdateSecrets::new(vec![
        SecretChange::Remove { name: "A".into() },
        SecretChange::Remove { name: "B".into() },
    ]);
    let failed = SecretsResult::Failed {
        applied_count: 1,
        failed_index: 1,
        error: ControlError::rejected("unknown_secret", "missing secret"),
    };
    assert_eq!(
        request
            .decode(message("control.secrets.result", &failed))
            .unwrap(),
        failed
    );
    for result in [
        SecretsResult::Complete { applied_count: 1 },
        SecretsResult::Failed {
            applied_count: 0,
            failed_index: 1,
            error: ControlError::rejected("internal", "failed"),
        },
    ] {
        assert!(matches!(
            request.decode(message("control.secrets.result", &result)),
            Err(ControlClientError::InvalidResponse { .. })
        ));
    }
    let mut value: Value = wire::decode_value(&wire::encode(&failed).unwrap()).unwrap();
    if let Value::Map(fields) = &mut value
        && let Some((_, Value::Map(error))) = fields
            .iter_mut()
            .find(|(key, _)| key.as_text() == Some("error"))
    {
        error.push((Value::Text("future".into()), Value::Null));
        error.push((Value::Text("future".into()), Value::Null));
    }
    let malformed = message("control.secrets.result", &value);
    assert!(matches!(
        request.decode(malformed),
        Err(ControlClientError::InvalidResponse { .. })
    ));
}
