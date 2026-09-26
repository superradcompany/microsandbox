use microsandbox_protocol::{
    codec,
    supervisor::{
        ClientInstanceId, HomeDigest, LaunchProfile, RetryClass, SUPERVISOR_MAGIC,
        SUPERVISOR_PROTOCOL, SupervisorError, SupervisorInstanceId, SupervisorLimits,
        SupervisorStatus, SupervisorWelcome,
    },
    wire::Envelope,
};
use microsandbox_protocol_client::{CborEnvelopeCodec, EnvelopeCodec};
use microsandbox_supervisor_client::{
    GetSupervisorStatus, SupervisorClient, SupervisorClientConfig, SupervisorClientError,
    decode_catalog_event,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[tokio::test]
async fn configured_setup_writes_msbs_and_runs_checked_requests() {
    let (client_stream, mut server_stream) = tokio::io::duplex(16 * 1024);
    let home = HomeDigest([0x44; 32]);
    let server = tokio::spawn(async move {
        let mut magic = [0; 4];
        server_stream.read_exact(&mut magic).await.unwrap();
        assert_eq!(&magic, SUPERVISOR_MAGIC);
        let opening = codec::read_raw_frame(&mut server_stream).await.unwrap();
        let envelope = Envelope::decode(&opening.body).unwrap();
        assert_eq!(
            (opening.id, opening.flags, envelope.t.as_str()),
            (0, 0, "supervisor.hello")
        );
        let hello: microsandbox_protocol::supervisor::SupervisorHello = envelope.payload().unwrap();
        assert_eq!(hello.canonical_home_digest, home);
        let welcome = SupervisorWelcome {
            protocol: SUPERVISOR_PROTOCOL.into(),
            generation: 1,
            implementation_version: "test".into(),
            supervisor_instance_id: SupervisorInstanceId([0x55; 16]),
            canonical_home_digest: home,
            effective_limits: SupervisorLimits {
                max_frame_size: 256 * 1024,
                max_in_flight: 32,
                max_watches: 8,
            },
            current_catalog_revision: 9,
            oldest_catalog_revision: 0,
            launch_profile: LaunchProfile::Supervised,
        };
        let response = Envelope::new(1, "supervisor.welcome", &welcome)
            .unwrap()
            .frame(0, 1)
            .unwrap();
        codec::write_raw_frame(&mut server_stream, &response)
            .await
            .unwrap();

        let request = codec::read_raw_frame(&mut server_stream).await.unwrap();
        let request_envelope = Envelope::decode(&request.body).unwrap();
        assert_eq!(request_envelope.t, "supervisor.status");
        let status = SupervisorStatus {
            supervisor_instance_id: welcome.supervisor_instance_id,
            catalog_revision: 9,
            sandbox_count: 2,
            running_count: 1,
            reconciled: true,
        };
        let response = Envelope::new(1, "supervisor.status.result", &status)
            .unwrap()
            .frame(request.id, 1)
            .unwrap();
        codec::write_raw_frame(&mut server_stream, &response)
            .await
            .unwrap();
    });

    let client = SupervisorClient::connect_stream(
        client_stream,
        SupervisorClientConfig {
            implementation_version: "test".into(),
            client_instance_id: ClientInstanceId([0x11; 16]),
            canonical_home_digest: home,
            resume_catalog_revision: None,
            max_watches: 8,
        },
    )
    .await
    .unwrap();
    let status = client.request_typed(&GetSupervisorStatus).await.unwrap();
    assert_eq!(status.catalog_revision, 9);
    client.close().await;
    server.await.unwrap();
}

#[tokio::test]
async fn setup_rejects_a_welcome_for_another_home() {
    let (client_stream, mut server_stream) = tokio::io::duplex(16 * 1024);
    let server = tokio::spawn(async move {
        let mut magic = [0; 4];
        server_stream.read_exact(&mut magic).await.unwrap();
        let _ = codec::read_raw_frame(&mut server_stream).await.unwrap();
        let welcome = SupervisorWelcome {
            protocol: SUPERVISOR_PROTOCOL.into(),
            generation: 1,
            implementation_version: "test".into(),
            supervisor_instance_id: SupervisorInstanceId([3; 16]),
            canonical_home_digest: HomeDigest([9; 32]),
            effective_limits: SupervisorLimits::default(),
            current_catalog_revision: 0,
            oldest_catalog_revision: 0,
            launch_profile: LaunchProfile::Supervised,
        };
        let response = Envelope::new(1, "supervisor.welcome", &welcome)
            .unwrap()
            .frame(0, 1)
            .unwrap();
        codec::write_raw_frame(&mut server_stream, &response)
            .await
            .unwrap();
        server_stream.shutdown().await.unwrap();
    });
    let error = SupervisorClient::connect_stream(
        client_stream,
        SupervisorClientConfig {
            implementation_version: "test".into(),
            client_instance_id: ClientInstanceId([1; 16]),
            canonical_home_digest: HomeDigest([2; 32]),
            resume_catalog_revision: None,
            max_watches: 8,
        },
    )
    .await
    .err()
    .unwrap();
    assert_eq!(
        error.kind,
        microsandbox_supervisor_client::ErrorKind::InvalidData
    );
    server.await.unwrap();
}

#[test]
fn terminal_stream_errors_remain_structured_peer_failures() {
    let error = SupervisorError {
        code: "catalog_compacted".into(),
        message: "resume from a newer revision".into(),
        retry_class: RetryClass::AfterCorrection,
        details: Vec::new(),
    };
    let raw = Envelope::new(1, "supervisor.error", &error)
        .unwrap()
        .frame(7, 1)
        .unwrap();
    let message = CborEnvelopeCodec.decode(raw).unwrap();
    assert!(matches!(
        decode_catalog_event(message),
        Err(SupervisorClientError::Peer { .. })
    ));
}
