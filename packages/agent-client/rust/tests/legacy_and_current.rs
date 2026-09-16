//! Original agent handshake/generation regression cases, migrated to Client<AgentProtocol>.

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "uds", unix))]
    use microsandbox_protocol::exec::ExecRequest;
    #[cfg(all(feature = "uds", unix))]
    use microsandbox_protocol::message::PROTOCOL_VERSION;
    #[cfg(all(feature = "uds", unix))]
    use tokio::io::AsyncWriteExt;
    #[cfg(all(feature = "uds", unix))]
    use tokio::net::UnixListener;
    #[cfg(all(feature = "uds", unix))]
    use tokio::sync::oneshot;

    use microsandbox_agent_client::protocol::LEGACY_PROTOCOL_VERSION;
    use microsandbox_agent_client::{
        AgentClient, AgentProtocol, AgentWireFormat, ClientError, ErrorKind, TypedMessage,
    };
    use microsandbox_protocol::{
        codec,
        core::Ready as AgentReadyPayload,
        message::{Message, MessageType},
    };
    use std::time::Duration;
    use tokio::time::Instant;

    #[cfg(all(feature = "uds", unix))]
    #[tokio::test]
    async fn connect_decodes_ready_payload() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = AgentReadyPayload {
            bulk_transport: None,
            local_transport: None,
            relay_lease: None,
            workload_transport_barrier_version: None,
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            agent_version: "9.9.9".to_string(),
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&1u32.to_be_bytes()).await.unwrap();
            socket.write_all(&8u32.to_be_bytes()).await.unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client = connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(client.ready().wire_format, AgentWireFormat::Current);
        // Both peers speak the current generation, so that is what is negotiated.
        assert_eq!(client.ready().negotiated_version, PROTOCOL_VERSION);
        assert!(client.ready().supports(MessageType::FsRequest));
        // The runtime's self-reported version round-trips from the ready frame.
        assert_eq!(client.ready().agent_version(), "9.9.9");
        let decoded = client.ready().agent.clone();
        assert_eq!(decoded.boot_time_ns, ready.boot_time_ns);
        assert_eq!(decoded.init_time_ns, ready.init_time_ns);
        assert_eq!(decoded.ready_time_ns, ready.ready_time_ns);

        let raw_msg: Message = ciborium::from_reader(client.ready().ready_bytes()).unwrap();
        assert_eq!(raw_msg.t, MessageType::Ready);
    }

    #[cfg(all(feature = "named-pipe", windows))]
    #[tokio::test]
    async fn connect_decodes_ready_payload_from_named_pipe() {
        use microsandbox_protocol::message::PROTOCOL_VERSION;
        use tokio::io::AsyncWriteExt;
        use tokio::net::windows::named_pipe::{PipeMode, ServerOptions};

        let pipe_path = unique_named_pipe("ready");
        let server = ServerOptions::new()
            .first_pipe_instance(true)
            .pipe_mode(PipeMode::Byte)
            .create(&pipe_path)
            .unwrap();
        let ready = AgentReadyPayload {
            bulk_transport: None,
            local_transport: None,
            relay_lease: None,
            workload_transport_barrier_version: None,
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            agent_version: "named-pipe-test".to_string(),
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();

        tokio::spawn(async move {
            let mut server = server;
            server.connect().await.unwrap();
            server.write_all(&1u32.to_be_bytes()).await.unwrap();
            server.write_all(&8u32.to_be_bytes()).await.unwrap();
            codec::write_message(&mut server, &ready_msg).await.unwrap();
        });

        let client = connect_with_deadline(
            std::path::Path::new(&pipe_path),
            Instant::now() + Duration::from_secs(1),
        )
        .await
        .unwrap();

        assert_eq!(client.ready().wire_format, AgentWireFormat::Current);
        assert_eq!(client.ready().negotiated_version, PROTOCOL_VERSION);
        assert_eq!(client.ready().agent_version(), "named-pipe-test");
        let decoded = client.ready().agent.clone();
        assert_eq!(decoded.boot_time_ns, ready.boot_time_ns);
        assert_eq!(decoded.init_time_ns, ready.init_time_ns);
        assert_eq!(decoded.ready_time_ns, ready.ready_time_ns);
    }

    #[cfg(all(feature = "uds", unix))]
    #[tokio::test]
    async fn connect_negotiates_down_to_older_guest_generation() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = AgentReadyPayload {
            bulk_transport: None,
            local_transport: None,
            relay_lease: None,
            workload_transport_barrier_version: None,
            boot_time_ns: 1,
            init_time_ns: 2,
            ready_time_ns: 3,
            ..Default::default()
        };
        // A current-codec guest that advertises an older capability generation in
        // its ready frame (a runtime one generation behind this host).
        let mut ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();
        ready_msg.v = 1;

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&1u32.to_be_bytes()).await.unwrap();
            socket
                .write_all(&microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP.to_be_bytes())
                .await
                .unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client = connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();

        // Current codec, but the capability gate is pinned to the guest's older
        // generation: min(host PROTOCOL_VERSION, guest's advertised 1) == 1.
        assert_eq!(client.ready().wire_format, AgentWireFormat::Current);
        assert_eq!(client.ready().negotiated_version, 1);
        // Exec is in the baseline; filesystem is not, at generation 1.
        assert!(client.ready().supports(MessageType::ExecRequest));
        assert!(!client.ready().supports(MessageType::FsRequest));
    }

    #[cfg(all(feature = "uds", unix))]
    #[tokio::test]
    async fn connect_accepts_legacy_relay_handshake() {
        assert_accepts_legacy_relay_handshake(0).await;
        assert_accepts_legacy_relay_handshake(268_435_455).await;
    }

    #[cfg(all(feature = "uds", unix))]
    #[tokio::test]
    async fn legacy_relay_requests_use_v1_and_legacy_id_range() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = AgentReadyPayload {
            bulk_transport: None,
            local_transport: None,
            relay_lease: None,
            workload_transport_barrier_version: None,
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            ..Default::default()
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();
        let id_offset = 268_435_455u32;
        let (frame_tx, frame_rx) = oneshot::channel();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&id_offset.to_be_bytes()).await.unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
            let frame = codec::read_raw_frame(&mut socket).await.unwrap();
            frame_tx.send(frame).unwrap();
        });

        let client = connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();
        let request = ExecRequest {
            cmd: "/bin/true".into(),
            args: Vec::new(),
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let stream = client
            .stream(TypedMessage::new(MessageType::ExecRequest, &request))
            .await
            .unwrap();

        let frame = frame_rx.await.unwrap();
        let message = codec::raw_frame_to_message(frame).unwrap();

        assert_eq!(stream.id(), id_offset + 1);
        assert_eq!(message.id, id_offset + 1);
        assert_eq!(message.v, LEGACY_PROTOCOL_VERSION);
        assert_eq!(message.t, MessageType::ExecRequest);
    }

    #[test]
    fn version_compat_across_generations() {
        use MessageType::{ExecRequest, FsRequest};
        // (message type, peer generation, expected allowed). Generation 1 is the
        // pre-0.5 legacy runtime (no filesystem); generation 2 introduced the
        // Fs* types; generation 6 is current.
        let cases = [
            (ExecRequest, 1, true),
            (ExecRequest, 2, true),
            (ExecRequest, 3, true),
            (FsRequest, 1, false),
            (FsRequest, 2, true),
            (FsRequest, 3, true),
        ];
        for (t, generation, allowed) in cases {
            assert_eq!(
                AgentProtocol::ensure_version_compat_for(t, generation).is_ok(),
                allowed,
                "{t:?} at generation {generation}"
            );
        }
    }

    #[test]
    fn version_compat_rejection_is_typed() {
        // Filesystem on the legacy (generation 1) runtime is rejected before any
        // send, with the structured error whose message tells the user to restart.
        let err = AgentProtocol::ensure_version_compat_for(
            MessageType::FsRequest,
            LEGACY_PROTOCOL_VERSION,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ClientError {
                kind: ErrorKind::UnsupportedOperation,
                ..
            }
        ));
    }

    #[cfg(all(feature = "uds", unix))]
    #[tokio::test]
    async fn connect_preserves_current_peer_protocol_version() {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = AgentReadyPayload {
            bulk_transport: None,
            local_transport: None,
            relay_lease: None,
            workload_transport_barrier_version: None,
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            ..Default::default()
        };
        let mut ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();
        ready_msg.v = 2;

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&1u32.to_be_bytes()).await.unwrap();
            socket
                .write_all(&microsandbox_protocol::AGENT_RELAY_ID_RANGE_STEP.to_be_bytes())
                .await
                .unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client = connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(client.ready().wire_format, AgentWireFormat::Current);
        // The runtime reported generation 2, so that is the negotiated capability.
        assert_eq!(client.ready().negotiated_version, 2);
        // TCP forwarding (generation 4) is unavailable to a generation-2 runtime.
        assert!(!client.ready().supports(MessageType::TcpConnect));
    }

    #[cfg(all(feature = "uds", unix))]
    async fn assert_accepts_legacy_relay_handshake(id_offset: u32) {
        let temp = tempfile::tempdir().unwrap();
        let sock_path = temp.path().join("agent.sock");
        let listener = UnixListener::bind(&sock_path).unwrap();
        let ready = AgentReadyPayload {
            bulk_transport: None,
            local_transport: None,
            relay_lease: None,
            workload_transport_barrier_version: None,
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            ..Default::default()
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();

        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            socket.write_all(&id_offset.to_be_bytes()).await.unwrap();
            codec::write_message(&mut socket, &ready_msg).await.unwrap();
        });

        let client = connect_with_deadline(&sock_path, Instant::now() + Duration::from_secs(1))
            .await
            .unwrap();

        assert_eq!(client.ready().wire_format, AgentWireFormat::LegacyV1);
        assert_eq!(client.ready().negotiated_version, LEGACY_PROTOCOL_VERSION);
        let decoded = client.ready().agent.clone();
        assert_eq!(decoded.boot_time_ns, ready.boot_time_ns);
        assert_eq!(decoded.init_time_ns, ready.init_time_ns);
        assert_eq!(decoded.ready_time_ns, ready.ready_time_ns);
    }

    #[cfg(all(feature = "named-pipe", windows))]
    fn unique_named_pipe(name: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        format!(
            r"\\.\pipe\msb-agent-client-{name}-{}-{nanos}",
            std::process::id()
        )
    }

    #[cfg(feature = "stream")]
    #[tokio::test]
    async fn connect_stream_handshakes_and_streams_exec() {
        use microsandbox_protocol::exec::{ExecExited, ExecRequest, ExecStdout};
        use tokio::io::AsyncWriteExt;

        let (client_io, mut server_io) = tokio::io::duplex(64 * 1024);
        let ready = AgentReadyPayload {
            bulk_transport: None,
            local_transport: None,
            relay_lease: None,
            workload_transport_barrier_version: None,
            boot_time_ns: 11,
            init_time_ns: 22,
            ready_time_ns: 33,
            agent_version: "stream-test".to_string(),
        };
        let ready_msg = Message::with_payload(MessageType::Ready, 0, &ready).unwrap();

        tokio::spawn(async move {
            // Relay handshake: [id_min][id_max] then the core.ready frame.
            server_io.write_all(&1u32.to_be_bytes()).await.unwrap();
            server_io.write_all(&1024u32.to_be_bytes()).await.unwrap();
            codec::write_message(&mut server_io, &ready_msg)
                .await
                .unwrap();

            // One exec stream echoed back: stdout, then a terminal exited.
            let request = codec::read_raw_frame(&mut server_io).await.unwrap();
            let stdout = Message::with_payload(
                MessageType::ExecStdout,
                request.id,
                &ExecStdout {
                    data: b"hi".to_vec(),
                },
            )
            .unwrap();
            codec::write_message(&mut server_io, &stdout).await.unwrap();
            let exited =
                Message::with_payload(MessageType::ExecExited, request.id, &ExecExited { code: 0 })
                    .unwrap();
            codec::write_message(&mut server_io, &exited).await.unwrap();
        });

        let client =
            connect_stream_with_deadline(client_io, Instant::now() + Duration::from_secs(1))
                .await
                .unwrap();

        assert_eq!(client.ready().wire_format, AgentWireFormat::Current);
        assert_eq!(client.ready().agent_version(), "stream-test");
        assert!(client.ready().supports(MessageType::ExecRequest));

        let request = ExecRequest {
            cmd: "echo".into(),
            args: vec!["hi".into()],
            env: Vec::new(),
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: Vec::new(),
        };
        let mut rx = client
            .stream(TypedMessage::new(MessageType::ExecRequest, &request))
            .await
            .unwrap();

        let first = rx.recv().await.unwrap().unwrap();
        assert_eq!(first.t, MessageType::ExecStdout.as_str());
        let out: ExecStdout = first.payload().unwrap();
        assert_eq!(out.data, b"hi");

        let second = rx.recv().await.unwrap().unwrap();
        assert_eq!(second.t, MessageType::ExecExited.as_str());
        let exit: ExecExited = second.payload().unwrap();
        assert_eq!(exit.code, 0);
    }

    #[cfg(any(all(feature = "uds", unix), all(feature = "named-pipe", windows)))]
    async fn connect_with_deadline(
        path: impl AsRef<std::path::Path>,
        deadline: Instant,
    ) -> Result<AgentClient, ClientError> {
        AgentClient::connect_with(path, |o| {
            o.setup_timeout(deadline.saturating_duration_since(Instant::now()))
        })
        .await
    }

    #[cfg(feature = "stream")]
    async fn connect_stream_with_deadline(
        stream: impl microsandbox_protocol_client::ByteTransport,
        deadline: Instant,
    ) -> Result<AgentClient, ClientError> {
        AgentClient::connect_stream_with(stream, |o| {
            o.setup_timeout(deadline.saturating_duration_since(Instant::now()))
        })
        .await
    }
}
