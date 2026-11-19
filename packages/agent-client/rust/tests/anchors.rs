use std::time::Duration;

use microsandbox_agent_client::{AgentClient, Delivery, EncodedMessage, ErrorKind, TypedMessage};
use microsandbox_protocol::{
    exec::{ExecExited, ExecRequest, ExecStderr, ExecStdin, ExecStdout},
    fs::{FsOp, FsRequest, FsResponse},
    message::MessageType,
};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires MSB_AGENT_TEST_SOCKET and MSB_AGENT_ANCHOR_WIRE"]
async fn live_anchor_metadata_execution_and_unsupported_ping() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let path = std::env::var_os("MSB_AGENT_TEST_SOCKET").expect("live agent socket");
        let client = AgentClient::connect(path).await.unwrap();
        assert_eq!(
            client.ready().agent_version(),
            std::env::var("MSB_AGENT_TEST_VERSION").unwrap()
        );
        let wire = std::env::var("MSB_AGENT_ANCHOR_WIRE").unwrap();
        assert_eq!(client.ready().is_legacy_protocol(), wire == "legacy_v1");
        assert_eq!(
            client.ready().negotiated_version,
            std::env::var("MSB_AGENT_ANCHOR_GENERATION")
                .unwrap()
                .parse::<u8>()
                .unwrap()
        );
        eprintln!("anchor ready: {:?}", client.ready());
        // Ping was added after these anchors. Reject it locally, then prove
        // the same connection still executes a command with streamed stdin.
        let error = client
            .request(EncodedMessage::new(MessageType::Ping, vec![0xa0]))
            .await
            .unwrap_err();
        assert_eq!(error.kind, ErrorKind::UnsupportedOperation);
        assert_eq!(error.delivery, Delivery::NotSent);
        let request = ExecRequest {
            cmd: "/bin/sh".into(),
            args: vec![
                "-c".into(),
                "read value; printf '%s' \"$value\"; printf 'compat-stderr' >&2".into(),
            ],
            env: vec![],
            cwd: None,
            user: None,
            tty: false,
            rows: 24,
            cols: 80,
            rlimits: vec![],
        };
        let stream = client
            .stream(TypedMessage::new(MessageType::ExecRequest, &request))
            .await
            .unwrap();
        let id = stream.id();
        let (sender, mut receiver) = stream.into_parts();
        let started = receiver.recv().await.unwrap().unwrap();
        assert_eq!(started.t, "core.exec.started");
        client
            .send(
                id,
                TypedMessage::new(
                    MessageType::ExecStdin,
                    ExecStdin {
                        data: b"compat-input\n".to_vec(),
                    },
                ),
            )
            .await
            .unwrap();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let mut exit = None;
        while let Some(message) = receiver.recv().await.unwrap() {
            match message.t.as_str() {
                "core.exec.stdout" => stdout.extend(message.payload::<ExecStdout>().unwrap().data),
                "core.exec.stderr" => stderr.extend(message.payload::<ExecStderr>().unwrap().data),
                "core.exec.exited" => exit = Some(message.payload::<ExecExited>().unwrap().code),
                name => panic!("unexpected live exec message: {name}"),
            }
        }
        assert_eq!(stdout, b"compat-input");
        assert_eq!(stderr, b"compat-stderr");
        assert_eq!(exit, Some(0));
        assert!(
            sender
                .send(TypedMessage::new(
                    MessageType::ExecStdin,
                    ExecStdin { data: vec![] }
                ))
                .await
                .is_err()
        );
        client.close().await;
    })
    .await
    .expect("live agent deadline");
}

#[tokio::test]
#[ignore = "requires MSB_AGENT_TEST_SOCKET and MSB_AGENT_ANCHOR_FILESYSTEM"]
async fn live_anchor_filesystem_matches_the_supported_historical_workflow() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let path = std::env::var_os("MSB_AGENT_TEST_SOCKET").unwrap();
        let client = AgentClient::connect(path).await.unwrap();
        let response = client
            .request(TypedMessage::new(
                MessageType::FsRequest,
                FsRequest {
                    bulk: None,
                    op: FsOp::Stat {
                        path: "/etc/os-release".into(),
                        follow_symlink: true,
                    },
                },
            ))
            .await;
        // The fixture expectation comes from the release's supported workflow,
        // independently of the current client's generation gate.
        if std::env::var("MSB_AGENT_ANCHOR_FILESYSTEM").as_deref() == Ok("supported") {
            let response = response.expect("historically supported filesystem stat");
            assert_eq!(response.t, "core.fs.response");
            assert!(response.payload::<FsResponse>().unwrap().ok);
        } else {
            let error = response.unwrap_err();
            assert_eq!(error.kind, ErrorKind::UnsupportedOperation);
            assert_eq!(error.delivery, Delivery::NotSent);
        }
        client.close().await;
    })
    .await
    .expect("live filesystem deadline");
}
