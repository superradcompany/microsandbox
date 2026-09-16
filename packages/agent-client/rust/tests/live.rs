use std::time::Duration;

use microsandbox_agent_client::{AgentClient, EncodedMessage, TypedMessage};
use microsandbox_protocol::{
    exec::{ExecExited, ExecRequest, ExecStderr, ExecStdin, ExecStdout},
    fs::{FsOp, FsRequest, FsResponse},
    message::MessageType,
};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires MSB_AGENT_TEST_SOCKET and MSB_AGENT_TEST_VERSION"]
async fn live_existing_agent_preserves_execution_streams_and_filesystem_requests() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let path = std::env::var_os("MSB_AGENT_TEST_SOCKET").expect("live agent socket");
        let client = AgentClient::connect(path).await.unwrap();
        assert_eq!(
            client.ready().agent_version(),
            std::env::var("MSB_AGENT_TEST_VERSION").unwrap()
        );
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
            .await
            .unwrap();
        assert_eq!(response.t, "core.fs.response");
        assert!(response.payload::<FsResponse>().unwrap().ok);
        let ping = client
            .request(EncodedMessage::new(MessageType::Ping, vec![0xa0]))
            .await
            .unwrap();
        assert_eq!(ping.t, "core.pong");
        assert!(!ping.raw().body.is_empty());
        client.close().await;
    })
    .await
    .expect("live agent deadline");
}
