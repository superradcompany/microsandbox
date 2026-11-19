//! Live acceptance coverage for sandbox-owned execution flow control.

use std::time::Duration;

use microsandbox::{Sandbox, agent::AgentClient};
use microsandbox_protocol::{
    exec::{EXEC_OUTPUT_EVENT_OVERHEAD, ExecOutputAck, ExecRequest, ExecStdin, ExecStdout},
    message::{Message, MessageType},
};
use microsandbox_types::ExecLimits;
use test_utils::msb_test;
use tokio::time::timeout;

fn request(command: &str) -> ExecRequest {
    ExecRequest {
        cmd: "sh".into(),
        args: vec!["-c".into(), command.into()],
        env: vec![],
        cwd: None,
        user: None,
        tty: false,
        rows: 24,
        cols: 80,
        rlimits: vec![],
    }
}

#[msb_test]
async fn policy_duplex_large_input_keeps_output_and_controls_moving() {
    let name = "exec-limits-duplex";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(2)
        .memory(512)
        .replace()
        .create()
        .await
        .unwrap();
    let probe = AgentClient::connect_sandbox(name).await.unwrap();
    assert_eq!(
        probe.ready().unwrap().exec_limits.unwrap(),
        ExecLimits::default()
    );
    let mut stream = sandbox
        .exec_stream_with("sh", |e| {
            e.args(["-c", "head -c 2097152 /dev/zero; cat"])
                .stdin_pipe()
        })
        .await
        .unwrap();
    let input = stream.take_stdin().unwrap();
    let payload = vec![b'x'; 8 * 1024 * 1024];
    let (sent, output) = timeout(Duration::from_secs(30), async {
        tokio::join!(
            async {
                input.write(&payload).await?;
                input.close().await
            },
            stream.collect()
        )
    })
    .await
    .expect("duplex transfer stalled");
    sent.unwrap();
    let output = output.unwrap();
    assert!(output.status().success);
    let bytes = output.stdout().unwrap();
    assert_eq!(bytes.len(), 10 * 1024 * 1024);
    assert!(bytes.as_bytes()[..2 * 1024 * 1024].iter().all(|b| *b == 0));
    assert!(
        bytes.as_bytes()[2 * 1024 * 1024..]
            .iter()
            .all(|b| *b == b'x')
    );
    sandbox.stop().await.unwrap();
    Sandbox::remove(name).await.unwrap();
}

#[msb_test]
async fn admission_is_shared_and_exited_output_retains_its_slot() {
    let name = "exec-limits-admission";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .unwrap();
    let first = AgentClient::connect_sandbox(name).await.unwrap();
    let second = AgentClient::connect_sandbox(name).await.unwrap();
    let (id, mut rx) = first
        .stream(MessageType::ExecRequest, &request("printf retained"))
        .await
        .unwrap();
    assert_eq!(rx.recv().await.unwrap().t, MessageType::ExecStarted);
    let output = rx.recv().await.unwrap();
    let bytes = output.payload::<ExecStdout>().unwrap().data;
    assert_eq!(bytes, b"retained");
    assert!(
        timeout(Duration::from_millis(100), rx.recv())
            .await
            .is_err()
    );
    // Exited-but-unacknowledged streams keep their admission slots: fill the
    // rest of the default allowance without acknowledging any output.
    let mut retained = Vec::new();
    for _ in 1..ExecLimits::default().max_executions {
        let (_, mut rx) = first
            .stream(MessageType::ExecRequest, &request("printf retained"))
            .await
            .unwrap();
        assert_eq!(rx.recv().await.unwrap().t, MessageType::ExecStarted);
        assert_eq!(rx.recv().await.unwrap().t, MessageType::ExecStdout);
        retained.push(rx);
    }
    let (_, mut denied) = second
        .stream(MessageType::ExecRequest, &request("true"))
        .await
        .unwrap();
    assert_eq!(denied.recv().await.unwrap().t, MessageType::ExecFailed);
    first
        .send(
            id,
            MessageType::ExecOutputAck,
            &ExecOutputAck {
                consumed: bytes.len() as u64 + u64::from(EXEC_OUTPUT_EVENT_OVERHEAD),
            },
        )
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(5), rx.recv())
            .await
            .unwrap()
            .unwrap()
            .t,
        MessageType::ExecExited
    );
    let (_, mut accepted) = second
        .stream(MessageType::ExecRequest, &request("true"))
        .await
        .unwrap();
    assert_eq!(accepted.recv().await.unwrap().t, MessageType::ExecStarted);
    assert_eq!(accepted.recv().await.unwrap().t, MessageType::ExecExited);
    sandbox.stop().await.unwrap();
    Sandbox::remove(name).await.unwrap();
}

#[msb_test]
async fn protocol_violations_close_only_the_offending_connection() {
    let name = "exec-limits-violations";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .unwrap();
    for forged_ack in [false, true] {
        let client = AgentClient::connect_sandbox(name).await.unwrap();
        let (id, mut rx) = client
            .stream(MessageType::ExecRequest, &request("sleep 120"))
            .await
            .unwrap();
        assert_eq!(rx.recv().await.unwrap().t, MessageType::ExecStarted);
        let invalid = if forged_ack {
            Message::with_payload(
                MessageType::ExecOutputAck,
                id,
                &ExecOutputAck { consumed: 1 },
            )
            .unwrap()
        } else {
            Message::with_payload(
                MessageType::ExecStdin,
                id,
                &ExecStdin {
                    data: vec![0; 16385],
                },
            )
            .unwrap()
        };
        let mut body = Vec::new();
        microsandbox_protocol::codec::encode_to_buf(&invalid, &mut body).unwrap();
        let _ = client.send_raw(id, invalid.flags, &body[9..]).await;
        assert!(
            timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("offending connection stayed open")
                .is_none()
        );
        assert!(
            timeout(
                Duration::from_secs(5),
                sandbox.exec("true", std::iter::empty::<&str>())
            )
            .await
            .unwrap()
            .unwrap()
            .status()
            .success
        );
    }
    sandbox.stop().await.unwrap();
    Sandbox::remove(name).await.unwrap();
}

/// Released peers do not send execution acknowledgements. Their stream must still complete.
#[msb_test]
async fn legacy_execution_does_not_require_new_acknowledgements() {
    let name = "exec-limits-legacy";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .unwrap();
    let client = AgentClient::connect_sandbox(name).await.unwrap();
    let mut message = Message::with_payload(
        MessageType::ExecRequest,
        0,
        &request("head -c 2097152 /dev/zero"),
    )
    .unwrap();
    message.v = 9;
    let mut wire = Vec::new();
    microsandbox_protocol::codec::encode_to_buf(&message, &mut wire).unwrap();
    let (_, mut rx) = client
        .stream_raw(message.flags, wire[9..].to_vec())
        .await
        .unwrap();
    let bytes = timeout(Duration::from_secs(15), async {
        let mut bytes = 0;
        while let Some(frame) = rx.recv().await {
            let message = microsandbox_protocol::codec::raw_frame_to_message(frame).unwrap();
            match message.t {
                MessageType::ExecStdout => {
                    bytes += message.payload::<ExecStdout>().unwrap().data.len()
                }
                MessageType::ExecExited => return bytes,
                MessageType::ExecFailed => panic!("legacy command failed"),
                _ => {}
            }
        }
        panic!("legacy stream closed before exit")
    })
    .await
    .expect("legacy stream waited for an acknowledgement");
    assert_eq!(bytes, 2 * 1024 * 1024);
    sandbox.stop().await.unwrap();
    Sandbox::remove(name).await.unwrap();
}
