//! Live execution credit, cancellation, and concurrent slow-reader checks.
//!
//! Run with an isolated MSB_HOME and a signed MSB_PATH built from this revision:
//! cargo test -p microsandbox --test exec_limits_live -- --ignored --test-threads=1

use std::time::Duration;

use microsandbox::{ExecEvent, Sandbox};
use test_utils::msb_test;
use tokio::time::{sleep, timeout};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MIB: usize = 1024 * 1024;
const DEADLINE: Duration = Duration::from_secs(30);

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn larger_exec_windows_still_backpressure_and_release_on_cancel() {
    let name = "exec-limits-live";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine:3.20")
        .cpus(1)
        .memory(512)
        .create()
        .await
        .unwrap();
    let client = sandbox.client().await.unwrap();
    let policy = client.ready().unwrap().exec_limits.unwrap();
    assert_eq!(policy.input_limit, MIB as u32);
    assert_eq!(policy.output_limit, (4 * MIB) as u32);
    assert_eq!(policy.max_executions, 128);

    let mut held = Vec::new();
    for index in 0..4 {
        let script = format!("head -c {} /dev/zero; touch /tmp/done-{index}", 8 * MIB);
        held.push(sandbox.exec_stream("sh", ["-c", &script]).await.unwrap());
    }
    sleep(Duration::from_secs(1)).await;
    // No reader has returned output credit. Each command must still be blocked,
    // while an unrelated command on the same connection remains usable.
    for index in 0..4 {
        let path = format!("/tmp/done-{index}");
        let output = timeout(DEADLINE, sandbox.exec("test", ["!", "-e", &path]))
            .await
            .unwrap()
            .unwrap();
        assert!(
            output.status().success,
            "unread command escaped its output window"
        );
    }
    for mut stream in held {
        let mut bytes = 0;
        let mut exited = false;
        timeout(DEADLINE, async {
            while let Some(event) = stream.recv().await {
                match event {
                    ExecEvent::Stdout(data) => {
                        assert!(data.iter().all(|byte| *byte == 0));
                        bytes += data.len();
                    }
                    ExecEvent::Exited { code } => {
                        assert_eq!(code, 0);
                        exited = true;
                        break;
                    }
                    ExecEvent::Failed(error) => panic!("execution failed: {error:?}"),
                    _ => {}
                }
            }
        })
        .await
        .unwrap();
        assert!(exited);
        assert_eq!(bytes, 8 * MIB);
    }

    let mut blocked = sandbox
        .exec_stream_with("sleep", |e| e.args(["120"]).stdin_pipe())
        .await
        .unwrap();
    assert!(matches!(
        timeout(DEADLINE, blocked.recv()).await.unwrap(),
        Some(ExecEvent::Started { .. })
    ));
    let input = blocked.take_stdin().unwrap();
    // Send one full window after startup before timing the blocked remainder.
    // A slow spawn must not satisfy the backpressure assertion on its own.
    timeout(DEADLINE, input.write(vec![0; MIB]))
        .await
        .unwrap()
        .unwrap();
    assert!(
        timeout(Duration::from_millis(500), input.write(vec![0; 8 * MIB]))
            .await
            .is_err(),
        "stdin must wait once its bounded allowance is full"
    );
    timeout(DEADLINE, blocked.kill()).await.unwrap().unwrap();
    assert!(
        !timeout(DEADLINE, blocked.wait())
            .await
            .unwrap()
            .unwrap()
            .success
    );
    drop(input);
    assert!(
        timeout(DEADLINE, sandbox.exec("true", [] as [&str; 0]))
            .await
            .unwrap()
            .unwrap()
            .status()
            .success
    );

    sandbox.stop().await.unwrap();
    Sandbox::remove(name).await.unwrap();
}
