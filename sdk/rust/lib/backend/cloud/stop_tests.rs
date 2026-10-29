//! Exercise cloud stop completion through the public SDK against scripted HTTP responses.

use std::{sync::Arc, time::Duration};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use crate::backend::{Backend, CloudCreateSandboxResponse};
use crate::sandbox::{Sandbox, SandboxConfig, SandboxHandle};
use crate::{MicrosandboxError, test_support};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const ID: &str = "00000000-0000-0000-0000-000000000002";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn response(ephemeral: bool, status: &str) -> Value {
    json!({
        "id": ID, "org_id": "00000000-0000-0000-0000-000000000001",
        "name": "agent", "slug": "test-agent", "status": status,
        "ephemeral": ephemeral, "created_at": "2026-10-27T00:00:00Z"
    })
}

async fn serve(
    script: Vec<(&'static str, u16, Value)>,
) -> (Arc<dyn Backend>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = Arc::new(
        test_support::cloud_backend(
            format!("http://{}", listener.local_addr().unwrap()),
            "test-key",
        )
        .unwrap(),
    );
    let server = tokio::spawn(async move {
        for (method, status, body) in script {
            let (stream, _) = listener.accept().await.unwrap();
            let mut reader = BufReader::new(stream);
            let mut line = String::new();
            reader.read_line(&mut line).await.unwrap();
            let suffix = if method == "POST" { "/stop" } else { "" };
            assert_eq!(
                line.trim(),
                format!("{method} /v1/sandboxes/{ID}{suffix} HTTP/1.1")
            );
            let mut length = 0;
            loop {
                line.clear();
                assert_ne!(reader.read_line(&mut line).await.unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((key, value)) = line.split_once(':')
                    && key.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            reader.read_exact(&mut vec![0; length]).await.unwrap();
            let body = body.to_string();
            reader.get_mut().write_all(format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len(),
            ).as_bytes()).await.unwrap();
        }
    });
    (backend, server)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn cloud_stop_accepts_only_confirmed_ephemeral_deletion() {
    for handle_api in [false, true] {
        for ephemeral in [false, true] {
            for final_status in [200, 404, 401, 500] {
                let final_body = if final_status == 200 {
                    response(ephemeral, "stopped")
                } else {
                    json!({"error":{"message":"test failure"}})
                };
                let (backend, server) = serve(vec![
                    ("GET", 200, response(ephemeral, "running")),
                    ("POST", 200, response(ephemeral, "stopping")),
                    ("GET", 200, response(ephemeral, "stopping")),
                    ("GET", final_status, final_body),
                ])
                .await;
                let cloud: CloudCreateSandboxResponse =
                    serde_json::from_value(response(ephemeral, "running")).unwrap();
                let result = if handle_api {
                    SandboxHandle::from_cloud(backend, cloud)
                        .unwrap()
                        .stop_with_timeout(Duration::from_secs(3))
                        .await
                } else {
                    Sandbox::from_cloud(backend, cloud, SandboxConfig::default())
                        .stop_with_timeout(Duration::from_secs(3))
                        .await
                };
                assert_eq!(
                    result.is_ok(),
                    final_status == 200 || (ephemeral && final_status == 404),
                    "{result:?}"
                );
                tokio::time::timeout(Duration::from_secs(1), server)
                    .await
                    .unwrap()
                    .unwrap();
            }
        }
    }
}

#[tokio::test]
async fn cloud_stop_does_not_hide_missing_targets_or_failed_requests() {
    for missing_before_stop in [false, true] {
        let mut script = vec![];
        if !missing_before_stop {
            script.push(("GET", 200, response(true, "running")));
        }
        script.push((
            if missing_before_stop { "GET" } else { "POST" },
            404,
            json!({"error":{"code":"sandbox_not_found","message":"missing"}}),
        ));
        let (backend, server) = serve(script).await;
        let cloud = serde_json::from_value(response(true, "running")).unwrap();
        let result = Sandbox::from_cloud(backend, cloud, SandboxConfig::default())
            .stop_with_timeout(Duration::from_secs(3))
            .await;
        assert!(
            matches!(result, Err(MicrosandboxError::SandboxNotFound(_))),
            "{result:?}"
        );
        tokio::time::timeout(Duration::from_secs(1), server)
            .await
            .unwrap()
            .unwrap();
    }
}

#[tokio::test]
async fn cloud_stop_preserves_zero_budget_and_bounded_waiting() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend = Arc::new(
        test_support::cloud_backend(
            format!("http://{}", listener.local_addr().unwrap()),
            "test-key",
        )
        .unwrap(),
    );
    let cloud = serde_json::from_value(response(true, "running")).unwrap();
    let sandbox = Sandbox::from_cloud(backend, cloud, SandboxConfig::default());
    assert!(matches!(
        sandbox.stop_with_timeout(Duration::ZERO).await,
        Err(MicrosandboxError::StopTimeout { .. })
    ));
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    assert!(matches!(
        sandbox.stop_with_timeout(Duration::from_millis(20)).await,
        Err(MicrosandboxError::StopTimeout { .. })
    ));
}
