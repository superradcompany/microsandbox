//! Cloud exec must avoid unnecessary config reads without skipping identity or lifecycle checks.

use std::{path::Path, process::Output, time::Duration};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::time::timeout;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct Reply {
    status: u16,
    body: String,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn sandbox(id: &str, status: &str) -> Reply {
    Reply {
        status: 200,
        body: json!({
            "id": id, "org_id": "org", "name": "task", "slug": "task", "status": status,
            "ephemeral": false, "created_at": "2026-11-15T00:00:00Z",
            "spec": {
                "image": "alpine:3.20", "resources": { "vcpus": 1, "memory_mib": 512 },
                "runtime": { "cmd": ["true"] }, "env": [], "labels": {}, "rlimits": [],
                "lifecycle": { "ephemeral": false }, "mounts": [],
                "network": { "enabled": true, "ports": [], "trust_host_cas": false }
            }
        })
        .to_string(),
    }
}

fn agent_unavailable() -> Reply {
    // Stop at the upgrade boundary: this test checks routing and preparation,
    // while live VM tests cover the command and its output.
    Reply {
        status: 503,
        body: "agent unavailable for test".into(),
    }
}

async fn cloud_cli(dir: &Path, api_url: &str, args: &[&str]) -> Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_msb"));
    for (key, _) in std::env::vars_os() {
        if key.to_string_lossy().starts_with("MSB_") {
            command.env_remove(key);
        }
    }

    timeout(
        Duration::from_secs(30),
        command
            .env("MSB_CONFIG_PATH", dir.join("config.json"))
            .env("MSB_HOME", dir.join("runtime"))
            .env("MSB_BACKEND", "cloud")
            .env("MSB_API_KEY", "test-key")
            .env("MSB_API_URL", api_url)
            .env("NO_COLOR", "1")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("exec command must finish")
    .expect("spawn built CLI")
}

async fn server(replies: Vec<Reply>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for reply in replies {
            let (mut socket, _) = timeout(Duration::from_secs(10), listener.accept())
                .await
                .expect("CLI must issue every expected request")
                .unwrap();
            let mut request = Vec::new();
            let header_end = loop {
                let mut chunk = [0; 4096];
                let read = socket.read(&mut chunk).await.unwrap();
                assert!(read > 0, "client closed before sending request headers");
                request.extend_from_slice(&chunk[..read]);
                if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                    break end + 4;
                }
            };
            let headers = String::from_utf8_lossy(&request[..header_end]).into_owned();
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("content-length")
                        .then(|| value.trim().parse::<usize>().unwrap())
                })
                .unwrap_or(0);
            while request.len() < header_end + content_length {
                let mut chunk = [0; 4096];
                let read = socket.read(&mut chunk).await.unwrap();
                assert!(read > 0, "client closed before sending request body");
                request.extend_from_slice(&chunk[..read]);
            }
            requests.push(headers.lines().next().unwrap().to_string());

            let reason = match reply.status {
                200 => "OK",
                409 => "Conflict",
                503 => "Service Unavailable",
                status => panic!("unsupported test status {status}"),
            };
            let response = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                reply.status,
                reason,
                reply.body.len(),
                reply.body
            );
            socket.write_all(response.as_bytes()).await.unwrap();
        }
        requests
    });

    (url, task)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn explicit_exec_uses_two_observations_then_the_captured_uuid() {
    let dir = tempfile::tempdir().unwrap();
    let (url, requests) = server(vec![
        sandbox("original", "running"),
        sandbox("original", "running"),
        agent_unavailable(),
    ])
    .await;
    let output = cloud_cli(
        dir.path(),
        &url,
        &["exec", "task", "--no-stdin", "--", "true"],
    )
    .await;
    assert!(!output.status.success());
    assert_eq!(
        requests.await.unwrap(),
        [
            "GET /v1/sandboxes/by-name/task HTTP/1.1",
            "GET /v1/sandboxes/by-name/task HTTP/1.1",
            "GET /v1/sandboxes/original/agent HTTP/1.1",
        ]
    );
}

#[tokio::test]
async fn omitted_command_still_reads_fresh_config() {
    let dir = tempfile::tempdir().unwrap();
    let mut latest = sandbox("original", "running");
    let mut body: Value = serde_json::from_str(&latest.body).unwrap();
    // A newly cleared command must prevent execution; cached initial config
    // would still attempt to run true and contact the agent route.
    body["spec"]["runtime"]["cmd"] = json!([]);
    latest.body = body.to_string();
    let (url, requests) = server(vec![sandbox("original", "running"), latest]).await;
    let output = cloud_cli(dir.path(), &url, &["exec", "task", "--no-stdin"]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(output.status.success(), "{stderr}");
    assert!(stderr.contains("no command provided"), "{stderr}");
    assert_eq!(
        requests.await.unwrap(),
        [
            "GET /v1/sandboxes/by-name/task HTTP/1.1",
            "GET /v1/sandboxes/by-name/task HTTP/1.1",
        ]
    );
}

#[tokio::test]
async fn explicit_exec_rejects_a_same_name_replacement_before_connecting() {
    let dir = tempfile::tempdir().unwrap();
    let (url, requests) = server(vec![
        sandbox("original", "running"),
        sandbox("replacement", "running"),
    ])
    .await;
    let output = cloud_cli(
        dir.path(),
        &url,
        &["exec", "task", "--no-stdin", "--", "true"],
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(stderr.contains("replaced"), "{stderr}");
    assert_eq!(requests.await.unwrap().len(), 2);
}

#[tokio::test]
async fn explicit_exec_rechecks_shutdown_before_connecting() {
    let dir = tempfile::tempdir().unwrap();
    let (url, requests) = server(vec![
        sandbox("original", "running"),
        sandbox("original", "stopping"),
    ])
    .await;
    let output = cloud_cli(
        dir.path(),
        &url,
        &["exec", "task", "--no-stdin", "--", "true"],
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success());
    assert!(
        stderr.contains("shutdown is already in progress"),
        "{stderr}"
    );
    assert_eq!(requests.await.unwrap().len(), 2);
}
