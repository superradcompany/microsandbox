//! Service command behavior at the CLI boundary.

use std::{path::Path, process::Output, time::Duration};

use serde_json::{Value, json};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::process::Command;
use tokio::task::JoinHandle;
use tokio::time::timeout;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SERVICE: &str =
    include_str!("../../../packages/microsandbox-types/rust/lib/cloud/fixtures/service.json");
const SERVICE_PAGE: &str =
    include_str!("../../../packages/microsandbox-types/rust/lib/cloud/fixtures/service-page.json");

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

async fn local_cli(dir: &Path, args: &[&str]) -> Output {
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
            .env("MSB_BACKEND", "local")
            .env("NO_COLOR", "1")
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .expect("service command must finish without a backend connection")
    .expect("spawn built CLI")
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
    .expect("service command must finish")
    .expect("spawn built CLI")
}

async fn server(replies: Vec<Reply>) -> (String, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let mut requests = Vec::new();
        for reply in replies {
            let (mut socket, _) = listener.accept().await.unwrap();
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
async fn every_service_command_explains_how_to_select_cloud_on_local() {
    let dir = tempfile::tempdir().unwrap();

    for args in [
        vec!["service", "create", "my-app", "--target", "web-1:8080"],
        vec!["service", "update", "my-app", "--target", "web-2:8080"],
        vec!["service", "enable", "my-app"],
        vec!["service", "disable", "my-app"],
        vec!["service", "inspect", "my-app", "--format", "json"],
        vec!["service", "ls"],
        vec!["service", "remove", "my-app"],
    ] {
        let output = local_cli(dir.path(), &args).await;

        let stderr = String::from_utf8_lossy(&output.stderr);
        assert_eq!(output.status.code(), Some(1), "{args:?}: {stderr}");
        assert!(output.stdout.is_empty(), "{args:?}");
        assert!(
            stderr.contains("services require a cloud backend")
                && stderr.contains("MSB_BACKEND=cloud")
                && stderr.contains("msb context use"),
            "{args:?}: {stderr}"
        );
    }
}

#[tokio::test]
async fn create_on_an_owned_slug_points_to_update() {
    let dir = tempfile::tempdir().unwrap();
    let conflict = json!({
        "error": {
            "code": "service_already_exists",
            "message": "slug unavailable",
            "details": null
        }
    });
    let (url, requests) = server(vec![
        Reply {
            status: 409,
            body: conflict.to_string(),
        },
        Reply {
            status: 200,
            body: SERVICE.to_string(),
        },
    ])
    .await;

    let output = cloud_cli(
        dir.path(),
        &url,
        &["service", "create", "my-app", "--target", "web-1:8080"],
    )
    .await;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(output.stdout.is_empty());
    assert!(
        stderr.contains(
            "service my-app already exists; use 'msb service update' to change its target"
        ),
        "{stderr}"
    );
    assert_eq!(
        requests.await.unwrap(),
        [
            "POST /v1/services HTTP/1.1",
            "GET /v1/services/my-app HTTP/1.1"
        ]
    );
}

#[tokio::test]
async fn disable_refuses_a_detached_service_without_sending_a_change() {
    let dir = tempfile::tempdir().unwrap();
    let mut detached: Value = serde_json::from_str(SERVICE).unwrap();
    detached["slug"] = json!("my-app");
    detached["status"] = json!("detached");
    detached["target"] = Value::Null;
    let (url, requests) = server(vec![Reply {
        status: 200,
        body: detached.to_string(),
    }])
    .await;

    let output = cloud_cli(dir.path(), &url, &["service", "disable", "my-app"]).await;
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert_eq!(output.status.code(), Some(1), "{stderr}");
    assert!(output.stdout.is_empty());
    assert!(
        stderr.contains("service my-app is detached; set a target with 'msb service update'"),
        "{stderr}"
    );
    assert_eq!(
        requests.await.unwrap(),
        ["GET /v1/services/my-app HTTP/1.1"]
    );
}

#[tokio::test]
async fn list_collects_every_page_and_json_keeps_the_list_shape() {
    let dir = tempfile::tempdir().unwrap();
    let final_page = json!({"data": [], "next_cursor": null, "has_more": false});
    let (url, requests) = server(vec![
        Reply {
            status: 200,
            body: SERVICE_PAGE.to_string(),
        },
        Reply {
            status: 200,
            body: final_page.to_string(),
        },
    ])
    .await;

    let output = cloud_cli(dir.path(), &url, &["service", "ls", "--format", "json"]).await;
    let services: Value = serde_json::from_slice(&output.stdout).unwrap();

    assert!(output.status.success());
    assert!(services.is_array());
    assert_eq!(services.as_array().unwrap().len(), 1);
    assert_eq!(
        requests.await.unwrap(),
        [
            "GET /v1/services?limit=100 HTTP/1.1",
            "GET /v1/services?cursor=shop&limit=100 HTTP/1.1"
        ]
    );
}
