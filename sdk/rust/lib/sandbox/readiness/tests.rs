//! Public readiness paths against a scripted provider, without starting a VM.

use std::{sync::Arc, time::Duration};

use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

use crate::{Context, MicrosandboxError, Sandbox, test_support};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn sandbox(id: &str, status: &str) -> Value {
    json!({
        "id": id, "org_id": "org", "name": "task", "slug": "task", "status": status,
        "ephemeral": false, "created_at": "2026-11-15T00:00:00Z"
    })
}

async fn provider(
    script: Vec<(&'static str, &'static str, u16, Value)>,
) -> (Arc<dyn Context>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let context: Arc<dyn Context> = Arc::new(
        test_support::cloud_backend(
            format!("http://{}", listener.local_addr().unwrap()),
            "test-key",
        )
        .unwrap(),
    );
    let server = tokio::spawn(async move {
        for (method, path, status, body) in script {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            let parts: Vec<_> = line.split_whitespace().collect();
            assert_eq!(parts[0], method);
            assert_eq!(parts[1].split('?').next().unwrap(), path);
            let mut length = 0;
            loop {
                line.clear();
                assert_ne!(stream.read_line(&mut line).await.unwrap(), 0);
                if line == "\r\n" {
                    break;
                }
                if let Some((key, value)) = line.split_once(':')
                    && key.eq_ignore_ascii_case("content-length")
                {
                    length = value.trim().parse::<usize>().unwrap();
                }
            }
            stream.read_exact(&mut vec![0; length]).await.unwrap();
            let body = body.to_string();
            stream.get_mut().write_all(format!(
                "HTTP/1.1 {status} Test\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}", body.len(),
            ).as_bytes()).await.unwrap();
        }
        // Closing the listener also makes any unexpected create/start request fail.
    });
    (context, server)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn get_running_connects_existing_run_without_start_or_ownership() {
    for associated in [false, true] {
        let (context, server) = provider(vec![
            (
                "GET",
                "/v1/sandboxes/by-name/task",
                200,
                sandbox("original", "running"),
            ),
            (
                "GET",
                "/v1/sandboxes/by-name/task",
                200,
                sandbox("original", "running"),
            ),
        ])
        .await;
        let result = if associated {
            async {
                let destination: std::sync::Arc<dyn crate::Context> = context;
                destination.sandboxes().get_running("task").await
            }
            .await
        } else {
            let sandboxes = Sandbox::ctx(context.as_ref());
            drop(context);
            sandboxes.get_running("task").await
        }
        .unwrap();
        assert_eq!(result.id(), crate::sandbox::SandboxId::cloud("original"));
        assert!(!result.owns_lifecycle());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn get_preparation_retains_the_latest_inspected_runtime() {
    let mut observed = sandbox("original", "running");
    observed["spec"] = json!({
        "image": "python",
        "runtime": { "shell": "/bin/bash", "cmd": ["printf", "ready"], "workdir": "/tmp" }
    });
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "running"),
        ),
        ("GET", "/v1/sandboxes/by-name/task", 200, observed),
    ])
    .await;
    let resource = Sandbox::ctx(context.as_ref()).get("task").await.unwrap();
    assert!(resource.binding.current().is_none());

    resource.ensure_running().await.unwrap();

    let session = resource.binding.current().unwrap();
    assert_eq!(
        session.config.spec.runtime.shell.as_deref(),
        Some("/bin/bash")
    );
    assert_eq!(session.config.spec.runtime.workdir.as_deref(), Some("/tmp"));
    assert_eq!(
        session.config.spec.runtime.cmd,
        Some(vec!["printf".into(), "ready".into()])
    );
    assert!(!resource.owns_lifecycle());
    server.await.unwrap();
}

#[tokio::test]
async fn get_running_starts_the_captured_identity_when_stopped() {
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "GET",
            "/v1/sandboxes/original",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "POST",
            "/v1/sandboxes/original/start",
            200,
            sandbox("original", "running"),
        ),
    ])
    .await;
    let result = Sandbox::ctx(context.as_ref())
        .get_running("task")
        .await
        .unwrap();
    assert_eq!(result.id(), crate::sandbox::SandboxId::cloud("original"));
    assert!(
        !result.owns_lifecycle(),
        "remote startup must not acquire client ownership"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn get_running_rejects_replacement_between_lookup_and_preparation() {
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("replacement", "stopped"),
        ),
    ])
    .await;
    let result = Sandbox::ctx(context.as_ref()).get_running("task").await;
    assert!(matches!(
        result,
        Err(MicrosandboxError::SandboxReplaced { .. })
    ));
    server.await.unwrap();
}

#[tokio::test]
async fn get_running_does_not_create_missing_or_inaccessible_resources() {
    for status in [404, 401, 500] {
        let (context, server) = provider(vec![(
            "GET",
            "/v1/sandboxes/by-name/task",
            status,
            json!({"error":{"message":"lookup failed"}}),
        )])
        .await;
        assert!(
            Sandbox::ctx(context.as_ref())
                .get_running("task")
                .await
                .is_err()
        );
        server.await.unwrap();
    }
}

#[tokio::test]
async fn get_running_observes_an_in_progress_start_without_starting_again() {
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "starting"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "starting"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "running"),
        ),
    ])
    .await;
    let sandboxes = Sandbox::ctx(context.as_ref());
    let result = tokio::time::timeout(Duration::from_secs(3), sandboxes.get_running("task"))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(result.id(), crate::sandbox::SandboxId::cloud("original"));
    server.await.unwrap();
}

#[tokio::test]
async fn lookup_and_inspection_do_not_prepare_a_runtime() {
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "running"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
    ])
    .await;
    let resource = Sandbox::ctx(context.as_ref()).get("task").await.unwrap();
    assert!(resource.binding.current().is_none());
    assert_eq!(resource.id().as_str(), "cloud:original");
    assert_eq!(resource.name(), "task");
    assert_eq!(
        resource.info().await.unwrap().status,
        crate::sandbox::SandboxStatus::Running
    );
    assert_eq!(
        resource.status().await.unwrap(),
        crate::sandbox::SandboxStatus::Stopped
    );
    assert!(resource.binding.current().is_none());
    server.await.unwrap();
}

#[tokio::test]
async fn concurrent_clone_preparation_publishes_one_shared_session() {
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "GET",
            "/v1/sandboxes/original",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "POST",
            "/v1/sandboxes/original/start",
            200,
            sandbox("original", "running"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "running"),
        ),
    ])
    .await;
    let resource = Sandbox::ctx(context.as_ref()).get("task").await.unwrap();
    let clone = resource.clone();
    let (first, second) = tokio::join!(resource.prepare_runtime(), clone.prepare_runtime());
    let first = first.unwrap();
    let second = second.unwrap();
    assert!(Arc::ptr_eq(&first, &second));
    assert!(Arc::ptr_eq(&first, &resource.binding.current().unwrap()));
    assert!(!resource.owns_lifecycle());
    server.await.unwrap();
}

#[tokio::test]
async fn failed_preparation_keeps_receiver_usable_for_retry() {
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            500,
            json!({"message":"unavailable"}),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "running"),
        ),
    ])
    .await;
    let resource = Sandbox::ctx(context.as_ref()).get("task").await.unwrap();
    assert!(resource.ensure_running().await.is_err());
    assert!(resource.binding.current().is_none());
    resource.ensure_running().await.unwrap();
    assert!(resource.binding.current().is_some());
    server.await.unwrap();
}

#[tokio::test]
async fn config_does_not_replace_unavailable_or_malformed_provider_data_with_defaults() {
    let mut malformed = sandbox("original", "stopped");
    malformed["spec"] = json!({"unexpected":true});
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        ("GET", "/v1/sandboxes/by-name/task", 200, malformed),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            500,
            json!({"message":"unavailable"}),
        ),
    ])
    .await;
    let resource = Sandbox::ctx(context.as_ref()).get("task").await.unwrap();
    assert!(matches!(
        resource.config().await,
        Err(MicrosandboxError::Unsupported { .. })
    ));
    assert!(resource.config().await.is_err());
    assert!(resource.config().await.is_err());
    assert!(resource.binding.current().is_none());
    server.await.unwrap();
}

#[tokio::test]
async fn remote_raw_client_is_unsupported_without_preparation() {
    let (context, server) = provider(vec![(
        "GET",
        "/v1/sandboxes/by-name/task",
        200,
        sandbox("original", "stopped"),
    )])
    .await;
    let resource = Sandbox::ctx(context.as_ref()).get("task").await.unwrap();
    assert!(matches!(
        resource.client().await,
        Err(MicrosandboxError::Unsupported { .. })
    ));
    assert!(resource.binding.current().is_none());
    server.await.unwrap();
}

#[tokio::test]
async fn list_returns_unprepared_resources_and_inspection_uses_retained_context() {
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes",
            200,
            json!({"data": [sandbox("original", "stopped")], "next_cursor": "next"}),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "running"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            503,
            json!({"error": "unavailable"}),
        ),
    ])
    .await;
    let collection = Sandbox::ctx(context.as_ref());
    drop(context);
    let page = collection.list().await.unwrap();
    assert_eq!(page.next_cursor.as_deref(), Some("next"));
    assert_eq!(page.sandboxes.len(), 1);
    let resource = &page.sandboxes[0];
    assert_eq!(resource.name(), "task");
    assert!(!resource.owns_lifecycle());
    assert!(resource.prepared_runtime().is_err());
    // No extra lookup happens while constructing the page. The next scripted
    // lookup is the explicit inspection, and its failure cannot reuse old data.
    let info = resource.info().await.unwrap();
    let json = serde_json::to_value(info).unwrap();
    assert_eq!(json["id"], resource.id().to_string());
    assert_eq!(json["status"], "running");
    assert!(resource.info().await.is_err());
    assert!(resource.prepared_runtime().is_err());
    server.await.unwrap();
}

#[tokio::test]
async fn status_wait_returns_only_completion_without_preparing_a_run() {
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "running"),
        ),
    ])
    .await;
    let resource = Sandbox::ctx(context.as_ref()).get("task").await.unwrap();
    let _: () = resource
        .wait_for_status(crate::sandbox::SandboxStatus::Stopped)
        .await
        .unwrap();
    assert!(resource.binding.current().is_none());
    assert_eq!(
        resource.status().await.unwrap(),
        crate::sandbox::SandboxStatus::Running
    );
    server.await.unwrap();
}

#[tokio::test]
async fn status_wait_rejects_replacement_and_failed_observation() {
    for (code, observation) in [
        (200, sandbox("replacement", "stopped")),
        (503, json!({"error":"unavailable"})),
    ] {
        let (context, server) = provider(vec![
            (
                "GET",
                "/v1/sandboxes/by-name/task",
                200,
                sandbox("original", "stopped"),
            ),
            ("GET", "/v1/sandboxes/by-name/task", code, observation),
        ])
        .await;
        let resource = Sandbox::ctx(context.as_ref()).get("task").await.unwrap();
        assert!(
            resource
                .wait_for_status(crate::sandbox::SandboxStatus::Stopped)
                .await
                .is_err()
        );
        assert!(resource.binding.current().is_none());
        server.await.unwrap();
    }
}

#[tokio::test]
async fn retained_checkpoint_rejects_replaced_source_before_capture() {
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("original", "stopped"),
        ),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            200,
            sandbox("replacement", "stopped"),
        ),
    ])
    .await;
    let resource = context.sandboxes().get("task").await.unwrap();
    let result = resource.checkpoint("saved").await;
    assert!(
        matches!(result, Err(MicrosandboxError::SandboxReplaced { .. })),
        "{result:?}"
    );
    server.await.unwrap();
}

#[tokio::test]
async fn config_returns_fresh_typed_remote_observations_without_preparation() {
    let mut first = sandbox("original", "stopped");
    first["spec"] = crate::sandbox::config_inspection::tests::projection();
    let mut second = first.clone();
    second["spec"]["runtime"]["shell"] = json!("/bin/zsh");
    let (context, server) = provider(vec![
        ("GET", "/v1/sandboxes/by-name/task", 200, first.clone()),
        ("GET", "/v1/sandboxes/by-name/task", 200, first),
        ("GET", "/v1/sandboxes/by-name/task", 200, second),
        (
            "GET",
            "/v1/sandboxes/by-name/task",
            503,
            json!({"message":"unavailable"}),
        ),
    ])
    .await;
    let resource = Sandbox::ctx(context.as_ref()).get("task").await.unwrap();
    let captured = resource.config().await.unwrap();
    assert_eq!(captured.runtime().shell.as_deref(), Some("/bin/bash"));
    assert_eq!(
        resource.config().await.unwrap().runtime().shell.as_deref(),
        Some("/bin/zsh")
    );
    assert!(resource.config().await.is_err());
    assert_eq!(captured.runtime().shell.as_deref(), Some("/bin/bash"));
    assert!(resource.binding.current().is_none());
    server.await.unwrap();
}

#[tokio::test]
async fn remote_stop_waits_through_checkpoint_save() {
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes/original",
            200,
            sandbox("original", "running"),
        ),
        (
            "POST",
            "/v1/sandboxes/original/stop",
            200,
            sandbox("original", "stopping"),
        ),
        (
            "GET",
            "/v1/sandboxes/original",
            200,
            sandbox("original", "saving_state"),
        ),
        (
            "GET",
            "/v1/sandboxes/original",
            200,
            sandbox("original", "saving_state"),
        ),
        (
            "GET",
            "/v1/sandboxes/original",
            200,
            sandbox("original", "stopped"),
        ),
    ])
    .await;
    // An exited VM with a checkpoint still saving is not stop completion.
    context
        .as_cloud()
        .unwrap()
        .stop_complete("original")
        .await
        .unwrap();
    server.await.unwrap();
}

#[tokio::test]
async fn remote_stop_observes_in_progress_shutdown_without_resubmitting_stop() {
    for status in ["stopping", "saving_state"] {
        let (context, server) = provider(vec![
            (
                "GET",
                "/v1/sandboxes/original",
                200,
                sandbox("original", status),
            ),
            (
                "GET",
                "/v1/sandboxes/original",
                200,
                sandbox("original", "stopped"),
            ),
        ])
        .await;
        context
            .as_cloud()
            .unwrap()
            .stop_complete("original")
            .await
            .unwrap();
        server.await.unwrap();
    }
}

#[tokio::test]
async fn remote_save_failure_propagates_without_inventing_completion() {
    let (context, server) = provider(vec![
        (
            "GET",
            "/v1/sandboxes/original",
            200,
            sandbox("original", "saving_state"),
        ),
        (
            "GET",
            "/v1/sandboxes/original",
            503,
            json!({"message":"unavailable"}),
        ),
    ])
    .await;
    assert!(
        context
            .as_cloud()
            .unwrap()
            .stop_complete("original")
            .await
            .is_err()
    );
    server.await.unwrap();
}
