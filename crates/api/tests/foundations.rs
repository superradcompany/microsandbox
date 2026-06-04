use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use axum::{
    body::Body,
    http::{Request, StatusCode, header::AUTHORIZATION},
};
use microsandbox_api::{
    auth::optional_auth,
    dto::{
        DevboxCreateRequest, DevboxListView, DevboxView, EmptyRecord, ExecuteAsyncRequest,
        ExecuteRequest, ExecutionView, SendStdinRequest, WaitForExecutionStatusRequest,
    },
    error::{ApiError, ErrorResponse},
    ids::{new_devbox_id, new_execution_id},
    server::{ServeConfig, validate_bind_addr_for_test},
};
use tower::ServiceExt;

#[test]
fn generated_ids_are_prefixed_and_short() {
    let devbox_id = new_devbox_id();
    let execution_id = new_execution_id();

    assert!(devbox_id.starts_with("dbx_"));
    assert!(devbox_id.len() <= 128);
    assert!(execution_id.starts_with("exec_"));
    assert!(execution_id.len() <= 128);
}

#[test]
fn non_loopback_bind_requires_opt_in() {
    let config = ServeConfig {
        addr: SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 8080),
        allow_non_loopback: false,
        ..ServeConfig::default()
    };

    assert!(validate_bind_addr_for_test(&config).is_err());
}

#[test]
fn api_error_serializes_expected_shape() {
    let response = ErrorResponse::from(ApiError::not_found("Devbox 'dbx_1' was not found."));
    let value = serde_json::to_value(response).unwrap();

    assert_eq!(value["error"]["code"], "not_found");
    assert_eq!(value["error"]["message"], "Devbox 'dbx_1' was not found.");
}

#[tokio::test]
async fn optional_auth_allows_missing_bearer_token() {
    let app = axum::Router::new()
        .route("/ok", axum::routing::get(|| async { "ok" }))
        .layer(axum::middleware::from_fn(optional_auth));

    let response = app
        .oneshot(Request::builder().uri("/ok").body(Body::empty()).unwrap())
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[tokio::test]
async fn optional_auth_allows_arbitrary_bearer_token() {
    let app = axum::Router::new()
        .route("/ok", axum::routing::get(|| async { "ok" }))
        .layer(axum::middleware::from_fn(optional_auth));

    let response = app
        .oneshot(
            Request::builder()
                .uri("/ok")
                .header(AUTHORIZATION, "Bearer arbitrary")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
}

#[test]
fn dtos_serialize_and_deserialize_expected_shapes() {
    let _: DevboxCreateRequest = serde_json::from_value(serde_json::json!({
        "name": "local",
        "image": "ubuntu:latest",
        "blueprint_id": null,
        "blueprint_name": null,
        "metadata": { "owner": "test" },
        "environment_variables": { "RUST_LOG": "debug" }
    }))
    .unwrap();
    let _: ExecuteRequest = serde_json::from_value(serde_json::json!({
        "command_id": "cmd_1",
        "command": "echo ok",
        "shell_name": null,
        "optimistic_timeout": 1
    }))
    .unwrap();
    let _: ExecuteAsyncRequest = serde_json::from_value(serde_json::json!({
        "command": "sleep 1",
        "shell_name": null,
        "attach_stdin": true
    }))
    .unwrap();
    let _: SendStdinRequest = serde_json::from_value(serde_json::json!({
        "content": "input\n"
    }))
    .unwrap();
    let _: WaitForExecutionStatusRequest = serde_json::from_value(serde_json::json!({
        "statuses": ["completed"],
        "timeout_seconds": 25
    }))
    .unwrap();

    let value = serde_json::to_value(DevboxListView {
        devboxes: vec![DevboxView {
            id: "dbx_test".into(),
            name: Some("local".into()),
            status: "running".into(),
            metadata: [("owner".into(), "test".into())].into(),
        }],
        has_more: false,
        total_count: Some(1),
    })
    .unwrap();
    assert_eq!(value["devboxes"][0]["id"], "dbx_test");

    let execution = serde_json::to_value(ExecutionView {
        id: "exec_test".into(),
        devbox_id: "dbx_test".into(),
        status: "completed".into(),
        exit_code: Some(0),
        stdout: "ok\n".into(),
        stderr: String::new(),
        error: None,
    })
    .unwrap();
    assert_eq!(execution["id"], "exec_test");

    let empty = serde_json::to_value(EmptyRecord {}).unwrap();
    assert_eq!(empty, serde_json::json!({}));
}
