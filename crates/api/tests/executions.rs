use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use microsandbox_api::{
    dto::ExecutionView,
    routes,
    state::ApiState,
    store::{ExecutionInsert, ExecutionStatus},
};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn execute_rejects_shell_name() {
    let app = routes::router(ApiState::for_test().await.unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devboxes/dbx_1/execute")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "command": "pwd", "shell_name": "main" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn execute_async_rejects_shell_name() {
    let app = routes::router(ApiState::for_test().await.unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devboxes/dbx_1/execute_async")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "command": "pwd", "shell_name": "main" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn execute_missing_devbox_does_not_persist_execution() {
    let state = ApiState::for_test().await.unwrap();
    let app = routes::router(state.clone());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devboxes/dbx_missing/execute")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "command_id": "exec_missing", "command": "pwd" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_FOUND);
    let row = state
        .store
        .get("dbx_missing", "exec_missing")
        .await
        .unwrap();
    assert!(row.is_none());
}

#[tokio::test]
async fn get_execution_returns_persisted_row() {
    let state = ApiState::for_test().await.unwrap();
    state
        .store
        .insert(ExecutionInsert {
            devbox_id: "dbx_1".into(),
            execution_id: "exec_1".into(),
            command: "echo hello".into(),
            stdin_attached: false,
        })
        .await
        .unwrap();
    state.store.mark_running("dbx_1", "exec_1").await.unwrap();
    state
        .store
        .append_output("dbx_1", "exec_1", b"hello\n", b"")
        .await
        .unwrap();
    state
        .store
        .mark_completed("dbx_1", "exec_1", 0)
        .await
        .unwrap();

    let app = routes::router(state);
    let response = app
        .oneshot(
            Request::builder()
                .uri("/v1/devboxes/dbx_1/executions/exec_1")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: ExecutionView = serde_json::from_slice(&body).unwrap();
    assert_eq!(value.id, "exec_1");
    assert_eq!(value.devbox_id, "dbx_1");
    assert_eq!(value.status, ExecutionStatus::Completed.as_str());
    assert_eq!(value.exit_code, Some(0));
    assert_eq!(value.stdout, "hello\n");
    assert_eq!(value.stderr, "");
}

#[tokio::test]
async fn wait_for_status_rejects_empty_statuses_without_vm() {
    let app = routes::router(ApiState::for_test().await.unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devboxes/dbx_1/executions/exec_1/wait_for_status")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "statuses": [] }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
}
