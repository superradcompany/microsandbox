use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use microsandbox_api::{routes, state::ApiState};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn unsupported_api_routes_return_not_implemented() {
    let app = routes::router(ApiState::for_test().await.unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devboxes/dbx_missing/pty_sessions")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "unsupported_locally");
}

#[tokio::test]
async fn wait_for_status_rejects_empty_statuses_without_vm() {
    let app = routes::router(ApiState::for_test().await.unwrap());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devboxes/dbx_missing/wait_for_status")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "statuses": [] }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn write_file_contents_rejects_large_contents_without_vm() {
    let app = routes::router(ApiState::for_test().await.unwrap());
    let contents = "x".repeat(10 * 1024 * 1024 + 1);
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devboxes/dbx_missing/write_file_contents")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "file_path": "/tmp/large.txt", "contents": contents }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "size_limit_exceeded");
}

#[tokio::test]
async fn upload_file_requires_path_without_vm() {
    let app = routes::router(ApiState::for_test().await.unwrap());
    let boundary = "microsandbox-boundary";
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"file\"; filename=\"hello.txt\"\r\n\
         Content-Type: application/octet-stream\r\n\r\n\
         hello\r\n\
         --{boundary}--\r\n"
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devboxes/dbx_missing/upload_file")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "invalid_request");
}

#[tokio::test]
async fn upload_file_requires_file_without_vm() {
    let app = routes::router(ApiState::for_test().await.unwrap());
    let boundary = "microsandbox-boundary";
    let body = format!(
        "--{boundary}\r\n\
         Content-Disposition: form-data; name=\"path\"\r\n\r\n\
         /tmp/hello.txt\r\n\
         --{boundary}--\r\n"
    );

    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devboxes/dbx_missing/upload_file")
                .header(
                    "content-type",
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "invalid_request");
}
