use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode},
};
use microsandbox_api::{routes, state::ApiState};
use serde_json::json;
use tower::ServiceExt;

#[tokio::test]
async fn create_rejects_blueprint_id() {
    let app = routes::router(ApiState::default());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devboxes")
                .header("content-type", "application/json")
                .body(Body::from(json!({ "blueprint_id": "bp_1" }).to_string()))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "unsupported_field");
}

#[tokio::test]
async fn create_rejects_blueprint_name() {
    let app = routes::router(ApiState::default());
    let response = app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/v1/devboxes")
                .header("content-type", "application/json")
                .body(Body::from(
                    json!({ "blueprint_name": "python" }).to_string(),
                ))
                .unwrap(),
        )
        .await
        .unwrap();

    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    let body = to_bytes(response.into_body(), usize::MAX).await.unwrap();
    let value: serde_json::Value = serde_json::from_slice(&body).unwrap();
    assert_eq!(value["error"]["code"], "unsupported_field");
}
