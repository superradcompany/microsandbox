use std::collections::HashMap;

use microsandbox_api::dto::{DevboxListView, DevboxView, ExecutionView};
use serde_json::json;

#[test]
fn devbox_view_matches_runloop_shape() {
    let value = serde_json::to_value(DevboxView {
        id: "dbx_123".into(),
        name: Some("worker".into()),
        status: "running".into(),
        metadata: HashMap::new(),
    })
    .unwrap();

    assert_eq!(value["id"], "dbx_123");
    assert_eq!(value["name"], "worker");
    assert_eq!(value["status"], "running");
    assert!(value["metadata"].is_object());
}

#[test]
fn devbox_list_view_matches_runloop_shape() {
    let value = serde_json::to_value(DevboxListView {
        devboxes: vec![],
        has_more: false,
        total_count: Some(0),
    })
    .unwrap();

    assert_eq!(
        value,
        json!({ "devboxes": [], "has_more": false, "total_count": 0 })
    );
}

#[test]
fn execution_view_matches_runloop_core_shape() {
    let value = serde_json::to_value(ExecutionView {
        id: "exec_123".into(),
        devbox_id: "dbx_123".into(),
        status: "completed".into(),
        exit_code: Some(0),
        stdout: "ok\n".into(),
        stderr: String::new(),
        error: None,
    })
    .unwrap();

    assert_eq!(value["id"], "exec_123");
    assert_eq!(value["devbox_id"], "dbx_123");
    assert_eq!(value["status"], "completed");
    assert_eq!(value["exit_code"], 0);
}
