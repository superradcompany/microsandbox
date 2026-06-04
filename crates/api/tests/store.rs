use microsandbox_api::store::{ExecutionInsert, ExecutionStatus, ExecutionStore};

#[tokio::test]
async fn execution_store_creates_parent_directories() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("nested").join("api.sqlite");

    ExecutionStore::open(&path).await.unwrap();

    assert!(path.exists());
}

#[tokio::test]
async fn execution_store_persists_and_updates_execution() {
    let dir = tempfile::tempdir().unwrap();
    let store = ExecutionStore::open(dir.path().join("api.sqlite"))
        .await
        .unwrap();

    store
        .insert(ExecutionInsert {
            devbox_id: "dbx_test".into(),
            execution_id: "exec_test".into(),
            command: "echo hello".into(),
            stdin_attached: false,
        })
        .await
        .unwrap();

    store.mark_running("dbx_test", "exec_test").await.unwrap();
    store
        .append_output("dbx_test", "exec_test", b"hello\n", b"")
        .await
        .unwrap();
    store
        .mark_completed("dbx_test", "exec_test", 0)
        .await
        .unwrap();

    let execution = store.get("dbx_test", "exec_test").await.unwrap().unwrap();

    assert_eq!(execution.status, ExecutionStatus::Completed);
    assert_eq!(execution.exit_code, Some(0));
    assert_eq!(execution.stdout, "hello\n");
}

#[tokio::test]
async fn startup_reconciliation_marks_queued_and_running_executions_failed() {
    let dir = tempfile::tempdir().unwrap();
    let store = ExecutionStore::open(dir.path().join("api.sqlite"))
        .await
        .unwrap();

    store
        .insert(ExecutionInsert {
            devbox_id: "dbx_test".into(),
            execution_id: "exec_queued".into(),
            command: "echo queued".into(),
            stdin_attached: false,
        })
        .await
        .unwrap();
    store
        .insert(ExecutionInsert {
            devbox_id: "dbx_test".into(),
            execution_id: "exec_running".into(),
            command: "sleep 60".into(),
            stdin_attached: false,
        })
        .await
        .unwrap();
    store
        .mark_running("dbx_test", "exec_running")
        .await
        .unwrap();

    let count = store.reconcile_incomplete_on_startup().await.unwrap();
    let queued = store.get("dbx_test", "exec_queued").await.unwrap().unwrap();
    let running = store
        .get("dbx_test", "exec_running")
        .await
        .unwrap()
        .unwrap();

    assert_eq!(count, 2);
    assert_eq!(queued.status, ExecutionStatus::Failed);
    assert_eq!(running.status, ExecutionStatus::Failed);
    assert!(queued.error.unwrap().contains("API server restarted"));
    assert!(running.error.unwrap().contains("API server restarted"));
}

#[tokio::test]
async fn execution_store_keeps_newest_output_after_cap() {
    let dir = tempfile::tempdir().unwrap();
    let store = ExecutionStore::open(dir.path().join("api.sqlite"))
        .await
        .unwrap();

    store
        .insert(ExecutionInsert {
            devbox_id: "dbx_test".into(),
            execution_id: "exec_test".into(),
            command: "yes".into(),
            stdin_attached: false,
        })
        .await
        .unwrap();

    store
        .append_output(
            "dbx_test",
            "exec_test",
            vec![b'a'; 1024 * 1024].as_slice(),
            b"",
        )
        .await
        .unwrap();
    store
        .append_output("dbx_test", "exec_test", b"tail", b"")
        .await
        .unwrap();

    let execution = store.get("dbx_test", "exec_test").await.unwrap().unwrap();

    assert_eq!(execution.stdout.len(), 1024 * 1024);
    assert!(execution.stdout.ends_with("tail"));
    assert!(execution.stdout_truncated);
}
