//! Real-runtime qualification of helpers retaining their original owned run.

use std::time::Duration;

use microsandbox::Sandbox;
use microsandbox::sandbox::{SandboxStatus, fs::FsOpenOptions};
use test_utils::msb_test;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn create(name: &str) -> Sandbox {
    Sandbox::builder(name)
        .image("alpine")
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .expect("create disposable sandbox")
}

async fn await_stopped(observer: &Sandbox) {
    // Final-owner fallback preserves the platform's watchdog/job behavior. Windows job
    // termination can report Crashed; it must still complete and release the active run.
    tokio::time::timeout(Duration::from_secs(20), observer.wait_until_stopped())
        .await
        .expect("last helper did not release the run")
        .expect("observe shutdown");
    observer.destroy().await.expect("remove stopped fixture");
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn open_file_retains_run_until_explicit_close() {
    let owner = create("retained-file-owner").await;
    owner.fs().write("/tmp/marker", b"original").await.unwrap();
    let observer = Sandbox::get(owner.name()).await.unwrap();
    let file = owner
        .fs()
        .open_file(
            "/tmp/marker",
            FsOpenOptions {
                read: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    drop(owner);
    assert_eq!(observer.status().await.unwrap(), SandboxStatus::Running);
    assert_eq!(&file.read(0, None).await.unwrap()[..], b"original");
    file.close().await.unwrap();
    await_stopped(&observer).await;
}

#[msb_test]
async fn stale_file_cannot_read_or_write_a_restarted_run() {
    let owner = create("retained-file-restart").await;
    owner.fs().write("/tmp/marker", b"old").await.unwrap();
    let file = owner
        .fs()
        .open_file(
            "/tmp/marker",
            FsOpenOptions {
                read: true,
                write: true,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    owner.stop().await.unwrap();
    let restarted = Sandbox::start(owner.name()).await.unwrap();
    restarted.fs().write("/tmp/marker", b"new").await.unwrap();
    assert!(file.read(0, None).await.is_err());
    assert!(file.write(0, b"bad").await.is_err());
    // Closing a stale connection can fail, but may never close the new run's file.
    let _ = file.close().await;
    drop(owner);
    assert_eq!(
        restarted.fs().read("/tmp/marker").await.unwrap(),
        b"new".as_slice()
    );
    assert_eq!(restarted.status().await.unwrap(), SandboxStatus::Running);
    restarted.destroy().await.unwrap();
}

#[cfg(feature = "ssh")]
#[msb_test]
async fn open_ssh_client_retains_run_until_close() {
    let owner = create("retained-ssh-owner").await;
    let observer = Sandbox::get(owner.name()).await.unwrap();
    let client = owner.ssh().open_client().await.unwrap();
    drop(owner);
    assert_eq!(observer.status().await.unwrap(), SandboxStatus::Running);
    let output = client.exec("printf retained").await.unwrap();
    assert_eq!(output.status, 0);
    assert_eq!(output.stdout.as_ref(), b"retained");
    client.close().await.unwrap();
    await_stopped(&observer).await;
}
