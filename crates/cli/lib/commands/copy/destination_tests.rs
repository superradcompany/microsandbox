//! Regression tests for sandbox copies to relative host destinations.

use std::{env, fs, path::Path, process::Command, sync::Arc, time::Duration};

use futures::future::BoxFuture;
use microsandbox::{
    LocalBackend, MicrosandboxResult,
    agent::AgentClient,
    backend::{Backend, BackendKind, SandboxBackend, SnapshotBackend, VolumeBackend},
    sandbox::SandboxFsOps,
};
use microsandbox_protocol::{
    codec::{read_message, write_message},
    core::Ready,
    fs::{FsData, FsEntryInfo, FsOp, FsRequest, FsResponse, FsResponseData},
    message::{Message, MessageType},
};
use tokio::io::{AsyncWriteExt, DuplexStream, duplex};

use super::copy_sandbox_to_local;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const COPY_CONTENT: &[u8] = b"copied sandbox content\n";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Use the SDK's filesystem dispatch with an in-memory agent instead of a VM.
struct CopyBackend(LocalBackend);

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Backend for CopyBackend {
    fn kind(&self) -> BackendKind {
        BackendKind::Local
    }

    fn sandboxes(&self) -> &dyn SandboxBackend {
        &self.0
    }

    fn volumes(&self) -> &dyn VolumeBackend {
        &self.0
    }

    fn snapshots(&self) -> &dyn SnapshotBackend {
        &self.0
    }

    fn dial_agent<'a>(
        &'a self,
        _name: &'a str,
        timeout: Duration,
    ) -> BoxFuture<'a, MicrosandboxResult<AgentClient>> {
        Box::pin(async move {
            let (client, server) = duplex(8192);
            tokio::spawn(async move { serve_copy_fixture(server).await.unwrap() });

            Ok(AgentClient::connect_stream_with_timeout(client, timeout).await?)
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn serve_copy_fixture(mut stream: DuplexStream) -> anyhow::Result<()> {
    stream.write_all(&1u32.to_be_bytes()).await?;
    stream.write_all(&32u32.to_be_bytes()).await?;

    // Use the inline filesystem protocol so this fixture needs no bulk transport.
    let mut ready = Message::with_payload(MessageType::Ready, 0, &Ready::default())?;
    ready.v = 7;
    write_message(&mut stream, &ready).await?;

    while let Ok(message) = read_message(&mut stream).await {
        assert_eq!(message.t, MessageType::FsRequest);
        let request: FsRequest = message.payload()?;
        let data = match request.op {
            FsOp::Stat {
                path,
                follow_symlink,
            } => {
                assert!(!follow_symlink);
                Some(FsResponseData::Stat(fixture_entry(&path)))
            }
            FsOp::List { path } => {
                assert_eq!(path, "/fixture");
                Some(FsResponseData::List(vec![fixture_entry(
                    "/fixture/file.txt",
                )]))
            }
            FsOp::OpenFile { path, options } => {
                assert_eq!(path, "/fixture/file.txt");
                assert!(options.read);
                Some(FsResponseData::Handle(1))
            }
            FsOp::Read { handle, offset, .. } => {
                assert_eq!(handle, 1);
                assert_eq!(offset, 0);
                let data = FsData {
                    data: COPY_CONTENT.to_vec(),
                };
                let reply = Message::with_payload(MessageType::FsData, message.id, &data)?;
                write_message(&mut stream, &reply).await?;
                None
            }
            FsOp::CloseHandle { handle } => {
                assert_eq!(handle, 1);
                None
            }
            other => panic!("unexpected copy fixture operation: {other:?}"),
        };

        let response = FsResponse {
            ok: true,
            error: None,
            data,
        };
        let reply = Message::with_payload(MessageType::FsResponse, message.id, &response)?;
        write_message(&mut stream, &reply).await?;
    }

    Ok(())
}

fn fixture_entry(path: &str) -> FsEntryInfo {
    assert!(matches!(path, "/fixture" | "/fixture/file.txt"));
    let is_directory = path == "/fixture";

    FsEntryInfo {
        path: path.to_string(),
        kind: if is_directory { "dir" } else { "file" }.to_string(),
        size: if is_directory {
            0
        } else {
            COPY_CONTENT.len() as u64
        },
        mode: if is_directory { 0o755 } else { 0o644 },
        modified: None,
        uid: 0,
        gid: 0,
        atime: None,
        mtime: None,
    }
}

fn copy_in_subprocess(source: &str, destination: &str, expected_file: &str) {
    let temp = tempfile::tempdir().unwrap();
    let output = Command::new(env::current_exe().unwrap())
        .args([
            "--exact",
            "commands::copy::destination_tests::copy_destination_child",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("MSB_TEST_COPY_SOURCE", source)
        .env("MSB_TEST_COPY_DESTINATION", destination)
        .current_dir(temp.path())
        .output()
        .unwrap();

    assert!(
        output.status.success(),
        "copy {source} to {destination} failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let copied_file = temp.path().join(expected_file);
    assert!(fs::symlink_metadata(&copied_file).unwrap().is_file());
    assert_eq!(fs::read(copied_file).unwrap(), COPY_CONTENT);
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn copy_destination_bare_file_name() {
    copy_in_subprocess("/fixture/file.txt", "out.txt", "out.txt");
}

#[test]
fn copy_destination_bare_directory_name() {
    copy_in_subprocess("/fixture", "newdir", "newdir/file.txt");
}

#[test]
fn copy_destination_dot_file_name() {
    copy_in_subprocess("/fixture/file.txt", "./out.txt", "out.txt");
}

#[test]
fn copy_destination_dot_directory_name() {
    copy_in_subprocess("/fixture", "./newdir", "newdir/file.txt");
}

#[tokio::test]
async fn copy_destination_child() {
    let Ok(source) = env::var("MSB_TEST_COPY_SOURCE") else {
        return;
    };
    let destination = env::var("MSB_TEST_COPY_DESTINATION").unwrap();
    let cwd = env::current_dir().unwrap();
    let local = LocalBackend::builder()
        .config_path(cwd.join("config.json"))
        .home(cwd.join("home"))
        .build_lazy()
        .unwrap();
    let backend = Arc::new(CopyBackend(local));
    let fs = SandboxFsOps::with_backend(backend, "copy-fixture");

    copy_sandbox_to_local(&fs, &source, Path::new(&destination))
        .await
        .unwrap();
}
