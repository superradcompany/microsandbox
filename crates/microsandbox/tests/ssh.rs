#![cfg(feature = "ssh")]

//! Integration tests for SSH client/server behavior.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo test -p microsandbox --features ssh --test ssh -- --ignored

use std::io::SeekFrom;

use microsandbox::Sandbox;
use russh_sftp::protocol::{FileAttributes, OpenFlags};
use test_utils::msb_test;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn ssh_exec_preserves_status_stdout_and_stderr() {
    let name = "ssh-exec-status-streams";
    let sandbox = create_sandbox(name).await;
    let ssh = sandbox
        .ssh()
        .open_client()
        .await
        .expect("connect SSH client");

    let output = ssh
        .exec("printf 'stdout:%s\\n' ok; printf 'stderr:%s\\n' bad >&2; exit 17")
        .await
        .expect("run SSH exec");

    ssh.close().await.expect("close SSH client");
    cleanup(sandbox, name).await;

    assert_eq!(output.status, 17);
    assert_eq!(String::from_utf8_lossy(&output.stdout), "stdout:ok\n");
    assert_eq!(String::from_utf8_lossy(&output.stderr), "stderr:bad\n");
}

#[msb_test]
async fn ssh_exec_with_pty_merges_stderr_into_stdout() {
    let name = "ssh-exec-pty";
    let sandbox = create_sandbox(name).await;
    let ssh = sandbox
        .ssh()
        .open_client()
        .await
        .expect("connect SSH client");

    let output = ssh
        .exec_with("printf 'out'; printf 'err' >&2", |exec| exec.tty(true))
        .await
        .expect("run SSH exec with PTY");

    ssh.close().await.expect("close SSH client");
    cleanup(sandbox, name).await;

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert_eq!(output.status, 0);
    assert!(stdout.contains("out"), "stdout was {stdout:?}");
    assert!(stdout.contains("err"), "stdout was {stdout:?}");
    assert!(
        output.stderr.is_empty(),
        "PTY stderr should be merged into stdout, got {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[msb_test]
async fn ssh_sftp_exercises_handles_offsets_metadata_and_links() {
    let name = "ssh-sftp-roundtrip";
    let sandbox = create_sandbox(name).await;
    let ssh = sandbox
        .ssh()
        .open_client()
        .await
        .expect("connect SSH client");
    let sftp = ssh.sftp().await.expect("open SFTP session");

    let dir = "/tmp/msb-ssh-sftp";
    let file_path = format!("{dir}/payload.txt");
    let renamed_path = format!("{dir}/renamed.txt");
    let link_path = format!("{dir}/payload.link");

    sftp.create_dir(dir).await.expect("create SFTP dir");

    let mut attrs = FileAttributes::default();
    attrs.permissions = Some(0o600);
    let mut file = sftp
        .open_with_flags_and_attributes(
            &file_path,
            OpenFlags::CREATE | OpenFlags::WRITE | OpenFlags::TRUNCATE,
            attrs,
        )
        .await
        .expect("open SFTP file");
    file.write_all(b"alpha------omega")
        .await
        .expect("initial SFTP write");
    file.seek(SeekFrom::Start(5))
        .await
        .expect("seek SFTP handle");
    file.write_all(b":ssh:").await.expect("offset SFTP write");
    file.shutdown().await.expect("close SFTP file handle");

    let data = sftp.read(&file_path).await.expect("read SFTP file");
    assert_eq!(data, b"alpha:ssh:-omega");

    let mut metadata = sftp.metadata(&file_path).await.expect("stat SFTP file");
    metadata.permissions = Some(0o640);
    sftp.set_metadata(&file_path, metadata)
        .await
        .expect("set SFTP metadata");
    let metadata = sftp
        .metadata(&file_path)
        .await
        .expect("stat SFTP file after chmod");
    assert_eq!(metadata.permissions.map(|mode| mode & 0o777), Some(0o640));

    sftp.symlink("payload.txt", &link_path)
        .await
        .expect("create SFTP symlink");
    let target = sftp.read_link(&link_path).await.expect("read SFTP symlink");
    assert_eq!(target, "payload.txt");

    sftp.rename(&file_path, &renamed_path)
        .await
        .expect("rename SFTP file");
    assert!(
        sftp.try_exists(&renamed_path)
            .await
            .expect("check renamed file exists")
    );
    assert!(
        !sftp
            .try_exists(&file_path)
            .await
            .expect("check old file is gone")
    );

    let mut entries = sftp
        .read_dir(dir)
        .await
        .expect("list SFTP dir")
        .map(|entry| entry.file_name().to_string())
        .collect::<Vec<_>>();
    entries.sort();
    assert_eq!(entries, vec!["payload.link", "renamed.txt"]);

    sftp.remove_file(&renamed_path)
        .await
        .expect("remove SFTP file");
    sftp.remove_file(&link_path)
        .await
        .expect("remove SFTP symlink");
    sftp.remove_dir(dir).await.expect("remove SFTP dir");

    sftp.close().await.expect("close SFTP session");
    ssh.close().await.expect("close SSH client");
    cleanup(sandbox, name).await;
}

#[msb_test]
async fn ssh_attach_interactive_shell_accepts_tty_input() {
    if std::env::var_os("MSB_SSH_INTERACTIVE_TEST").is_none() {
        eprintln!("skipping interactive SSH attach test; set MSB_SSH_INTERACTIVE_TEST=1");
        return;
    }

    let name = "ssh-attach-interactive";
    let sandbox = create_sandbox(name).await;
    let ssh = sandbox
        .ssh()
        .open_client()
        .await
        .expect("connect SSH client");

    let code = ssh.attach().await.expect("attach SSH shell");

    ssh.close().await.expect("close SSH client");
    cleanup(sandbox, name).await;

    assert_eq!(code, 0);
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn create_sandbox(name: &str) -> Sandbox {
    Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await
        .expect("create sandbox")
}

async fn cleanup(sandbox: Sandbox, name: &str) {
    drop(sandbox);
    let handle = Sandbox::get(name).await.expect("get sandbox");
    handle.stop().await.expect("stop sandbox");
    Sandbox::remove(name).await.expect("remove sandbox");
}
