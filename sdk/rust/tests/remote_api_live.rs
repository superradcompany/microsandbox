//! Opt-in, real-provider qualification. All mutations use unique disposable resources.
#![cfg(feature = "cloud")]

use microsandbox::sandbox::SandboxStatus;
use microsandbox::{
    Checkpoint, Context, MicrosandboxError, MicrosandboxResult, RemoteContext, Sandbox, Volume,
};
use serde_json::{Value, json};
use std::{
    fmt::Display,
    future::Future,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct Audit {
    rows: Vec<Value>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Audit {
    async fn check<T, E: Display>(
        &mut self,
        name: &str,
        future: impl Future<Output = Result<T, E>>,
    ) -> Option<T> {
        let result = tokio::time::timeout(Duration::from_secs(420), future).await;
        let (value, verdict, reason) = match result {
            Ok(Ok(value)) => {
                let expected_error = name.contains("missing")
                    || name.contains("cleanup_verified")
                    || name == "start_already_running";
                (
                    Some(value),
                    if expected_error { "FAIL" } else { "PASS" },
                    if expected_error {
                        "expected_rejection".to_string()
                    } else {
                        String::new()
                    },
                )
            }
            other => {
                let message = match other {
                    Ok(Err(e)) => e.to_string(),
                    _ => "audit timeout".into(),
                };
                let m = message.to_lowercase();
                let reason = if m.contains("untagged enum createrequest") {
                    "config_projection"
                } else if m.contains("unsupported")
                    || m.contains("not supported")
                    || m.contains("local-only")
                {
                    "unsupported"
                } else if m.contains("404") || m.contains("not found") {
                    "not_found"
                } else if m.contains("409") || m.contains("already running") {
                    "already_running"
                } else if m.contains("timeout") {
                    "timeout"
                } else {
                    "sdk_error"
                };
                let expected = (name.contains("missing") || name.contains("cleanup_verified"))
                    && reason == "not_found"
                    || name == "start_already_running" && reason == "already_running";
                let verdict = if reason == "unsupported" {
                    "UNSUPPORTED"
                } else if expected {
                    "PASS"
                } else {
                    "FAIL"
                };
                (None, verdict, reason.to_string())
            }
        };
        let row = json!({"feature":name,"verdict":verdict,"reason":reason});
        println!("{row}");
        self.rows.push(row);
        std::fs::write(
            std::env::var("MSB_AUDIT_REPORT").unwrap(),
            serde_json::to_vec_pretty(&json!({"sdk":"rust","rows":self.rows})).unwrap(),
        )
        .unwrap();
        value
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn verify(ok: bool) -> MicrosandboxResult<()> {
    if ok {
        Ok(())
    } else {
        Err(MicrosandboxError::InvalidConfig(
            "audit observation differed".into(),
        ))
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires MSB_REMOTE_AUDIT=1 and an authorized disposable remote account"]
async fn remote_api_live() {
    assert_eq!(std::env::var("MSB_REMOTE_AUDIT").as_deref(), Ok("1"));
    let mut a = Audit { rows: vec![] };
    let name = format!(
        "audit-rs-{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    std::fs::write(
        format!(
            "{}.resources.json",
            std::env::var("MSB_AUDIT_REPORT").unwrap()
        ),
        json!({"prefix":name}).to_string(),
    )
    .unwrap();
    let s = Sandbox::remote().unwrap();
    let v = Volume::remote().unwrap();
    let p = Checkpoint::remote().unwrap();
    let context = RemoteContext::from_env().unwrap();
    a.check("context_derivation", async {
        context.to_builder().build()?.sandboxes().list().await
    })
    .await;
    a.check("sandbox_list", s.list()).await;
    a.check("volume_list", v.list()).await;
    a.check("snapshot_list", p.list()).await;
    a.check("sandbox_missing", s.get(&format!("{name}-missing")))
        .await;
    a.check("volume_missing", v.get(&format!("{name}-missing")))
        .await;
    a.check("snapshot_missing", p.get(&format!("{name}-missing")))
        .await;
    a.check("volume_default", v.get_default()).await;
    let vol = a.check("volume_create", v.builder(&name).create()).await;
    if let Some(vol) = &vol {
        a.check("volume_info", vol.info()).await;
        let fs = vol.fs();
        a.check("volume_fs_mkdir", fs.mkdir("audit")).await;
        a.check("volume_fs_write_read", async {
            fs.write("audit/a", b"hello").await?;
            verify(fs.read("audit/a").await?.as_ref() == b"hello")
        })
        .await;
        a.check("volume_fs_stat", fs.stat("audit/a")).await;
        a.check("volume_fs_list", fs.list("audit")).await;
        a.check("volume_fs_exists", async {
            verify(fs.exists("audit/a").await? && !fs.exists("audit/missing").await?)
        })
        .await;
        a.check("volume_fs_copy", fs.copy("audit/a", "audit/b"))
            .await;
        a.check("volume_fs_rename", fs.rename("audit/b", "audit/c"))
            .await;
        a.check("volume_fs_large_stream", async {
            let data = vec![37u8; 2_100_000];
            let mut w = fs.write_stream("audit/stream").await?;
            w.write(&data).await?;
            w.close().await?;
            verify(
                fs.read_stream("audit/stream")
                    .await?
                    .collect()
                    .await?
                    .as_ref()
                    == data,
            )
        })
        .await;
        a.check("volume_fs_remove", async {
            fs.remove("audit/a").await?;
            fs.remove_dir("audit").await
        })
        .await;
    }
    let sb = a
        .check(
            "sandbox_create",
            s.builder(&name)
                .image("python")
                .env("AUDIT_ENV", "retained")
                .ephemeral(false)
                .create(),
        )
        .await;
    if let Some(sb) = &sb {
        a.check("sandbox_identity", async {
            verify(s.get(&name).await?.id() == sb.id() && !sb.owns_lifecycle())
        })
        .await;
        a.check("sandbox_info", sb.info()).await;
        a.check("sandbox_status", sb.status()).await;
        a.check("sandbox_config", sb.config()).await;
        a.check("failure_message", sb.last_failure_message()).await;
        a.check("get_running", s.get_running(&name)).await;
        a.check("ensure_running_repeat", async {
            sb.ensure_running().await?;
            sb.ensure_running().await
        })
        .await;
        a.check("exec", async {
            verify(
                sb.exec("printf", ["exec-ok"])
                    .await?
                    .stdout_bytes()
                    .as_ref()
                    == b"exec-ok",
            )
        })
        .await;
        a.check("shell", async {
            verify(
                sb.shell("printf \"$AUDIT_ENV\"")
                    .await?
                    .stdout_bytes()
                    .as_ref()
                    == b"retained",
            )
        })
        .await;
        a.check("exec_options", async {
            let out = sb
                .exec_with("/bin/sh", |e| {
                    e.args(["-c", "printf \"$OVERRIDE:$PWD\"; printf err >&2; exit 7"])
                        .cwd("/tmp")
                        .env("OVERRIDE", "set")
                })
                .await?;
            verify(
                out.status().code == 7
                    && out.stdout_bytes().as_ref() == b"set:/tmp"
                    && out.stderr_bytes().as_ref() == b"err",
            )
        })
        .await;
        a.check("exec_collect_repeat_wait", async {
            let mut e = sb.shell_stream("printf stream; exit 3").await?;
            let o = e.collect().await?;
            verify(
                o.stdout_bytes().as_ref() == b"stream"
                    && e.wait().await?.code == 3
                    && e.wait().await?.code == 3,
            )
        })
        .await;
        a.check("exec_recv_repeat_wait", async {
            let mut e = sb.shell_stream("printf event; exit 4").await?;
            while e.recv().await.is_some() {}
            verify(e.wait().await?.code == 4)
        })
        .await;
        a.check("exec_stdin", async {
            let mut e = sb.exec_stream_with("cat", |e| e.stdin_pipe()).await?;
            let w = e.take_stdin().unwrap();
            w.write(b"input").await?;
            w.close().await?;
            verify(e.collect().await?.stdout_bytes().as_ref() == b"input")
        })
        .await;
        a.check("exec_kill", async {
            let mut e = sb.exec_stream("sleep", ["60"]).await?;
            e.kill().await?;
            verify(e.wait().await?.code != 0)
        })
        .await;
        a.check("exec_signal", async {
            let mut e = sb.exec_stream("sleep", ["60"]).await?;
            e.signal(15).await?;
            verify(e.wait().await?.code != 0)
        })
        .await;
        a.check("exec_pty_resize", async {
            let mut e = sb
                .exec_stream_with("/bin/sh", |e| {
                    e.args(["-c", "sleep 1; stty size"]).tty(true)
                })
                .await?;
            e.resize(35, 95).await?;
            verify(String::from_utf8_lossy(e.collect().await?.stdout_bytes()).contains("35 95"))
        })
        .await;
        let fs = sb.fs();
        a.check("sandbox_fs_mkdir", fs.mkdir("/tmp/audit")).await;
        a.check("sandbox_fs_write_read", async {
            fs.write("/tmp/audit/a", b"hello").await?;
            verify(fs.read("/tmp/audit/a").await?.as_ref() == b"hello")
        })
        .await;
        a.check("sandbox_fs_stat", fs.stat("/tmp/audit/a")).await;
        a.check("sandbox_fs_list", fs.list("/tmp/audit")).await;
        a.check("sandbox_fs_exists", async {
            verify(fs.exists("/tmp/audit/a").await? && !fs.exists("/tmp/audit/missing").await?)
        })
        .await;
        a.check("sandbox_fs_copy", fs.copy("/tmp/audit/a", "/tmp/audit/b"))
            .await;
        a.check(
            "sandbox_fs_rename",
            fs.rename("/tmp/audit/b", "/tmp/audit/c"),
        )
        .await;
        a.check(
            "sandbox_fs_symlink",
            fs.symlink("/tmp/audit/a", "/tmp/audit/link"),
        )
        .await;
        a.check("sandbox_fs_readlink", fs.read_link("/tmp/audit/link"))
            .await;
        a.check("sandbox_fs_realpath", fs.real_path("/tmp/audit/link"))
            .await;
        a.check("sandbox_fs_open_dir", async {
            let handle = fs.open_dir("/tmp/audit").await?;
            fs.close_handle(handle).await
        })
        .await;
        a.check("sandbox_fs_large_stream", async {
            let data = vec![37u8; 2_100_000];
            let w = fs.write_stream("/tmp/audit/stream").await?;
            for chunk in data.chunks(65536) {
                w.write(chunk).await?;
            }
            w.close().await?;
            verify(
                fs.read_stream("/tmp/audit/stream")
                    .await?
                    .collect()
                    .await?
                    .as_ref()
                    == data,
            )
        })
        .await;
        a.check("sandbox_fs_remove", async {
            fs.remove("/tmp/audit/a").await?;
            fs.remove_dir("/tmp/audit").await
        })
        .await;
        a.check("ping", sb.ping()).await;
        a.check("touch", sb.touch()).await;
        a.check("metrics", sb.metrics()).await;
        a.check("logs", sb.logs(&Default::default())).await;
        a.check("jobs_list", sb.list_jobs()).await;
        a.check("job_create", sb.exec_detached("printf", ["job"]))
            .await;
        a.check("pause", sb.pause()).await;
        a.check("resume", sb.resume()).await;
        a.check("request_kill", sb.request_kill()).await;
        a.check("request_drain", sb.request_drain()).await;
        a.check("detach", sb.detach()).await;
        a.check("stop", sb.stop()).await;
        a.check("wait_status", sb.wait_for_status(SandboxStatus::Stopped))
            .await;
        a.check("wait_stopped", sb.wait_until_stopped()).await;
        let snap = a
            .check(
                "snapshot_create",
                p.builder(&name).from_sandbox(&name).create(),
            )
            .await;
        if let Some(snap) = &snap {
            a.check("snapshot_get", p.open_ref(snap.reference())).await;
            a.check("snapshot_manifest", snap.manifest()).await;
            a.check("snapshot_state", snap.state()).await;
            a.check("snapshot_verify", snap.verify()).await;
            let restored = a
                .check(
                    "snapshot_restore",
                    s.restore_ref(snap.reference())
                        .name(format!("{name}-restore"))
                        .restore(),
                )
                .await;
            if let Some(restored) = restored {
                a.check("restored_exec", restored.shell("printf restored"))
                    .await;
                a.check("restore_cleanup", restored.destroy()).await;
            }
            a.check("snapshot_cleanup", snap.destroy(false)).await;
            a.check("snapshot_cleanup_verified", p.open_ref(snap.reference()))
                .await;
        }
        a.check("start", s.start(&name)).await;
        a.check("start_already_running", s.start(&name)).await;
        a.check("restart", sb.restart()).await;
        a.check("kill", sb.kill()).await;
        a.check("stop_again", sb.stop()).await;
        a.check("automatic_start", sb.shell("printf restarted"))
            .await;
        a.check("sandbox_cleanup", sb.destroy()).await;
    }
    if let Some(vol) = vol {
        a.check("volume_cleanup", vol.destroy()).await;
    }
    a.check("sandbox_cleanup_verified", s.get(&name)).await;
    a.check("volume_cleanup_verified", v.get(&name)).await;
    assert!(
        !a.rows.iter().any(|r| r["verdict"] == "FAIL"),
        "remote qualification found failures; see redacted report"
    );
}

#[tokio::test]
#[ignore = "requires MSB_REMOTE_AUDIT=1 and an authorized disposable remote account"]
async fn remote_transport_probe() {
    assert_eq!(std::env::var("MSB_REMOTE_AUDIT").as_deref(), Ok("1"));
    let mut a = Audit { rows: vec![] };
    let name = format!(
        "audit-transport-{:x}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_millis()
    );
    std::fs::write(
        format!(
            "{}.resources.json",
            std::env::var("MSB_AUDIT_REPORT").unwrap()
        ),
        json!({"prefix":name}).to_string(),
    )
    .unwrap();
    let remote = RemoteContext::from_env().unwrap();
    if let Some(sb) = a
        .check(
            "sandbox_create",
            remote
                .sandboxes()
                .builder(&name)
                .image("python")
                .ephemeral(false)
                .create(),
        )
        .await
    {
        if let Some(client) = a
            .check(
                "agent_handshake",
                remote.dial_agent(&name, Duration::from_secs(20)),
            )
            .await
        {
            a.rows.push(json!({"feature":"agent_version","verdict":"OBSERVED","protocol":client.negotiated_version(),"version":client.agent_version()}));
        }
        let fs = sb.fs();
        for size in [2_000_000, 2_097_000, 2_097_152, 2_100_000, 3_000_000] {
            let path = format!("/tmp/size-{size}");
            let data = vec![37u8; size];
            a.check(&format!("direct_write_{size}"), fs.write(&path, &data))
                .await;
            a.check(&format!("direct_read_{size}"), async {
                verify(fs.read(&path).await?.as_ref() == data)
            })
            .await;
        }
        a.check("sandbox_cleanup", sb.destroy()).await;
        a.check("cleanup_verified", remote.sandboxes().get(&name))
            .await;
    }
    assert!(
        !a.rows.iter().any(|r| r["verdict"] == "FAIL"),
        "transport qualification found failures"
    );
}

/// Read/execute the exact cross-SDK inspection fixture. Setup and cleanup are
/// owned by inspection.mjs, so this probe cannot delete another SDK's fixture.
#[tokio::test]
#[ignore = "requires explicit staging opt-in and a disposable shared fixture"]
async fn remote_inspection_live() -> MicrosandboxResult<()> {
    assert_eq!(std::env::var("MSB_REMOTE_AUDIT").as_deref(), Ok("1"));
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("MSB_INSPECTION_FIXTURE").unwrap()).unwrap(),
    )
    .unwrap();
    let name = fixture["name"].as_str().unwrap();
    let context = RemoteContext::from_env()?;
    let sb = context.sandboxes().get(name).await?;
    assert_eq!(sb.id().as_str(), fixture["id"].as_str().unwrap());
    let mut cursor = None;
    let listed = loop {
        let page = context
            .sandboxes()
            .list_with(|mut b| {
                if let Some(c) = cursor.take() {
                    b = b.cursor(c);
                }
                b
            })
            .await?;
        if let Some(found) = page.sandboxes.into_iter().find(|s| s.id() == sb.id()) {
            break found;
        }
        cursor = page.next_cursor;
        assert!(cursor.is_some(), "fixture not listed");
    };
    let mut rows = vec![];
    for (kind, resource) in [("get", sb), ("list", listed)] {
        let config = resource.config().await?;
        assert!(config.remote_spec().is_some());
        assert_eq!(config.runtime().shell.as_deref(), Some("/bin/bash"));
        assert_eq!(config.runtime().workdir.as_deref(), Some("/tmp"));
        assert!(config.unavailable.contains(&"init".to_string()));
        rows.push(json!({"feature":format!("{kind}_config"),"verdict":"PASS"}));
        assert_eq!(
            resource
                .shell("test -n \"$BASH_VERSION\" && printf bash")
                .await?
                .stdout()
                .unwrap(),
            "bash"
        );
        rows.push(json!({"feature":format!("{kind}_shell"),"verdict":"PASS"}));
        assert_eq!(
            resource.exec_default().await?.stdout().unwrap(),
            "configured-default"
        );
        rows.push(json!({"feature":format!("{kind}_default_command"),"verdict":"PASS"}));
        assert_eq!(
            resource
                .exec("pwd", std::iter::empty::<&str>())
                .await?
                .stdout()
                .unwrap()
                .trim(),
            "/tmp"
        );
        rows.push(json!({"feature":format!("{kind}_workdir"),"verdict":"PASS"}));
    }
    std::fs::write(
        std::env::var("MSB_AUDIT_REPORT").unwrap(),
        serde_json::to_vec_pretty(&json!({"sdk":"rust","rows":rows})).unwrap(),
    )
    .unwrap();
    Ok(())
}

/// Destructive qualification is separate from the shared, read/execute probe.
/// Only the explicitly recorded fixture may be removed.
#[tokio::test]
#[ignore = "requires staging opt-in and exclusive ownership of the recorded fixture"]
async fn remote_cleanup_live() -> MicrosandboxResult<()> {
    assert_eq!(std::env::var("MSB_REMOTE_AUDIT").as_deref(), Ok("1"));
    let fixture: Value = serde_json::from_slice(
        &std::fs::read(std::env::var("MSB_INSPECTION_FIXTURE").unwrap()).unwrap(),
    )
    .unwrap();
    let name = fixture["name"].as_str().unwrap();
    let context = RemoteContext::from_env()?;
    let sandbox = context.sandboxes().get(name).await?;
    assert_eq!(sandbox.id().as_str(), fixture["id"].as_str().unwrap());
    sandbox.shell("printf ready").await?;
    sandbox.destroy().await?;
    assert!(matches!(
        context.sandboxes().get(name).await,
        Err(MicrosandboxError::SandboxNotFound(_))
    ));
    std::fs::write(
        std::env::var("MSB_AUDIT_REPORT").unwrap(),
        serde_json::to_vec_pretty(&json!({"sdk":"rust","rows":[
            {"feature":"destroy","verdict":"PASS"},
            {"feature":"destroy_absent","verdict":"PASS"}
        ]}))
        .unwrap(),
    )
    .unwrap();
    Ok(())
}
