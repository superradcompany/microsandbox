//! Opt-in end-to-end checks against an already-running disposable sandbox.
//! Set MSB_JOB_TEST_SANDBOX and the normal MSB_HOME/runtime overrides explicitly.
//! Run serially, without other suites using the VM: the resource tests fill its job capacity.
//! Saturated-input checks cover control delivery through the shared foreground/job transport.

use std::time::Duration;

use futures::StreamExt;
use microsandbox::{
    Sandbox,
    jobs::{JobEvent, JobLogOptions, JobReplay, JobState},
};

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
#[ignore = "requires a running disposable VM and MSB_JOB_TEST_SANDBOX"]
async fn managed_job_control_survives_resident_pause() -> Result<(), Box<dyn std::error::Error>> {
    let name = std::env::var("MSB_JOB_TEST_SANDBOX")?;
    let sandbox = Sandbox::get(&name).await?.connect().await?;
    let job = sandbox
        .exec_detached("cat", std::iter::empty::<String>())
        .await?;
    let mut waiting = Box::pin(job.wait());
    assert!(
        tokio::time::timeout(Duration::from_millis(100), &mut waiting)
            .await
            .is_err()
    );
    sandbox.pause().await?;

    let outcome = async {
        // A waiter already polling and a newly discovered handle must both retain the live owner.
        assert_eq!(job.inspect().await?.state, JobState::Running);
        let fresh = Sandbox::get(&name)
            .await?
            .get_job(job.id().as_ref())
            .await?;
        assert_eq!(fresh.inspect().await?.state, JobState::Running);
        assert!(
            sandbox
                .list_jobs()
                .await?
                .items
                .iter()
                .any(|info| &info.id == job.id())
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(300), &mut waiting)
                .await
                .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(300), fresh.wait())
                .await
                .is_err()
        );
        Ok::<_, Box<dyn std::error::Error>>(())
    }
    .await;
    sandbox.resume().await?;
    job.eof().await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), &mut waiting)
            .await??
            .success
    );
    outcome?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a running disposable VM and MSB_JOB_TEST_SANDBOX"]
async fn managed_job_lifetime_io_and_deadlines() -> Result<(), Box<dyn std::error::Error>> {
    let name = std::env::var("MSB_JOB_TEST_SANDBOX")?;
    let sandbox = Sandbox::get(&name).await?.connect().await?;
    let job = sandbox
        .exec_detached("cat", std::iter::empty::<String>())
        .await?;
    assert_eq!(job.inspect().await?.state, JobState::Running);
    // Every observer shares the backend's control connection with the input owner. Overlapping
    // control replies and cancelled polls must not exhaust reply capacity or close that session.
    let observers =
        futures::future::try_join_all((0..12).map(|_| job.attach_with(|b| b.read_only(true))))
            .await?;
    let input = job.attach().await?;
    for _ in 0..8 {
        let receiving =
            futures::future::try_join_all(observers.iter().map(|observer| observer.recv()));
        let writing = input.write_stdin(b"concurrent\n");
        let (events, ()) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::try_join!(receiving, writing)
        })
        .await??;
        assert!(
            events
                .iter()
                .all(|event| matches!(event, Some(JobEvent::Output(_))))
        );
    }
    for observer in observers {
        observer.detach().await?;
    }
    input.detach().await?;
    job.kill().await?;
    job.wait().await?;
    let job = sandbox
        .exec_detached("cat", std::iter::empty::<String>())
        .await?;
    let id = job.id().to_string();
    let first = job.attach().await?;
    assert_eq!(job.attach().await.err().unwrap().code(), "input_busy");
    let observer = job.attach_with(|b| b.read_only(true)).await?;
    assert_eq!(
        observer.write_stdin(b"denied").await.unwrap_err().code(),
        "read_only"
    );
    first.write_stdin(b"before detach\n").await?;
    let event = tokio::time::timeout(Duration::from_secs(5), first.recv()).await??;
    let cursor = match event {
        Some(JobEvent::Output(entry)) => {
            assert_eq!(entry.data.as_ref(), b"before detach\n");
            entry.cursor
        }
        other => panic!("unexpected cat output: {other:?}"),
    };
    first.detach().await?;
    observer.detach().await?;
    drop(first);
    drop(job);
    let job = sandbox.get_job(&id).await?;
    let second = job
        .attach_with(|b| b.replay(JobReplay::After(cursor)))
        .await?;
    second.write_stdin(b"after reattach\n").await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), job.wait())
            .await
            .is_err()
    );
    assert_eq!(job.inspect().await?.state, JobState::Running);
    job.eof().await?;
    assert_eq!(
        second.write_stdin(b"late").await.unwrap_err().code(),
        "stdin_closed"
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(5), job.wait())
            .await??
            .success
    );
    let logs = job.logs(&JobLogOptions::default()).await?;
    let bytes: Vec<_> = logs
        .into_iter()
        .flat_map(|entry| entry.data.to_vec())
        .collect();
    assert_eq!(bytes, b"before detach\nafter reattach\n");
    second.detach().await?;

    let finite = sandbox
        .exec_detached_with("cat", |b| b.stdin_bytes(vec![0, 255, 128, 10]))
        .await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), finite.wait())
            .await??
            .success
    );
    let bytes: Vec<_> = finite
        .logs(&JobLogOptions::default())
        .await?
        .into_iter()
        .flat_map(|entry| entry.data.to_vec())
        .collect();
    assert_eq!(bytes, [0, 255, 128, 10]);

    let deadline = sandbox
        .exec_detached_with("sleep", |b| {
            b.args(["30"]).timeout(Duration::from_millis(100))
        })
        .await?;
    let result = tokio::time::timeout(Duration::from_secs(5), deadline.wait()).await??;
    assert!(result.timed_out);
    assert!(!result.success);

    let tty = sandbox.exec_detached_with("sh", |b| b.tty(true)).await?;
    let attachment = tty.attach().await?;
    attachment.resize(40, 120).await?;
    assert_eq!(tty.eof().await.unwrap_err().code(), "invalid_options");
    attachment.write_stdin(b"echo tty-marker; exit 0\n").await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), tty.wait())
            .await??
            .success
    );
    attachment.detach().await?;
    let tty_output = tty.logs(&JobLogOptions::default()).await?;
    assert!(
        tty_output
            .iter()
            .any(|entry| String::from_utf8_lossy(&entry.data).contains("tty-marker"))
    );

    let quick = sandbox
        .exec_detached("true", std::iter::empty::<String>())
        .await?;
    quick.wait().await?;
    let mut stream = quick.follow_logs(&JobLogOptions::default()).await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(5), stream.next())
            .await?
            .is_none()
    );
    let mut cursor = None;
    loop {
        let page = sandbox
            .list_jobs_with(|b| match cursor {
                Some(cursor) => b.all(true).cursor(cursor),
                None => b.all(true),
            })
            .await?;
        if page.items.iter().any(|info| info.id.as_str() == id) {
            break;
        }
        cursor = Some(page.next_cursor.expect("job missing from retained history"));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires a running disposable VM and MSB_JOB_TEST_SANDBOX"]
async fn managed_job_options_logs_and_validation() -> Result<(), Box<dyn std::error::Error>> {
    use microsandbox::sandbox::RlimitResource;

    let sandbox = Sandbox::get(&std::env::var("MSB_JOB_TEST_SANDBOX")?)
        .await?
        .connect()
        .await?;
    let job = sandbox
        .exec_detached_with("sh", |b| {
            b.args([
                "-c",
                "pwd; id -u; printf '%s\\n' \"$JOB_TEST_VALUE\"; ulimit -n; echo err >&2; exit 7",
            ])
            .cwd("/tmp")
            .user("65534:65534")
            .env("JOB_TEST_VALUE", "private-value")
            .rlimit(RlimitResource::Nofile, 128)
            .stdin_null()
        })
        .await?;
    let result = job.wait().await?;
    assert_eq!(result.code, 7);
    assert!(!result.success && !result.timed_out);
    let info = job.inspect().await?;
    assert!(info.pid.is_some() && info.stdin_closed && !info.tty);
    // Environment values must not leak into durable job metadata.
    assert!(!serde_json::to_string(&info)?.contains("private-value"));
    let stdout = job
        .logs(&JobLogOptions {
            sources: vec!["stdout".into()],
            ..Default::default()
        })
        .await?;
    assert_eq!(output_bytes(&stdout), b"/tmp\n65534\nprivate-value\n128\n");
    let stderr = job
        .logs(&JobLogOptions {
            sources: vec!["stderr".into()],
            ..Default::default()
        })
        .await?;
    assert_eq!(output_bytes(&stderr), b"err\n");
    let logs = job.logs(&JobLogOptions::default()).await?;
    let last = logs.last().unwrap();
    assert!(
        job.logs(&JobLogOptions {
            from_cursor: Some(last.cursor.clone()),
            ..Default::default()
        })
        .await?
        .is_empty()
    );
    assert_eq!(
        job.logs(&JobLogOptions {
            tail: Some(1),
            ..Default::default()
        })
        .await?
        .len(),
        1
    );
    assert!(
        job.logs(&JobLogOptions {
            until: Some(logs[0].timestamp),
            ..Default::default()
        })
        .await?
        .is_empty()
    );
    assert_eq!(
        job.logs(&JobLogOptions {
            since: Some(logs[0].timestamp),
            ..Default::default()
        })
        .await?
        .len(),
        logs.len()
    );
    let replay = job
        .attach_with(|b| b.read_only(true).replay(JobReplay::Recent { max_bytes: 3 }))
        .await?;
    let mut replay_bytes = Vec::new();
    while let Some(event) = replay.recv().await? {
        if let JobEvent::Output(entry) = event {
            replay_bytes.extend_from_slice(&entry.data);
        }
    }
    assert_eq!(
        replay_bytes,
        output_bytes(&logs)[output_bytes(&logs).len() - 3..]
    );
    replay.detach().await?;
    assert_eq!(
        sandbox
            .exec_detached_with("cat", |b| b.tty(true).stdin_null())
            .await
            .err()
            .unwrap()
            .code(),
        "invalid_options"
    );
    assert_eq!(
        sandbox
            .exec_detached_with("cat", |b| b.stdin_bytes(vec![0; 65537]))
            .await
            .err()
            .unwrap()
            .code(),
        "invalid_options"
    );
    assert_eq!(
        sandbox
            .exec_detached_with("cat", |b| b.tty(true).stdin_bytes(b"x".to_vec()))
            .await
            .err()
            .unwrap()
            .code(),
        "invalid_options"
    );
    assert_eq!(
        sandbox
            .list_jobs_with(|b| b.limit(0))
            .await
            .unwrap_err()
            .code(),
        "invalid_options"
    );
    assert_eq!(
        sandbox.get_job("../../outside").await.err().unwrap().code(),
        "invalid_id"
    );
    let finite = sandbox
        .exec_detached_with("wc", |b| b.args(["-c"]).stdin_bytes(vec![42; 65536]))
        .await?;
    assert!(finite.wait().await?.success);
    assert_eq!(
        String::from_utf8(output_bytes(&finite.logs(&JobLogOptions::default()).await?))?.trim(),
        "65536"
    );
    assert_eq!(
        finite
            .logs(&JobLogOptions {
                from_cursor: Some(last.cursor.clone()),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        "invalid_cursor"
    );
    eprintln!(
        "options, user, cwd, resource limits, filters, replay, binary limits and validation passed"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a running disposable VM and MSB_JOB_TEST_SANDBOX"]
async fn managed_job_input_backpressure_and_lease_heartbeat()
-> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::get(&std::env::var("MSB_JOB_TEST_SANDBOX")?)
        .await?
        .connect()
        .await?;
    let counter = sandbox.exec_detached("wc", ["-c"]).await?;
    let attachment = counter.attach().await?;
    attachment.write_stdin([]).await?;
    assert!(!counter.inspect().await?.stdin_closed);
    assert_eq!(
        attachment
            .write_stdin(vec![0; 16385])
            .await
            .unwrap_err()
            .code(),
        "invalid_options"
    );
    assert_eq!(
        attachment.resize(24, 80).await.unwrap_err().code(),
        "invalid_options"
    );
    for _ in 0..128 {
        attachment.write_stdin(vec![7; 16384]).await?;
    }
    counter.eof().await?;
    counter.eof().await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(10), counter.wait())
            .await??
            .success
    );
    assert_eq!(
        String::from_utf8(output_bytes(
            &counter.logs(&JobLogOptions::default()).await?
        ))?
        .trim(),
        "2097152"
    );
    attachment.detach().await?;

    let closed = sandbox
        .exec_detached("sh", ["-c", "exec 0<&-; echo ready; sleep 60"])
        .await?;
    let writer = closed.attach().await?;
    tokio::time::sleep(Duration::from_millis(100)).await;
    writer.write_stdin(b"trigger EPIPE\n").await?;
    tokio::time::timeout(Duration::from_secs(5), async {
        while !closed.inspect().await?.stdin_closed {
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        Ok::<_, microsandbox::JobError>(())
    })
    .await??;
    assert_eq!(
        writer.write_stdin(b"late").await.unwrap_err().code(),
        "stdin_closed"
    );
    closed.kill().await?;
    closed.wait().await?;
    writer.detach().await?;

    let heartbeat = sandbox
        .exec_detached("cat", std::iter::empty::<String>())
        .await?;
    let owner = heartbeat.attach().await?;
    let observer = heartbeat.attach_with(|b| b.read_only(true)).await?;
    assert_eq!(
        observer.resize(24, 80).await.unwrap_err().code(),
        "read_only"
    );
    // Keep an idle owner beyond the 30-second runtime lease; renewal must preserve exclusivity.
    tokio::time::sleep(Duration::from_secs(32)).await;
    assert_eq!(heartbeat.attach().await.err().unwrap().code(), "input_busy");
    owner.write_stdin(b"alive after idle\n").await?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), observer.recv()).await??,
        Some(JobEvent::Output(_))
    ));
    drop(owner);
    let replacement = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match heartbeat.attach().await {
                Ok(attachment) => break Ok(attachment),
                Err(error) if error.code() == "input_busy" => {
                    tokio::time::sleep(Duration::from_millis(25)).await
                }
                Err(error) => break Err(error),
            }
        }
    })
    .await??;
    heartbeat.eof().await?;
    assert!(heartbeat.wait().await?.success);
    replacement.detach().await?;
    observer.detach().await?;
    eprintln!("two MiB input, ordered EOF, EPIPE, heartbeat and drop passed");
    Ok(())
}

#[tokio::test]
#[ignore = "requires an otherwise idle disposable VM; run with --test-threads=1"]
async fn managed_job_bounds_rotation_and_pagination() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::get(&std::env::var("MSB_JOB_TEST_SANDBOX")?)
        .await?
        .connect()
        .await?;
    assert!(
        sandbox.list_jobs().await?.items.is_empty(),
        "resource test requires no other active jobs"
    );
    let mut active = Vec::new();
    for _ in 0..32 {
        active.push(sandbox.exec_detached("sleep", ["120"]).await?);
    }
    assert_eq!(
        sandbox
            .exec_detached("true", std::iter::empty::<String>())
            .await
            .err()
            .unwrap()
            .code(),
        "resource_limit"
    );
    let mut ids = std::collections::BTreeSet::new();
    let mut cursor = None;
    loop {
        let page = sandbox
            .list_jobs_with(|b| match cursor {
                Some(cursor) => b.limit(7).cursor(cursor),
                None => b.limit(7),
            })
            .await?;
        assert!(page.items.len() <= 7);
        for info in page.items {
            assert!(info.state.is_active());
            assert!(ids.insert(info.id));
        }
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(ids.len(), 32);
    let mut observers = Vec::new();
    for _ in 0..16 {
        observers.push(active[0].attach_with(|b| b.read_only(true)).await?);
    }
    assert_eq!(
        active[0]
            .attach_with(|b| b.read_only(true))
            .await
            .err()
            .unwrap()
            .code(),
        "resource_limit"
    );
    for observer in observers {
        observer.detach().await?;
    }
    for job in active {
        job.kill().await?;
        job.wait().await?;
    }

    let flood = sandbox
        .exec_detached(
            "sh",
            [
                "-c",
                "echo first; read start; head -c 3145728 /dev/zero; echo last",
            ],
        )
        .await?;
    let owner = flood
        .attach_with(|b| b.replay(JobReplay::Recent { max_bytes: 100 }))
        .await?;
    let cursor = loop {
        let records = flood.logs(&JobLogOptions::default()).await?;
        if let Some(first) = records.first() {
            break first.cursor.clone();
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    };
    let slow = flood
        .attach_with(|b| b.read_only(true).replay(JobReplay::After(cursor.clone())))
        .await?;
    owner.write_stdin(b"go\n").await?;
    assert!(
        tokio::time::timeout(Duration::from_secs(20), flood.wait())
            .await??
            .success
    );
    assert!(matches!(slow.recv().await?, Some(JobEvent::Gap { .. })));
    assert_eq!(
        flood
            .logs(&JobLogOptions {
                from_cursor: Some(cursor),
                ..Default::default()
            })
            .await
            .unwrap_err()
            .code(),
        "output_gap"
    );
    let output = output_bytes(&flood.logs(&JobLogOptions::default()).await?);
    assert!(output.ends_with(b"last\n") && output.len() < 1024 * 1024);
    owner.detach().await?;
    slow.detach().await?;

    // Completed history is pruned while an older active job remains owned and attachable.
    let retained = sandbox
        .exec_detached("cat", std::iter::empty::<String>())
        .await?;
    for _ in 0..260 {
        sandbox
            .exec_detached("true", std::iter::empty::<String>())
            .await?
            .wait()
            .await?;
    }
    let mut cursor = None;
    let mut count = 0;
    loop {
        let page = sandbox
            .list_jobs_with(|b| match cursor {
                Some(cursor) => b.all(true).limit(100).cursor(cursor),
                None => b.all(true).limit(100),
            })
            .await?;
        count += page.items.len();
        cursor = page.next_cursor;
        if cursor.is_none() {
            break;
        }
    }
    assert_eq!(count, 256);
    let attachment = retained.attach().await?;
    attachment.write_stdin(b"retained active\n").await?;
    retained.eof().await?;
    assert!(retained.wait().await?.success);
    attachment.detach().await?;
    eprintln!(
        "32-job/16-attachment limits, pagination, three MiB rotation, gaps and 256-job retention passed"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a running disposable VM and MSB_JOB_TEST_SANDBOX"]
async fn managed_job_z_blocked_input_signal() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::get(&std::env::var("MSB_JOB_TEST_SANDBOX")?)
        .await?
        .connect()
        .await?;
    // Saturating guest stdin must never block the independent signal/control worker.
    for tty in [false, true] {
        let blocked = sandbox
            .exec_detached_with("sh", |e| {
                e.args([
                    "-c",
                    if tty {
                        "stty raw -echo; echo ready; sleep 120"
                    } else {
                        "sleep 120"
                    },
                ])
                .tty(tty)
            })
            .await?;
        let writer = blocked
            .attach_with(|b| b.replay(JobReplay::Recent { max_bytes: 1024 }))
            .await?;
        if tty {
            assert!(
                matches!(tokio::time::timeout(Duration::from_secs(5), writer.recv()).await??,
                Some(JobEvent::Output(entry)) if String::from_utf8_lossy(&entry.data).contains("ready"))
            );
        }
        let filling = async {
            for _ in 0..512 {
                writer.write_stdin(vec![0; 16384]).await?;
            }
            Ok::<_, microsandbox::JobError>(())
        };
        assert!(
            tokio::time::timeout(Duration::from_secs(2), filling)
                .await
                .is_err()
        );
        if tty {
            // Resize still uses the ordinary agent path; it must not hold the signal worker hostage.
            writer.resize(40, 100).await?;
        }
        eprintln!("stdin is backpressured (tty={tty}); requesting kill");
        tokio::time::timeout(Duration::from_secs(5), blocked.kill()).await??;
        eprintln!("kill was admitted; waiting for guest exit");
        let exited = tokio::time::timeout(Duration::from_secs(5), blocked.wait()).await;
        if exited.is_err() {
            // Admission and delivery are distinct. Preserve the runtime's delivery
            // diagnostic on failure without allowing inspection to hang the test.
            eprintln!(
                "job after kill timeout (tty={tty}): {:?}",
                tokio::time::timeout(Duration::from_secs(2), blocked.inspect()).await
            );
        }
        assert!(!exited??.success);
        writer.detach().await?;
    }

    eprintln!("signalling under saturated input passed");
    Ok(())
}

#[tokio::test]
#[ignore = "requires a running disposable VM and MSB_JOB_TEST_SANDBOX"]
async fn managed_job_z_blocked_input_timeout() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::get(&std::env::var("MSB_JOB_TEST_SANDBOX")?)
        .await?
        .connect()
        .await?;
    let job = sandbox
        .exec_detached_with("sleep", |b| b.args(["120"]).timeout(Duration::from_secs(3)))
        .await?;
    let writer = job.attach().await?;
    let filling = async {
        for _ in 0..512 {
            writer.write_stdin(vec![0; 16384]).await?;
        }
        Ok::<_, microsandbox::JobError>(())
    };
    assert!(
        tokio::time::timeout(Duration::from_secs(2), filling)
            .await
            .is_err()
    );
    let result = tokio::time::timeout(Duration::from_secs(6), job.wait()).await;
    eprintln!(
        "deadline state after saturated input: {:?}",
        job.inspect().await?
    );
    assert!(result??.timed_out);
    writer.detach().await?;
    Ok(())
}

#[tokio::test]
#[ignore = "requires a running disposable VM and MSB_JOB_TEST_SANDBOX"]
async fn exec_control_creation_backpressure_and_pause() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::get(&std::env::var("MSB_JOB_TEST_SANDBOX")?)
        .await?
        .connect()
        .await?;
    let mut early = sandbox
        .exec_stream_with("sleep", |e| e.args(["120"]).stdin_pipe())
        .await?;
    // Zero is accepted by ordinary exec, but is not an acknowledged liveness query.
    early.signal(0).await?;
    for invalid in [-1, 65, i32::MAX] {
        assert!(
            early
                .signal(invalid)
                .await
                .unwrap_err()
                .to_string()
                .contains("invalid_signal")
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(100), early.wait())
            .await
            .is_err()
    );
    early.kill().await?;
    assert!(
        !tokio::time::timeout(Duration::from_secs(5), early.wait())
            .await??
            .success
    );
    for tty in [false, true] {
        let mut stream = sandbox
            .exec_stream_with("sh", |e| {
                e.args([
                    "-c",
                    if tty {
                        "stty raw -echo; echo ready; sleep 120"
                    } else {
                        "sleep 120"
                    },
                ])
                .stdin_pipe()
                .tty(tty)
            })
            .await?;
        if tty {
            loop {
                if let Some(microsandbox::ExecEvent::Stdout(bytes)) =
                    tokio::time::timeout(Duration::from_secs(5), stream.recv()).await?
                    && String::from_utf8_lossy(&bytes).contains("ready")
                {
                    break;
                }
            }
        }
        let input = stream.take_stdin().unwrap();
        let filling = async {
            for _ in 0..512 {
                input.write(vec![0; 16384]).await?;
            }
            Ok::<_, microsandbox::MicrosandboxError>(())
        };
        assert!(
            tokio::time::timeout(Duration::from_secs(2), filling)
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(5), stream.signal(0)).await??;
        assert!(
            tokio::time::timeout(Duration::from_millis(100), stream.wait())
                .await
                .is_err()
        );
        tokio::time::timeout(Duration::from_secs(5), stream.kill()).await??;
        assert!(
            !tokio::time::timeout(Duration::from_secs(5), stream.wait())
                .await??
                .success
        );
        drop(input);
    }
    // Pause gates physical delivery, while Resume must remain independently dispatchable.
    let mut stream = sandbox
        .exec_stream_with("sleep", |e| e.args(["120"]))
        .await?;
    assert!(matches!(
        stream.recv().await,
        Some(microsandbox::ExecEvent::Started { .. })
    ));
    sandbox.pause().await?;
    let control = stream.control();
    let signal = tokio::spawn(async move { control.kill().await });
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert!(!signal.is_finished());
    tokio::time::timeout(Duration::from_secs(2), sandbox.resume()).await??;
    tokio::time::timeout(Duration::from_secs(5), signal).await???;
    assert!(
        !tokio::time::timeout(Duration::from_secs(5), stream.wait())
            .await??
            .success
    );
    let mut delayed = sandbox.exec_stream("sleep", ["120"]).await?;
    assert!(matches!(
        delayed.recv().await,
        Some(microsandbox::ExecEvent::Started { .. })
    ));
    sandbox.pause().await?;
    let uncertain = tokio::time::timeout(Duration::from_secs(5), delayed.kill())
        .await?
        .unwrap_err();
    assert!(
        uncertain.to_string().contains("delivery_unconfirmed"),
        "{uncertain}"
    );
    // The timed-out request was admitted while paused. Resume can deliver it; replaying a signal
    // would be unsafe, so wait for the original execution's terminal result instead.
    sandbox.resume().await?;
    assert!(
        !tokio::time::timeout(Duration::from_secs(5), delayed.wait())
            .await??
            .success
    );
    assert!(delayed.kill().await.is_err());
    let result = tokio::time::timeout(
        Duration::from_secs(10),
        sandbox.exec_with("sleep", |e| {
            e.args(["120"])
                .stdin_bytes(vec![0; 1024 * 1024])
                .timeout(Duration::from_secs(2))
        }),
    )
    .await?;
    assert!(
        matches!(result, Err(microsandbox::MicrosandboxError::ExecTimeout(_))),
        "unexpected foreground timeout result: {result:?}"
    );
    assert_eq!(
        sandbox
            .exec("echo", ["still-responsive"])
            .await?
            .stdout_bytes()
            .as_ref(),
        b"still-responsive\n"
    );
    eprintln!(
        "foreground immediate kill, pipe/PTY saturation, paused signal/resume and timeout passed"
    );
    Ok(())
}

#[tokio::test]
#[ignore = "requires a disposable VM and restarts it; set MSB_JOB_TEST_RESTART=1"]
async fn managed_job_zz_saturated_shutdown() -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(std::env::var("MSB_JOB_TEST_RESTART")?, "1");
    let name = std::env::var("MSB_JOB_TEST_SANDBOX")?;
    let sandbox = Sandbox::get(&name).await?.connect().await?;
    sandbox
        .exec("sh", ["-c", "echo persisted >/tmp/control-stop-marker"])
        .await?;
    let job = sandbox.exec_detached("sleep", ["120"]).await?;
    let writer = job.attach().await?;
    let filling = async {
        for _ in 0..512 {
            writer.write_stdin(vec![0; 16384]).await?;
        }
        Ok::<_, microsandbox::JobError>(())
    };
    assert!(
        tokio::time::timeout(Duration::from_secs(2), filling)
            .await
            .is_err()
    );
    sandbox.stop_with_timeout(Duration::from_secs(15)).await?;
    drop(writer);
    drop(sandbox);
    let restarted = Sandbox::get(&name).await?.start().await?;
    assert_eq!(
        restarted
            .exec("cat", ["/tmp/control-stop-marker"])
            .await?
            .stdout_bytes()
            .as_ref(),
        b"persisted\n"
    );
    assert!(matches!(
        restarted
            .get_job(job.id().as_str())
            .await?
            .inspect()
            .await?
            .state,
        JobState::Exited | JobState::Lost
    ));
    eprintln!("graceful shutdown under saturated stdin and persisted filesystem marker passed");
    Ok(())
}

fn output_bytes(entries: &[microsandbox::jobs::JobLogEntry]) -> Vec<u8> {
    entries
        .iter()
        .flat_map(|entry| entry.data.iter().copied())
        .collect()
}

#[tokio::test]
#[ignore = "requires a running disposable VM and MSB_JOB_TEST_SANDBOX"]
async fn exec_stream_deadlines() -> Result<(), Box<dyn std::error::Error>> {
    use microsandbox::{ExecEvent, MicrosandboxError};

    let sandbox = Sandbox::get(&std::env::var("MSB_JOB_TEST_SANDBOX")?)
        .await?
        .connect()
        .await?;
    let duration = Duration::from_millis(500);
    for tty in [false, true] {
        let mut stream = sandbox
            .exec_stream_with("sleep", |e| e.args(["120"]).tty(tty).timeout(duration))
            .await?;
        let pid = match stream.recv().await {
            Some(ExecEvent::Started { pid }) => pid,
            other => panic!("missing start: {other:?}"),
        };
        // No handle method is polled while the deadline expires. Prove guest death before
        // calling wait, so a timer implemented only inside wait cannot pass this test.
        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(
            !sandbox
                .exec("kill", ["-0".to_string(), pid.to_string()])
                .await?
                .status()
                .success
        );
        assert!(
            matches!(stream.wait().await, Err(MicrosandboxError::ExecTimeout(d)) if d == duration)
        );
    }
    let mut cancelled = sandbox
        .exec_stream_with("sleep", |e| e.args(["120"]).timeout(duration))
        .await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(50), cancelled.wait())
            .await
            .is_err()
    );
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), cancelled.collect()).await?,
        Err(MicrosandboxError::ExecTimeout(_))
    ));

    let mut zero = sandbox
        .exec_stream_with("sleep", |e| e.args(["120"]).timeout(Duration::ZERO))
        .await?;
    assert!(
        matches!(tokio::time::timeout(Duration::from_secs(5), zero.wait()).await?, Err(MicrosandboxError::ExecTimeout(d)) if d.is_zero())
    );
    let mut failed = sandbox
        .exec_stream_with("/nonexistent-stream-timeout-command", |e| {
            e.timeout(Duration::ZERO)
        })
        .await?;
    assert!(matches!(
        failed.wait().await,
        Err(MicrosandboxError::ExecFailed(_))
    ));
    let mut fast = sandbox
        .exec_stream_with("sh", |e| {
            e.args(["-c", "printf out; printf err >&2; exit 7"])
                .timeout(Duration::from_secs(10))
        })
        .await?;
    let output = fast.collect().await?;
    assert_eq!(output.status().code, 7);
    assert_eq!(output.stdout_bytes().as_ref(), b"out");
    assert_eq!(output.stderr_bytes().as_ref(), b"err");
    let mut unlimited = sandbox.exec_stream("sleep", ["1"]).await?;
    assert!(unlimited.wait().await?.success);

    // A deadline must reach the same reserved control path as explicit kill, even
    // while the guest refuses pipe or raw PTY input and the producer is blocked.
    for tty in [false, true] {
        let mut blocked = sandbox
            .exec_stream_with("sh", |e| {
                e.args([
                    "-c",
                    if tty {
                        "stty raw -echo; echo ready; sleep 120"
                    } else {
                        "echo ready; sleep 120"
                    },
                ])
                .stdin_pipe()
                .tty(tty)
                .timeout(Duration::from_secs(3))
            })
            .await?;
        loop {
            match tokio::time::timeout(Duration::from_secs(5), blocked.recv()).await? {
                Some(ExecEvent::Stdout(bytes))
                    if String::from_utf8_lossy(&bytes).contains("ready") =>
                {
                    break;
                }
                Some(ExecEvent::Started { .. }) => {}
                other => panic!("missing ready: {other:?}"),
            }
        }
        let input = blocked.take_stdin().unwrap();
        let fill = async {
            for _ in 0..512 {
                input.write(vec![0; 16384]).await?;
            }
            Ok::<_, MicrosandboxError>(())
        };
        assert!(
            tokio::time::timeout(Duration::from_secs(1), fill)
                .await
                .is_err()
        );
        assert!(matches!(
            tokio::time::timeout(Duration::from_secs(7), blocked.wait()).await?,
            Err(MicrosandboxError::ExecTimeout(_))
        ));
    }

    let mut paused = sandbox
        .exec_stream_with("sleep", |e| e.args(["120"]).timeout(duration))
        .await?;
    assert!(matches!(
        paused.recv().await,
        Some(ExecEvent::Started { .. })
    ));
    sandbox.pause().await?;
    // Resume before the transport's delivery-confirmation limit; a paused guest
    // cannot acknowledge a signal or exit until the vCPUs run again.
    tokio::time::sleep(Duration::from_secs(1)).await;
    sandbox.resume().await?;
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(5), paused.wait()).await?,
        Err(MicrosandboxError::ExecTimeout(_))
    ));
    eprintln!(
        "stream deadlines: idle consumer, cancelled wait, zero/start failure, output/status, pipe/PTY saturation and pause/resume passed"
    );
    Ok(())
}
