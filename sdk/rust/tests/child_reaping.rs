//! Integration coverage for agentd's process lifecycle management.
//!
//! This test boots a real microVM and therefore requires KVM on Linux or
//! libkrun on macOS. Run it explicitly with:
//!
//! ```text
//! cargo test -p microsandbox --test child_reaping -- --ignored --nocapture
//! ```

use std::panic::{AssertUnwindSafe, resume_unwind};
use std::time::{Duration, Instant};

use futures::{FutureExt, future::join_all};
use microsandbox::Sandbox;
use test_utils::msb_test;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const RAPID_EXIT_COUNT: usize = 24;
const RAPID_EXIT_ROUNDS: usize = 3;
const SCENARIO_TIMEOUT: Duration = Duration::from_secs(90);
const CLEANUP_TIMEOUT: Duration = Duration::from_secs(15);

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn stop_and_remove(name: &str) {
    if let Ok(Ok(handle)) = tokio::time::timeout(CLEANUP_TIMEOUT, Sandbox::get(name)).await {
        let _ = tokio::time::timeout(CLEANUP_TIMEOUT, handle.stop()).await;
    }
    let _ = tokio::time::timeout(CLEANUP_TIMEOUT, Sandbox::remove(name)).await;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn agentd_manages_concurrent_exits_and_adopted_descendants() {
    let name = "agentd-child-reaping";
    let sandbox = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(256)
        .replace()
        .create()
        .await
        .expect("create child reaping sandbox");

    let scenario = async {
        let background = sandbox
            .shell("for i in 1 2 3 4; do sleep 300 >/dev/null 2>&1 & printf '%s ' \"$!\"; done")
            .await
            .expect("spawn background descendants");
        let background_pids: Vec<u32> = background
            .stdout()
            .expect("background PIDs are UTF-8")
            .split_whitespace()
            .map(|pid| pid.parse().expect("parse background PID"))
            .collect();
        assert_eq!(background_pids.len(), 4);

        let adoption_deadline = Instant::now() + Duration::from_secs(5);
        let adopted_by_init = loop {
            let pid_list = background_pids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            let output = sandbox
            .shell(format!(
                "for pid in {pid_list}; do awk '/^PPid:/{{print $2}}' /proc/$pid/status 2>/dev/null || echo missing; done"
            ))
            .await
            .expect("read background process parents");
            let parents = output.stdout().expect("PPids are UTF-8");
            if parents.lines().count() == background_pids.len()
                && parents.lines().all(|parent| parent.trim() == "1")
            {
                break true;
            }
            if Instant::now() >= adoption_deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };

        let pipe = sandbox.shell("exit 23").await.expect("run pipe exec");
        let pty = sandbox
            .shell_with("exit 47", |exec| exec.tty(true))
            .await
            .expect("run PTY exec");

        let mut rapid_exits = Vec::with_capacity(RAPID_EXIT_ROUNDS * RAPID_EXIT_COUNT);
        for round in 0..RAPID_EXIT_ROUNDS {
            rapid_exits.extend(
                join_all((0..RAPID_EXIT_COUNT).map(|index| {
                    let sandbox = &sandbox;
                    async move {
                        let code = 10 + index as i32;
                        let tty = index % 2 == 1;
                        let output = sandbox
                            .shell_with(format!("exit {code}"), |exec| exec.tty(tty))
                            .await;
                        (round, code, tty, output)
                    }
                }))
                .await,
            );
        }

        let output_then_exit = sandbox
        .shell(
            "i=0; while [ $i -lt 65536 ]; do printf abcd; printf wxyz >&2; i=$((i+1)); done; printf tail; printf err-tail >&2; exit 39",
        )
        .await
        .expect("run output-heavy exec");

        let signaled_pipe = sandbox
            .shell("kill -TERM $$")
            .await
            .expect("run signaled pipe exec");
        let signaled_pty = sandbox
            .shell_with("kill -TERM $$", |exec| exec.tty(true))
            .await
            .expect("run signaled PTY exec");

        let spawn_failure = sandbox
            .exec(
                "/definitely/not/a/real/binary",
                std::iter::empty::<String>(),
            )
            .await;
        let pty_spawn_failure = sandbox
            .exec_with("/definitely/not/a/real/binary", |exec| exec.tty(true))
            .await;
        let pipe_after_spawn_failure = sandbox
            .shell("exit 61")
            .await
            .expect("run pipe exec after spawn failure");
        let pty_after_spawn_failure = sandbox
            .shell_with("exit 62", |exec| exec.tty(true))
            .await
            .expect("run PTY exec after spawn failure");

        sandbox
            .shell(format!(
                "kill {}",
                background_pids
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join(" ")
            ))
            .await
            .expect("terminate background descendants");

        let reap_deadline = Instant::now() + Duration::from_secs(10);
        let descendants_reaped = loop {
            let pid_list = background_pids
                .iter()
                .map(u32::to_string)
                .collect::<Vec<_>>()
                .join(" ");
            let output = sandbox
            .shell(format!(
                "for pid in {pid_list}; do if [ -e /proc/$pid ]; then echo present; else echo gone; fi; done"
            ))
            .await
            .expect("check background process states");
            let states = output.stdout().expect("process states are UTF-8");
            if states.lines().count() == background_pids.len()
                && states.lines().all(|state| state.trim() == "gone")
            {
                break true;
            }
            if Instant::now() >= reap_deadline {
                break false;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        };

        assert!(adopted_by_init, "background child was not adopted by PID 1");
        assert!(
            descendants_reaped,
            "one or more background children remained in /proc"
        );
        assert_eq!(pipe.status().code, 23);
        assert_eq!(pty.status().code, 47);
        for (round, expected_code, tty, output) in rapid_exits {
            let output = output.unwrap_or_else(|error| {
            panic!(
                "rapid exec failed before exit (round={round}, tty={tty}, code={expected_code}): {error}"
            )
        });
            assert_eq!(
                output.status().code,
                expected_code,
                "wrong rapid exit status for round={round}, tty={tty}"
            );
        }
        assert_eq!(output_then_exit.status().code, 39);
        let stdout = output_then_exit
            .stdout()
            .expect("output-heavy stdout is UTF-8");
        assert_eq!(stdout.len(), 256 * 1024 + 4);
        assert!(stdout.ends_with("tail"));
        assert_eq!(
            output_then_exit
                .stderr()
                .expect("output-heavy stderr is UTF-8"),
            format!("{}err-tail", "wxyz".repeat(65536))
        );
        assert_eq!(signaled_pipe.status().code, -1);
        assert_eq!(signaled_pty.status().code, -1);
        assert!(
            spawn_failure.is_err(),
            "missing executable unexpectedly ran"
        );
        assert!(
            pty_spawn_failure.is_err(),
            "missing PTY executable unexpectedly ran"
        );
        assert_eq!(pipe_after_spawn_failure.status().code, 61);
        assert_eq!(pty_after_spawn_failure.status().code, 62);
    };
    let scenario = AssertUnwindSafe(tokio::time::timeout(SCENARIO_TIMEOUT, scenario))
        .catch_unwind()
        .await;

    drop(sandbox);
    stop_and_remove(name).await;

    match scenario {
        Ok(Ok(())) => {}
        Ok(Err(_)) => panic!("process lifecycle scenario exceeded {SCENARIO_TIMEOUT:?}"),
        Err(payload) => resume_unwind(payload),
    }
}
