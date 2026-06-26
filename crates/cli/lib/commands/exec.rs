//! `msb exec` command — execute a command in a sandbox.

use std::io::{IsTerminal, Write};
use std::time::Duration;

use clap::Args;
use microsandbox::sandbox::exec::{ExecEvent, ExecHandle};
use microsandbox::sandbox::{ExecOptionsBuilder, ExecOutput, RlimitResource, Sandbox};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Run a command in a running sandbox.
#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Sandbox to run the command in.
    pub name: String,

    /// Set an environment variable (KEY=value).
    #[arg(short, long)]
    pub env: Vec<String>,

    /// Set the working directory for the command.
    #[arg(short, long)]
    pub workdir: Option<String>,

    /// Run the command as the specified guest user.
    #[arg(short = 'u', long)]
    pub user: Option<String>,

    /// Allocate a pseudo-terminal (enables colors, line editing).
    #[arg(short = 't', long)]
    pub tty: bool,

    /// Kill the command after this duration (e.g. 30s, 5m, 1h).
    #[arg(long)]
    pub timeout: Option<String>,

    /// Set a POSIX resource limit (e.g. nofile=1024, nproc=64, as=1073741824).
    #[arg(long)]
    pub rlimit: Vec<String>,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,

    /// Stream stdin/stdout bidirectionally without a PTY
    /// (no echo/CRLF translation — safe for JSON lines).
    ///
    /// Conflicts with `--tty`: a PTY reintroduces echo and CRLF
    /// translation, defeating the byte-faithful streaming this mode exists
    /// to provide. Use `--tty` (or interactive mode) for a PTY session.
    #[arg(long, conflicts_with = "tty")]
    pub stream: bool,

    /// Command to run inside the sandbox (after --).
    /// When omitted in interactive mode, attaches to the default shell.
    #[arg(last = true)]
    pub command: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb exec` command.
pub async fn run(args: ExecArgs) -> anyhow::Result<()> {
    // Fail fast before starting anything: `--stream` targets a piped host
    // driver. A terminal stdin would be read in cooked mode (local echo, line
    // buffering, Ctrl-C delivered to msb) — the opposite of the byte-faithful
    // stream this mode promises. Interactive users want the PTY path (`--tty`).
    if args.stream && std::io::stdin().is_terminal() {
        anyhow::bail!(
            "`--stream` requires piped (non-terminal) stdin; use `--tty` for an interactive terminal session"
        );
    }

    let sandbox = super::resolve_and_start(&args.name, args.quiet).await?;

    // Build exec options.
    let env_pairs: Vec<(String, String)> = args
        .env
        .iter()
        .map(|s| ui::parse_env(s).map_err(anyhow::Error::msg))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let workdir = args.workdir;
    let interactive = std::io::stdin().is_terminal();

    // Read piped stdin upfront so it can be forwarded into the sandbox.
    // Skipped in `--stream` mode, where stdin is forwarded incrementally.
    let piped_stdin = if !interactive && !args.stream {
        let mut buf = Vec::new();
        tokio::io::stdin().read_to_end(&mut buf).await.ok();
        Some(buf)
    } else {
        None
    };

    // Resolve the command with exec semantics: an explicit command runs
    // directly, while omitted commands can still fall back to the sandbox's
    // configured image command/default shell.
    let (cmd, cmd_args) =
        match super::common::resolve_exec_command(sandbox.config(), args.command, interactive)? {
            (Some(cmd), cmd_args) => (cmd, cmd_args),
            (None, _) => {
                super::maybe_stop(&sandbox).await;
                std::process::exit(0);
            }
        };

    // Parse rlimits.
    let rlimits: Vec<_> = args
        .rlimit
        .iter()
        .map(|s| super::common::parse_rlimit(s))
        .collect::<anyhow::Result<Vec<_>>>()?;

    // Parse timeout.
    let timeout = match &args.timeout {
        Some(t) => Some(Duration::from_secs(super::common::parse_duration_secs(t)?)),
        None => None,
    };

    if args.stream {
        return run_stream(
            &sandbox, cmd, cmd_args, &env_pairs, &workdir, &args.user, timeout, &rlimits,
        )
        .await;
    }

    if interactive {
        // Interactive mode with TTY — use attach.
        let exit_code = sandbox
            .attach_with(cmd, |a| {
                let mut a = a.args(cmd_args);
                for (k, v) in &env_pairs {
                    a = a.env(k, v);
                }
                if let Some(ref cwd) = workdir {
                    a = a.cwd(cwd);
                }
                if let Some(ref user) = args.user {
                    a = a.user(user);
                }
                for &(resource, soft, hard) in &rlimits {
                    a = a.rlimit_range(resource, soft, hard);
                }
                a
            })
            .await?;

        super::maybe_stop(&sandbox).await;

        if exit_code != 0 {
            std::process::exit(exit_code);
        }
    } else {
        // Non-interactive: exec and capture output.
        let output: ExecOutput = sandbox
            .exec_with(cmd, |e| {
                let mut e = apply_common_exec_opts(
                    e.args(cmd_args)
                        .stdin_bytes(piped_stdin.unwrap_or_default()),
                    &env_pairs,
                    &workdir,
                    &args.user,
                    timeout,
                    &rlimits,
                );
                if args.tty {
                    e = e.tty(true);
                }
                e
            })
            .await?;

        std::io::stdout().write_all(output.stdout_bytes())?;
        std::io::stderr().write_all(output.stderr_bytes())?;

        super::maybe_stop(&sandbox).await;

        if !output.status().success {
            std::process::exit(output.status().code);
        }
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Apply the options shared by every `exec` mode (env, cwd, user, timeout,
/// rlimits) onto an [`ExecOptionsBuilder`]. Mode-specific bits (stdin handling,
/// PTY) are layered on by the caller.
fn apply_common_exec_opts(
    mut e: ExecOptionsBuilder,
    env_pairs: &[(String, String)],
    workdir: &Option<String>,
    user: &Option<String>,
    timeout: Option<Duration>,
    rlimits: &[(RlimitResource, u64, u64)],
) -> ExecOptionsBuilder {
    for (k, v) in env_pairs {
        e = e.env(k, v);
    }
    if let Some(cwd) = workdir {
        e = e.cwd(cwd);
    }
    if let Some(user) = user {
        e = e.user(user);
    }
    if let Some(t) = timeout {
        e = e.timeout(t);
    }
    for &(resource, soft, hard) in rlimits {
        e = e.rlimit_range(resource, soft, hard);
    }
    e
}

/// Drive a non-PTY bidirectional streaming exec session (`--stream`).
///
/// Forwards host stdin into the guest incrementally and flushes guest
/// stdout/stderr per chunk, so a host driver can run the guest turn by turn.
/// Always stops the sandbox (when we own its lifecycle) before returning, so a
/// broken host pipe or a timeout can't leak it.
#[allow(clippy::too_many_arguments)]
async fn run_stream(
    sandbox: &Sandbox,
    cmd: String,
    cmd_args: Vec<String>,
    env_pairs: &[(String, String)],
    workdir: &Option<String>,
    user: &Option<String>,
    timeout: Option<Duration>,
    rlimits: &[(RlimitResource, u64, u64)],
) -> anyhow::Result<()> {
    let mut handle = match sandbox
        .exec_stream_with(cmd, |e| {
            apply_common_exec_opts(
                e.args(cmd_args).stdin_pipe(),
                env_pairs,
                workdir,
                user,
                timeout,
                rlimits,
            )
        })
        .await
    {
        Ok(handle) => handle,
        Err(e) => {
            super::maybe_stop(sandbox).await;
            return Err(e.into());
        }
    };

    // Forward host stdin → guest incrementally in the background so it runs
    // concurrently with draining output. EOF or any read/write error closes the
    // guest's stdin exactly once, so a guest blocked on read always sees EOF.
    if let Some(sink) = handle.take_stdin() {
        tokio::spawn(async move {
            let mut stdin = tokio::io::stdin();
            let mut buf = [0u8; 8192];
            loop {
                match stdin.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if sink.write(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                }
            }
            let _ = sink.close().await;
        });
    }

    let result = drive_stream(&mut handle, timeout).await;

    // Stop before propagating so neither a host-pipe error nor a timeout can
    // leave the sandbox running.
    super::maybe_stop(sandbox).await;

    match result {
        Ok(0) => Ok(()),
        Ok(code) => std::process::exit(code),
        Err(e) => Err(e),
    }
}

/// Pump events from a streaming exec session to the host's stdout/stderr until
/// the guest exits, returning its exit code.
///
/// Enforces `timeout` by killing the guest on expiry — the SDK leaves timeout
/// enforcement to the stream driver, mirroring the buffered path's
/// `tokio::time::timeout` + kill.
async fn drive_stream(handle: &mut ExecHandle, timeout: Option<Duration>) -> anyhow::Result<i32> {
    let deadline = timeout.map(|d| tokio::time::Instant::now() + d);
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();

    loop {
        let event = match deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, handle.recv()).await {
                Ok(event) => event,
                Err(_) => {
                    let _ = handle.kill().await;
                    let secs = timeout.unwrap_or_default().as_secs();
                    anyhow::bail!("exec timed out after {secs}s");
                }
            },
            None => handle.recv().await,
        };

        // No `Exited` event = abnormal end (e.g. agent dropped); fail like the
        // buffered `collect()` path instead of reporting success.
        let Some(event) = event else {
            anyhow::bail!("exec session ended without exit event");
        };

        match event {
            ExecEvent::Stdout(data) => {
                // A host write failure (e.g. a downstream `head` closed the
                // pipe) must not bypass cleanup: stop the guest and return so
                // the caller can stop the sandbox.
                if write_chunk(&mut stdout, &data).await.is_err() {
                    let _ = handle.kill().await;
                    return Ok(0);
                }
            }
            ExecEvent::Stderr(data) => {
                if write_chunk(&mut stderr, &data).await.is_err() {
                    let _ = handle.kill().await;
                    return Ok(0);
                }
            }
            ExecEvent::Exited { code } => return Ok(code),
            ExecEvent::Failed(payload) => anyhow::bail!("exec failed to start: {payload:?}"),
            ExecEvent::StdinError(err) => {
                // Surface the failure instead of silently dropping host input.
                eprintln!("msb: warning: failed to forward stdin to guest: {err:?}");
            }
            // Explicit (not `_`) so a new ExecEvent variant fails to compile here.
            ExecEvent::Started { .. } => {}
        }
    }
}

/// Write one output chunk to the host and flush it immediately, so the host
/// reader sees each turn's output before the guest exits.
async fn write_chunk<W: tokio::io::AsyncWrite + Unpin>(
    w: &mut W,
    data: &[u8],
) -> std::io::Result<()> {
    w.write_all(data).await?;
    w.flush().await?;
    Ok(())
}
