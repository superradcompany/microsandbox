//! `msb exec` command — execute a command in a sandbox.

use std::io::{IsTerminal, Read, Write};
use std::time::Duration;

use clap::Args;
use microsandbox::sandbox::exec::{ExecEvent, ExecHandle, ExecSink};
use microsandbox::sandbox::{ExecOptionsBuilder, ExecOutput, RlimitResource, Sandbox};
use tokio::io::AsyncWriteExt;

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
    #[arg(short = 't', long, conflicts_with = "no_tty")]
    pub tty: bool,

    /// Disable pseudo-terminal allocation and run non-interactively.
    #[arg(long = "no-tty", conflicts_with = "tty")]
    pub no_tty: bool,

    /// Leave host stdin untouched and give the command EOF (disables automatic TTY).
    #[arg(long, conflicts_with = "tty")]
    pub no_stdin: bool,

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
    let stdin_is_terminal = std::io::stdin().is_terminal();
    if args.stream && stdin_is_terminal && !args.no_stdin {
        anyhow::bail!(
            "`--stream` requires piped stdin or `--no-stdin`; use `--tty` for an interactive terminal session"
        );
    }

    let env_pairs: Vec<(String, String)> = args
        .env
        .iter()
        .map(|s| ui::parse_env(s).map_err(anyhow::Error::msg))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let interactive =
        super::common::use_interactive_tty(stdin_is_terminal, args.no_tty || args.no_stdin);

    let rlimits = args
        .rlimit
        .iter()
        .map(|s| super::common::parse_rlimit(s))
        .collect::<anyhow::Result<Vec<_>>>()?;

    let timeout = args
        .timeout
        .as_deref()
        .map(super::common::parse_duration_secs)
        .transpose()?
        .map(Duration::from_secs);

    let sandbox = super::resolve_and_start(&args.name, args.quiet).await?;

    let result = run_started(
        &sandbox,
        args,
        env_pairs,
        timeout,
        rlimits,
        stdin_is_terminal,
        interactive,
    )
    .await;

    // `maybe_stop` is a no-op for a sandbox that was already running, but it
    // synchronously restores a sandbox that `exec` temporarily started.
    super::maybe_stop(&sandbox).await;

    let exit_code = result?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }

    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Run validated inputs while the caller retains responsibility for cleanup.
#[allow(clippy::too_many_arguments)]
async fn run_started(
    sandbox: &Sandbox,
    args: ExecArgs,
    env_pairs: Vec<(String, String)>,
    timeout: Option<Duration>,
    rlimits: Vec<(RlimitResource, u64, u64)>,
    stdin_is_terminal: bool,
    interactive: bool,
) -> anyhow::Result<i32> {
    let workdir = args.workdir;

    // Resolve the command with exec semantics: an explicit command runs
    // directly, while omitted commands can still fall back to the sandbox's
    // configured image command/default shell.
    let (cmd, cmd_args) =
        match super::common::resolve_exec_command(sandbox.config(), args.command, interactive)? {
            (Some(cmd), cmd_args) => (cmd, cmd_args),
            (None, _) => return Ok(0),
        };

    if args.stream || (!interactive && !stdin_is_terminal) {
        let options = apply_common_exec_opts(
            ExecOptionsBuilder::default().args(cmd_args).tty(args.tty),
            &env_pairs,
            &workdir,
            &args.user,
            timeout,
            &rlimits,
        );
        if args.no_stdin {
            let mut handle = sandbox
                .exec_stream_with(cmd, |_| options.stdin_bytes(Vec::new()))
                .await?;
            return drive_stream(&mut handle, timeout, args.stream).await;
        }
        return run_piped(sandbox, cmd, options, timeout, args.stream).await;
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
        Ok(exit_code)
    } else {
        // Non-interactive: exec and capture output.
        let output: ExecOutput = sandbox
            .exec_with(cmd, |e| {
                let mut e = apply_common_exec_opts(
                    // No host input is forwarded on this noninteractive terminal path.
                    e.args(cmd_args).stdin_bytes(Vec::new()),
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
        Ok(output.status().code)
    }
}

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

/// Forward piped input while running the command, independently of output buffering.
async fn run_piped(
    sandbox: &Sandbox,
    cmd: String,
    options: ExecOptionsBuilder,
    timeout: Option<Duration>,
    stream_output: bool,
) -> anyhow::Result<i32> {
    let mut handle = sandbox
        .exec_stream_with(cmd, |_| options.stdin_pipe())
        .await?;
    let sink = handle.take_stdin().expect("piped exec has a stdin sink");
    let control = handle.control();
    let output = drive_stream(&mut handle, timeout, stream_output);
    tokio::pin!(output);

    tokio::select! {
        // Preserve the guest's result if it exits while input forwarding fails.
        biased;
        result = &mut output => result,
        result = forward_stdin(sink) => {
            if let Err(error) = result {
                let _ = control.kill().await;
                return Err(error);
            }
            output.await
        }
    }
}

/// Read stdin outside Tokio's blocking pool so an open pipe cannot hold up CLI exit.
async fn forward_stdin(sink: ExecSink) -> anyhow::Result<()> {
    // Tokio's stdin uses an uncancellable blocking read; dropping its task still
    // makes runtime shutdown wait for EOF. A dedicated detached thread does not
    // hold up process exit. The bounded channel limits read-ahead, and dropping
    // its receiver ends the reader on its next read/send. No stdin flags change.
    let (sender, mut receiver) = tokio::sync::mpsc::channel(1);
    std::thread::Builder::new()
        .name("msb-stdin".into())
        .spawn(move || {
            let mut stdin = std::io::stdin().lock();
            let mut buffer = [0u8; 8192];
            loop {
                let chunk = match stdin.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(n) => Ok(buffer[..n].to_vec()),
                    Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        // Launchers may supply a nonblocking stdin descriptor.
                        // Wait for more input without changing its shared flags.
                        if sender.is_closed() {
                            break;
                        }
                        std::thread::sleep(Duration::from_millis(10));
                        continue;
                    }
                    Err(error) => Err(error),
                };
                let failed = chunk.is_err();
                if sender.blocking_send(chunk).is_err() || failed {
                    break;
                }
            }
        })?;

    while let Some(chunk) = receiver.recv().await {
        let chunk = chunk.map_err(|error| anyhow::anyhow!("failed to read stdin: {error}"))?;
        sink.write(&chunk).await?;
    }
    sink.close().await?;
    Ok(())
}

/// Pump events from a streaming exec session to the host's stdout/stderr until
/// the guest exits, returning its exit code.
///
/// Enforces `timeout` by killing the guest on expiry — the SDK leaves timeout
/// enforcement to the stream driver, mirroring the buffered path's
/// `tokio::time::timeout` + kill.
async fn drive_stream(
    handle: &mut ExecHandle,
    timeout: Option<Duration>,
    stream_output: bool,
) -> anyhow::Result<i32> {
    let deadline = timeout.map(|d| tokio::time::Instant::now() + d);
    let mut stdout = tokio::io::stdout();
    let mut stderr = tokio::io::stderr();
    let mut captured_stdout = Vec::new();
    let mut captured_stderr = Vec::new();

    loop {
        let event = match deadline {
            Some(deadline) => match tokio::time::timeout_at(deadline, handle.recv()).await {
                Ok(event) => event,
                Err(_) => {
                    let _ = handle.kill().await;
                    let _ = tokio::time::timeout(Duration::from_secs(5), handle.collect()).await;
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
                if !stream_output {
                    captured_stdout.extend_from_slice(&data);
                    continue;
                }
                // A host write failure (e.g. a downstream `head` closed the
                // pipe) must not bypass cleanup: stop the guest and return so
                // the caller can stop the sandbox.
                if write_chunk(&mut stdout, &data).await.is_err() {
                    let _ = handle.kill().await;
                    return Ok(0);
                }
            }
            ExecEvent::Stderr(data) => {
                if !stream_output {
                    captured_stderr.extend_from_slice(&data);
                    continue;
                }
                if write_chunk(&mut stderr, &data).await.is_err() {
                    let _ = handle.kill().await;
                    return Ok(0);
                }
            }
            ExecEvent::Exited { code } => {
                if !stream_output {
                    std::io::stdout().write_all(&captured_stdout)?;
                    std::io::stderr().write_all(&captured_stderr)?;
                }
                return Ok(code);
            }
            ExecEvent::Failed(payload) => {
                return Err(microsandbox::MicrosandboxError::ExecFailed(payload).into());
            }
            ExecEvent::StdinError(err) => {
                // Match buffered collect(): an early guest stdin close is not
                // an error on the captured path. Keep streaming diagnostics.
                if stream_output {
                    ui::warn(&format!("failed to forward stdin to guest: {err:?}"));
                }
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

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clap::Parser;
    use clap::error::ErrorKind;

    use super::*;

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        args: ExecArgs,
    }

    fn parse_exec_args(args: &[&str]) -> ExecArgs {
        TestCli::parse_from(std::iter::once("msb").chain(args.iter().copied())).args
    }

    #[test]
    fn no_tty_parses_before_command_delimiter() {
        let args = parse_exec_args(&["box", "--no-tty", "--", "python3", "-c", "print('ok')"]);

        assert!(args.no_tty);
        assert_eq!(args.name, "box");
        assert_eq!(
            args.command,
            vec![
                "python3".to_string(),
                "-c".to_string(),
                "print('ok')".to_string()
            ]
        );
    }

    #[test]
    fn noninteractive_flags_conflict_with_tty() {
        for flag in ["--no-tty", "--no-stdin"] {
            let err = TestCli::try_parse_from(["msb", "--tty", flag, "box"]).unwrap_err();
            assert_eq!(err.kind(), ErrorKind::ArgumentConflict);
        }
    }
}
