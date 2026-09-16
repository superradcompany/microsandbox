//! `msb ssh` command — connect to and serve sandboxes over SSH.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::Context;
use clap::{ArgGroup, Args, Subcommand};
use microsandbox::sandbox::{
    DEFAULT_SSH_HOST, DEFAULT_SSH_PORT, SshClientOptionsBuilder, SshServerOptionsBuilder,
    SshStdioStream,
};
use russh::keys::PublicKeyBase64;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

use crate::ui;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Connect to a sandbox over SSH.
#[derive(Debug, Args)]
#[command(args_conflicts_with_subcommands = true)]
pub struct SshArgs {
    /// Explicit sandbox name. Useful when the sandbox is named like a subcommand.
    #[arg(long)]
    pub name: Option<String>,

    /// Sandbox to connect to.
    pub sandbox: Option<String>,

    /// Remote command to run inside the sandbox (after --).
    #[arg(last = true)]
    pub remote_command: Vec<String>,

    /// SSH inactivity timeout options.
    #[command(flatten)]
    pub inactivity: SshInactivityTimeoutArgs,

    /// SSH subcommand.
    #[command(subcommand)]
    pub subcommand: Option<SshCommand>,
}

/// SSH subcommands.
#[derive(Debug, Subcommand)]
pub enum SshCommand {
    /// Connect to a sandbox over SSH.
    Connect(SshConnectArgs),

    /// Serve a sandbox over SSH.
    Serve(SshServeArgs),

    /// Add a public key to microsandbox SSH authorization.
    Authorize(SshAuthorizeArgs),
}

/// Arguments for `msb ssh connect`.
#[derive(Debug, Args)]
pub struct SshConnectArgs {
    /// Explicit sandbox name. Useful when the sandbox is named like a subcommand.
    #[arg(long)]
    pub name: Option<String>,

    /// Sandbox to connect to.
    pub sandbox: Option<String>,

    /// Remote command to run inside the sandbox (after --).
    #[arg(last = true)]
    pub remote_command: Vec<String>,

    /// SSH inactivity timeout options.
    #[command(flatten)]
    pub inactivity: SshInactivityTimeoutArgs,
}

/// Arguments for `msb ssh serve`.
#[derive(Debug, Args)]
pub struct SshServeArgs {
    /// Sandbox to serve.
    pub sandbox: String,

    /// Listener host.
    #[arg(long, conflicts_with = "stdio")]
    pub host: Option<String>,

    /// Listener port.
    #[arg(long, conflicts_with = "stdio")]
    pub port: Option<u16>,

    /// Serve one SSH transport over stdin/stdout.
    #[arg(long)]
    pub stdio: bool,

    /// SSH inactivity timeout options.
    #[command(flatten)]
    pub inactivity: SshInactivityTimeoutArgs,
}

/// Arguments controlling SSH session inactivity timeouts.
#[derive(Debug, Args)]
pub struct SshInactivityTimeoutArgs {
    /// Disconnect after this duration without SSH traffic. Use 0 to disable.
    #[arg(
        long,
        value_name = "DURATION",
        conflicts_with = "no_inactivity_timeout"
    )]
    pub inactivity_timeout: Option<String>,

    /// Disable the SSH session inactivity timeout.
    #[arg(long)]
    pub no_inactivity_timeout: bool,
}

/// Arguments for `msb ssh authorize`.
#[derive(Debug, Args)]
#[command(group(
    ArgGroup::new("source")
        .required(true)
        .args(["file", "key", "stdin"])
))]
pub struct SshAuthorizeArgs {
    /// Read a public key from this file.
    #[arg(long)]
    pub file: Option<PathBuf>,

    /// Public key string.
    #[arg(long)]
    pub key: Option<String>,

    /// Read a public key from stdin.
    #[arg(long)]
    pub stdin: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb ssh` command.
pub async fn run(args: SshArgs) -> anyhow::Result<()> {
    match args.subcommand {
        Some(SshCommand::Connect(connect)) => run_connect_args(connect).await,
        Some(SshCommand::Serve(args)) => run_serve(args).await,
        Some(SshCommand::Authorize(args)) => run_authorize(args),
        None => run_connect(args).await,
    }
}

async fn run_connect(args: SshArgs) -> anyhow::Result<()> {
    let inactivity_timeout = parse_inactivity_timeout(&args.inactivity)?;
    let mut remote_command = args.remote_command;
    let sandbox = match (args.name.as_ref(), args.sandbox) {
        (None, None)
            if remote_command
                .first()
                .is_some_and(|value| is_reserved_name(value)) =>
        {
            Some(remote_command.remove(0))
        }
        (_, sandbox) => sandbox,
    };
    let name = resolve_sandbox_name(args.name, sandbox)?;
    connect_to_sandbox(name, remote_command, inactivity_timeout).await
}

async fn run_connect_args(args: SshConnectArgs) -> anyhow::Result<()> {
    let inactivity_timeout = parse_inactivity_timeout(&args.inactivity)?;
    let name = resolve_sandbox_name(args.name, args.sandbox)?;
    connect_to_sandbox(name, args.remote_command, inactivity_timeout).await
}

async fn connect_to_sandbox(
    name: String,
    remote_command: Vec<String>,
    inactivity_timeout: Option<Option<Duration>>,
) -> anyhow::Result<()> {
    let sandbox = super::resolve_and_start(&name, false).await?;
    let result = async {
        let ssh = sandbox
            .ssh()
            .open_client_with(|builder| {
                apply_client_inactivity_timeout(builder, inactivity_timeout)
            })
            .await?;
        if remote_command.is_empty() {
            ssh.attach().await
        } else {
            let output = ssh.exec(remote_command.join(" ")).await?;
            let mut stdout = tokio::io::stdout();
            let mut stderr = tokio::io::stderr();
            stdout.write_all(&output.stdout).await?;
            stdout.flush().await?;
            stderr.write_all(&output.stderr).await?;
            stderr.flush().await?;
            Ok(output.status)
        }
    }
    .await;
    super::maybe_stop(&sandbox).await;

    let exit_code = result?;
    if exit_code != 0 {
        std::process::exit(exit_code);
    }
    Ok(())
}

async fn run_serve(args: SshServeArgs) -> anyhow::Result<()> {
    let inactivity_timeout = parse_inactivity_timeout(&args.inactivity)?;
    let sandbox = super::resolve_and_start(&args.sandbox, args.stdio).await?;
    let host = args.host.unwrap_or_else(|| DEFAULT_SSH_HOST.to_string());
    let port = args.port.unwrap_or(DEFAULT_SSH_PORT);

    let result = async {
        let server = sandbox
            .ssh()
            .prepare_server_with(|builder| {
                apply_server_inactivity_timeout(builder, inactivity_timeout)
            })
            .await?;
        if args.stdio {
            server.serve_connection(SshStdioStream::new()).await
        } else {
            let listener = TcpListener::bind((host.as_str(), port)).await?;
            let addr = listener.local_addr()?;
            ui::success("SSH listening", &addr.to_string());
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (stream, _) = accepted?;
                        let server = server.clone();
                        tokio::spawn(async move {
                            if let Err(error) = server.serve_connection(stream).await {
                                tracing::debug!(%error, "SSH connection failed");
                            }
                        });
                    }
                    signal = tokio::signal::ctrl_c() => {
                        signal?;
                        break Ok(());
                    }
                }
            }
        }
    }
    .await;
    super::maybe_stop(&sandbox).await;
    result.map_err(Into::into)
}

fn run_authorize(args: SshAuthorizeArgs) -> anyhow::Result<()> {
    let key_text = read_public_key_source(args)?;
    let (key_base64, line) = parse_public_key_line(&key_text)?;
    let local_backend = microsandbox::LocalBackend::lazy();
    let ssh_dir = local_backend.config().ssh_dir();
    create_secure_dir(&ssh_dir)?;
    let authorized_keys = ssh_dir.join("authorized_keys");

    let existing = std::fs::read_to_string(&authorized_keys).unwrap_or_default();
    for existing_line in existing.lines() {
        if let Ok((existing_base64, _)) = parse_public_key_line(existing_line)
            && existing_base64 == key_base64
        {
            ui::success("Already authorized", &authorized_keys.display().to_string());
            return Ok(());
        }
    }

    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&authorized_keys)
        .with_context(|| format!("failed to open {}", authorized_keys.display()))?;
    if !existing.is_empty() && !existing.ends_with('\n') {
        writeln!(file)?;
    }
    writeln!(file, "{line}")?;
    set_private_file_permissions(&authorized_keys)?;
    ui::success("Authorized key", &authorized_keys.display().to_string());
    Ok(())
}

fn resolve_sandbox_name(name: Option<String>, sandbox: Option<String>) -> anyhow::Result<String> {
    match (name, sandbox) {
        (Some(_), Some(_)) => {
            anyhow::bail!("use either --name or the sandbox positional, not both")
        }
        (Some(name), None) | (None, Some(name)) => Ok(name),
        (None, None) => anyhow::bail!("missing sandbox name"),
    }
}

fn is_reserved_name(value: &str) -> bool {
    matches!(value, "serve" | "authorize" | "help")
}

fn parse_inactivity_timeout(
    args: &SshInactivityTimeoutArgs,
) -> anyhow::Result<Option<Option<Duration>>> {
    if args.no_inactivity_timeout {
        return Ok(Some(None));
    }
    let Some(value) = &args.inactivity_timeout else {
        return Ok(None);
    };
    let timeout = super::common::parse_duration(value)
        .map_err(|error| anyhow::anyhow!("--inactivity-timeout: {error}"))?;
    Ok(Some((!timeout.is_zero()).then_some(timeout)))
}

fn apply_client_inactivity_timeout(
    builder: SshClientOptionsBuilder,
    timeout: Option<Option<Duration>>,
) -> SshClientOptionsBuilder {
    match timeout {
        Some(Some(timeout)) => builder.inactivity_timeout(timeout),
        Some(None) => builder.disable_inactivity_timeout(),
        None => builder,
    }
}

fn apply_server_inactivity_timeout(
    builder: SshServerOptionsBuilder,
    timeout: Option<Option<Duration>>,
) -> SshServerOptionsBuilder {
    match timeout {
        Some(Some(timeout)) => builder.inactivity_timeout(timeout),
        Some(None) => builder.disable_inactivity_timeout(),
        None => builder,
    }
}

fn read_public_key_source(args: SshAuthorizeArgs) -> anyhow::Result<String> {
    if let Some(path) = args.file {
        return std::fs::read_to_string(&path)
            .with_context(|| format!("failed to read {}", path.display()));
    }
    if let Some(key) = args.key {
        return Ok(key);
    }
    if args.stdin {
        let mut input = String::new();
        std::io::stdin()
            .read_to_string(&mut input)
            .context("failed to read public key from stdin")?;
        return Ok(input);
    }
    unreachable!("clap requires exactly one public key source")
}

fn parse_public_key_line(line: &str) -> anyhow::Result<(String, String)> {
    let line = line.trim();
    if line.is_empty() || line.starts_with('#') {
        anyhow::bail!("public key cannot be empty");
    }

    let mut parts = line.split_whitespace();
    let first = parts.next().context("public key cannot be empty")?;
    let key_part = if first.starts_with("ssh-") || first.starts_with("ecdsa-") {
        parts.next().context("public key is missing key data")?
    } else {
        first
    };
    let key = russh::keys::parse_public_key_base64(key_part).context("invalid public key")?;
    let canonical = if first.starts_with("ssh-") || first.starts_with("ecdsa-") {
        line.to_string()
    } else {
        key.to_openssh().context("failed to encode public key")?
    };
    Ok((key.public_key_base64(), canonical))
}

fn create_secure_dir(path: &Path) -> anyhow::Result<()> {
    std::fs::create_dir_all(path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

fn set_private_file_permissions(_path: &Path) -> anyhow::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(_path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn args(timeout: Option<&str>, disabled: bool) -> SshInactivityTimeoutArgs {
        SshInactivityTimeoutArgs {
            inactivity_timeout: timeout.map(str::to_string),
            no_inactivity_timeout: disabled,
        }
    }

    #[test]
    fn inactivity_timeout_inherits_when_unspecified() {
        assert_eq!(parse_inactivity_timeout(&args(None, false)).unwrap(), None);
    }

    #[test]
    fn inactivity_timeout_parses_duration() {
        assert_eq!(
            parse_inactivity_timeout(&args(Some("30m"), false)).unwrap(),
            Some(Some(Duration::from_secs(1800)))
        );
    }

    #[test]
    fn inactivity_timeout_zero_and_disable_flag_turn_it_off() {
        assert_eq!(
            parse_inactivity_timeout(&args(Some("0"), false)).unwrap(),
            Some(None)
        );
        assert_eq!(
            parse_inactivity_timeout(&args(None, true)).unwrap(),
            Some(None)
        );
    }

    #[test]
    fn inactivity_timeout_rejects_invalid_duration() {
        assert!(parse_inactivity_timeout(&args(Some("later"), false)).is_err());
    }
}
