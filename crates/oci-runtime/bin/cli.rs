//! Command-line parsing for the `microsandbox-runtime` binary.

use std::path::PathBuf;

use clap::{Parser, ValueEnum};

use crate::commands::Command;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// OCI Runtime Specification-compatible runtime for Microsandbox.
#[derive(Debug, Parser)]
#[command(name = "microsandbox-runtime", version)]
pub(crate) struct Cli {
    /// Root directory for OCI runtime state.
    #[arg(short = 'r', long, global = true, value_name = "DIR", default_value = default_root())]
    pub(crate) root: PathBuf,

    /// Enable debug logging.
    #[arg(long, global = true)]
    pub(crate) debug: bool,

    /// Log file path used by Docker/containerd for runtime diagnostics.
    #[arg(short = 'l', long, global = true, value_name = "FILE")]
    pub(crate) log: Option<PathBuf>,

    /// Log format expected by the caller.
    #[arg(long, global = true, value_enum, default_value_t = LogFormat::Text)]
    pub(crate) log_format: LogFormat,

    /// Log level expected by crun-compatible callers.
    #[arg(long, global = true, value_enum)]
    pub(crate) log_level: Option<LogLevel>,

    /// Accept crun-compatible cgroup manager selection.
    #[arg(long, global = true, value_name = "MANAGER")]
    pub(crate) cgroup_manager: Option<String>,

    /// Accept runc/youki-compatible systemd cgroup flag.
    #[arg(short = 's', long, global = true)]
    pub(crate) systemd_cgroup: bool,

    /// Accept runc-compatible rootless mode flag.
    #[arg(long, global = true, value_name = "MODE")]
    pub(crate) rootless: Option<String>,

    /// OCI lifecycle command.
    #[command(subcommand)]
    pub(crate) command: Command,
}

/// Runtime log format.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum LogFormat {
    /// Human-readable text logs.
    Text,

    /// JSON log records.
    Json,
}

/// Runtime log level.
#[derive(Debug, Clone, Copy, ValueEnum)]
pub(crate) enum LogLevel {
    /// Error-level diagnostics only.
    Error,

    /// Warning-level diagnostics.
    Warning,

    /// Debug-level diagnostics.
    Debug,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn default_root() -> &'static str {
    "/run/microsandbox-runtime"
}
