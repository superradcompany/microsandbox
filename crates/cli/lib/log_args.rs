//! Shared CLI verbosity flags for `msb` and its hidden runtime subcommands.

use clap::Args;
use microsandbox_runtime::logging::LogLevel;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::filter::Directive;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Mutually-exclusive tracing verbosity flags.
#[derive(Debug, Clone, Default, Args)]
pub struct LogArgs {
    /// Show error-level diagnostic logs.
    #[arg(long, global = true, conflicts_with_all = ["warn", "info", "debug", "trace"])]
    pub error: bool,

    /// Show warning and error diagnostic logs.
    #[arg(long, global = true, conflicts_with_all = ["error", "info", "debug", "trace"])]
    pub warn: bool,

    /// Show info, warning, and error diagnostic logs.
    #[arg(long, global = true, conflicts_with_all = ["error", "warn", "debug", "trace"])]
    pub info: bool,

    /// Show debug and higher diagnostic logs.
    #[arg(long, global = true, conflicts_with_all = ["error", "warn", "info", "trace"])]
    pub debug: bool,

    /// Show all diagnostic logs (most verbose).
    #[arg(long, global = true, conflicts_with_all = ["error", "warn", "info", "debug"])]
    pub trace: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Install a tracing subscriber for the selected level.
///
/// `ansi` controls whether the formatter emits color escape sequences.
/// Pass `true` for the user-facing CLI (colored output on a TTY) and
/// `false` for the sandbox subprocess (whose stderr is captured into
/// `runtime.log`, where escape codes would be junk).
///
/// If no level is selected, logging stays disabled.
pub fn init_tracing(log_level: Option<LogLevel>, ansi: bool) {
    if let Some(level) = log_level {
        // Silence oci_client logs — the crate logs the auth token in debug mode
        // See: https://github.com/oras-project/rust-oci-client/issues/254
        let filter = EnvFilter::new(level.as_tracing_level().to_string())
            .add_directive("oci_client=info".parse::<Directive>().unwrap());

        tracing_subscriber::fmt()
            .with_writer(std::io::stderr)
            .with_env_filter(filter)
            .with_ansi(ansi)
            .init();
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LogArgs {
    /// Return the selected log level, if any.
    pub const fn selected_level(&self) -> Option<LogLevel> {
        if self.error {
            Some(LogLevel::Error)
        } else if self.warn {
            Some(LogLevel::Warn)
        } else if self.info {
            Some(LogLevel::Info)
        } else if self.debug {
            Some(LogLevel::Debug)
        } else if self.trace {
            Some(LogLevel::Trace)
        } else {
            None
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{Parser, Subcommand};

    #[derive(Debug, Parser)]
    struct TestCli {
        #[command(flatten)]
        logs: LogArgs,

        #[command(subcommand)]
        command: TestCommand,
    }

    #[derive(Debug, Subcommand)]
    enum TestCommand {
        Sandbox,
        Run,
    }

    #[test]
    fn test_global_log_flag_after_subcommand() {
        let cli = TestCli::parse_from(["msb", "run", "--debug"]);
        assert_eq!(cli.logs.selected_level(), Some(LogLevel::Debug));
    }

    #[test]
    fn test_no_log_flag_means_silent() {
        let cli = TestCli::parse_from(["msb", "sandbox"]);
        assert_eq!(cli.logs.selected_level(), None);
    }

    #[test]
    fn test_log_flags_conflict() {
        let err = TestCli::try_parse_from(["msb", "--info", "--debug", "sandbox"]).unwrap_err();
        let rendered = err.to_string();
        assert!(rendered.contains("--debug"));
        assert!(rendered.contains("--info"));
    }
}
