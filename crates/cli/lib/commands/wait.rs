//! `msb wait` command — wait for a sandbox to reach a terminal state.

use std::time::Duration;

use clap::Args;
use microsandbox::sandbox::{Sandbox, SandboxStatus, SandboxStopResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Wait for a sandbox to stop or crash.
#[derive(Debug, Args)]
pub struct WaitArgs {
    /// Sandbox to wait for.
    pub name: String,

    /// Stop waiting after this duration (e.g. 30s, 5m, 1h).
    #[arg(long)]
    pub timeout: Option<String>,

    /// Output format (json).
    #[arg(long, value_name = "FORMAT", value_parser = ["json"])]
    pub format: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb wait` command.
pub async fn run(args: WaitArgs) -> anyhow::Result<()> {
    let wait = async {
        let handle = Sandbox::get(&args.name).await?;
        anyhow::Ok(handle.wait_until_stopped().await?)
    };
    let result = if let Some(timeout) = args.timeout.as_deref() {
        tokio::time::timeout(parse_timeout(timeout)?, wait)
            .await
            .map_err(|_| anyhow::anyhow!("timed out waiting for sandbox '{}'", args.name))??
    } else {
        wait.await?
    };

    print_result(&result, args.format.as_deref() == Some("json"))?;
    Ok(())
}

fn parse_timeout(value: &str) -> anyhow::Result<Duration> {
    super::common::parse_duration(value)
}

fn is_terminal(status: SandboxStatus) -> bool {
    matches!(status, SandboxStatus::Stopped | SandboxStatus::Crashed)
}

fn print_result(result: &SandboxStopResult, json: bool) -> anyhow::Result<()> {
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&wait_result_json(result))?
        );
    } else {
        println!("{} {:?}", result.name, result.status);
    }
    Ok(())
}

fn wait_result_json(result: &SandboxStopResult) -> serde_json::Value {
    serde_json::json!({
        "name": result.name,
        "status": format!("{:?}", result.status),
        "terminal": is_terminal(result.status),
        "exit_code": result.exit_code,
        "signal": result.signal,
        "observed_at": result.observed_at.to_rfc3339(),
        "source": result.source,
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use clap::Parser;
    use microsandbox::sandbox::SandboxStatus;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: WaitArgs,
    }

    fn parse_wait_args(args: &[&str]) -> WaitArgs {
        TestCli::parse_from(std::iter::once("msb").chain(args.iter().copied())).args
    }

    #[test]
    fn parses_timeout_and_json_format() {
        let args = parse_wait_args(&["worker", "--timeout", "30s", "--format", "json"]);

        assert_eq!(args.name, "worker");
        assert_eq!(args.timeout.as_deref(), Some("30s"));
        assert_eq!(args.format.as_deref(), Some("json"));
    }

    #[test]
    fn parses_human_duration() {
        assert_eq!(
            parse_timeout("1500ms").unwrap(),
            Duration::from_millis(1500)
        );
        assert_eq!(parse_timeout("2m").unwrap(), Duration::from_secs(120));
    }

    #[test]
    fn classifies_only_stopped_and_crashed_as_terminal() {
        assert!(is_terminal(SandboxStatus::Stopped));
        assert!(is_terminal(SandboxStatus::Crashed));
        assert!(!is_terminal(SandboxStatus::Running));
        assert!(!is_terminal(SandboxStatus::Paused));
    }

    #[test]
    fn renders_terminal_result_as_json() {
        let result = SandboxStopResult {
            name: "worker".to_string(),
            status: SandboxStatus::Crashed,
            exit_code: Some(137),
            signal: Some(9),
            observed_at: "2026-08-18T09:30:00Z".parse().unwrap(),
            source: Some("owned process".to_string()),
        };
        let json = wait_result_json(&result);

        assert_eq!(
            json,
            serde_json::json!({
                "name": "worker",
                "status": "Crashed",
                "terminal": true,
                "exit_code": 137,
                "signal": 9,
                "observed_at": "2026-08-18T09:30:00+00:00",
                "source": "owned process",
            })
        );
    }
}
