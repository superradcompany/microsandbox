//! `msb touch` command — explicitly refresh sandbox idle activity.

use clap::Args;
use microsandbox::sandbox::Sandbox;

use crate::ui;

use super::common;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Refresh the idle timer for one or more running sandboxes.
#[derive(Debug, Args)]
pub struct TouchArgs {
    /// Sandbox(es) to touch. Required unless `--label` is given.
    #[arg(required_unless_present = "label")]
    pub names: Vec<String>,

    /// Touch every sandbox carrying this label (`KEY=VALUE`). Repeatable;
    /// AND-matched. Unioned with any explicitly named sandboxes.
    #[arg(long)]
    pub label: Vec<String>,

    /// Suppress progress output.
    #[arg(short, long)]
    pub quiet: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb touch` command.
pub async fn run(args: TouchArgs) -> anyhow::Result<()> {
    let names = common::resolve_bulk_targets(&args.names, &args.label, args.quiet).await?;
    let mut failed = false;

    for name in &names {
        match touch_one(name, args.quiet).await {
            Ok(()) => {}
            Err(e) => {
                if !args.quiet {
                    ui::error(&format!("{e}"));
                }
                failed = true;
            }
        }
    }

    if failed {
        std::process::exit(1);
    }

    Ok(())
}

async fn touch_one(name: &str, quiet: bool) -> anyhow::Result<()> {
    let handle = Sandbox::get(name).await?;
    let spinner = if quiet {
        ui::Spinner::quiet()
    } else {
        ui::Spinner::start("Touching", name)
    };

    match handle.touch().await {
        Ok(_) => {
            spinner.finish_success("Touched");
            Ok(())
        }
        Err(e) => {
            spinner.finish_clear();
            Err(e.into())
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use clap::Parser;

    use super::*;

    #[derive(Parser)]
    struct TestCli {
        #[command(flatten)]
        args: TouchArgs,
    }

    fn parse_touch_args(args: &[&str]) -> TouchArgs {
        TestCli::parse_from(std::iter::once("msb").chain(args.iter().copied())).args
    }

    #[test]
    fn parses_one_name() {
        let args = parse_touch_args(&["api"]);

        assert_eq!(args.names, vec!["api"]);
    }

    #[test]
    fn parses_label_and_quiet() {
        let args = parse_touch_args(&["--label", "app=api", "--quiet"]);

        assert!(args.names.is_empty());
        assert_eq!(args.label, vec!["app=api"]);
        assert!(args.quiet);
    }
}
