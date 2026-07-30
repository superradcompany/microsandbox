//! `msb completion` command — generate shell completion scripts.

use std::io;

use clap::Args;
use clap_complete::Shell;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Generate a shell completion script for `msb`.
#[derive(Debug, Args)]
pub struct CompletionArgs {
    /// Shell to generate the completion script for.
    #[arg(value_enum)]
    pub shell: Shell,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Execute the `msb completion` command.
///
/// Writes the completion script for the requested shell to stdout so users
/// can redirect it to a directory their shell loads completions from, e.g.
/// `msb completion zsh > ~/.zsh/completions/_msb` (with that directory
/// added to `fpath` before `compinit` runs).
pub fn run(args: CompletionArgs, mut cmd: clap::Command) -> anyhow::Result<()> {
    let bin_name = cmd.get_name().to_string();
    clap_complete::generate(args.shell, &mut cmd, bin_name, &mut io::stdout());
    Ok(())
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
        args: CompletionArgs,
    }

    fn parse_completion_args(args: &[&str]) -> CompletionArgs {
        TestCli::parse_from(std::iter::once("msb").chain(args.iter().copied())).args
    }

    #[test]
    fn parses_each_supported_shell() {
        for (name, shell) in [
            ("bash", Shell::Bash),
            ("elvish", Shell::Elvish),
            ("fish", Shell::Fish),
            ("powershell", Shell::PowerShell),
            ("zsh", Shell::Zsh),
        ] {
            let args = parse_completion_args(&[name]);

            assert_eq!(args.shell, shell);
        }
    }

    #[test]
    fn rejects_unknown_shell() {
        let result = TestCli::try_parse_from(["msb", "tcsh"]);

        assert!(result.is_err());
    }
}
