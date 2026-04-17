//! Thin shim that forwards all arguments to the installed `msb` binary.
//!
//! Resolution order:
//! 1. `MSB_PATH` environment variable
//! 2. `~/.microsandbox/bin/msb` (populated by `build.rs`)

use std::env;
use std::path::PathBuf;
use std::process::{Command, ExitCode};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn main() -> ExitCode {
    let msb = match resolve_msb() {
        Some(p) => p,
        None => {
            eprintln!(
                "microsandbox: msb binary not found. Set MSB_PATH or ensure \
                 ~/.microsandbox/bin/msb exists."
            );
            return ExitCode::from(127);
        }
    };

    let args: Vec<_> = env::args_os().skip(1).collect();

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new(&msb).args(&args).exec();
        eprintln!("microsandbox: failed to exec {}: {err}", msb.display());
        ExitCode::from(127)
    }

    #[cfg(not(unix))]
    {
        match Command::new(&msb).args(&args).status() {
            Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
            Err(err) => {
                eprintln!("microsandbox: failed to run {}: {err}", msb.display());
                ExitCode::from(127)
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn resolve_msb() -> Option<PathBuf> {
    if let Ok(path) = env::var("MSB_PATH") {
        return Some(PathBuf::from(path));
    }
    let home = env::var("HOME").ok()?;
    let path = PathBuf::from(home)
        .join(".microsandbox")
        .join("bin")
        .join("msb");
    path.is_file().then_some(path)
}
