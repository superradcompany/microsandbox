//! Cargo-installed `microsandbox` wrapper for the `msb` executable.

use std::{
    path::PathBuf,
    process::{Command, ExitCode},
};

use microsandbox::{
    config::LocalConfig,
    setup::{EnsureOptions, ensure_runtime},
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn main() -> ExitCode {
    let runtime = match tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .and_then(|runtime| {
            runtime
                .block_on(ensure_runtime(
                    &LocalConfig::default(),
                    EnsureOptions::default(),
                ))
                .map_err(std::io::Error::other)
        }) {
        Ok(runtime) => runtime,
        Err(error) => {
            eprintln!("microsandbox: failed to prepare runtime: {error}");
            return ExitCode::from(127);
        }
    };

    forward(runtime.msb_path)
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

#[cfg(unix)]
fn forward(msb: PathBuf) -> ExitCode {
    use std::os::unix::process::CommandExt;

    let error = Command::new(&msb).args(std::env::args_os().skip(1)).exec();
    eprintln!("microsandbox: failed to exec {}: {error}", msb.display());
    ExitCode::from(127)
}

#[cfg(not(unix))]
fn forward(msb: PathBuf) -> ExitCode {
    match Command::new(&msb)
        .args(std::env::args_os().skip(1))
        .status()
    {
        Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
        Err(error) => {
            eprintln!("microsandbox: failed to run {}: {error}", msb.display());
            ExitCode::from(127)
        }
    }
}
