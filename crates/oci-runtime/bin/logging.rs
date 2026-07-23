//! Logging setup and OCI runtime error log writing.

use std::fs;
use std::path::PathBuf;

use chrono::Utc;

use crate::cli::{LogFormat, LogLevel};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn init_tracing(debug: bool, log_level: Option<LogLevel>) {
    let default = match log_level {
        Some(LogLevel::Error) => "error",
        Some(LogLevel::Warning) => "warn",
        Some(LogLevel::Debug) => "debug",
        None if debug => "debug",
        None => "error",
    };
    let filter = tracing_subscriber::EnvFilter::try_from_default_env()
        .or_else(|_| tracing_subscriber::EnvFilter::try_new(default))
        .expect("valid tracing filter");
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .init();
}

pub(crate) fn write_runtime_error_log(path: Option<&PathBuf>, format: LogFormat, message: &str) {
    let Some(path) = path else {
        return;
    };
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    let line = match format {
        LogFormat::Json => serde_json::json!({
            "time": Utc::now().to_rfc3339(),
            "level": "error",
            "msg": message,
        })
        .to_string(),
        LogFormat::Text => format!(
            "time=\"{}\" level=error msg={:?}",
            Utc::now().to_rfc3339(),
            message
        ),
    };
    let _ = fs::write(path, format!("{line}\n"));
}
