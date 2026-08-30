//! Logging contracts shared by runtime clients and the VM runner.

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::LogLevel;

    #[test]
    fn test_log_level_display_values() {
        assert_eq!(LogLevel::Error.to_string(), "error");
        assert_eq!(LogLevel::Warn.to_string(), "warn");
        assert_eq!(LogLevel::Info.to_string(), "info");
        assert_eq!(LogLevel::Debug.to_string(), "debug");
        assert_eq!(LogLevel::Trace.to_string(), "trace");
    }
}

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::SandboxLogLevel as LogLevel;

#[cfg(feature = "runner")]
pub use crate::runner::logging::RotatingLog;
