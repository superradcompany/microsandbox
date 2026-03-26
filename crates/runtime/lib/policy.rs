//! Sandbox lifecycle policies.

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Sandbox lifecycle policy.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct SandboxPolicy {
    /// Hard cap on total sandbox lifetime in seconds. `None` = run forever.
    pub max_duration_secs: Option<u64>,

    /// Idle timeout in seconds. `None` = no idle detection.
    pub idle_timeout_secs: Option<u64>,
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn serde_roundtrip() {
        let policy = SandboxPolicy {
            max_duration_secs: Some(3600),
            idle_timeout_secs: Some(120),
        };

        let json = serde_json::to_string(&policy).unwrap();
        let decoded: SandboxPolicy = serde_json::from_str(&json).unwrap();

        assert_eq!(decoded.max_duration_secs, Some(3600));
        assert_eq!(decoded.idle_timeout_secs, Some(120));
    }

    #[test]
    fn default_policy() {
        let policy = SandboxPolicy::default();
        assert!(policy.max_duration_secs.is_none());
        assert!(policy.idle_timeout_secs.is_none());
    }
}
