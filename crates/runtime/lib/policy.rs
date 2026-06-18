//! Sandbox lifecycle policies.

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_types::SandboxPolicy;

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
