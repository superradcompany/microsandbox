//! Shared transport configuration and independent resource identity binding.

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn retained_context_shares_transport_without_rebinding_other_resources() {
        let context = RemoteContext::new("http://localhost:8123", "test-key").unwrap();
        let retained = context.clone_shared();
        assert!(Arc::ptr_eq(
            &context.inner,
            &retained.as_cloud().unwrap().inner
        ));
        let a = context
            .with_agent_identity("same-name", "identity-a")
            .unwrap();
        let b = context
            .with_agent_identity("same-name", "identity-b")
            .unwrap();
        assert!(context.agent_identity.is_none());
        assert_eq!(
            a.as_cloud().unwrap().agent_identity.as_ref().unwrap().1,
            "identity-a"
        );
        assert_eq!(
            b.as_cloud().unwrap().agent_identity.as_ref().unwrap().1,
            "identity-b"
        );
        assert!(Arc::ptr_eq(
            &a.as_cloud().unwrap().inner,
            &b.as_cloud().unwrap().inner
        ));
    }
}
