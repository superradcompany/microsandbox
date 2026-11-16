//! Shared transport configuration and independent resource identity binding.

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::*;

    #[test]
    fn constructors_select_hosted_or_explicit_endpoint() {
        let hosted = RemoteContext::new("test-key").unwrap();
        assert_eq!(hosted.url(), DEFAULT_CLOUD_API_URL);
        let custom = RemoteContext::with_url("https://provider.example/", "test-key").unwrap();
        assert_eq!(custom.url(), "https://provider.example");
        assert!(RemoteContext::new(" ").is_err());
        assert!(RemoteContext::with_url(" ", "test-key").is_err());
    }

    #[test]
    fn retained_context_shares_transport_without_rebinding_other_resources() {
        let context = RemoteContext::with_url("http://localhost:8123", "test-key").unwrap();
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
