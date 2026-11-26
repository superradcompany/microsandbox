//! Shared transport configuration and independent resource identity binding.

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::super::*;
    use reqwest::header::HeaderMap;

    #[test]
    fn remote_constructor_env_precedence() {
        // Process isolation also exercises omission when the developer has real credentials set.
        const CASE: &str = "MSB_TEST_REMOTE_ENV_CASE";
        let Ok(case) = std::env::var(CASE) else {
            for case in ["empty", "configured"] {
                let mut child = std::process::Command::new(std::env::current_exe().unwrap());
                child
                    .arg("remote_constructor_env_precedence")
                    .env(CASE, case)
                    .env_remove("MSB_API_KEY")
                    .env_remove("MSB_API_URL");
                if case == "configured" {
                    child
                        .env("MSB_API_KEY", "env-key")
                        .env("MSB_API_URL", "https://env.example/");
                }
                assert!(child.status().unwrap().success());
            }
            return;
        };
        if case == "empty" {
            assert_eq!(
                RemoteContext::new("key").unwrap().url(),
                DEFAULT_CLOUD_API_URL
            );
            assert!(RemoteContext::builder().build().is_err());
            return;
        }

        let shared = RemoteContext::builder()
            .compute_type(ComputeType::Shared)
            .build()
            .unwrap();
        assert_eq!(shared.url(), "https://env.example");
        assert_eq!(shared.inner.api_key, "env-key");
        assert_eq!(shared.inner.compute_type, Some(ComputeType::Shared));
        let key_only = RemoteContext::new("explicit").unwrap();
        assert_eq!(key_only.url(), shared.url());
        assert_eq!(key_only.inner.api_key, "explicit");
        let url_only = RemoteContext::builder()
            .url("https://provider.example")
            .build()
            .unwrap();
        assert_eq!(url_only.url(), "https://provider.example");
        assert_eq!(url_only.inner.api_key, "env-key");
        // A saved profile with no URL keeps its key on the hosted endpoint.
        let profile: crate::context::profile::Profile =
            serde_json::from_str(r#"{"kind":"remote","api_key_ref":"inline:profile-key"}"#)
                .unwrap();
        let profiled = profile.cloud_builder("test").unwrap().build().unwrap();
        assert_eq!(profiled.url(), DEFAULT_CLOUD_API_URL);
        assert_eq!(profiled.inner.api_key, "profile-key");

        assert!(RemoteContext::new(" ").is_err());
        assert!(RemoteContext::with_url(" ", "key").is_err());
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

    #[test]
    fn derivation_retains_captured_configuration_and_transport_options() {
        let directory = tempfile::tempdir().unwrap();
        let user = directory.path().join("config.json");
        let managed = directory.path().join("managed.json");
        std::fs::write(&user, r#"{"sandbox_defaults":{"cpus":4}}"#).unwrap();
        std::fs::write(&managed, r#"{"overrides":{"sandbox_defaults":{"cpus":2}}}"#).unwrap();
        let source = RemoteContext::builder()
            .url("https://original.example")
            .api_key("original-key")
            .request_timeout(Duration::from_secs(17))
            .user_agent("captured-agent")
            .config_sources(BackendConfig::load_from(&user, Some(&managed)).unwrap())
            .build()
            .unwrap()
            .with_selection_metadata(ContextSelectionSource::Profile, Some("original".into()));
        let retained = source.clone_shared();
        let mut bound = source.clone();
        bound.agent_identity = Some(("task".into(), "old-id".into()));
        let builder = bound.to_builder();
        // Neither profile/config changes nor a resource identity binding may leak into derivation.
        std::fs::write(&user, "invalid").unwrap();
        std::fs::write(&managed, "invalid").unwrap();
        let derived = builder
            .url("https://derived.example/")
            .api_key("derived-key")
            .build()
            .unwrap();
        assert_eq!(source.url(), "https://original.example");
        assert_eq!(retained.as_cloud().unwrap().inner.api_key, "original-key");
        assert_eq!(derived.url(), "https://derived.example");
        assert_eq!(derived.inner.api_key, "derived-key");
        assert_eq!(derived.inner.request_timeout, Duration::from_secs(17));
        assert_eq!(derived.inner.user_agent.as_deref(), Some("captured-agent"));
        assert_eq!(
            derived
                .config_sources()
                .resolved_config()
                .sandbox_defaults
                .cpus,
            2
        );
        assert!(Arc::ptr_eq(&source.inner.config, &derived.inner.config));
        assert!(!Arc::ptr_eq(&source.inner, &derived.inner));
        assert!(derived.agent_identity.is_none());
        assert!(derived.inner.profile.is_none());
        assert_eq!(
            derived.inner.selection_source,
            ContextSelectionSource::Programmatic
        );
        assert!(source.to_builder().url(" ").build().is_err());
        assert!(source.to_builder().api_key("bad\nkey").build().is_err());
        let unchanged = source.to_builder().build().unwrap();
        assert_eq!(unchanged.url(), source.url());
        assert_eq!(unchanged.inner.api_key, source.inner.api_key);
    }

    #[tokio::test]
    async fn derivation_uses_context_auth_even_with_a_custom_client() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            let mut requests = Vec::new();
            for _ in 0..4 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).await.unwrap();
                    bytes.push(byte[0]);
                }
                requests.push(String::from_utf8(bytes).unwrap().to_ascii_lowercase());
                socket.write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\nConnection: close\r\n\r\n{}").await.unwrap();
            }
            requests
        });
        for custom in [false, true] {
            let mut builder = RemoteContext::builder()
                .url(&url)
                .api_key("source-key")
                .user_agent("retained-agent")
                .config_sources(BackendConfig::new(Default::default(), Default::default()));
            if custom {
                let mut headers = HeaderMap::new();
                headers.insert(
                    reqwest::header::AUTHORIZATION,
                    HeaderValue::from_static("Bearer wrong-client-key"),
                );
                builder = builder.client(
                    reqwest::Client::builder()
                        .default_headers(headers)
                        .user_agent("custom-agent")
                        .build()
                        .unwrap(),
                );
            }
            let source = builder.build().unwrap();
            let derived = source
                .to_builder()
                .api_key("derived-key")
                .user_agent("derived-agent")
                .build()
                .unwrap();
            assert!(derived.get_sandbox("task").await.is_err());
            assert!(source.get_sandbox("task").await.is_err());
        }
        let requests = tokio::time::timeout(Duration::from_secs(10), server)
            .await
            .unwrap()
            .unwrap();
        for (index, request) in requests.iter().enumerate() {
            let key = if index % 2 == 0 {
                "derived-key"
            } else {
                "source-key"
            };
            assert!(request.contains(&format!("authorization: bearer {key}\r\n")));
            assert!(!request.contains("wrong-client-key"));
            let agent = match index {
                0 => "derived-agent",
                1 => "retained-agent",
                _ => "custom-agent",
            };
            assert!(request.contains(&format!("user-agent: {agent}\r\n")));
        }
    }

    #[test]
    fn binding_derivation_validates_overrides_without_exporting_secrets() {
        let source = RemoteContext::builder()
            .api_key("secret-key")
            .config_sources(BackendConfig::new(Default::default(), Default::default()))
            .build()
            .unwrap();
        let derived = crate::context::derive_remote_from_options_json(
            &source,
            r#"{"url":"https://derived.example","requestTimeoutMs":17,"userAgent":"new-agent"}"#,
        )
        .unwrap();
        let remote = derived.as_cloud().unwrap();
        assert_eq!(remote.url(), "https://derived.example");
        assert_eq!(remote.inner.api_key, "secret-key");
        assert_eq!(remote.inner.request_timeout, Duration::from_millis(17));
        for invalid in [
            r#"{"profile":"reload"}"#,
            r#"{"apiKey":""}"#,
            r#"{"requestTimeoutMs":-1}"#,
            r#"{"computeType":"turbo"}"#,
            r#"{"computeType":3}"#,
        ] {
            assert!(crate::context::derive_remote_from_options_json(&source, invalid).is_err());
        }
    }
    #[tokio::test]
    async fn derivation_applies_timeout_without_changing_the_original() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut socket, _) = listener.accept().await.unwrap();
                let mut bytes = Vec::new();
                while !bytes.ends_with(b"\r\n\r\n") {
                    let mut byte = [0];
                    socket.read_exact(&mut byte).await.unwrap();
                    bytes.push(byte[0]);
                }
                tokio::time::sleep(Duration::from_millis(100)).await;
                let body = r#"{"id":"test-id","org_id":"org","name":"task","slug":"task","status":"stopped","ephemeral":false,"created_at":"2026-11-16T00:00:00Z"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                // The first caller has already timed out; failure writing its response is expected.
                let _ = socket.write_all(response.as_bytes()).await;
            }
        });
        let source = RemoteContext::builder()
            .url(url)
            .api_key("fixture")
            .request_timeout(Duration::from_secs(2))
            .config_sources(BackendConfig::new(Default::default(), Default::default()))
            .build()
            .unwrap();
        let derived = source
            .to_builder()
            .request_timeout(Duration::from_millis(20))
            .build()
            .unwrap();
        assert!(derived.get_sandbox("task").await.is_err());
        assert!(source.get_sandbox("task").await.is_ok());
        tokio::time::timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
    }
}
