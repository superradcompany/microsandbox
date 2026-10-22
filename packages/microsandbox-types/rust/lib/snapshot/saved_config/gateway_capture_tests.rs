//! Capture must retain gateway semantics without exporting source-host resource ownership.

use serde::Serialize;
use serde_json::json;

use crate::{
    DnsConfig, InterceptCaConfig, OutboundProxy, PortProtocol, PublishedPortSpec,
    ScopedUpstreamCaCert, ScopedVerifyUpstream, SecretSource, SnapshotManifestResult,
    Socks5Credentials, TlsConfig,
};

use super::*;

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn resolver_projection_preserves_order_policy_and_zero_without_source_addresses() {
    let source = DnsConfig {
        rebind_protection: false,
        nameservers: vec!["SENTINEL_FIRST:53".into(), "SENTINEL_SECOND:5353".into()],
        query_timeout_ms: 0,
    };
    let before = serde_json::to_value(&source).unwrap();
    let saved = SavedDnsConfig::from_source(&source, vec![binding("z"), binding("a")]).unwrap();
    assert_eq!(
        portable(&saved),
        json!({
            "rebind_protection":false, "query_timeout_ms":0,
            "resolvers":[{"id":"z"},{"id":"a"}]
        })
    );
    assert_eq!(serde_json::to_value(&source).unwrap(), before);
}

#[test]
fn resolver_capture_refuses_missing_extra_duplicate_and_invalid_bindings() {
    let source = DnsConfig {
        nameservers: vec!["SENTINEL_RESOLVER".into()],
        ..Default::default()
    };
    for bindings in [vec![], vec![binding("one"), binding("two")]] {
        rejected(
            SavedDnsConfig::from_source(&source, bindings),
            "SCFG_BINDING",
        );
    }
    rejected(
        SavedDnsConfig::from_source(&source, vec![binding("/SENTINEL_PATH")]),
        "SCFG_BINDING",
    );
    rejected(
        SavedDnsConfig::from_source(
            &DnsConfig {
                nameservers: vec!["SENTINEL_ONE".into(), "SENTINEL_TWO".into()],
                ..Default::default()
            },
            vec![binding("same"), binding("same")],
        ),
        "SCFG_IDENTITY",
    );
}

#[test]
fn source_resolver_discovery_does_not_become_a_host_configuration_lookup() {
    let saved = SavedDnsConfig::from_source(&DnsConfig::default(), vec![]).unwrap();
    assert!(saved.resolvers.is_empty());
    rejected(
        SavedDnsConfig::from_source(&DnsConfig::default(), vec![binding("unexpected")]),
        "SCFG_BINDING",
    );
}

#[test]
fn all_proxy_protocols_preserve_authentication_presence_and_exclude_material() {
    let cases = [
        (
            OutboundProxy::HttpConnect {
                address: "SENTINEL_HTTP:80".into(),
            },
            SavedProxyProtocol::HttpConnect,
            false,
        ),
        (
            OutboundProxy::Socks4 {
                address: "SENTINEL_SOCKS4:1080".into(),
                user_id: None,
            },
            SavedProxyProtocol::Socks4,
            false,
        ),
        (
            OutboundProxy::Socks4 {
                address: "SENTINEL_SOCKS4:1080".into(),
                user_id: Some("SENTINEL_USER".into()),
            },
            SavedProxyProtocol::Socks4,
            true,
        ),
        (
            OutboundProxy::Socks4 {
                address: "SENTINEL_SOCKS4:1080".into(),
                user_id: Some(String::new()),
            },
            SavedProxyProtocol::Socks4,
            true,
        ),
        (
            OutboundProxy::Socks5 {
                address: "SENTINEL_SOCKS5:1080".into(),
                credentials: None,
            },
            SavedProxyProtocol::Socks5,
            false,
        ),
        (
            OutboundProxy::Socks5 {
                address: "SENTINEL_SOCKS5:1080".into(),
                credentials: Some(Socks5Credentials {
                    username: "SENTINEL_USERNAME".into(),
                    password: SecretSource::env("SENTINEL_PASSWORD_SOURCE"),
                }),
            },
            SavedProxyProtocol::Socks5,
            true,
        ),
    ];
    for (source, protocol, authenticated) in cases {
        let before = serde_json::to_value(&source).unwrap();
        let saved = SavedProxy::from_source(
            &source,
            binding("proxy"),
            authenticated.then(|| binding("credential")),
        )
        .unwrap();
        assert_eq!(saved.protocol, protocol);
        assert_eq!(saved.credentials.is_some(), authenticated);
        portable(&saved);
        assert_eq!(serde_json::to_value(&source).unwrap(), before);
        // A caller cannot lose authentication or introduce a new mode by
        // accidentally supplying the wrong set of logical replacements.
        rejected(
            SavedProxy::from_source(
                &source,
                binding("proxy"),
                (!authenticated).then(|| binding("credential")),
            ),
            "SCFG_BINDING",
        );
    }
}

#[test]
fn proxy_bindings_reject_endpoint_syntax_and_secret_source_names() {
    let source = OutboundProxy::Socks5 {
        address: "SENTINEL:1080".into(),
        credentials: Some(Socks5Credentials {
            username: "SENTINEL".into(),
            password: SecretSource::env("SENTINEL"),
        }),
    };
    for (endpoint, credentials) in [
        ("/SENTINEL/endpoint", "credential"),
        ("proxy", "${SENTINEL}"),
    ] {
        rejected(
            SavedProxy::from_source(&source, binding(endpoint), Some(binding(credentials))),
            "SCFG_BINDING",
        );
    }
}

#[test]
fn listener_capture_keeps_guest_service_without_transferring_host_port() {
    for protocol in [PortProtocol::Tcp, PortProtocol::Udp] {
        let source = PublishedPortSpec {
            host_port: 54321,
            host_bind: "SENTINEL_SOURCE_HOST".into(),
            guest_port: 8080,
            protocol,
        };
        let saved = SavedPublishedPort::from_source(&source, binding("listener")).unwrap();
        let json = portable(&saved);
        assert_eq!(json["guest_port"], 8080);
        assert!(json.get("host_port").is_none());
        assert!(json.get("host_bind").is_none());
        assert_eq!(saved.protocol, protocol);
        rejected(
            SavedPublishedPort::from_source(&source, binding("SENTINEL:54321")),
            "SCFG_BINDING",
        );
    }
}

#[test]
fn tls_capture_preserves_order_and_relaxations_without_keys_paths_or_cache() {
    let source = tls_source();
    let before = serde_json::to_value(&source).unwrap();
    let saved = SavedTlsConfig::from_source(&source, tls_bindings()).unwrap();
    let value = portable(&saved);
    assert_eq!(value["verify_upstream"], false);
    assert_eq!(value["block_quic_on_intercept"], false);
    assert_eq!(value["bypass"], json!(["second.example", "first.example"]));
    assert_eq!(value["intercepted_ports"], json!([8443, 443]));
    assert_eq!(value["upstream_cas"], json!([{"id":"z"},{"id":"a"}]));
    assert_eq!(
        value["scoped_upstream_cas"],
        json!([
            {"pattern":"*.second.example","binding":{"id":"scoped.z"}},
            {"pattern":"first.example","binding":{"id":"scoped.a"}}
        ])
    );
    assert_eq!(
        value["scoped_verify_upstream"],
        json!([
            {"pattern":"*.second.example","verify":false},
            {"pattern":"first.example","verify":true}
        ])
    );
    assert_eq!(value["intercept_ca"], json!({"id":"identity"}));
    assert!(value.get("cache").is_none());
    assert_eq!(serde_json::to_value(&source).unwrap(), before);
    // The helper succeeds with nonexistent source paths: it neither loads
    // credential material nor treats the paths as portable fallback inputs.
}

#[test]
fn tls_capture_requires_binding_for_generated_and_configured_identities() {
    let mut source = TlsConfig::default();
    SavedTlsConfig::from_source(&source, SavedTlsCaptureBindings::default()).unwrap();

    source.enabled = true;
    rejected(
        SavedTlsConfig::from_source(&source, SavedTlsCaptureBindings::default()),
        "SCFG_BINDING",
    );
    let saved = SavedTlsConfig::from_source(
        &source,
        SavedTlsCaptureBindings {
            intercept_ca: Some(binding("generated.identity")),
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(
        portable(&saved)["intercept_ca"],
        json!({"id":"generated.identity"})
    );

    source.enabled = false;
    for cert_only in [true, false] {
        source.intercept_ca = InterceptCaConfig {
            cert_path: cert_only.then(|| "/SENTINEL/cert".into()),
            key_path: (!cert_only).then(|| "/SENTINEL/key".into()),
        };
        rejected(
            SavedTlsConfig::from_source(&source, SavedTlsCaptureBindings::default()),
            "SCFG_BINDING",
        );
    }
}

#[test]
fn tls_capture_refuses_partial_bindings_and_malformed_policy() {
    for family in 0..3 {
        let mut bindings = tls_bindings();
        match family {
            0 => bindings.upstream_cas.clear(),
            1 => bindings.scoped_upstream_cas.push(binding("extra")),
            _ => bindings.intercept_ca = None,
        }
        rejected(
            SavedTlsConfig::from_source(&tls_source(), bindings),
            "SCFG_BINDING",
        );
    }
    let mut source = tls_source();
    source.scoped_upstream_ca_cert[0].pattern = "SENTINEL\n".into();
    rejected(
        SavedTlsConfig::from_source(&source, tls_bindings()),
        "SCFG_VALUE",
    );
    let mut bindings = tls_bindings();
    bindings.upstream_cas[1] = binding("z");
    rejected(
        SavedTlsConfig::from_source(&tls_source(), bindings),
        "SCFG_IDENTITY",
    );
}

#[test]
fn capture_checks_bounds_and_document_binding_kinds_before_acceptance() {
    let source = DnsConfig {
        nameservers: vec!["SENTINEL".into(); MAX_SAVED_CONFIG_ENTRIES + 1],
        ..Default::default()
    };
    rejected(SavedDnsConfig::from_source(&source, vec![]), "SCFG_LIMIT");

    let mut source = tls_source();
    source.bypass = vec!["SENTINEL".into(); MAX_SAVED_CONFIG_ENTRIES + 1];
    rejected(
        SavedTlsConfig::from_source(&source, tls_bindings()),
        "SCFG_LIMIT",
    );
    // Individual projections are not whole-document admission. Two valid
    // projections must not reuse an ID for incompatible destination types.
    let config = SavedSandboxConfig {
        schema_version: SAVED_CONFIG_SCHEMA_VERSION,
        active: SavedActiveConfig {
            network: SavedNetworkConfig {
                dns: Some(observed(
                    SavedDnsConfig::from_source(
                        &DnsConfig {
                            nameservers: vec!["SENTINEL".into()],
                            ..Default::default()
                        },
                        vec![binding("shared")],
                    )
                    .unwrap(),
                )),
                ports: Some(observed(vec![
                    SavedPublishedPort::from_source(
                        &PublishedPortSpec {
                            host_port: 0,
                            host_bind: "SENTINEL".into(),
                            guest_port: 80,
                            protocol: PortProtocol::Tcp,
                        },
                        binding("shared"),
                    )
                    .unwrap(),
                ])),
                ..Default::default()
            },
            ..Default::default()
        },
        bindings: Default::default(),
        provenance: SavedCaptureProvenance {
            producer_version: "test".into(),
            source_name: None,
            active_generation: observed("generation".into()),
            construction_resources: None,
        },
        pending: None,
    };
    let error = config.validate().unwrap_err().to_string();
    assert!(error.contains("incompatible destination kinds"), "{error}");
    assert!(!error.contains("SENTINEL"), "{error}");
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn binding(id: &str) -> SavedBindingReference {
    SavedBindingReference { id: id.into() }
}

fn observed<T>(value: T) -> SavedValue<T> {
    SavedValue::Value {
        value,
        origin: SavedOrigin::Observed,
    }
}

fn portable(value: &impl Serialize) -> serde_json::Value {
    let bytes = serde_json::to_vec(value).unwrap();
    assert!(!String::from_utf8_lossy(&bytes).contains("SENTINEL"));
    serde_json::from_slice(&bytes).unwrap()
}

fn rejected<T>(result: SnapshotManifestResult<T>, code: &str) {
    let error = result.err().expect("capture must reject").to_string();
    assert!(error.contains(code), "{error}");
    assert!(!error.contains("SENTINEL"), "{error}");
}

fn tls_source() -> TlsConfig {
    TlsConfig {
        enabled: true,
        intercepted_ports: vec![8443, 443],
        bypass: vec!["second.example".into(), "first.example".into()],
        verify_upstream: false,
        block_quic_on_intercept: false,
        upstream_ca_cert: vec!["/SENTINEL/upstream.z".into(), "/SENTINEL/upstream.a".into()],
        scoped_upstream_ca_cert: vec![
            ScopedUpstreamCaCert {
                pattern: "*.second.example".into(),
                path: "/SENTINEL/scoped.z".into(),
            },
            ScopedUpstreamCaCert {
                pattern: "first.example".into(),
                path: "/SENTINEL/scoped.a".into(),
            },
        ],
        scoped_verify_upstream: vec![
            ScopedVerifyUpstream {
                pattern: "*.second.example".into(),
                verify: false,
            },
            ScopedVerifyUpstream {
                pattern: "first.example".into(),
                verify: true,
            },
        ],
        intercept_ca: InterceptCaConfig {
            cert_path: Some("/SENTINEL/identity.crt".into()),
            key_path: Some("/SENTINEL/identity.key".into()),
        },
        ..Default::default()
    }
}

fn tls_bindings() -> SavedTlsCaptureBindings {
    SavedTlsCaptureBindings {
        upstream_cas: vec![binding("z"), binding("a")],
        scoped_upstream_cas: vec![binding("scoped.z"), binding("scoped.a")],
        intercept_ca: Some(binding("identity")),
    }
}
