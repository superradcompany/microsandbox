//! Integration tests for the HTTP/HTTPS `403 Forbidden` answer the gateway
//! returns when egress is denied by a domain rule.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --tests --run-ignored=only

use microsandbox::sandbox::HttpDenyResponseFormat;
use microsandbox::{NetworkPolicy, Sandbox};
use microsandbox_network::policy::Rule;
use test_utils::msb_test;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Image with `curl` preinstalled; no package mirror needs allowing.
const CURL_IMAGE: &str = "mirror.gcr.io/curlimages/curl";

/// A public name the sandbox can resolve but is never allowed to reach.
const DENIED_HOST: &str = "example.com";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Deny-by-default egress with gateway DNS open, so the guest resolves
/// `DENIED_HOST` and the deny lands at the TCP/TLS proxy instead of as
/// NXDOMAIN.
fn dns_only_policy() -> NetworkPolicy {
    let mut policy = NetworkPolicy::none();
    policy.rules.push(Rule::allow_dns());
    policy
}

async fn spawn(
    name: &str,
    tls: bool,
    enabled: bool,
    message: Option<&str>,
    format: HttpDenyResponseFormat,
) -> Sandbox {
    let message = message.map(str::to_owned);
    Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .network(move |mut n| {
            n = n.policy(dns_only_policy());
            // JSON cases exercise the defaults, without configuring HTTP at all.
            if !enabled {
                n = n.http(|h| h.deny_response(false));
            }
            if format == HttpDenyResponseFormat::Text {
                n = n.http(|h| h.deny_response_format(format));
            }
            if tls {
                n = n.tls(|t| t.enabled(true));
            }
            if let Some(message) = message {
                n = n.http(|h| match format {
                    HttpDenyResponseFormat::Text => h.deny_message(message),
                    HttpDenyResponseFormat::Json => h.network_deny_message(message),
                });
            }
            n
        })
        .create()
        .await
        .expect("create sandbox")
}

async fn teardown(sb: Sandbox, name: &str) {
    // Keep the owner alive until explicit shutdown finishes.
    sb.stop().await.expect("stop");
    drop(sb);
    let _ = Sandbox::remove(name).await;
}

/// Run curl against `url`; returns `(http_code, body)`.
async fn probe(sb: &Sandbox, url: &str) -> (String, String) {
    let cmd = format!(
        "curl -k -sS --http1.1 -m 30 -o /tmp/body -w '%{{http_code}}' {url} 2>/tmp/err; \
         echo; cat /tmp/body; echo; echo '--stderr--'; cat /tmp/err"
    );
    let out = sb.shell(&cmd).await.expect("curl");
    let stdout = out.stdout().unwrap_or_default();
    let mut lines = stdout.lines();
    let code = lines.next().unwrap_or_default().trim().to_string();
    let body = lines
        .take_while(|line| *line != "--stderr--")
        .collect::<Vec<_>>()
        .join("\n");
    (code, body)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// With responses explicitly disabled, neither plaintext nor intercepted TLS returns HTTP.
#[msb_test]
async fn denied_requests_fail_with_explicit_opt_out() {
    let name = "http-deny-default";
    let sb = spawn(
        name,
        true,
        false,
        Some("must not enable responses"),
        HttpDenyResponseFormat::Json,
    )
    .await;
    for scheme in ["http", "https"] {
        let (code, body) = probe(&sb, &format!("{scheme}://{DENIED_HOST}/")).await;
        assert_eq!(
            code, "000",
            "disabled response returned HTTP: {code} ({body})"
        );
        assert!(
            !body.contains("must not enable responses"),
            "disabled response returned the custom body: {body}"
        );
    }
    teardown(sb, name).await;
}

/// Plain HTTP to a denied name answers 403 with a structured policy error.
#[msb_test]
async fn denied_plain_http_gets_403_with_json_error() {
    let name = "http-deny-plain";
    let sb = spawn(name, false, true, None, HttpDenyResponseFormat::Json).await;

    let (code, body) = probe(&sb, &format!("http://{DENIED_HOST}/")).await;
    assert_eq!(
        code, "403",
        "expected 403 from the gateway, got {code} ({body})"
    );
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["code"], "network_policy_denied");
    assert_eq!(error["domain"], DENIED_HOST);
    assert_eq!(error["message"], "Request blocked by network policy.");

    teardown(sb, name).await;
}

/// With TLS interception on, denied HTTPS completes the handshake and
/// answers 403 inside the tunnel instead of resetting.
#[msb_test]
async fn denied_https_gets_403_inside_intercepted_tls() {
    let name = "http-deny-tls";
    let sb = spawn(name, true, true, None, HttpDenyResponseFormat::Json).await;

    let (code, body) = probe(&sb, &format!("https://{DENIED_HOST}/")).await;
    assert_eq!(
        code, "403",
        "expected 403 from the gateway, got {code} ({body})"
    );
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["code"], "network_policy_denied");
    assert_eq!(error["domain"], DENIED_HOST);
    assert_eq!(error["message"], "Request blocked by network policy.");

    teardown(sb, name).await;
}

/// Custom messages are literal; the requested domain is a separate JSON field.
#[msb_test]
async fn custom_http_deny_message_is_literal() {
    let name = "http-deny-custom";
    let sb = spawn(
        name,
        true,
        true,
        Some("blocked {host}: call the AllowHost tool to request access"),
        HttpDenyResponseFormat::Json,
    )
    .await;

    let (code, body) = probe(&sb, &format!("https://{DENIED_HOST}/")).await;
    assert_eq!(code, "403", "expected 403, got {code} ({body})");
    let error: serde_json::Value = serde_json::from_str(&body).unwrap();
    assert_eq!(error["code"], "network_policy_denied");
    assert_eq!(error["domain"], DENIED_HOST);
    assert_eq!(
        error["message"],
        "blocked {host}: call the AllowHost tool to request access"
    );

    teardown(sb, name).await;
}

/// Without TLS interception a denied TLS first flight is still closed
/// silently: plaintext HTTP must never be injected into a TLS stream.
#[msb_test]
async fn denied_https_without_interception_still_fails_closed() {
    let name = "http-deny-tls-off";
    let sb = spawn(name, false, true, None, HttpDenyResponseFormat::Json).await;

    let (code, body) = probe(&sb, &format!("https://{DENIED_HOST}/")).await;
    assert_ne!(code, "403", "no HTTP answer expected without interception");
    assert!(
        code == "000" || code.is_empty(),
        "curl must fail to connect, got {code} ({body})"
    );

    teardown(sb, name).await;
}

/// Legacy SDK settings keep plain-text denials on both transports.
#[msb_test]
async fn legacy_text_denials_preserve_custom_messages() {
    let name = "http-deny-legacy";
    let sb = spawn(
        name,
        true,
        true,
        Some("blocked {host}"),
        HttpDenyResponseFormat::Text,
    )
    .await;
    for scheme in ["http", "https"] {
        let (code, body) = probe(&sb, &format!("{scheme}://{DENIED_HOST}/")).await;
        assert_eq!(code, "403");
        assert_eq!(body.trim_end(), "blocked example.com");
    }
    teardown(sb, name).await;
}
