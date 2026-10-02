//! Integration tests for the HTTP/HTTPS `403 Forbidden` answer the gateway
//! returns when egress is denied by a domain rule.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --tests --run-ignored=only

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

async fn spawn(name: &str, tls: bool, enabled: bool, message: Option<&str>) -> Sandbox {
    let message = message.map(str::to_owned);
    Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .network(move |mut n| {
            n = n
                .policy(dns_only_policy())
                .http(|h| h.deny_response(enabled));
            if tls {
                n = n.tls(|t| t.enabled(true));
            }
            if let Some(message) = message {
                n = n.http(|h| h.deny_message(message));
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
    let body = lines.collect::<Vec<_>>().join("\n");
    (code, body)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// With the default settings, neither plaintext nor intercepted TLS returns HTTP.
#[msb_test]
async fn denied_requests_fail_without_opt_in() {
    let name = "http-deny-default";
    let sb = spawn(name, true, false, Some("must not enable responses")).await;
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

/// Plain HTTP to a denied name answers 403 with the default agent note.
#[msb_test]
async fn denied_plain_http_gets_403_with_agent_note() {
    let name = "http-deny-plain";
    let sb = spawn(name, false, true, None).await;

    let (code, body) = probe(&sb, &format!("http://{DENIED_HOST}/")).await;
    assert_eq!(
        code, "403",
        "expected 403 from the gateway, got {code} ({body})"
    );
    assert!(
        body.contains(&format!("`{DENIED_HOST}`")),
        "body must name the blocked host: {body}"
    );
    assert!(body.contains("Note to agent:"), "body: {body}");
    assert!(
        !body.contains("{host}"),
        "placeholder must be rendered: {body}"
    );

    teardown(sb, name).await;
}

/// With TLS interception on, denied HTTPS completes the handshake and
/// answers 403 inside the tunnel instead of resetting.
#[msb_test]
async fn denied_https_gets_403_inside_intercepted_tls() {
    let name = "http-deny-tls";
    let sb = spawn(name, true, true, None).await;

    let (code, body) = probe(&sb, &format!("https://{DENIED_HOST}/")).await;
    assert_eq!(
        code, "403",
        "expected 403 from the gateway, got {code} ({body})"
    );
    assert!(
        body.contains(&format!("`{DENIED_HOST}`")),
        "body must name the blocked host: {body}"
    );
    assert!(
        body.contains("not allowed by the sandbox network policy"),
        "body must explain the policy denial: {body}"
    );
    assert!(body.contains("Note to agent:"), "body: {body}");

    teardown(sb, name).await;
}

/// `http.deny_message` replaces the body and still renders `{host}`.
#[msb_test]
async fn custom_http_deny_message_is_rendered() {
    let name = "http-deny-custom";
    let sb = spawn(
        name,
        true,
        true,
        Some("blocked {host}: call the AllowHost tool to request access"),
    )
    .await;

    let (code, body) = probe(&sb, &format!("https://{DENIED_HOST}/")).await;
    assert_eq!(code, "403", "expected 403, got {code} ({body})");
    assert!(
        body.contains(&format!(
            "blocked {DENIED_HOST}: call the AllowHost tool to request access"
        )),
        "custom body not rendered: {body}"
    );
    assert!(!body.contains("Note to agent:"), "default leaked: {body}");

    teardown(sb, name).await;
}

/// Without TLS interception a denied TLS first flight is still closed
/// silently: plaintext HTTP must never be injected into a TLS stream.
#[msb_test]
async fn denied_https_without_interception_still_fails_closed() {
    let name = "http-deny-tls-off";
    let sb = spawn(name, false, true, None).await;

    let (code, body) = probe(&sb, &format!("https://{DENIED_HOST}/")).await;
    assert_ne!(code, "403", "no HTTP answer expected without interception");
    assert!(
        code == "000" || code.is_empty(),
        "curl must fail to connect, got {code} ({body})"
    );

    teardown(sb, name).await;
}
