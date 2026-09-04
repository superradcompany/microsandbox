//! Integration tests for the HTTP/HTTPS `403 Forbidden` answer the gateway
//! returns when egress is denied by a domain rule.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --tests --run-ignored=only

use microsandbox::{NetworkPolicy, Sandbox};
use microsandbox_network::http_deny::DEFAULT_HTTP_DENY_MESSAGE;
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

async fn spawn(name: &str, tls: bool, message: Option<&str>) -> Sandbox {
    let message = message.map(str::to_owned);
    Sandbox::builder(name)
        .image(CURL_IMAGE)
        .cpus(1)
        .memory(256)
        .user("0")
        .replace()
        .network(move |mut n| {
            n = n.policy(dns_only_policy());
            if tls {
                n = n.tls(|t| t.enabled(true));
            }
            if let Some(message) = message {
                n = n.http_deny_message(message);
            }
            n
        })
        .create()
        .await
        .expect("create sandbox")
}

async fn teardown(sb: Sandbox, name: &str) {
    drop(sb);
    let handle = Sandbox::get(name).await.expect("get");
    handle.stop().await.expect("stop");
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

/// Plain HTTP to a denied name answers 403 with the default agent note.
#[msb_test]
async fn denied_plain_http_gets_403_with_agent_note() {
    let name = "http-deny-plain";
    let sb = spawn(name, false, None).await;

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
    let sb = spawn(name, true, None).await;

    let (code, body) = probe(&sb, &format!("https://{DENIED_HOST}/")).await;
    assert_eq!(
        code, "403",
        "expected 403 from the gateway, got {code} ({body})"
    );
    assert!(
        body.contains(&format!("`{DENIED_HOST}`")),
        "body must name the blocked host: {body}"
    );
    let expected = DEFAULT_HTTP_DENY_MESSAGE.replace("{host}", DENIED_HOST);
    assert!(
        body.contains(expected.trim()),
        "body must be the default message: {body}"
    );

    teardown(sb, name).await;
}

/// `http_deny_message` replaces the body and still renders `{host}`.
#[msb_test]
async fn custom_http_deny_message_is_rendered() {
    let name = "http-deny-custom";
    let sb = spawn(
        name,
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
    let sb = spawn(name, false, None).await;

    let (code, body) = probe(&sb, &format!("https://{DENIED_HOST}/")).await;
    assert_ne!(code, "403", "no HTTP answer expected without interception");
    assert!(
        code == "000" || code.is_empty(),
        "curl must fail to connect, got {code} ({body})"
    );

    teardown(sb, name).await;
}
