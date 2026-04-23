//! Integration tests for Domain/DomainSuffix network-policy rules.
//!
//! Spins up a real sandbox, installs `curl`, and exercises the fix for
//! issue 603: a default-deny policy with explicit `Destination::Domain`
//! / `Destination::DomainSuffix` allow rules must let matching HTTPS
//! egress through after the guest resolves the hostname via the
//! in-process DNS interceptor. Before the fix, any connection to a
//! resolved IP would fall through to default-deny and return
//! `ConnectionRefused`.
//!
//! These tests require KVM (or libkrun on macOS) and real outbound
//! connectivity to `pypi.org`, `files.pythonhosted.org`, and
//! `example.com`. The `#[msb_test]` attribute marks them `#[ignore]`,
//! so plain `cargo test --workspace` skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --tests --run-ignored=only
//!
//! Set `MSB_TEST_ISOLATE_HOME=1` (CI does this) to give each test its
//! own `~/.microsandbox` so they can run in parallel without sharing
//! the sqlite db, image cache, or sandbox namespace.

use microsandbox::{NetworkPolicy, Sandbox};
use microsandbox_network::policy::{Action, Destination, Direction, PortRange, Protocol, Rule};
use test_utils::msb_test;

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

/// Sentinel emitted when `curl` fails to establish a connection.
/// Collisions with real HTTP codes are impossible since `%{http_code}`
/// is three digits; `FAIL` is printed by the shell fallback only when
/// curl's exit status is non-zero.
const CURL_FAIL: &str = "FAIL";

/// Outbound HTTPS (TCP/443) allow rule for a specific hostname.
fn allow_domain_https(domain: &str) -> Rule {
    Rule {
        direction: Direction::Outbound,
        destination: Destination::Domain(domain.into()),
        protocol: Some(Protocol::Tcp),
        ports: Some(PortRange::single(443)),
        action: Action::Allow,
    }
}

/// Outbound HTTPS (TCP/443) allow rule for a DNS suffix.
fn allow_domain_suffix_https(suffix: &str) -> Rule {
    Rule {
        direction: Direction::Outbound,
        destination: Destination::DomainSuffix(suffix.into()),
        protocol: Some(Protocol::Tcp),
        ports: Some(PortRange::single(443)),
        action: Action::Allow,
    }
}

/// Create an Alpine sandbox with the given policy and install `curl`.
///
/// Base Alpine ships only busybox wget, which has uneven TLS behaviour
/// across versions. `curl` gives us a portable `%{http_code}` and a
/// deterministic non-zero exit for connection failures, which we turn
/// into the [`CURL_FAIL`] sentinel.
async fn setup_alpine(name: &str, policy: NetworkPolicy) -> Sandbox {
    let sb = Sandbox::builder(name)
        .image("alpine")
        .cpus(1)
        .memory(512)
        .network(|n| n.policy(policy))
        .replace()
        .create()
        .await
        .expect("create sandbox");
    sb.shell("apk add --quiet --no-progress curl >/dev/null 2>&1")
        .await
        .expect("install curl");
    sb
}

/// Run an HTTPS probe inside the guest. Returns the HTTP status code
/// as a 3-digit string on success, or [`CURL_FAIL`] when curl couldn't
/// complete the request (connection refused, TLS handshake aborted,
/// timeout, etc).
async fn probe_https(sb: &Sandbox, url: &str) -> String {
    let cmd = format!(
        "curl -sS --max-time 10 -o /dev/null -w '%{{http_code}}' {url} 2>/dev/null \
         || echo {CURL_FAIL}"
    );
    let out = sb.shell(&cmd).await.expect("shell");
    out.stdout().unwrap_or_default().trim().to_string()
}

/// True when `probe_https` returned a 3-digit HTTP status (i.e. curl
/// actually reached the server and got a response). We don't care
/// about the status code itself — any response from the real origin
/// means the policy let the connection through.
fn reached_server(probe_output: &str) -> bool {
    probe_output.len() == 3 && probe_output.chars().all(|c| c.is_ascii_digit())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Direct reproduction of issue 603: a default-deny policy with
/// explicit allow rules for `pypi.org` and `files.pythonhosted.org`
/// must permit HTTPS to those hostnames after the guest resolves them
/// via the in-process DNS interceptor.
///
/// Bundles three probes into one sandbox to amortise image-pull and
/// VM-boot cost:
///
/// 1. `pypi.org:443` is whitelisted → reaches server.
/// 2. `files.pythonhosted.org:443` is whitelisted → reaches server.
/// 3. `example.com:443` is not whitelisted → curl fails (sandbox
///    dropped the TCP SYN).
#[msb_test]
async fn domain_policy_allows_whitelisted_https() {
    let name = "net-domain-policy-allow";
    let policy = NetworkPolicy {
        default_action: Action::Deny,
        rules: vec![
            allow_domain_https("pypi.org"),
            allow_domain_https("files.pythonhosted.org"),
        ],
    };
    let sb = setup_alpine(name, policy).await;

    // DNS resolution itself must succeed (the interceptor bypasses
    // the egress policy for queries aimed at the gateway). This is
    // the invariant issue 603 noted was working pre-fix.
    let dns = sb
        .shell("getent hosts pypi.org | awk '{print $1; exit}'")
        .await
        .expect("dns probe");
    let dns_out = dns.stdout().unwrap_or_default().trim().to_string();
    assert!(
        !dns_out.is_empty(),
        "DNS resolution of pypi.org should succeed via the gateway resolver"
    );

    let pypi = probe_https(&sb, "https://pypi.org/simple/pip/").await;
    assert!(
        reached_server(&pypi),
        "HTTPS to pypi.org should be allowed (issue 603 repro): got `{pypi}`"
    );

    let files = probe_https(&sb, "https://files.pythonhosted.org/").await;
    assert!(
        reached_server(&files),
        "HTTPS to files.pythonhosted.org should be allowed: got `{files}`"
    );

    let example = probe_https(&sb, "https://example.com/").await;
    assert_eq!(
        example, CURL_FAIL,
        "HTTPS to example.com should be denied by default-action: got `{example}`"
    );

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

/// `Destination::DomainSuffix` must match subdomains but not unrelated
/// hosts. One sandbox, two probes:
///
/// 1. `files.pythonhosted.org:443` matches `.pythonhosted.org` →
///    reaches server.
/// 2. `pypi.org:443` does not match the suffix → curl fails.
#[msb_test]
async fn domain_policy_suffix_allows_subdomain_https() {
    let name = "net-domain-policy-suffix";
    let policy = NetworkPolicy {
        default_action: Action::Deny,
        rules: vec![allow_domain_suffix_https(".pythonhosted.org")],
    };
    let sb = setup_alpine(name, policy).await;

    let files = probe_https(&sb, "https://files.pythonhosted.org/").await;
    assert!(
        reached_server(&files),
        "files.pythonhosted.org should match .pythonhosted.org suffix: got `{files}`"
    );

    let pypi = probe_https(&sb, "https://pypi.org/simple/pip/").await;
    assert_eq!(
        pypi, CURL_FAIL,
        "pypi.org should not match .pythonhosted.org suffix: got `{pypi}`"
    );

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}
