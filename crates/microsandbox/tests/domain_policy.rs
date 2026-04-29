//! Integration tests for Domain/DomainSuffix network-policy rules.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
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
        direction: Direction::Egress,
        destination: Destination::Domain(domain.parse().expect("valid domain")),
        protocols: vec![Protocol::Tcp],
        ports: vec![PortRange::single(443)],
        action: Action::Allow,
    }
}

/// Outbound HTTPS (TCP/443) allow rule for a DNS suffix.
fn allow_domain_suffix_https(suffix: &str) -> Rule {
    Rule {
        direction: Direction::Egress,
        destination: Destination::DomainSuffix(suffix.parse().expect("valid domain suffix")),
        protocols: vec![Protocol::Tcp],
        ports: vec![PortRange::single(443)],
        action: Action::Allow,
    }
}

/// Create an Alpine sandbox with the given policy and install `curl`.
///
/// Base Alpine ships only busybox wget, which has uneven TLS behaviour
/// across versions. `curl` gives us a portable `%{http_code}` and a
/// deterministic non-zero exit for connection failures, which we turn
/// into the [`CURL_FAIL`] sentinel.
///
/// The policy is prepended with an allow rule for `*.alpinelinux.org:443`
/// so that `apk add curl` can reach the package mirror even when the
/// caller supplies a default-deny policy. Test targets live on other
/// domains, so this injection never shadows the rules under test.
async fn setup_alpine(name: &str, policy: NetworkPolicy) -> Sandbox {
    let mut policy = policy;
    policy
        .rules
        .insert(0, allow_domain_suffix_https(".alpinelinux.org"));
    let sb = Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
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
///
/// `curl -w '%{http_code}'` always prints a code even on failure (using
/// `000` for "no HTTP response"), so we capture it and explicitly map
/// `000`/empty back to [`CURL_FAIL`]. Without this, a denied connection
/// leaves `000` on stdout alongside `FAIL` from the exit-code fallback,
/// producing ambiguous `000FAIL` strings.
///
/// Timeout is 30s rather than 10s so a slow CI runner isn't the thing
/// tipping a probe over on the TLS handshake.
async fn probe_https(sb: &Sandbox, url: &str) -> String {
    let cmd = format!(
        "code=$(curl -sS --max-time 30 -o /dev/null -w '%{{http_code}}' {url} 2>/dev/null); \
         case \"$code\" in 000|\"\") echo {CURL_FAIL};; *) printf '%s' \"$code\";; esac"
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

/// A default-deny policy with explicit allow rules for `pypi.org` and
/// `files.pythonhosted.org` must permit HTTPS to those hostnames after
/// the guest resolves them via the in-process DNS interceptor.
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
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        rules: vec![
            allow_domain_https("pypi.org"),
            allow_domain_https("files.pythonhosted.org"),
        ],
    };
    let sb = setup_alpine(name, policy).await;

    // DNS resolution itself must succeed: the interceptor bypasses
    // the egress policy for queries aimed at the gateway, so the
    // guest can populate its cache before the policy-gated connect.
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
        "HTTPS to pypi.org should be allowed: got `{pypi}`"
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

/// `deny Domain("example.com")` must cause DNS resolution for that
/// name to fail at the gateway resolver (REFUSED), while unrelated
/// names continue to resolve normally. The deny lives at the DNS layer
/// because `dns_query_denied` consults Domain rules before the
/// forwarder forwards upstream.
#[msb_test]
async fn domain_policy_deny_domain_refuses_dns() {
    let name = "net-domain-policy-deny-dns";
    let policy = NetworkPolicy {
        default_egress: Action::Allow,
        default_ingress: Action::Allow,
        rules: vec![Rule::deny_egress(Destination::Domain(
            "example.com".parse().expect("valid domain"),
        ))],
    };
    let sb = setup_alpine(name, policy).await;

    // Denied: gateway returns REFUSED, getent prints nothing.
    let denied = sb
        .shell("getent hosts example.com | awk '{print $1; exit}'")
        .await
        .expect("dns probe denied");
    let denied_out = denied.stdout().unwrap_or_default().trim().to_string();
    assert!(
        denied_out.is_empty(),
        "example.com DNS lookup should be refused: got `{denied_out}`"
    );

    // Companion: an unrelated name still resolves.
    let allowed = sb
        .shell("getent hosts pypi.org | awk '{print $1; exit}'")
        .await
        .expect("dns probe allowed");
    let allowed_out = allowed.stdout().unwrap_or_default().trim().to_string();
    assert!(
        !allowed_out.is_empty(),
        "pypi.org DNS lookup should succeed under default-allow: got `{allowed_out}`"
    );

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

/// `deny DomainSuffix(".example.com")` must refuse DNS for the apex
/// and any subdomain. Mirrors the suffix-match invariant tested for
/// allow rules: `matches_suffix` is label-aware, so the apex itself
/// matches as well as deeper labels.
#[msb_test]
async fn domain_policy_deny_suffix_refuses_dns_apex_and_subdomain() {
    let name = "net-domain-policy-deny-suffix-dns";
    let policy = NetworkPolicy {
        default_egress: Action::Allow,
        default_ingress: Action::Allow,
        rules: vec![Rule::deny_egress(Destination::DomainSuffix(
            ".example.com".parse().expect("valid domain suffix"),
        ))],
    };
    let sb = setup_alpine(name, policy).await;

    // Apex: `.example.com` suffix matches `example.com` itself.
    let apex = sb
        .shell("getent hosts example.com | awk '{print $1; exit}'")
        .await
        .expect("dns probe apex");
    let apex_out = apex.stdout().unwrap_or_default().trim().to_string();
    assert!(
        apex_out.is_empty(),
        "example.com (apex) should be refused by .example.com suffix: got `{apex_out}`"
    );

    // Subdomain: `www.example.com` also matches.
    let sub = sb
        .shell("getent hosts www.example.com | awk '{print $1; exit}'")
        .await
        .expect("dns probe subdomain");
    let sub_out = sub.stdout().unwrap_or_default().trim().to_string();
    assert!(
        sub_out.is_empty(),
        "www.example.com should be refused by .example.com suffix: got `{sub_out}`"
    );

    // Companion: an unrelated suffix still resolves.
    let allowed = sb
        .shell("getent hosts pypi.org | awk '{print $1; exit}'")
        .await
        .expect("dns probe allowed");
    let allowed_out = allowed.stdout().unwrap_or_default().trim().to_string();
    assert!(
        !allowed_out.is_empty(),
        "pypi.org DNS lookup should succeed under default-allow: got `{allowed_out}`"
    );

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

/// `Destination::DomainSuffix` must match subdomains but not unrelated
/// hosts. One sandbox, two probes:
///
/// 1. `files.pythonhosted.org:443` matches `.pythonhosted.org` →
///    reaches server.
/// 2. `example.com:443` does not match the suffix → curl fails.
///
/// The negative case deliberately uses `example.com` (Akamai) rather
/// than another Fastly-hosted site like `pypi.org`: both `pypi.org` and
/// `*.pythonhosted.org` share Fastly CDN IPs, so once both names are in
/// the DNS cache the shared IP would match the suffix rule through the
/// wrong hostname and defeat the assertion.
#[msb_test]
async fn domain_policy_suffix_allows_subdomain_https() {
    let name = "net-domain-policy-suffix";
    let policy = NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        rules: vec![allow_domain_suffix_https(".pythonhosted.org")],
    };
    let sb = setup_alpine(name, policy).await;

    let files = probe_https(&sb, "https://files.pythonhosted.org/").await;
    assert!(
        reached_server(&files),
        "files.pythonhosted.org should match .pythonhosted.org suffix: got `{files}`"
    );

    let example = probe_https(&sb, "https://example.com/").await;
    assert_eq!(
        example, CURL_FAIL,
        "example.com should not match .pythonhosted.org suffix: got `{example}`"
    );

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}
