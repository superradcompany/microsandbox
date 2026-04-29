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
    // Capture curl's exit code and stderr alongside the http_code so a
    // FAIL surfaces the specific reason (DNS, TCP, TLS, etc.) instead
    // of an opaque sentinel.
    let cmd = format!(
        "tmp=$(mktemp); \
         code=$(curl -sS --max-time 30 -o /dev/null -w '%{{http_code}}' {url} 2>\"$tmp\"); \
         exit=$?; \
         err=$(tr '\\n' ' ' <\"$tmp\"; rm -f \"$tmp\"); \
         case \"$code\" in \
             000|\"\") printf 'FAIL exit=%s err=%s' \"$exit\" \"$err\" ;; \
             *) printf '%s' \"$code\" ;; \
         esac"
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

/// True when `probe_https` reported a curl-side failure (any output
/// starting with [`CURL_FAIL`]). The full output includes curl's exit
/// code and stderr so the failure reason is visible in test logs.
fn curl_failed(probe_output: &str) -> bool {
    probe_output.starts_with(CURL_FAIL)
}

/// `getent hosts <name>` with a small retry. Self-hosted CI runners
/// occasionally drop a single DNS forward; the policy under test is
/// unchanged across retries, so a one-shot probe is the only thing
/// that flakes — not the rule engine itself.
async fn dns_lookup(sb: &Sandbox, name: &str) -> String {
    let cmd = format!(
        "for i in 1 2 3; do \
           ip=$(getent hosts {name} | awk '{{print $1; exit}}'); \
           [ -n \"$ip\" ] && {{ printf '%s' \"$ip\"; exit 0; }}; \
           sleep 1; \
         done"
    );
    let out = sb.shell(&cmd).await.expect("dns probe");
    out.stdout().unwrap_or_default().trim().to_string()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Default-deny policy with explicit allow rules for `cloudflare.com`
/// and `www.cloudflare.com` permits HTTPS to both, denies the rest.
#[msb_test]
async fn domain_policy_allows_whitelisted_https() {
    let name = "net-domain-policy-allow";
    let policy = NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        rules: vec![
            allow_domain_https("cloudflare.com"),
            allow_domain_https("www.cloudflare.com"),
        ],
    };
    let sb = setup_alpine(name, policy).await;

    // DNS resolution itself must succeed: the interceptor bypasses
    // the egress policy for queries aimed at the gateway, so the
    // guest can populate its cache before the policy-gated connect.
    let dns_out = dns_lookup(&sb, "cloudflare.com").await;
    assert!(
        !dns_out.is_empty(),
        "DNS resolution of cloudflare.com should succeed via the gateway resolver"
    );

    let apex = probe_https(&sb, "https://cloudflare.com/").await;
    assert!(
        reached_server(&apex),
        "HTTPS to cloudflare.com should be allowed: got `{apex}`"
    );

    let www = probe_https(&sb, "https://www.cloudflare.com/").await;
    assert!(
        reached_server(&www),
        "HTTPS to www.cloudflare.com should be allowed: got `{www}`"
    );

    let example = probe_https(&sb, "https://example.com/").await;
    assert!(
        curl_failed(&example),
        "HTTPS to example.com should be denied by default-action: got `{example}`"
    );

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

/// `deny Domain("example.com")` refuses DNS for that name; unrelated
/// names still resolve.
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

    // Companion: an unrelated name still resolves. We pick the alpine
    // mirror because `setup_alpine` just resolved it via apk, so the
    // forwarder has demonstrably reached it once already.
    let allowed_out = dns_lookup(&sb, "dl-cdn.alpinelinux.org").await;
    assert!(
        !allowed_out.is_empty(),
        "dl-cdn.alpinelinux.org DNS lookup should succeed under default-allow: got `{allowed_out}`"
    );

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

/// `deny DomainSuffix(".example.com")` refuses DNS for the apex and
/// any subdomain.
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

    // Companion: an unrelated suffix still resolves. The alpine mirror
    // is a known-reachable name (resolved during setup_alpine).
    let allowed_out = dns_lookup(&sb, "dl-cdn.alpinelinux.org").await;
    assert!(
        !allowed_out.is_empty(),
        "dl-cdn.alpinelinux.org DNS lookup should succeed under default-allow: got `{allowed_out}`"
    );

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

/// SNI-based enforcement on shared-CDN IPs (the over-allow fix).
/// Allow only `files.pythonhosted.org`, resolve both that name and
/// `pypi.org` (often co-located on Fastly), and assert HTTPS to
/// `pypi.org` fails while `files.pythonhosted.org` succeeds.
#[msb_test]
async fn domain_policy_sni_disambiguates_shared_cdn_ip() {
    let name = "net-domain-policy-sni-shared-ip";
    let policy = NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        // Allow only files.pythonhosted.org. pypi.org has no allow rule.
        rules: vec![allow_domain_https("files.pythonhosted.org")],
    };
    let sb = setup_alpine(name, policy).await;

    // Resolve both names so the DNS cache associates each with its IP
    // (and any shared Fastly addresses with both names). The
    // disallowed name's resolution succeeds because there is no deny
    // rule for it — only its connection is gated.
    sb.shell("getent hosts pypi.org > /dev/null")
        .await
        .expect("dns probe pypi.org");
    sb.shell("getent hosts files.pythonhosted.org > /dev/null")
        .await
        .expect("dns probe files.pythonhosted.org");

    // Allowed name: SNI matches the rule, connection proceeds.
    let allowed = probe_https(&sb, "https://files.pythonhosted.org/").await;
    assert!(
        reached_server(&allowed),
        "files.pythonhosted.org should be allowed: got `{allowed}`"
    );

    // Disallowed name: even if the destination IP is shared with the
    // allowed name's cache entry, SNI disambiguates and the rule no
    // longer matches.
    let denied = probe_https(&sb, "https://pypi.org/simple/pip/").await;
    assert!(
        curl_failed(&denied),
        "pypi.org should be denied even on shared Fastly IP: got `{denied}`"
    );

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

/// `Destination::DomainSuffix` matches subdomains but not unrelated
/// hosts: `www.cloudflare.com` matches `.cloudflare.com`,
/// `example.com` does not.
#[msb_test]
async fn domain_policy_suffix_allows_subdomain_https() {
    let name = "net-domain-policy-suffix";
    let policy = NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        rules: vec![allow_domain_suffix_https(".cloudflare.com")],
    };
    let sb = setup_alpine(name, policy).await;

    let www = probe_https(&sb, "https://www.cloudflare.com/").await;
    assert!(
        reached_server(&www),
        "www.cloudflare.com should match .cloudflare.com suffix: got `{www}`"
    );

    let example = probe_https(&sb, "https://example.com/").await;
    assert!(
        curl_failed(&example),
        "example.com should not match .cloudflare.com suffix: got `{example}`"
    );

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}
