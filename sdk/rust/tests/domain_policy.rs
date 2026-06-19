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

use std::net::{IpAddr, ToSocketAddrs};

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

async fn stop_and_remove(name: &str) {
    let handle = Sandbox::get(name).await.expect("get");
    handle.stop().await.expect("stop");
    let _ = Sandbox::remove(name).await;
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
    probe_https_result(sb, url)
        .await
        .unwrap_or_else(|err| format!("{CURL_FAIL} exec={err}"))
}

async fn probe_https_result(sb: &Sandbox, url: &str) -> Result<String, String> {
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
    collect_probe_output(sb, &cmd).await
}

async fn collect_probe_output(sb: &Sandbox, cmd: &str) -> Result<String, String> {
    let out = sb.shell(cmd).await.map_err(|err| err.to_string())?;
    Ok(out.stdout().unwrap_or_default().trim().to_string())
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

/// `probe_https` with a small retry for the success case. Self-hosted
/// runners occasionally drop a single TLS handshake to shared-CDN
/// edges; the policy under test is unchanged across retries, so a
/// one-shot probe is the only thing that flakes.
async fn probe_https_with_retry(sb: &Sandbox, url: &str) -> String {
    let mut last = String::new();
    for _ in 0..3 {
        last = match probe_https_result(sb, url).await {
            Ok(output) => output,
            // Retryable success probes should tolerate a single dropped
            // exec stream the same way they tolerate a dropped TLS
            // handshake. Persistent exec failures still surface in the
            // final assertion with the original runtime error attached.
            Err(err) => format!("{CURL_FAIL} exec={err}"),
        };
        if reached_server(&last) {
            return last;
        }
    }
    last
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

/// Resolve a test hostname on the host side. This gives the test a
/// reachable IP without populating the sandbox's resolved-hostname
/// cache for that name.
fn host_resolved_ipv4(name: &str) -> String {
    (name, 443)
        .to_socket_addrs()
        .expect("host DNS lookup")
        .find_map(|addr| match addr.ip() {
            IpAddr::V4(ip) => Some(ip.to_string()),
            IpAddr::V6(_) => None,
        })
        .unwrap_or_else(|| panic!("host DNS lookup for {name} returned no IPv4 address"))
}

/// Like [`probe_https`], but force curl to connect to `ip` while still
/// sending `host` as the HTTP Host header and TLS SNI.
async fn probe_https_with_resolve(sb: &Sandbox, host: &str, ip: &str) -> String {
    probe_https_with_resolve_result(sb, host, ip)
        .await
        .unwrap_or_else(|err| format!("{CURL_FAIL} exec={err}"))
}

async fn probe_https_with_resolve_result(
    sb: &Sandbox,
    host: &str,
    ip: &str,
) -> Result<String, String> {
    let cmd = format!(
        "tmp=$(mktemp); \
         code=$(curl -sS --max-time 30 -o /dev/null \
                -w '%{{http_code}}' \
                --resolve {host}:443:{ip} \
                https://{host}/ 2>\"$tmp\"); \
         exit=$?; \
         err=$(tr '\\n' ' ' <\"$tmp\"; rm -f \"$tmp\"); \
         case \"$code\" in \
             000|\"\") printf 'FAIL exit=%s err=%s' \"$exit\" \"$err\" ;; \
             *) printf '%s' \"$code\" ;; \
         esac"
    );
    collect_probe_output(sb, &cmd).await
}

async fn probe_https_with_resolve_retry(sb: &Sandbox, host: &str, ip: &str) -> String {
    let mut last = String::new();
    for _ in 0..3 {
        last = match probe_https_with_resolve_result(sb, host, ip).await {
            Ok(output) => output,
            Err(err) => format!("{CURL_FAIL} exec={err}"),
        };
        if reached_server(&last) {
            return last;
        }
    }
    last
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

    // DNS resolution must succeed for `cloudflare.com`: the Domain
    // allow rule matches by name at DNS-decision time (ignoring its
    // proto/port filter), so the query is permitted and the guest's
    // cache is populated before the policy-gated connect.
    let dns_out = dns_lookup(&sb, "cloudflare.com").await;
    assert!(
        !dns_out.is_empty(),
        "DNS resolution of cloudflare.com should succeed via the gateway resolver"
    );

    let apex = probe_https_with_retry(&sb, "https://cloudflare.com/").await;
    assert!(
        reached_server(&apex),
        "HTTPS to cloudflare.com should be allowed: got `{apex}`"
    );

    let www = probe_https_with_retry(&sb, "https://www.cloudflare.com/").await;
    assert!(
        reached_server(&www),
        "HTTPS to www.cloudflare.com should be allowed: got `{www}`"
    );

    let example = probe_https(&sb, "https://example.com/").await;
    assert!(
        curl_failed(&example),
        "HTTPS to example.com should be denied by default-action: got `{example}`"
    );

    stop_and_remove(name).await;
}

/// `deny Domain("example.com")` denies DNS for that name; unrelated
/// names still resolve.
#[msb_test]
async fn domain_policy_deny_domain_denies_dns() {
    let name = "net-domain-policy-deny-dns";
    let policy = NetworkPolicy {
        default_egress: Action::Allow,
        default_ingress: Action::Allow,
        rules: vec![Rule::deny_egress(Destination::Domain(
            "example.com".parse().expect("valid domain"),
        ))],
    };
    let sb = setup_alpine(name, policy).await;

    // Denied: gateway returns NXDOMAIN, getent prints nothing.
    let denied = sb
        .shell("getent hosts example.com | awk '{print $1; exit}'")
        .await
        .expect("dns probe denied");
    let denied_out = denied.stdout().unwrap_or_default().trim().to_string();
    assert!(
        denied_out.is_empty(),
        "example.com DNS lookup should be denied: got `{denied_out}`"
    );

    // Companion: an unrelated name still resolves. We pick the alpine
    // mirror because `setup_alpine` just resolved it via apk, so the
    // forwarder has demonstrably reached it once already.
    let allowed_out = dns_lookup(&sb, "dl-cdn.alpinelinux.org").await;
    assert!(
        !allowed_out.is_empty(),
        "dl-cdn.alpinelinux.org DNS lookup should succeed under default-allow: got `{allowed_out}`"
    );

    stop_and_remove(name).await;
}

/// Default-allow plus `deny Domain("www.rfc-editor.org")` must block a
/// direct-IP TLS connection whose SNI is `www.rfc-editor.org`, even when
/// the sandbox never resolved that name through the gateway DNS cache.
#[msb_test]
async fn domain_policy_deny_domain_blocks_sni_direct_ip_without_dns_cache() {
    const ALLOWED_HOST: &str = "www.iana.org";
    const DENIED_HOST: &str = "www.rfc-editor.org";

    let name = "net-domain-policy-deny-sni-ip";
    let allowed_ip = host_resolved_ipv4(ALLOWED_HOST);
    let denied_ip = host_resolved_ipv4(DENIED_HOST);
    let policy = NetworkPolicy {
        default_egress: Action::Allow,
        default_ingress: Action::Allow,
        rules: vec![Rule::deny_egress(Destination::Domain(
            DENIED_HOST.parse().expect("valid domain"),
        ))],
    };
    let sb = setup_alpine(name, policy).await;

    // Baseline the bypass shape itself: `curl --resolve` connects by IP
    // and sends SNI without asking the sandbox DNS resolver.
    let allowed = probe_https_with_resolve_retry(&sb, ALLOWED_HOST, &allowed_ip).await;
    assert!(
        reached_server(&allowed),
        "direct-IP HTTPS to unrelated {ALLOWED_HOST} should be allowed: got `{allowed}`"
    );

    let denied = probe_https_with_resolve(&sb, DENIED_HOST, &denied_ip).await;
    assert!(
        curl_failed(&denied),
        "direct-IP HTTPS with denied SNI {DENIED_HOST} should be blocked: got `{denied}`"
    );

    stop_and_remove(name).await;
}

/// `deny DomainSuffix(".example.com")` denies DNS for the apex and
/// any subdomain.
#[msb_test]
async fn domain_policy_deny_suffix_denies_dns_apex_and_subdomain() {
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
        "example.com (apex) should be denied by .example.com suffix: got `{apex_out}`"
    );

    // Subdomain: `www.example.com` also matches.
    let sub = sb
        .shell("getent hosts www.example.com | awk '{print $1; exit}'")
        .await
        .expect("dns probe subdomain");
    let sub_out = sub.stdout().unwrap_or_default().trim().to_string();
    assert!(
        sub_out.is_empty(),
        "www.example.com should be denied by .example.com suffix: got `{sub_out}`"
    );

    // No baseline lookup here — `domain_policy_deny_domain_denies_dns`
    // already covers "unrelated names still resolve under default-allow,"
    // and rapid back-to-back queries trip the runner's egress DNS
    // rate-limit.

    stop_and_remove(name).await;
}

/// SNI-based enforcement on shared-CDN IPs (the over-allow fix).
/// Allow only `files.pythonhosted.org` for HTTPS plus DNS via the
/// gateway, resolve both that name and `pypi.org` (often co-located
/// on Fastly), and assert HTTPS to `pypi.org` fails while
/// `files.pythonhosted.org` succeeds.
#[msb_test]
async fn domain_policy_sni_disambiguates_shared_cdn_ip() {
    let name = "net-domain-policy-sni-shared-ip";
    let policy = NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        // Allow DNS for any name via the gateway forwarder, but only
        // permit HTTPS to files.pythonhosted.org. pypi.org has no
        // connection-level allow rule.
        rules: vec![
            Rule::allow_dns(),
            allow_domain_https("files.pythonhosted.org"),
        ],
    };
    let sb = setup_alpine(name, policy).await;

    // Resolve both names so the DNS cache associates each with its IP
    // (and any shared Fastly addresses with both names). Both lookups
    // succeed because `allow_dns()` permits DNS regardless of name;
    // SNI then disambiguates at connect time. Retry the priming
    // lookups so a single transient forward doesn't leave curl
    // resolving from scratch.
    let pypi_ip = dns_lookup(&sb, "pypi.org").await;
    let files_ip = dns_lookup(&sb, "files.pythonhosted.org").await;
    assert!(
        !pypi_ip.is_empty(),
        "pypi.org should resolve when DNS is explicitly allowed"
    );
    assert!(
        !files_ip.is_empty(),
        "files.pythonhosted.org should resolve when DNS is explicitly allowed"
    );

    // Allowed name: SNI matches the rule, connection proceeds.
    let allowed = probe_https_with_retry(&sb, "https://files.pythonhosted.org/").await;
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

    stop_and_remove(name).await;
}

/// SNI spoofing defense: claiming an allowed name in the ClientHello
/// while connecting to an IP no DNS lookup ever tied to that name
/// must be denied. Legit traffic for the same allowed name (resolved
/// via the gateway, cache populated) must still pass.
#[msb_test]
async fn domain_policy_sni_spoof_on_unrelated_ip_is_denied() {
    let name = "net-domain-policy-sni-spoof";
    let policy = NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        // DNS opens via the gateway, HTTPS allowed only for example.com.
        rules: vec![Rule::allow_dns(), allow_domain_https("example.com")],
    };
    let sb = setup_alpine(name, policy).await;

    // Prime an unrelated CDN's IP into the cache under its real name.
    // The same IP will be reused as the spoof target; nothing will
    // ever bind `example.com` to it.
    let spoof_ip = dns_lookup(&sb, "files.pythonhosted.org").await;
    assert!(
        !spoof_ip.is_empty(),
        "shared-cdn DNS lookup should resolve under allow_dns; got empty"
    );

    // Honest path: legitimate fetch of example.com (DNS via gateway,
    // example.com bound to its real IP in the cache) must succeed.
    // Establishes that the SNI+cache AND-check doesn't block normal
    // traffic before we test the spoof denial.
    let honest = probe_https_with_retry(&sb, "https://example.com/").await;
    assert!(
        reached_server(&honest),
        "honest example.com fetch should be allowed: got `{honest}`"
    );

    // Spoof: force curl to skip DNS and connect to the unrelated CDN
    // IP while sending `Host: example.com` and SNI=example.com.
    // The SNI byte-matches the rule, but no DNS lookup ever bound
    // `example.com` to this IP, so the cache check fails and the
    // proxy refuses to relay.
    let cmd = format!(
        "tmp=$(mktemp); \
         code=$(curl -sS --max-time 30 -o /dev/null \
                -w '%{{http_code}}' \
                --resolve example.com:443:{spoof_ip} \
                https://example.com/ 2>\"$tmp\"); \
         exit=$?; \
         err=$(tr '\\n' ' ' <\"$tmp\"; rm -f \"$tmp\"); \
         case \"$code\" in \
             000|\"\") printf 'FAIL exit=%s err=%s' \"$exit\" \"$err\" ;; \
             *) printf '%s' \"$code\" ;; \
         esac"
    );
    let spoof = sb.shell(&cmd).await.expect("curl spoof shell");
    let spoof_out = spoof.stdout().unwrap_or_default().trim().to_string();
    assert!(
        curl_failed(&spoof_out),
        "SNI spoof on unrelated IP {spoof_ip} should be denied: got `{spoof_out}`"
    );

    stop_and_remove(name).await;
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

    let www = probe_https_with_retry(&sb, "https://www.cloudflare.com/").await;
    assert!(
        reached_server(&www),
        "www.cloudflare.com should match .cloudflare.com suffix: got `{www}`"
    );

    let example = probe_https(&sb, "https://example.com/").await;
    assert!(
        curl_failed(&example),
        "example.com should not match .cloudflare.com suffix: got `{example}`"
    );

    stop_and_remove(name).await;
}
