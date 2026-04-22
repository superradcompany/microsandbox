//! DNS integration test matrix.
//!
//! Exercises every DNS path the interceptor supports, in combination
//! with domain block-list and network-egress-policy rules. Drives a
//! real guest via `dig` and asserts the DNS response status per
//! scenario:
//!
//! - Plain UDP/53 + TCP/53, both to the sandbox gateway and to external
//!   `@target` resolvers (`dig @1.1.1.1`, `dig @8.8.8.8`).
//! - Domain block list (exact + suffix) against every transport.
//! - Network egress policy denying a specific resolver IP.
//! - DoT (TCP/853): intercepted when TLS MITM is enabled; refused when
//!   it isn't.
//!
//! These tests require KVM (or libkrun on macOS). The `#[msb_test]`
//! attribute marks them `#[ignore]`, so plain `cargo test --workspace`
//! skips them. Run them via:
//!
//!     cargo nextest run -p microsandbox --tests --run-ignored=only
//!
//! Set `MSB_TEST_ISOLATE_HOME=1` (CI does this) to give each test its
//! own `~/.microsandbox` so the two sandboxes can set up in parallel
//! without sharing the sqlite db, image cache, or sandbox namespace.
//!
//! Split into two tests so each sandbox (plain DNS vs TLS-MITM) gets
//! its own process and a failure in one path doesn't block the other.

mod sandbox;
mod scenario;

use microsandbox::{NetworkPolicy, Sandbox};
use microsandbox_network::builder::NetworkBuilder;
use test_utils::msb_test;

use crate::sandbox::{deny_resolver, setup_sandbox};
use crate::scenario::{Expect, assert_scenario, dig};

const BLOCKED_EXACT: &str = "blocked.example.com";
const BLOCKED_SUFFIX: &str = ".blocked.test";
const DENIED_RESOLVER: &str = "8.8.8.8";

/// Location of the sandbox intercept CA inside the guest (installed by
/// agentd when TLS MITM is enabled). `dig +tls-ca=<path>` trusts it
/// directly so DoT handshakes against MITM'd targets validate.
const GUEST_TLS_CA: &str = "+tls-ca=/.msb/tls/ca.pem";

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Plain DNS matrix: UDP/53 + TCP/53 against the gateway, against
/// external `@targets`, and against a policy-denied resolver. Also
/// asserts that DoT without TLS interception is refused (stub should
/// fall back to plain DNS).
#[msb_test]
async fn dns_matrix_plain() {
    let name = "net-dns-matrix-plain";
    let deny_policy = deny_resolver(DENIED_RESOLVER).expect("policy");
    let blocked_suffix = format!("test{BLOCKED_SUFFIX}");
    let denied = format!("@{DENIED_RESOLVER}");

    let configure = |n| with_policy_and_block_list(n, deny_policy.clone());
    let (sb, _) = setup_sandbox(name, configure).await.expect("setup");

    #[rustfmt::skip]
    let scenarios: Vec<(&str, String, Expect)> = vec![
        // UDP/53, gateway.
        ("udp/53 gateway: allowed",         dig("example.com",   &[]),                          Expect::Resolves),
        ("udp/53 gateway: blocked exact",   dig(BLOCKED_EXACT,   &[]),                          Expect::Refused),
        ("udp/53 gateway: blocked suffix",  dig(&blocked_suffix, &[]),                          Expect::Refused),
        // UDP/53, @allowed external target.
        ("udp/53 @1.1.1.1: allowed",        dig("example.com",   &["@1.1.1.1"]),                Expect::Resolves),
        ("udp/53 @1.1.1.1: blocked exact",  dig(BLOCKED_EXACT,   &["@1.1.1.1"]),                Expect::Refused),
        // UDP/53, @policy-denied target.
        ("udp/53 @8.8.8.8 (denied)",        dig("example.com",   &[&denied]),                   Expect::Refused),
        // TCP/53, gateway.
        ("tcp/53 gateway: allowed",         dig("example.com",   &["+tcp"]),                    Expect::Resolves),
        ("tcp/53 gateway: blocked exact",   dig(BLOCKED_EXACT,   &["+tcp"]),                    Expect::Refused),
        ("tcp/53 gateway: blocked suffix",  dig(&blocked_suffix, &["+tcp"]),                    Expect::Refused),
        // TCP/53, @allowed external target.
        ("tcp/53 @1.1.1.1: allowed",        dig("example.com",   &["+tcp", "@1.1.1.1"]),        Expect::Resolves),
        ("tcp/53 @1.1.1.1: blocked exact",  dig(BLOCKED_EXACT,   &["+tcp", "@1.1.1.1"]),        Expect::Refused),
        // TCP/53, @policy-denied target.
        ("tcp/53 @8.8.8.8 (denied)",        dig("example.com",   &["+tcp", &denied]),           Expect::Refused),
        // DoT without MITM: smoltcp RSTs, stub should fall back.
        ("dot/853 @1.1.1.1 without MITM",   dig("example.com",   &["+tls", "@1.1.1.1"]),        Expect::NoAnswer),
    ];

    for (scenario, cmd, want) in &scenarios {
        assert_scenario(&sb, scenario, cmd, *want).await;
    }

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

/// DoT matrix with TLS interception enabled: guest → gateway and
/// guest → external `@target` over TCP/853, with block-list and
/// policy-denied cases.
#[msb_test]
async fn dns_matrix_dot() {
    let name = "net-dns-matrix-dot";
    let deny_policy = deny_resolver(DENIED_RESOLVER).expect("policy");
    let blocked_suffix = format!("test{BLOCKED_SUFFIX}");
    let denied = format!("@{DENIED_RESOLVER}");

    let configure = |n| with_policy_and_block_list(n, deny_policy.clone()).tls(|t| t);
    let (sb, gateway_ip) = setup_sandbox(name, configure).await.expect("setup");

    // DoT-specific dig arguments. BIND's `dig +tls` requires
    // `+tls-hostname=<h>` to validate the server cert (and to emit any
    // output at all). Using the peer IP works because our intercept CA
    // generates a cert with the IP in its SAN list.
    let ca = GUEST_TLS_CA;
    let gateway = format!("@{gateway_ip}");
    let gateway_hostname = format!("+tls-hostname={gateway_ip}");

    #[rustfmt::skip]
    let scenarios: Vec<(&str, String, Expect)> = vec![
        // DoT to gateway: forwarder uses configured upstream (plain DNS).
        ("dot/853 @<gateway>: allowed",        dig("example.com",   &["+tls", ca, &gateway_hostname, &gateway]),             Expect::Resolves),
        ("dot/853 @<gateway>: blocked exact",  dig(BLOCKED_EXACT,   &["+tls", ca, &gateway_hostname, &gateway]),             Expect::Refused),
        ("dot/853 @<gateway>: blocked suffix", dig(&blocked_suffix, &["+tls", ca, &gateway_hostname, &gateway]),             Expect::Refused),
        // DoT to @target: forwarder re-TLS upstream.
        ("dot/853 @1.1.1.1: allowed",          dig("example.com",   &["+tls", ca, "+tls-hostname=1.1.1.1", "@1.1.1.1"]),     Expect::Resolves),
        ("dot/853 @1.1.1.1: blocked exact",    dig(BLOCKED_EXACT,   &["+tls", ca, "+tls-hostname=1.1.1.1", "@1.1.1.1"]),     Expect::Refused),
        // DoT to policy-denied @target: forwarder refuses before upstream.
        ("dot/853 @8.8.8.8 (denied)",          dig("example.com",   &["+tls", ca, "+tls-hostname=8.8.8.8", &denied]),        Expect::Refused),
    ];

    for (scenario, cmd, want) in &scenarios {
        assert_scenario(&sb, scenario, cmd, *want).await;
    }

    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

//--------------------------------------------------------------------------------------------------
// Network config helpers
//--------------------------------------------------------------------------------------------------

/// Apply the network config shared by both sandboxes: the deny-resolver
/// policy and the DNS block list (exact + suffix).
fn with_policy_and_block_list(n: NetworkBuilder, policy: NetworkPolicy) -> NetworkBuilder {
    n.policy(policy).dns(|d| {
        d.block_domain(BLOCKED_EXACT)
            .block_domain_suffix(BLOCKED_SUFFIX)
    })
}
