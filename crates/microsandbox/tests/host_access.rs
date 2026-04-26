//! Integration tests for the `host.microsandbox.internal` alias.

use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use ipnetwork::{IpNetwork, Ipv4Network};
use microsandbox::{NetworkPolicy, Sandbox};
use microsandbox_network::policy::{Action, Destination, DestinationGroup, Rule};
use test_utils::msb_test;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

//--------------------------------------------------------------------------------------------------
// Host HTTP fixture
//--------------------------------------------------------------------------------------------------

/// Minimal HTTP server bound to `127.0.0.1` and `::1` on the same port. Dual-family avoids
/// flakes when the guest's happy-eyeballs picks v6 and the listener only lives on v4.
struct HostHttp {
    port: u16,
    shutdown: Option<oneshot::Sender<()>>,
    handle: Option<JoinHandle<()>>,
}

impl HostHttp {
    async fn start(body: &'static str) -> io::Result<Self> {
        let v4_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0))).await?;
        let port = v4_listener.local_addr()?.port();
        let v6_listener = TcpListener::bind(SocketAddr::from((Ipv6Addr::LOCALHOST, port))).await?;

        let (shutdown_tx, shutdown_rx) = oneshot::channel();
        let body = Arc::new(body.to_owned());

        let handle = tokio::spawn(async move {
            let mut shutdown_rx = shutdown_rx;
            loop {
                tokio::select! {
                    _ = &mut shutdown_rx => return,
                    accept = v4_listener.accept() => Self::handle_accept(accept, &body),
                    accept = v6_listener.accept() => Self::handle_accept(accept, &body),
                }
            }
        });

        Ok(Self {
            port,
            shutdown: Some(shutdown_tx),
            handle: Some(handle),
        })
    }

    fn handle_accept(accept: io::Result<(tokio::net::TcpStream, SocketAddr)>, body: &Arc<String>) {
        let Ok((mut stream, _)) = accept else { return };
        let body = body.clone();
        tokio::spawn(async move {
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body,
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }

    fn port(&self) -> u16 {
        self.port
    }
}

impl Drop for HostHttp {
    fn drop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
        if let Some(h) = self.handle.take() {
            h.abort();
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

/// Boot an alpine sandbox with the given policy (or the default when `None`).
async fn spawn_sandbox(name: &str, policy: Option<NetworkPolicy>) -> Sandbox {
    let builder = Sandbox::builder(name)
        .image("alpine")
        .cpus(1)
        .memory(256)
        .replace();
    match policy {
        Some(p) => builder.network(|n| n.policy(p)).create(),
        None => builder.create(),
    }
    .await
    .expect("create sandbox")
}

/// Stop the sandbox and remove it.
async fn teardown(sb: Sandbox, name: &str) {
    sb.stop_and_wait().await.expect("stop");
    let _ = Sandbox::remove(name).await;
}

/// Read the sandbox gateway IPv4 from the guest's `/etc/resolv.conf`.
async fn read_gateway_ip(sb: &Sandbox) -> String {
    let out = sb
        .shell("awk '/^nameserver /{print $2; exit}' /etc/resolv.conf")
        .await
        .expect("read resolv.conf");
    out.stdout().expect("utf8").trim().to_owned()
}

/// Allow host only; deny everything else.
fn allow_host_only_policy() -> NetworkPolicy {
    NetworkPolicy {
        default_egress: Action::Deny,
        default_ingress: Action::Allow,
        rules: vec![Rule::allow_egress(Destination::Group(
            DestinationGroup::Host,
        ))],
    }
}

/// Deny host only; allow everything else.
fn deny_host_group_policy() -> NetworkPolicy {
    NetworkPolicy {
        default_egress: Action::Allow,
        default_ingress: Action::Allow,
        rules: vec![Rule::deny_egress(Destination::Group(
            DestinationGroup::Host,
        ))],
    }
}

/// Deny the given gateway IPv4 `/32`; allow everything else.
fn deny_gateway_cidr_policy(gateway_ip: &str) -> NetworkPolicy {
    let addr: Ipv4Addr = gateway_ip.parse().expect("valid gateway ipv4");
    NetworkPolicy {
        default_egress: Action::Allow,
        default_ingress: Action::Allow,
        rules: vec![Rule::deny_egress(Destination::Cidr(IpNetwork::V4(
            Ipv4Network::new(addr, 32).expect("valid /32"),
        )))],
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

/// Baseline reachability by hostname and by raw gateway IPv4, plus `/etc/hosts` entry.
#[msb_test]
async fn host_alias_reachable_by_hostname_and_gateway_ip() {
    let server = HostHttp::start("hello from host")
        .await
        .expect("http fixture");
    let port = server.port();

    let name = "host-alias-baseline";
    let sb = spawn_sandbox(name, Some(NetworkPolicy::allow_all())).await;

    let out = sb
        .shell(format!(
            "wget -qO- --timeout=10 http://host.microsandbox.internal:{port}/"
        ))
        .await
        .expect("wget hostname");
    assert_eq!(
        out.stdout().unwrap().trim(),
        "hello from host",
        "hostname path body mismatch (stderr: {})",
        out.stderr().unwrap_or_default()
    );

    let gw = read_gateway_ip(&sb).await;
    let out = sb
        .shell(format!("wget -qO- --timeout=10 http://{gw}:{port}/"))
        .await
        .expect("wget gateway");
    assert_eq!(
        out.stdout().unwrap().trim(),
        "hello from host",
        "gateway-IP path body mismatch (stderr: {})",
        out.stderr().unwrap_or_default()
    );

    let hosts = sb
        .shell("cat /etc/hosts")
        .await
        .expect("cat /etc/hosts")
        .stdout()
        .unwrap()
        .to_owned();
    assert!(
        hosts.contains("host.microsandbox.internal"),
        "expected host.microsandbox.internal in /etc/hosts, got:\n{hosts}"
    );
    assert!(
        hosts.contains(&gw),
        "expected gateway IPv4 {gw} in /etc/hosts, got:\n{hosts}"
    );

    teardown(sb, name).await;
}

/// `dig` skips `/etc/hosts`, so a successful answer proves the forwarder synthesises the alias.
#[msb_test]
async fn host_alias_dns_synth_bypasses_hosts_file() {
    let name = "host-alias-dns-synth";
    let sb = spawn_sandbox(name, None).await;

    sb.shell("apk add --quiet --no-progress bind-tools >/dev/null 2>&1")
        .await
        .expect("install bind-tools");

    let gw = read_gateway_ip(&sb).await;
    let out = sb
        .shell("dig +short +time=3 +tries=1 host.microsandbox.internal A")
        .await
        .expect("dig alias");
    let answer = out.stdout().unwrap().trim().to_owned();
    assert_eq!(
        answer,
        gw,
        "expected DNS synth to return gateway {gw}, got {answer:?} (stderr: {})",
        out.stderr().unwrap_or_default()
    );

    teardown(sb, name).await;
}

/// CIDR deny on the gateway `/32` blocks host access (policy fires before the proxy rewrite).
#[msb_test]
async fn host_alias_denied_by_gateway_cidr_policy() {
    let server = HostHttp::start("should not see")
        .await
        .expect("http fixture");
    let port = server.port();

    // Boot once to read the gateway, tear down, then boot again with the CIDR policy.
    let probe_name = "host-alias-policy-probe";
    let probe = spawn_sandbox(probe_name, None).await;
    let gw = read_gateway_ip(&probe).await;
    teardown(probe, probe_name).await;

    let name = "host-alias-policy-deny";
    let sb = spawn_sandbox(name, Some(deny_gateway_cidr_policy(&gw))).await;

    // Dial v4 directly; via the hostname, happy-eyeballs could pick the v6 entry (not covered).
    let out = sb
        .shell(format!(
            "wget -qO- --timeout=5 http://{gw}:{port}/; echo status=$?"
        ))
        .await
        .expect("wget");
    let stdout = out.stdout().unwrap();
    assert!(
        stdout.contains("status=") && !stdout.trim_end().ends_with("status=0"),
        "expected wget to fail when gateway denied by policy; got: {stdout:?} (stderr: {})",
        out.stderr().unwrap_or_default()
    );

    teardown(sb, name).await;
}

/// Default `public_only` must block host access; users opt in explicitly.
#[msb_test]
async fn host_alias_denied_by_default_policy() {
    let server = HostHttp::start("should not see")
        .await
        .expect("http fixture");
    let port = server.port();

    let name = "host-alias-default-deny";
    let sb = spawn_sandbox(name, None).await;

    let out = sb
        .shell(format!(
            "wget -qO- --timeout=5 http://host.microsandbox.internal:{port}/; echo status=$?"
        ))
        .await
        .expect("wget");
    let stdout = out.stdout().unwrap();
    assert!(
        stdout.contains("status=") && !stdout.trim_end().ends_with("status=0"),
        "expected wget to fail under default public_only policy; got: {stdout:?} (stderr: {})",
        out.stderr().unwrap_or_default()
    );
    assert!(
        !stdout.contains("should not see"),
        "host body leaked through default-denied policy: {stdout:?}"
    );

    teardown(sb, name).await;
}

/// `Group::Host` allow on a deny-all base: host reachable, everything else denied.
#[msb_test]
async fn group_host_allow_narrows_to_gateway() {
    let server = HostHttp::start("host ok").await.expect("http fixture");
    let port = server.port();

    let name = "group-host-allow";
    let sb = spawn_sandbox(name, Some(allow_host_only_policy())).await;

    let out = sb
        .shell(format!(
            "wget -qO- --timeout=5 http://host.microsandbox.internal:{port}/"
        ))
        .await
        .expect("wget host");
    assert_eq!(
        out.stdout().unwrap().trim(),
        "host ok",
        "group host allow should let guest reach the host (stderr: {})",
        out.stderr().unwrap_or_default()
    );

    let out = sb
        .shell("wget -qO- --timeout=5 http://8.8.8.8/ ; echo status=$?")
        .await
        .expect("wget external");
    let stdout = out.stdout().unwrap();
    assert!(
        !stdout.trim_end().ends_with("status=0"),
        "non-host traffic should be denied under allow-host-only policy; got: {stdout:?}"
    );

    teardown(sb, name).await;
}

/// `Group::Host` deny on an allow-all base: host blocked, rest still works.
#[msb_test]
async fn group_host_deny_blocks_host_only() {
    let server = HostHttp::start("unreachable").await.expect("http fixture");
    let port = server.port();

    let name = "group-host-deny";
    let sb = spawn_sandbox(name, Some(deny_host_group_policy())).await;

    let out = sb
        .shell(format!(
            "wget -qO- --timeout=5 http://host.microsandbox.internal:{port}/ ; echo status=$?"
        ))
        .await
        .expect("wget host");
    let stdout = out.stdout().unwrap();
    assert!(
        !stdout.trim_end().ends_with("status=0"),
        "host should be denied by group-host deny rule; got: {stdout:?}"
    );

    teardown(sb, name).await;
}
