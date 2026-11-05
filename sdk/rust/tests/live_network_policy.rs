//! Integration tests for replacing a running sandbox's network policy.

use std::net::{Ipv4Addr, SocketAddr};

use microsandbox::{NetworkPolicy, Sandbox};
use test_utils::msb_test;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;

//--------------------------------------------------------------------------------------------------
// Helpers
//--------------------------------------------------------------------------------------------------

/// A host HTTP service on IPv4 loopback that answers every request with `ok`.
async fn host_service() -> u16 {
    let listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))
        .await
        .expect("bind host service");
    let port = listener.local_addr().expect("local addr").port();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                    )
                    .await;
                let _ = stream.shutdown().await;
            });
        }
    });
    port
}

async fn spawn_sandbox(name: &str, policy: NetworkPolicy) -> Sandbox {
    Sandbox::builder(name)
        .image("mirror.gcr.io/library/alpine")
        .cpus(1)
        .memory(256)
        .replace()
        .network(|n| n.policy(policy))
        .create()
        .await
        .expect("create sandbox")
}

/// Whether the guest gets the host service's answer through the host alias.
async fn reaches_host(sb: &Sandbox, port: u16) -> bool {
    let out = sb
        .shell(format!(
            "wget -qO- --timeout=5 http://host.microsandbox.internal:{port}/"
        ))
        .await
        .expect("run wget");
    out.stdout().unwrap_or_default().trim() == "ok"
}

async fn teardown(sb: Sandbox, name: &str) {
    sb.stop().await.expect("stop");
    drop(sb);
    let _ = Sandbox::remove(name).await;
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[msb_test]
async fn a_running_sandbox_loses_the_network_when_its_policy_is_closed() {
    let port = host_service().await;
    let name = "live-policy-close";
    let sb = spawn_sandbox(name, NetworkPolicy::allow_all()).await;
    assert!(
        reaches_host(&sb, port).await,
        "the open policy refused the host"
    );

    sb.set_network_policy(&NetworkPolicy::none())
        .await
        .expect("set the closed policy");
    let reached = reaches_host(&sb, port).await;

    teardown(sb, name).await;
    assert!(
        !reached,
        "the guest reached the host after its policy closed"
    );
}

#[msb_test]
async fn a_sandbox_booted_without_network_gains_it_when_its_policy_is_opened() {
    let port = host_service().await;
    let name = "live-policy-open";
    let sb = spawn_sandbox(name, NetworkPolicy::none()).await;
    assert!(
        !reaches_host(&sb, port).await,
        "the closed policy let the guest out"
    );

    sb.set_network_policy(&NetworkPolicy::allow_all())
        .await
        .expect("set the open policy");
    let reached = reaches_host(&sb, port).await;

    teardown(sb, name).await;
    assert!(
        reached,
        "the guest could not reach the host after its policy opened"
    );
}

#[msb_test]
async fn an_old_handle_cannot_change_a_sandbox_that_replaced_it_under_the_same_name() {
    let port = host_service().await;
    let name = "live-policy-replaced";
    let old = spawn_sandbox(name, NetworkPolicy::allow_all()).await;
    old.stop().await.expect("stop the first sandbox");
    let new = spawn_sandbox(name, NetworkPolicy::allow_all()).await;

    let refused = old.set_network_policy(&NetworkPolicy::none()).await;
    let reached = reaches_host(&new, port).await;

    teardown(new, name).await;
    assert!(
        matches!(
            refused,
            Err(microsandbox::MicrosandboxError::SandboxReplaced { .. })
        ),
        "{refused:?}"
    );
    assert!(reached, "the old handle closed the replacement's network");
}
