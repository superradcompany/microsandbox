//! Named-volume provisioning through the public SDK and the cloud HTTP boundary.

use std::time::Duration;

use serde_json::{Value, json};

use crate::MicrosandboxError;
use crate::error::{Operation, UnsupportedReason};
use crate::sandbox::{MountBuilder, Sandbox, SandboxBuilder};
use crate::test_support::fake_server::{FakeServer, Reply, respond};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn volume() -> Value {
    json!({
        "id": "volume-id", "name": "cache", "kind": "managed", "status": "active",
        "created_at": "2026-11-17T00:00:00Z", "updated_at": "2026-11-17T00:00:00Z"
    })
}

fn sandbox() -> Value {
    json!({
        "id": "sandbox-id", "org_id": "org-id", "name": "agent", "slug": "agent",
        "status": "running", "ephemeral": true, "created_at": "2026-11-17T00:00:00Z"
    })
}

fn reply(status: u16, body: Value) -> Reply {
    respond(status, None, &body.to_string())
}

fn builder(server: &FakeServer) -> SandboxBuilder {
    Sandbox::ctx(server.backend().as_ref())
        .builder("agent")
        .image("alpine")
        .volume("/cache", |m| m.named_with("cache", |v| v.ensure_exists()))
        .volume("/readonly", |m| {
            m.named_with("cache", |v| v.ensure_exists()).readonly()
        })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn named_volume_mounts_reuse_or_create_once_before_sandbox_create() {
    for (existing, race) in [(true, false), (false, false), (false, true)] {
        let mut replies = vec![reply(
            200,
            if existing {
                json!([volume()])
            } else {
                json!([])
            },
        )];
        if !existing {
            replies.push(if race {
                reply(409, json!({"error": {"code": "name_already_exists", "message": "volume already exists"}}))
            } else {
                reply(201, volume())
            });
        }
        if race {
            replies.push(reply(200, json!([volume()])));
        }
        replies.push(reply(201, sandbox()));
        let server = FakeServer::scripted(replies).await;

        let created = tokio::time::timeout(Duration::from_secs(5), builder(&server).create())
            .await
            .unwrap()
            .unwrap();

        let requests = server.requests();
        let mut expected = vec![("GET", "/v1/volumes")];
        if !existing {
            expected.push(("POST", "/v1/volumes"));
            let body: Value = serde_json::from_str(&requests[1].body).unwrap();
            assert_eq!(body, json!({"name": "cache", "labels": {}}));
        }
        if race {
            expected.push(("GET", "/v1/volumes"));
        }
        expected.push((
            "POST",
            "/v1/sandboxes?start=true&wait_for=running&wait_timeout=90",
        ));
        assert_eq!(
            requests
                .iter()
                .map(|r| (r.method.as_str(), r.target.as_str()))
                .collect::<Vec<_>>(),
            expected,
        );

        let body: Value = serde_json::from_str(&requests.last().unwrap().body).unwrap();
        let mounts = body["mounts"].as_array().unwrap();
        assert_eq!(mounts.len(), 2);
        for mount in mounts {
            assert_eq!(mount["name"], "cache");
            assert!(mount.get("create").is_none());
        }
        assert_eq!(mounts[0]["guest"], "/cache");
        assert_eq!(mounts[1]["guest"], "/readonly");
        assert_eq!(mounts[1]["options"]["readonly"], true);
        assert!(
            created
                .prepared_runtime()
                .unwrap()
                .config
                .spec
                .mounts
                .iter()
                .all(|m| m.named_create().is_none())
        );
    }
}

#[tokio::test]
async fn named_volume_failures_do_not_create_a_sandbox() {
    for create_failure in [false, true] {
        let mut replies = Vec::new();
        if create_failure {
            replies.push(reply(200, json!([])));
        }
        replies.push(reply(403, json!({"error": {"message": "denied"}})));
        let server = FakeServer::scripted(replies).await;

        let result = builder(&server).create().await;

        assert!(matches!(
            result,
            Err(MicrosandboxError::CloudHttp { status: 403, .. })
        ));
        let requests = server.requests();
        assert_eq!(requests.len(), if create_failure { 2 } else { 1 });
        assert!(requests.iter().all(|r| r.target == "/v1/volumes"));
    }
}

#[tokio::test]
async fn named_volume_options_and_invalid_sandboxes_fail_before_provisioning() {
    let mounts = [
        MountBuilder::new("/cache").named_with("cache", |v| v.create()),
        MountBuilder::new("/cache")
            .named_with("cache", |v| v.ensure_exists().disk().size(1024_u32)),
        MountBuilder::new("/cache").named_with("cache", |v| v.ensure_exists().quota(1024_u32)),
        MountBuilder::new("/cache").named_with("cache", |v| v.ensure_exists().size(1024_u32)),
        MountBuilder::new("/cache")
            .named_with("cache", |v| v.ensure_exists().label("key", "value")),
    ];
    let server = FakeServer::scripted(Vec::new()).await;
    for mount in mounts {
        let request = Sandbox::ctx(server.backend().as_ref())
            .builder("agent")
            .image("alpine")
            .volume("/a-first", |m| m.named_with("first", |v| v.ensure_exists()))
            .volume("/cache", |_| mount);

        let error = request
            .create()
            .await
            .err()
            .expect("unsupported creation settings must fail");

        assert!(
            matches!(
                error,
                MicrosandboxError::Unsupported {
                    op: Operation::SandboxCreate,
                    reason: UnsupportedReason::ConfigField("named volume inline create"),
                }
            ),
            "{error}"
        );
    }
    let result = builder(&server).replace().create().await;

    assert!(matches!(
        result,
        Err(MicrosandboxError::Unsupported {
            reason: UnsupportedReason::ConfigField("replace"),
            ..
        })
    ));
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn plain_named_mount_keeps_existing_only_behavior() {
    let server = FakeServer::scripted(vec![reply(201, sandbox())]).await;
    let request = Sandbox::ctx(server.backend().as_ref())
        .builder("agent")
        .image("alpine")
        .volume("/cache", |m| m.named("cache"));

    let _sandbox = request.create().await.unwrap();

    assert_eq!(
        server.only_request().target,
        "/v1/sandboxes?start=true&wait_for=running&wait_timeout=90"
    );
}
