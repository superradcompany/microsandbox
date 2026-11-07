use std::sync::atomic::{AtomicUsize, Ordering};

use serde_json::{Value, json};
use tokio::net::TcpListener;
use tokio::task::JoinSet;

use super::*;
use crate::backend::with_backend;
use crate::config::layers::BackendConfig;
use crate::test_support::fake_server::{Captured, FakeServer, Reply, respond};
use crate::{ChangeState, ServiceBuilder, ServiceStatus};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Golden Service body shared with the wire-type crate.
const SERVICE: &str =
    include_str!("../../../../../packages/microsandbox-types/rust/lib/cloud/fixtures/service.json");

/// Golden list page, including the `has_more` field the SDK ignores.
const SERVICE_PAGE: &str = include_str!(
    "../../../../../packages/microsandbox-types/rust/lib/cloud/fixtures/service-page.json"
);

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn error_body(code: &str) -> String {
    json!({"error": {"code": code, "message": format!("{code} message"), "details": null}})
        .to_string()
}

fn existing(backend: Arc<dyn Backend>) -> Service {
    Service::from_cloud(backend, serde_json::from_str(SERVICE).unwrap())
}

fn json_body(request: &Captured) -> Value {
    serde_json::from_str(&request.body).unwrap()
}

async fn every_change(server: &FakeServer) -> Vec<MicrosandboxError> {
    let backend = server.backend();
    let create = with_backend(
        backend.clone(),
        Service::builder("shop").target("web-1", 8080).create(),
    )
    .await;
    let update = existing(backend.clone())
        .update(|u| u.target("web-2", 8080))
        .await;
    let enable = existing(backend.clone()).enable().await;
    let disable = existing(backend.clone()).disable().await;
    let remove = existing(backend).remove().await;
    vec![
        create.unwrap_err(),
        update.unwrap_err(),
        enable.unwrap_err(),
        disable.unwrap_err(),
        remove.unwrap_err(),
    ]
}

fn assert_outcome_unknown(error: &MicrosandboxError) {
    assert!(
        matches!(
            error,
            MicrosandboxError::Service {
                error: ServiceError::OutcomeUnknown,
                ..
            }
        ),
        "expected OutcomeUnknown, got {error:?}"
    );
    assert_eq!(error.changed(), ChangeState::Unknown);
}

//--------------------------------------------------------------------------------------------------
// Tests: Error mapping
//--------------------------------------------------------------------------------------------------

#[test]
fn change_errors_map_from_stable_codes() {
    let wait = Some(Duration::from_secs(5));
    let cases: [(u16, &str, ServiceError); 7] = [
        (403, "service_quota_exceeded", ServiceError::QuotaExceeded),
        (
            403,
            "sandbox_service_limit_exceeded",
            ServiceError::SandboxLimitExceeded,
        ),
        (409, "service_conflict", ServiceError::Conflict),
        (409, "service_detached", ServiceError::Detached),
        (
            409,
            "target_unreachable",
            ServiceError::TargetUnreachable { retry_after: wait },
        ),
        (409, "sandbox_not_running", ServiceError::TargetNotRunning),
        (503, "outcome_unknown", ServiceError::OutcomeUnknown),
    ];
    for (status, code, expected) in cases {
        let body: CloudErrorBody = serde_json::from_str(&error_body(code)).unwrap();
        let error =
            service_change_error(status, Some(&body), "", ServiceChange::Update, "shop", wait);
        assert!(
            matches!(&error, MicrosandboxError::Service { slug, error } if slug == "shop" && *error == expected),
            "{code}: got {error:?}"
        );
        assert_eq!(error.changed(), expected.changed(), "{code}");
    }
}

#[test]
fn unknown_change_error_codes_remain_service_errors() {
    for code in ["new_service_refusal", "service_temporarily_unavailable"] {
        let body: CloudErrorBody = serde_json::from_str(&error_body(code)).unwrap();
        let error = service_change_error(409, Some(&body), "", ServiceChange::Update, "shop", None);

        assert!(
            matches!(
                &error,
                MicrosandboxError::Service {
                    slug,
                    error: ServiceError::Other {
                        code: actual_code,
                        status: 409,
                        message,
                    },
                } if slug == "shop"
                    && actual_code == code
                    && (code != "new_service_refusal"
                        || message == "new_service_refusal message")
            ),
            "{code}: got {error:?}"
        );
        assert_eq!(error.changed(), ChangeState::Unchanged, "{code}");
    }
}

#[test]
fn shared_codes_keep_their_existing_errors() {
    let mapped = |status, code: Option<&str>, change: ServiceChange| {
        let body = code.map(|code| serde_json::from_str(&error_body(code)).unwrap());
        service_change_error(status, body.as_ref(), "", change, "shop", None)
    };

    assert_eq!(
        mapped(404, Some("service_not_found"), ServiceChange::Update).to_string(),
        "service not found: shop"
    );
    assert_eq!(
        mapped(404, None, ServiceChange::Remove).to_string(),
        "service not found: shop"
    );
    assert!(matches!(
        mapped(404, Some("sandbox_not_found"), ServiceChange::Create),
        MicrosandboxError::SandboxNotFound(_)
    ));
    let taken = mapped(409, Some("service_already_exists"), ServiceChange::Create);
    assert!(
        matches!(&taken, MicrosandboxError::ServiceAlreadyExists(slug) if slug == "shop"),
        "got {taken:?}"
    );
    assert_eq!(
        taken.to_string(),
        "service slug unavailable: shop; choose another slug"
    );
    assert_eq!(taken.changed(), ChangeState::Unchanged);
    assert!(matches!(
        mapped(400, Some("invalid_request"), ServiceChange::Update),
        MicrosandboxError::InvalidConfig(_)
    ));

    let paused = service_change_error(
        503,
        Some(&serde_json::from_str(&error_body("service_changes_paused")).unwrap()),
        "",
        ServiceChange::Create,
        "shop",
        Some(Duration::from_secs(5)),
    );
    assert!(
        matches!(&paused, MicrosandboxError::Service { error: ServiceError::ChangesPaused { retry_after: Some(wait) }, .. } if *wait == Duration::from_secs(5)),
        "got {paused:?}"
    );
    assert_eq!(paused.changed(), ChangeState::Unchanged);
}

#[test]
fn read_routes_map_missing_services_and_bad_cursors() {
    let unknown_route = cloud_http_error(404, None, "", GET_OP);
    assert!(matches!(
        unknown_route,
        MicrosandboxError::ServiceNotFound(_)
    ));

    let body: CloudErrorBody = serde_json::from_str(&error_body("invalid_pagination")).unwrap();
    let bad_cursor = cloud_http_error(400, Some(&body), "", LIST_OP);
    assert!(matches!(bad_cursor, MicrosandboxError::InvalidConfig(_)));

    let body: CloudErrorBody = serde_json::from_str(&error_body("sandbox_not_running")).unwrap();
    let sandbox_route = cloud_http_error(409, Some(&body), "", "POST /v1/sandboxes/:id/start");
    assert!(matches!(
        sandbox_route,
        MicrosandboxError::CloudHttp { status: 409, .. }
    ));
}

#[test]
fn retry_after_accepts_delta_seconds_and_http_dates() {
    let mut headers = HeaderMap::new();
    headers.insert(RETRY_AFTER, "5".parse().unwrap());
    assert_eq!(parse_retry_after(&headers), Some(Duration::from_secs(5)));

    let deadline = SystemTime::now() + Duration::from_secs(3600);
    headers.insert(
        RETRY_AFTER,
        httpdate::fmt_http_date(deadline).parse().unwrap(),
    );
    assert!(parse_retry_after(&headers).is_some_and(|wait| !wait.is_zero()));

    headers.insert(
        RETRY_AFTER,
        httpdate::fmt_http_date(SystemTime::UNIX_EPOCH)
            .parse()
            .unwrap(),
    );
    assert_eq!(parse_retry_after(&headers), Some(Duration::ZERO));

    headers.insert(RETRY_AFTER, u64::MAX.to_string().parse().unwrap());
    assert_eq!(
        parse_retry_after(&headers),
        Some(Duration::from_secs(u64::MAX))
    );
}

#[test]
fn retry_after_rejects_malformed_values() {
    let mut headers = HeaderMap::new();
    for malformed in ["soon", "-5", "1.5"] {
        headers.insert(RETRY_AFTER, malformed.parse().unwrap());
        assert_eq!(parse_retry_after(&headers), None);
    }
}

//--------------------------------------------------------------------------------------------------
// Tests: Requests
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn create_sends_slug_and_target_and_accepts_both_success_statuses() {
    for status in [201, 200] {
        let server = FakeServer::start(respond(status, None, SERVICE)).await;
        let service = with_backend(
            server.backend(),
            Service::builder("shop").target("web-1", 8080).create(),
        )
        .await
        .unwrap();

        let request = server.only_request();
        assert_eq!(
            (request.method.as_str(), request.target.as_str()),
            ("POST", "/v1/services")
        );
        assert_eq!(
            json_body(&request),
            json!({"slug": "shop", "target": {"sandbox": "web-1", "port": 8080}})
        );
        assert_eq!(service.slug(), "shop");
        assert_eq!(service.url(), "https://shop.<domain>");
        assert_eq!(service.status(), ServiceStatus::Enabled);
        let target = service.target().unwrap();
        assert_eq!((target.sandbox.as_str(), target.port), ("web-1", 8080));
    }
}

#[tokio::test]
async fn get_and_list_decode_services_including_detached_ones() {
    let mut detached: Value = serde_json::from_str(SERVICE).unwrap();
    detached["status"] = json!("detached");
    detached["target"] = Value::Null;
    let server = FakeServer::start(respond(200, None, &detached.to_string())).await;
    let service = with_backend(server.backend(), Service::get("shop"))
        .await
        .unwrap();
    assert_eq!(server.only_request().target, "/v1/services/shop");
    assert_eq!(service.status(), ServiceStatus::Detached);
    assert!(service.target().is_none());

    let server = FakeServer::start(respond(404, None, &error_body("service_not_found"))).await;
    let missing = with_backend(server.backend(), Service::get("shop"))
        .await
        .unwrap_err();
    assert!(matches!(&missing, MicrosandboxError::ServiceNotFound(slug) if slug == "shop"));
    assert_eq!(missing.to_string(), "service not found: shop");

    let server = FakeServer::start(respond(200, None, SERVICE_PAGE)).await;
    let page = with_backend(
        server.backend(),
        Service::list_with(|l| l.sandbox("web-1").cursor("c1").limit(5)),
    )
    .await
    .unwrap();
    assert_eq!(
        server.only_request().target,
        "/v1/services?sandbox=web-1&cursor=c1&limit=5"
    );
    assert_eq!(page.services.len(), 1);
    assert_eq!(page.next_cursor.as_deref(), Some("shop"));

    let server = FakeServer::start(respond(200, None, SERVICE_PAGE)).await;
    with_backend(server.backend(), Service::list())
        .await
        .unwrap();
    assert_eq!(server.only_request().target, "/v1/services?limit=20");
}

#[tokio::test]
async fn update_and_actions_send_their_distinct_requests() {
    let server = FakeServer::start(respond(200, None, SERVICE)).await;
    existing(server.backend())
        .update(|u| u.target("web-2", 9000))
        .await
        .unwrap();
    let request = server.only_request();
    assert_eq!(
        (request.method.as_str(), request.target.as_str()),
        ("PATCH", "/v1/services/shop")
    );
    assert_eq!(
        json_body(&request),
        json!({"target": {"sandbox": "web-2", "port": 9000}})
    );

    for (path, enable) in [
        ("/v1/services/shop/enable", true),
        ("/v1/services/shop/disable", false),
    ] {
        let server = FakeServer::start(respond(200, None, SERVICE)).await;
        let service = existing(server.backend());
        if enable {
            service.enable().await.unwrap();
        } else {
            service.disable().await.unwrap();
        }
        let request = server.only_request();
        assert_eq!(
            (request.method.as_str(), request.target.as_str()),
            ("POST", path)
        );
        assert!(request.body.is_empty());
    }
}

#[tokio::test]
async fn update_redirect_is_an_unknown_outcome() {
    let target = FakeServer::start(respond(200, None, SERVICE)).await;
    let redirect = FakeServer::start(Reply::Respond(format!(
        "HTTP/1.1 302 Found\r\nConnection: close\r\nLocation: {}/redirected\r\nContent-Length: 0\r\n\r\n",
        target.url
    )))
    .await;

    let error = existing(redirect.backend())
        .update(|update| update.target("web-2", 9000))
        .await
        .unwrap_err();

    assert_outcome_unknown(&error);
    redirect.only_request();
    assert!(target.requests().is_empty());
}

#[tokio::test]
async fn remove_accepts_a_bodyless_no_content() {
    let server = FakeServer::start(respond(204, None, "")).await;
    existing(server.backend()).remove().await.unwrap();

    let request = server.only_request();
    assert_eq!(
        (request.method.as_str(), request.target.as_str()),
        ("DELETE", "/v1/services/shop")
    );
}

#[tokio::test]
async fn slugs_are_sent_as_one_encoded_path_segment() {
    let server = FakeServer::start(respond(200, None, SERVICE)).await;
    let backend = server.backend();
    let mut info: CloudService = serde_json::from_str(SERVICE).unwrap();
    info.slug = "a/b?c%2e".into();

    with_backend(backend.clone(), Service::get("a/b?c%2e"))
        .await
        .unwrap();
    let service = Service::from_cloud(backend, info);
    service.update(|u| u.target("web-2", 8080)).await.unwrap();
    service.enable().await.unwrap();
    service.disable().await.unwrap();
    // Only the route matters here: remove expects 204, so this 200 fails the call.
    service.remove().await.unwrap_err();

    let sent: Vec<(String, String)> = server
        .requests()
        .into_iter()
        .map(|request| (request.method, request.target))
        .collect();
    let expected = [
        ("GET", "/v1/services/a%2Fb%3Fc%252e"),
        ("PATCH", "/v1/services/a%2Fb%3Fc%252e"),
        ("POST", "/v1/services/a%2Fb%3Fc%252e/enable"),
        ("POST", "/v1/services/a%2Fb%3Fc%252e/disable"),
        ("DELETE", "/v1/services/a%2Fb%3Fc%252e"),
    ]
    .map(|(method, target)| (method.to_owned(), target.to_owned()));
    assert_eq!(sent, expected);
}

#[tokio::test]
async fn refused_changes_carry_the_server_wait() {
    let server =
        FakeServer::start(respond(409, Some("5"), &error_body("target_unreachable"))).await;
    let error = with_backend(
        server.backend(),
        Service::builder("shop").target("web-1", 8080).create(),
    )
    .await
    .unwrap_err();
    server.only_request();
    assert!(matches!(
        error,
        MicrosandboxError::Service {
            error: ServiceError::TargetUnreachable { retry_after: Some(wait) },
            ..
        } if wait == Duration::from_secs(5)
    ));
}

#[tokio::test]
async fn server_errors_on_changes_are_unknown_outcomes_sent_once() {
    for reply in [
        respond(500, None, ""),
        respond(502, None, "bad gateway"),
        respond(503, None, &error_body("outcome_unknown")),
        respond(504, None, &error_body("service_temporarily_unavailable")),
    ] {
        let server = FakeServer::start(reply).await;
        for error in every_change(&server).await {
            assert_outcome_unknown(&error);
        }
        assert_eq!(server.requests().len(), 5, "one request per change call");
    }
}

#[tokio::test]
async fn lost_responses_on_changes_are_unknown_outcomes_sent_once() {
    let server = FakeServer::start(Reply::Reset).await;
    for error in every_change(&server).await {
        assert_outcome_unknown(&error);
    }
    assert_eq!(server.requests().len(), 5, "one request per change call");

    let server = FakeServer::start(Reply::Hang).await;
    let backend = CloudBackend::builder()
        .url(&server.url)
        .api_key("test-key")
        .request_timeout(Duration::from_millis(300))
        .config_sources(BackendConfig::new(Default::default(), Default::default()))
        .build()
        .unwrap();
    let error = existing(Arc::new(backend)).disable().await.unwrap_err();
    assert_outcome_unknown(&error);
    server.only_request();
}

#[tokio::test]
async fn invalid_requests_fail_before_any_request() {
    let backend: Arc<dyn Backend> =
        Arc::new(crate::test_support::cloud_backend("http://127.0.0.1:1", "test-key").unwrap());
    let create = |builder: ServiceBuilder| with_backend(backend.clone(), builder.create());
    let list =
        |limit: u32| with_backend(backend.clone(), Service::list_with(move |l| l.limit(limit)));
    let with_slug = |slug: &str| {
        let mut info: CloudService = serde_json::from_str(SERVICE).unwrap();
        info.slug = slug.into();
        Service::from_cloud(backend.clone(), info)
    };

    let errors = [
        create(Service::builder("shop")).await.unwrap_err(),
        create(Service::builder("shop").target("web-1", 0))
            .await
            .unwrap_err(),
        existing(backend.clone()).update(|u| u).await.unwrap_err(),
        existing(backend.clone())
            .update(|u| u.target("web-2", 0))
            .await
            .unwrap_err(),
        with_backend(backend.clone(), Service::get(""))
            .await
            .unwrap_err(),
        with_slug(".").enable().await.unwrap_err(),
        with_slug("..").remove().await.unwrap_err(),
        list(0).await.unwrap_err(),
        list(101).await.unwrap_err(),
    ];
    for error in errors {
        assert!(
            matches!(error, MicrosandboxError::InvalidConfig(_)),
            "got {error:?}"
        );
        assert_eq!(error.changed(), ChangeState::Unchanged);
    }
}

#[tokio::test]
async fn refused_connections_are_transport_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    drop(listener);
    let backend: Arc<dyn Backend> =
        Arc::new(crate::test_support::cloud_backend(url, "test-key").unwrap());

    let error = existing(backend).disable().await.unwrap_err();
    assert!(
        matches!(&error, MicrosandboxError::Http(e) if e.is_connect()),
        "got {error:?}"
    );
    assert_eq!(error.changed(), ChangeState::Unchanged);
}

#[tokio::test]
async fn refused_http2_streams_are_not_resent() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let streams = Arc::new(AtomicUsize::new(0));
    let counted = streams.clone();
    let server = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let counted = counted.clone();
            connections.spawn(async move {
                let mut connection = h2::server::handshake(socket).await.unwrap();
                while let Some(Ok((_, mut respond))) = connection.accept().await {
                    counted.fetch_add(1, Ordering::SeqCst);
                    respond.send_reset(h2::Reason::REFUSED_STREAM);
                }
            });
        }
    });
    let client = service_change_client_builder()
        .http2_prior_knowledge()
        .build()
        .unwrap();
    let backend = CloudBackend::builder()
        .url(url)
        .api_key("test-key")
        .client(client)
        .config_sources(BackendConfig::new(Default::default(), Default::default()))
        .build()
        .unwrap();

    let error = existing(Arc::new(backend)).disable().await.unwrap_err();
    server.abort();

    assert_outcome_unknown(&error);
    assert_eq!(streams.load(Ordering::SeqCst), 1);
}
