use std::future::Future;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use serde_json::json;
use tokio::io::{
    AsyncBufRead, AsyncBufReadExt, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufReader,
};
use tokio::net::{TcpListener, TcpStream};

use super::*;
use crate::sandbox::SecretModificationPatch;

const SANDBOX_ID: &str = "6f1c1f7e-3b8a-4c2e-9d55-0a1b2c3d4e5f";
const VALUE: &str = "dummy-modify-value-7c1e";
const RESULT_UNKNOWN: &str =
    "; the result is unknown, and sending the same change again retries it";

//--------------------------------------------------------------------------------------------------
// Mock server
//--------------------------------------------------------------------------------------------------

#[derive(Clone)]
enum Reply {
    Json(u16, serde_json::Value),
    /// Wait, then answer.
    Slow(Duration, u16, serde_json::Value),
    /// Read the request, then close the connection without an answer.
    Hangup,
}

#[derive(Clone)]
struct Recorded {
    line: String,
    body: String,
}

type Handler = Arc<dyn Fn(usize, Duration) -> Reply + Send + Sync>;

/// Serves one request per connection; `handler` gets the request's index and
/// the time since the first request.
struct MockCloud {
    url: String,
    requests: Arc<Mutex<Vec<Recorded>>>,
}

impl MockCloud {
    async fn start(handler: impl Fn(usize, Duration) -> Reply + Send + Sync + 'static) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        Self::serve(listener, Arc::new(handler))
    }

    /// Replies in order, repeating the last.
    async fn replies(replies: Vec<Reply>) -> Self {
        Self::start(move |index, _| replies[index.min(replies.len() - 1)].clone()).await
    }

    fn serve(listener: TcpListener, handler: Handler) -> Self {
        let url = format!("http://{}", listener.local_addr().unwrap());
        let requests = Arc::new(Mutex::new(Vec::new()));
        let log = requests.clone();
        tokio::spawn(async move {
            let mut first = None;
            while let Ok((stream, _)) = listener.accept().await {
                let mut reader = BufReader::new(stream);
                let Some(request) = read_request(&mut reader).await else {
                    continue;
                };
                let started = *first.get_or_insert_with(Instant::now);
                let index = {
                    let mut log = log.lock().unwrap();
                    log.push(request);
                    log.len() - 1
                };
                let reply = handler(index, started.elapsed());
                let handler_stream = reader.into_inner();
                tokio::spawn(answer(handler_stream, reply));
            }
        });
        Self { url, requests }
    }

    fn backend(&self) -> crate::CloudBackend {
        crate::test_support::cloud_backend(&self.url, "test-key").unwrap()
    }

    fn requests(&self) -> Vec<Recorded> {
        self.requests.lock().unwrap().clone()
    }
}

async fn answer(mut stream: TcpStream, reply: Reply) {
    let (status, body) = match reply {
        Reply::Json(status, body) => (status, body),
        Reply::Slow(delay, status, body) => {
            tokio::time::sleep(delay).await;
            (status, body)
        }
        Reply::Hangup => return,
    };
    write_json(&mut stream, status, &body, true).await;
}

async fn read_request(reader: &mut (impl AsyncBufRead + Unpin)) -> Option<Recorded> {
    let mut line = String::new();
    if reader.read_line(&mut line).await.ok()? == 0 {
        return None;
    }
    let mut content_length = 0;
    loop {
        let mut header = String::new();
        if reader.read_line(&mut header).await.ok()? == 0 {
            return None;
        }
        if header == "\r\n" {
            break;
        }
        if let Some((name, value)) = header.split_once(':')
            && name.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse::<usize>().unwrap();
        }
    }
    let mut body = vec![0; content_length];
    reader.read_exact(&mut body).await.ok()?;
    Some(Recorded {
        line: line.trim_end().to_owned(),
        body: String::from_utf8(body).unwrap(),
    })
}

async fn write_json(
    stream: &mut (impl AsyncWrite + Unpin),
    status: u16,
    body: &serde_json::Value,
    close: bool,
) {
    let body = body.to_string();
    let connection = if close { "close" } else { "keep-alive" };
    let response = format!(
        "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {connection}\r\n\r\n{body}",
        body.len(),
    );
    stream.write_all(response.as_bytes()).await.unwrap();
}

//--------------------------------------------------------------------------------------------------
// Fixtures
//--------------------------------------------------------------------------------------------------

fn plan_json(applied: bool, disposition: &str) -> serde_json::Value {
    json!({
        "sandbox": "agent-1",
        "status": "running",
        "applied": applied,
        "policy": "no_restart",
        "changes": [{
            "kind": "secret",
            "field": "secret",
            "name": "API_KEY",
            "change": "rotated",
            "disposition": disposition,
        }],
        "conflicts": [],
        "warnings": [],
    })
}

fn error_json(code: &str, message: &str) -> serde_json::Value {
    json!({"error": {"code": code, "message": message}})
}

fn plan_line() -> String {
    format!("POST /v1/sandboxes/{SANDBOX_ID}/modifications/plan HTTP/1.1")
}

fn apply_line() -> String {
    format!("PUT /v1/sandboxes/{SANDBOX_ID} HTTP/1.1")
}

fn body(request: &Recorded) -> serde_json::Value {
    serde_json::from_str(&request.body).unwrap()
}

fn value_patch(value: &str) -> SandboxModificationPatch {
    SandboxModificationPatch {
        secrets: vec![SecretModificationPatch {
            name: "API_KEY".into(),
            value: value.to_string().into(),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn env_patch(var: &str) -> SandboxModificationPatch {
    SandboxModificationPatch {
        secrets: vec![SecretModificationPatch {
            name: "API_KEY".into(),
            source: Some(SecretSource::env(var)),
            ..Default::default()
        }],
        ..Default::default()
    }
}

/// Budgets on real time, short enough for tests.
fn short_budget(total_ms: u64) -> ApplyBudget {
    ApplyBudget {
        total: Duration::from_millis(total_ms),
        per_request: Duration::from_millis(total_ms),
        not_sent: Backoff {
            first: Duration::from_millis(50),
            max: Duration::from_millis(100),
            jitter: false,
        },
        in_progress: Backoff {
            first: Duration::from_millis(50),
            max: Duration::from_millis(200),
            jitter: true,
        },
    }
}

async fn apply_within(
    backend: &crate::CloudBackend,
    patch: &SandboxModificationPatch,
    budget: ApplyBudget,
) -> MicrosandboxResult<SandboxModificationPlan> {
    let request = CloudSandboxModificationApplyRequest::from_patch(
        patch,
        ModificationPolicy::NoRestart,
        |_| None,
    )
    .unwrap();
    backend
        .apply_with_retries(SANDBOX_ID, &request, budget)
        .await
}

/// Run `test` on its own runtime with `var` set to `value`, or unset, holding
/// the process environment lock outside any await point.
fn with_env<T>(var: &str, value: Option<&str>, test: impl Future<Output = T>) -> T {
    let _env = crate::test_support::lock_env();
    // SAFETY: environment mutation is serialized by `lock_env`.
    unsafe {
        match value {
            Some(value) => std::env::set_var(var, value),
            None => std::env::remove_var(var),
        }
    }
    let result = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(test);
    // SAFETY: environment mutation is serialized by `lock_env`.
    unsafe { std::env::remove_var(var) };
    result
}

fn is_not_confirmed(error: &MicrosandboxError) -> bool {
    matches!(error, MicrosandboxError::ModificationNotConfirmed { .. })
}

//--------------------------------------------------------------------------------------------------
// Tests: classify
//--------------------------------------------------------------------------------------------------

fn answered(status: u16, body: serde_json::Value) -> Attempt {
    classify(SendOutcome::Answered {
        status,
        body: body.to_string(),
    })
}

#[test]
fn classify_table() {
    assert!(matches!(
        answered(200, plan_json(true, "live")),
        Attempt::Done(plan) if plan.applied
    ));
    assert!(matches!(
        classify(SendOutcome::Answered { status: 200, body: "{\"sandbox\":".into() }),
        Attempt::Fail(MicrosandboxError::ModificationNotConfirmed { cause })
            if cause.ends_with(RESULT_UNKNOWN)
    ));
    assert!(matches!(
        answered(409, error_json(CLOUD_MODIFICATION_IN_PROGRESS, "busy")),
        Attempt::Retry {
            class: RetryClass::InProgress,
            at_deadline: MicrosandboxError::CloudHttp { status: 409, code: Some(code), .. },
        } if code == CLOUD_MODIFICATION_IN_PROGRESS
    ));
    assert!(matches!(
        answered(409, error_json(CLOUD_MODIFICATION_REFUSED, "cannot apply modification: secret API_KEY requires restart")),
        Attempt::Fail(MicrosandboxError::Custom(message))
            if message == "cannot apply modification: secret API_KEY requires restart"
    ));
    assert!(matches!(
        answered(409, error_json(CLOUD_MODIFICATION_UNSUPPORTED, "turned off")),
        Attempt::Fail(MicrosandboxError::Unsupported {
            op: Operation::SandboxModify,
            reason: UnsupportedReason::NotAvailable(message),
        }) if message.ends_with("turned off")
    ));
    let server_cause = "the stored secret state needs repair; contact support";
    assert!(matches!(
        answered(503, error_json(CLOUD_MODIFICATION_FAILED, server_cause)),
        Attempt::Fail(MicrosandboxError::ModificationNotConfirmed { cause }) if cause == server_cause
    ));
    for (status, body) in [
        (503, error_json("service_unavailable", "draining")),
        (500, error_json("internal_error", "boom")),
        (502, json!("bad gateway")),
        (504, json!(null)),
        (202, json!({})),
    ] {
        let attempt = answered(status, body);
        assert!(
            matches!(
                &attempt,
                Attempt::Fail(MicrosandboxError::ModificationNotConfirmed { cause })
                    if cause.ends_with(RESULT_UNKNOWN)
            ),
            "{status}"
        );
    }
    assert!(matches!(
        answered(400, error_json(CLOUD_MODIFICATION_FAILED, "bad request")),
        Attempt::Fail(MicrosandboxError::InvalidConfig(_))
    ));
    assert!(matches!(
        answered(409, error_json(CLOUD_MODIFICATION_FAILED, "conflict")),
        Attempt::Fail(MicrosandboxError::CloudHttp { status: 409, .. })
    ));
    assert!(matches!(
        answered(404, error_json("sandbox_not_found", "missing")),
        Attempt::Fail(MicrosandboxError::SandboxNotFound(_))
    ));
    assert!(matches!(
        answered(400, error_json("invalid_request", "bad name")),
        Attempt::Fail(MicrosandboxError::InvalidConfig(_))
    ));
    assert!(matches!(
        answered(409, error_json("invalid_state_transition", "deleting")),
        Attempt::Fail(MicrosandboxError::CloudHttp { status: 409, .. })
    ));
    for cause in [
        "no answer came before the request timed out",
        "the answer was cut off",
    ] {
        assert!(matches!(
            classify(SendOutcome::Lost(cause)),
            Attempt::Fail(MicrosandboxError::ModificationNotConfirmed { cause: text })
                if text == format!("{cause}{RESULT_UNKNOWN}")
        ));
    }
}

#[test]
fn error_codes_decode_once() {
    for (code, expected) in [
        (CLOUD_MODIFICATION_IN_PROGRESS, ModifyErrorCode::InProgress),
        (CLOUD_MODIFICATION_REFUSED, ModifyErrorCode::Refused),
        (CLOUD_MODIFICATION_UNSUPPORTED, ModifyErrorCode::Unsupported),
        (CLOUD_MODIFICATION_FAILED, ModifyErrorCode::Failed),
    ] {
        assert_eq!(code.parse::<ModifyErrorCode>(), Ok(expected));
    }
    assert!("sandbox_not_found".parse::<ModifyErrorCode>().is_err());
}

#[test]
fn backoff_doubles_to_its_cap_and_jitter_stays_within_twenty_percent() {
    let mut retries = 0;
    let delays: Vec<_> = (0..5)
        .map(|_| APPLY_BUDGET.not_sent.delay(&mut retries))
        .collect();
    assert_eq!(
        delays,
        [250, 500, 1000, 2000, 2000].map(Duration::from_millis)
    );

    let mut retries = 0;
    for nominal in [1, 2, 4, 8, 8] {
        let delay = APPLY_BUDGET.in_progress.delay(&mut retries);
        let nominal = Duration::from_secs(nominal);
        assert!(
            delay >= nominal.mul_f64(0.8) && delay < nominal.mul_f64(1.2),
            "{delay:?}"
        );
    }
}

//--------------------------------------------------------------------------------------------------
// Tests: failures before sending are sent again
//--------------------------------------------------------------------------------------------------

/// A cloud backend at `url` whose requests go through `client`.
fn backend_with(url: &str, client: reqwest::Client) -> crate::CloudBackend {
    let mut backend = crate::test_support::cloud_backend(url, "test-key").unwrap();
    backend.http = client;
    backend
}

/// Serve the mock on `addr` once 300 ms have passed; until then it refuses connections.
fn serve_later(addr: SocketAddr) -> tokio::task::JoinHandle<MockCloud> {
    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(300)).await;
        let listener = TcpListener::bind(addr).await.unwrap();
        MockCloud::serve(
            listener,
            Arc::new(|_, _| Reply::Json(200, plan_json(true, "live"))),
        )
    })
}

async fn closed_addr() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    listener.local_addr().unwrap()
}

/// Fails the first lookup, then resolves every name to `addr`.
struct FlakyResolver {
    addr: SocketAddr,
    lookups: Arc<AtomicUsize>,
}

impl reqwest::dns::Resolve for FlakyResolver {
    fn resolve(&self, _name: reqwest::dns::Name) -> reqwest::dns::Resolving {
        let first = self.lookups.fetch_add(1, Ordering::SeqCst) == 0;
        let addr = self.addr;
        Box::pin(async move {
            if first {
                return Err("no such host".into());
            }
            let addrs: reqwest::dns::Addrs = Box::new(std::iter::once(addr));
            Ok(addrs)
        })
    }
}

#[tokio::test]
async fn a_refused_connection_is_sent_again() {
    let addr = closed_addr().await;
    let backend = crate::test_support::cloud_backend(format!("http://{addr}"), "test-key").unwrap();
    let late = serve_later(addr);

    let plan = apply_within(&backend, &value_patch(VALUE), short_budget(5_000))
        .await
        .unwrap();

    assert!(plan.applied);
    assert_eq!(late.await.unwrap().requests().len(), 1);
}

#[tokio::test]
async fn a_failed_dns_lookup_is_sent_again() {
    let mock = MockCloud::replies(vec![Reply::Json(200, plan_json(true, "live"))]).await;
    let addr: SocketAddr = mock.url.trim_start_matches("http://").parse().unwrap();
    let lookups = Arc::new(AtomicUsize::new(0));
    let client = reqwest::Client::builder()
        .no_proxy()
        .dns_resolver(Arc::new(FlakyResolver {
            addr,
            lookups: lookups.clone(),
        }))
        .build()
        .unwrap();
    let backend = backend_with(&format!("http://cloud.test:{}", addr.port()), client);

    let plan = apply_within(&backend, &value_patch(VALUE), short_budget(5_000))
        .await
        .unwrap();

    assert!(plan.applied);
    assert_eq!(lookups.load(Ordering::SeqCst), 2);
    assert_eq!(mock.requests().len(), 1);
}

#[tokio::test]
async fn a_failed_tls_handshake_is_sent_again() {
    let key = rcgen::KeyPair::generate().unwrap();
    let cert = rcgen::CertificateParams::new(vec!["localhost".to_string()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    let config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        vec![rustls::pki_types::CertificateDer::from(cert.der().to_vec())],
        rustls::pki_types::PrivateKeyDer::Pkcs8(rustls::pki_types::PrivatePkcs8KeyDer::from(
            key.serialize_der(),
        )),
    )
    .unwrap();
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let served = requests.clone();
    tokio::spawn(async move {
        // The first connection answers in plain text, so its handshake fails;
        // the next one is a TLS server.
        let (mut plain, _) = listener.accept().await.unwrap();
        let _ = plain.write_all(b"not a TLS server\r\n").await;
        drop(plain);
        while let Ok((stream, _)) = listener.accept().await {
            let Ok(stream) = acceptor.accept(stream).await else {
                continue;
            };
            let mut reader = BufReader::new(stream);
            if read_request(&mut reader).await.is_some() {
                served.fetch_add(1, Ordering::SeqCst);
                write_json(reader.get_mut(), 200, &plan_json(true, "live"), true).await;
            }
        }
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .tls_danger_accept_invalid_certs(true)
        .build()
        .unwrap();
    let backend = backend_with(&format!("https://{addr}"), client);

    let plan = apply_within(&backend, &value_patch(VALUE), short_budget(5_000))
        .await
        .unwrap();

    assert!(plan.applied);
    assert_eq!(requests.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn a_refused_proxy_is_sent_again() {
    let proxy = closed_addr().await;
    let client = reqwest::Client::builder()
        .proxy(reqwest::Proxy::all(format!("http://{proxy}")).unwrap())
        .build()
        .unwrap();
    let backend = backend_with("http://cloud.example", client);
    // The proxy answers the forwarded request itself.
    let late = serve_later(proxy);

    let plan = apply_within(&backend, &value_patch(VALUE), short_budget(5_000))
        .await
        .unwrap();

    assert!(plan.applied);
    let requests = late.await.unwrap().requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(
        requests[0].line,
        format!("PUT http://cloud.example/v1/sandboxes/{SANDBOX_ID} HTTP/1.1")
    );
}

#[tokio::test]
async fn a_reset_after_the_request_on_a_reused_connection_is_not_confirmed() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let requests = Arc::new(Mutex::new(0));
    let count = requests.clone();
    tokio::spawn(async move {
        let (stream, _) = listener.accept().await.unwrap();
        let mut reader = BufReader::new(stream);
        // The first request is answered on a keep-alive connection; the
        // second one is read in full, then the connection is dropped.
        for answer in [true, false] {
            if read_request(&mut reader).await.is_none() {
                return;
            }
            *count.lock().unwrap() += 1;
            if answer {
                write_json(reader.get_mut(), 200, &plan_json(true, "live"), false).await;
            }
        }
    });
    let backend = crate::test_support::cloud_backend(&url, "test-key").unwrap();

    apply_within(&backend, &value_patch(VALUE), short_budget(3_000))
        .await
        .unwrap();
    let error = apply_within(&backend, &value_patch(VALUE), short_budget(3_000))
        .await
        .unwrap_err();

    assert!(is_not_confirmed(&error), "{error:?}");
    assert_eq!(
        *requests.lock().unwrap(),
        2,
        "the second request is sent once"
    );
}

//--------------------------------------------------------------------------------------------------
// Tests: transport
//--------------------------------------------------------------------------------------------------

#[tokio::test]
async fn apply_returns_the_plan() {
    let mock = MockCloud::replies(vec![Reply::Json(200, plan_json(true, "live"))]).await;

    let plan = mock
        .backend()
        .apply_modification(
            SANDBOX_ID,
            &value_patch(VALUE),
            ModificationPolicy::NoRestart,
        )
        .await
        .unwrap();

    assert_eq!(
        serde_json::to_value(&plan).unwrap(),
        plan_json(true, "live")
    );
    let requests = mock.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].line, apply_line());
    assert_eq!(
        body(&requests[0]),
        json!({"policy": "no_restart", "secrets": [{"name": "API_KEY", "value": VALUE}]})
    );
}

#[tokio::test]
async fn both_routes_read_the_cloud_spelling_into_the_local_plan() {
    let mut answer = plan_json(true, "next_start");
    answer["changes"][0]["change"] = json!("hosts_updated");
    let mock = MockCloud::replies(vec![
        Reply::Json(200, answer.clone()),
        Reply::Json(200, answer),
    ])
    .await;
    let backend = mock.backend();
    let patch = value_patch(VALUE);

    let planned = backend
        .plan_modification(SANDBOX_ID, &patch, ModificationPolicy::NoRestart)
        .await
        .unwrap();
    let applied = backend
        .apply_modification(SANDBOX_ID, &patch, ModificationPolicy::NoRestart)
        .await
        .unwrap();

    for plan in [planned, applied] {
        let local = serde_json::to_value(&plan).unwrap();
        assert_eq!(local["changes"][0]["disposition"], json!("next start"));
        assert_eq!(local["changes"][0]["change"], json!("hosts updated"));
    }
}

#[tokio::test]
async fn plan_sends_a_value_free_request() {
    let mock = MockCloud::replies(vec![Reply::Json(200, plan_json(false, "live"))]).await;

    let plan = mock
        .backend()
        .plan_modification(
            SANDBOX_ID,
            &value_patch(VALUE),
            ModificationPolicy::NoRestart,
        )
        .await
        .unwrap();

    assert!(!plan.applied);
    let requests = mock.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].line, plan_line());
    assert_eq!(
        body(&requests[0]),
        json!({"policy": "no_restart", "secrets": [{"name": "API_KEY", "material": {"type": "provided"}}]})
    );
    assert!(!requests[0].body.contains(VALUE));
}

#[test]
fn env_sources_are_read_for_apply_only() {
    const VAR: &str = "MSB_TEST_CLOUD_MODIFY_SOURCE";
    const ENV_VALUE: &str = "dummy-env-value-5d2b";

    let requests = with_env(VAR, Some(ENV_VALUE), async {
        let mock =
            MockCloud::start(|index, _| Reply::Json(200, plan_json(index == 1, "live"))).await;
        let backend = mock.backend();
        let patch = env_patch(VAR);
        backend
            .plan_modification(SANDBOX_ID, &patch, ModificationPolicy::NoRestart)
            .await
            .unwrap();
        backend
            .apply_modification(SANDBOX_ID, &patch, ModificationPolicy::NoRestart)
            .await
            .unwrap();
        mock.requests()
    });

    assert_eq!(requests.len(), 2);
    assert!(!requests[0].body.contains(ENV_VALUE));
    assert!(!requests[0].body.contains(VAR));
    assert_eq!(body(&requests[1])["secrets"][0]["value"], ENV_VALUE);

    let (error, requests) = with_env(VAR, None, async {
        let mock = MockCloud::replies(vec![Reply::Json(200, plan_json(true, "live"))]).await;
        let error = mock
            .backend()
            .apply_modification(SANDBOX_ID, &env_patch(VAR), ModificationPolicy::NoRestart)
            .await
            .unwrap_err();
        (error, mock.requests())
    });
    assert!(
        matches!(&error, MicrosandboxError::InvalidConfig(message)
            if message.contains(&format!("secrets.source: host environment variable {VAR} is not set"))),
        "{error:?}"
    );
    assert!(requests.is_empty());
}

#[tokio::test]
async fn a_lost_response_is_not_confirmed() {
    let mock = MockCloud::replies(vec![Reply::Hangup]).await;

    let error = apply_within(&mock.backend(), &value_patch(VALUE), short_budget(3_000))
        .await
        .unwrap_err();

    assert!(is_not_confirmed(&error), "{error:?}");
    assert_eq!(mock.requests().len(), 1);
}

#[tokio::test]
async fn a_slow_answer_is_not_confirmed() {
    let mock = MockCloud::replies(vec![Reply::Slow(
        Duration::from_millis(800),
        200,
        plan_json(true, "live"),
    )])
    .await;

    let error = apply_within(&mock.backend(), &value_patch(VALUE), short_budget(300))
        .await
        .unwrap_err();

    assert!(
        matches!(&error, MicrosandboxError::ModificationNotConfirmed { cause } if cause.contains("timed out")),
        "{error:?}"
    );
    assert_eq!(mock.requests().len(), 1);
}

#[tokio::test]
async fn in_progress_is_waited_out() {
    let busy = Reply::Json(409, error_json(CLOUD_MODIFICATION_IN_PROGRESS, "busy"));
    let mock = MockCloud::replies(vec![
        busy.clone(),
        busy,
        Reply::Json(200, plan_json(true, "live")),
    ])
    .await;

    let plan = apply_within(&mock.backend(), &value_patch(VALUE), short_budget(5_000))
        .await
        .unwrap();

    assert!(plan.applied);
    assert_eq!(mock.requests().len(), 3);
}

/// The real budget scaled down by 60: a crashed request's lock (90 s) is
/// waited out, then one full answer (67 s) still fits in the total (180 s).
#[tokio::test]
async fn a_crashed_lock_is_waited_out() {
    let scale = |budget: Duration| budget / 60;
    let lock = scale(Duration::from_secs(90));
    let answer = scale(Duration::from_secs(67));
    let budget = ApplyBudget {
        total: scale(APPLY_BUDGET.total),
        per_request: scale(APPLY_BUDGET.per_request),
        not_sent: Backoff {
            first: scale(APPLY_BUDGET.not_sent.first),
            max: scale(APPLY_BUDGET.not_sent.max),
            jitter: false,
        },
        in_progress: Backoff {
            first: scale(APPLY_BUDGET.in_progress.first),
            max: scale(APPLY_BUDGET.in_progress.max),
            jitter: true,
        },
    };
    let mock = MockCloud::start(move |_, elapsed| {
        if elapsed < lock {
            Reply::Json(409, error_json(CLOUD_MODIFICATION_IN_PROGRESS, "busy"))
        } else {
            Reply::Slow(answer, 200, plan_json(true, "live"))
        }
    })
    .await;

    let plan = apply_within(&mock.backend(), &value_patch(VALUE), budget).await;

    assert!(plan.is_ok(), "{plan:?}");
    assert!(mock.requests().len() > 2, "the lock was waited out");
}

#[tokio::test]
async fn in_progress_until_the_deadline_returns_the_409() {
    let mock = MockCloud::replies(vec![Reply::Json(
        409,
        error_json(CLOUD_MODIFICATION_IN_PROGRESS, "busy"),
    )])
    .await;

    let error = apply_within(&mock.backend(), &value_patch(VALUE), short_budget(600))
        .await
        .unwrap_err();

    assert!(
        matches!(
            &error,
            MicrosandboxError::CloudHttp { status: 409, code: Some(code), .. }
                if code == CLOUD_MODIFICATION_IN_PROGRESS
        ),
        "{error:?}"
    );
    assert!(mock.requests().len() > 1);
}

#[tokio::test]
async fn refused_maps_to_custom() {
    const MESSAGE: &str = "cannot apply modification: secret API_KEY requires restart, and this sandbox cannot be restarted by modify; use next_start, then stop and start it";
    let mock = MockCloud::replies(vec![Reply::Json(
        409,
        error_json(CLOUD_MODIFICATION_REFUSED, MESSAGE),
    )])
    .await;

    let error = apply_within(&mock.backend(), &value_patch(VALUE), short_budget(3_000))
        .await
        .unwrap_err();

    assert!(
        matches!(&error, MicrosandboxError::Custom(message) if message == MESSAGE),
        "{error:?}"
    );
    assert_eq!(mock.requests().len(), 1);
}

#[tokio::test]
async fn unsupported_maps_to_unsupported() {
    let unsupported = Reply::Json(
        409,
        error_json(
            CLOUD_MODIFICATION_UNSUPPORTED,
            "secret modification is turned off",
        ),
    );
    let mock = MockCloud::replies(vec![unsupported]).await;
    let backend = mock.backend();

    let errors = [
        backend
            .plan_modification(
                SANDBOX_ID,
                &value_patch(VALUE),
                ModificationPolicy::NoRestart,
            )
            .await
            .unwrap_err(),
        apply_within(&backend, &value_patch(VALUE), short_budget(3_000))
            .await
            .unwrap_err(),
    ];

    for error in errors {
        assert!(
            matches!(
                &error,
                MicrosandboxError::Unsupported {
                    op: Operation::SandboxModify,
                    reason: UnsupportedReason::NotAvailable(message),
                } if message.ends_with("secret modification is turned off")
            ),
            "{error:?}"
        );
    }
    assert_eq!(mock.requests().len(), 2);
}

#[tokio::test]
async fn rejected_patches_send_nothing() {
    let mock = MockCloud::replies(vec![Reply::Json(200, plan_json(true, "live"))]).await;
    let backend = mock.backend();
    let store = SandboxModificationPatch {
        secrets: vec![SecretModificationPatch {
            name: "API_KEY".into(),
            source: Some(SecretSource::Store {
                reference: "vault://api".into(),
            }),
            ..Default::default()
        }],
        ..Default::default()
    };
    let cpus = SandboxModificationPatch {
        cpus: Some(2),
        ..value_patch(VALUE)
    };

    for patch in [&store, &cpus] {
        for error in [
            backend
                .plan_modification(SANDBOX_ID, patch, ModificationPolicy::NoRestart)
                .await
                .unwrap_err(),
            backend
                .apply_modification(SANDBOX_ID, patch, ModificationPolicy::NoRestart)
                .await
                .unwrap_err(),
        ] {
            if patch.cpus.is_some() {
                assert!(
                    matches!(
                        &error,
                        MicrosandboxError::Unsupported {
                            op: Operation::SandboxModify,
                            reason: UnsupportedReason::NotAvailable(_),
                        }
                    ),
                    "{error:?}"
                );
            } else {
                assert!(
                    matches!(
                        &error,
                        MicrosandboxError::Custom(message) if message
                            == "cannot apply modification: secret API_KEY: store-backed secret sources are not supported yet"
                    ),
                    "{error:?}"
                );
            }
        }
    }
    assert!(mock.requests().is_empty());
}

#[tokio::test]
async fn no_value_in_debug_or_error() {
    let replies = vec![
        Reply::Hangup,
        Reply::Json(503, error_json(CLOUD_MODIFICATION_FAILED, "not confirmed")),
        Reply::Json(409, error_json(CLOUD_MODIFICATION_REFUSED, "refused")),
        Reply::Json(500, json!({})),
    ];
    for reply in replies {
        let mock = MockCloud::replies(vec![reply]).await;
        let error = apply_within(&mock.backend(), &value_patch(VALUE), short_budget(3_000))
            .await
            .unwrap_err();
        assert!(!format!("{error:?}").contains(VALUE));
        assert!(!error.to_string().contains(VALUE));
    }

    let request = CloudSandboxModificationApplyRequest::from_patch(
        &value_patch(VALUE),
        ModificationPolicy::NoRestart,
        |_| None,
    )
    .unwrap();
    assert!(!format!("{request:?}").contains(VALUE));
}
