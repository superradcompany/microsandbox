//! Cloud sandbox modification.
//!
//! Requests address the sandbox by the UUID captured with the builder, so a new
//! sandbox that reuses the name is never modified. Secret values are resolved in
//! this process and sent only in the apply request body.

use std::time::Duration;

use microsandbox_types::{
    CloudErrorDetails, CloudModificationOperationStatus, CloudModificationRejection,
    CloudSandboxModificationApplyRequest, CloudSandboxModificationOperation,
    CloudSandboxModificationPlanRequest, CloudSecretValue,
};
use tokio::time::Instant;

use super::CloudBackend;
use super::http::CloudModificationApplyResponse;
use super::sandbox::cloud_identity;
use crate::backend::SandboxIdentity;
use crate::error::{Operation, UnsupportedReason};
use crate::sandbox::{ModificationPolicy, SandboxModificationPatch, SandboxModificationPlan};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Time an apply or a resume waits for the modification to settle.
const MODIFICATION_SETTLE_BUDGET: Duration = Duration::from_secs(60);

/// First delay for operation polls and apply retries; each later delay doubles,
/// up to [`MODIFICATION_MAX_POLL_INTERVAL`].
const MODIFICATION_INITIAL_POLL_INTERVAL: Duration = Duration::from_millis(250);

/// Longest delay between operation polls or apply retries.
const MODIFICATION_MAX_POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Attempts per apply when no HTTP response arrives; all reuse one idempotency key.
const MODIFICATION_APPLY_ATTEMPTS: u32 = 3;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy)]
struct SettleSchedule {
    budget: Duration,
    initial_interval: Duration,
    max_interval: Duration,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SettleSchedule {
    const DEFAULT: Self = Self {
        budget: MODIFICATION_SETTLE_BUDGET,
        initial_interval: MODIFICATION_INITIAL_POLL_INTERVAL,
        max_interval: MODIFICATION_MAX_POLL_INTERVAL,
    };

    fn next_interval(&self, interval: Duration) -> Duration {
        interval.saturating_mul(2).min(self.max_interval)
    }
}

impl CloudBackend {
    /// Dry-run `patch`. The request carries no secret value; `Env` sources are not read.
    pub(super) async fn plan_modification(
        &self,
        identity: SandboxIdentity,
        patch: SandboxModificationPatch,
        policy: ModificationPolicy,
    ) -> MicrosandboxResult<SandboxModificationPlan> {
        let sandbox_id = cloud_identity(identity)?;
        let request = CloudSandboxModificationPlanRequest::from_patch(&patch, policy)
            .map_err(rejection_error)?;
        self.plan_sandbox_modification(&sandbox_id, &request).await
    }

    /// Apply `patch` and wait for it to settle. Each call uses a new idempotency key;
    /// on timeout the error is [`MicrosandboxError::ModificationIncomplete`].
    pub(super) async fn apply_modification(
        &self,
        identity: SandboxIdentity,
        patch: SandboxModificationPatch,
        policy: ModificationPolicy,
    ) -> MicrosandboxResult<SandboxModificationPlan> {
        self.apply_modification_within(identity, patch, policy, SettleSchedule::DEFAULT)
            .await
    }

    async fn apply_modification_within(
        &self,
        identity: SandboxIdentity,
        patch: SandboxModificationPatch,
        policy: ModificationPolicy,
        schedule: SettleSchedule,
    ) -> MicrosandboxResult<SandboxModificationPlan> {
        let sandbox_id = cloud_identity(identity)?;
        let request = CloudSandboxModificationApplyRequest::from_patch(
            &patch,
            policy,
            uuid::Uuid::new_v4().to_string(),
            resolve_env,
        )
        .map_err(rejection_error)?;
        let deadline = Instant::now() + schedule.budget;
        let response = self
            .send_modification(&sandbox_id, &request, deadline, &schedule)
            .await;
        drop(request);

        match response? {
            CloudModificationApplyResponse::Settled(plan) => Ok(plan),
            CloudModificationApplyResponse::Accepted(operation) => {
                let operation_id = operation.id.clone();
                self.settle_modification(
                    &sandbox_id,
                    &operation_id,
                    Some(operation),
                    deadline,
                    &schedule,
                )
                .await
            }
        }
    }

    /// Wait again for `operation_id` with a fresh budget. The lookup is scoped to
    /// this sandbox, so an operation of another sandbox is refused.
    pub(super) async fn resume_modification(
        &self,
        identity: SandboxIdentity,
        operation_id: String,
    ) -> MicrosandboxResult<SandboxModificationPlan> {
        let sandbox_id = cloud_identity(identity)?;
        if operation_id.trim().is_empty() {
            return Err(MicrosandboxError::InvalidConfig(
                "sandbox modification operation id must not be blank".into(),
            ));
        }
        let schedule = SettleSchedule::DEFAULT;
        let deadline = Instant::now() + schedule.budget;
        self.settle_modification(&sandbox_id, &operation_id, None, deadline, &schedule)
            .await
    }

    /// Sends `request`, retrying only when no HTTP response arrives. Retries reuse
    /// the idempotency key, so the server applies the change at most once.
    async fn send_modification(
        &self,
        sandbox_id: &str,
        request: &CloudSandboxModificationApplyRequest,
        deadline: Instant,
        schedule: &SettleSchedule,
    ) -> MicrosandboxResult<CloudModificationApplyResponse> {
        let mut interval = schedule.initial_interval;
        let mut attempt = 1;
        loop {
            match self.apply_sandbox_modification(sandbox_id, request).await {
                Err(MicrosandboxError::Http(_))
                    if attempt < MODIFICATION_APPLY_ATTEMPTS
                        && Instant::now() + interval < deadline =>
                {
                    tokio::time::sleep(interval).await;
                    interval = schedule.next_interval(interval);
                    attempt += 1;
                }
                result => return result,
            }
        }
    }

    /// Poll until the operation settles or `deadline` passes; without `observed`
    /// the first poll is immediate. Polls that get no HTTP response are retried,
    /// so a transport failure never loses the operation id.
    async fn settle_modification(
        &self,
        sandbox_id: &str,
        operation_id: &str,
        mut observed: Option<CloudSandboxModificationOperation>,
        deadline: Instant,
        schedule: &SettleSchedule,
    ) -> MicrosandboxResult<SandboxModificationPlan> {
        let incomplete = || MicrosandboxError::ModificationIncomplete {
            operation_id: operation_id.to_owned(),
            budget: schedule.budget,
            committed: None,
        };
        let mut interval = schedule.initial_interval;
        let mut wait = observed.is_some();
        loop {
            if let Some(operation) = observed.take()
                && let Some(outcome) = settled(operation_id, operation)
            {
                return outcome;
            }
            if wait {
                let now = Instant::now();
                if now >= deadline {
                    return Err(incomplete());
                }
                tokio::time::sleep_until((now + interval).min(deadline)).await;
                interval = schedule.next_interval(interval);
            }
            wait = true;
            observed = match tokio::time::timeout_at(
                deadline,
                self.get_sandbox_modification_operation(sandbox_id, operation_id),
            )
            .await
            {
                Err(_elapsed) => return Err(incomplete()),
                Ok(Ok(operation)) => Some(operation),
                Ok(Err(MicrosandboxError::Http(_))) => None,
                Ok(Err(error)) => return Err(error),
            };
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// The outcome of a settled operation, or `None` while it is in progress.
fn settled(
    operation_id: &str,
    operation: CloudSandboxModificationOperation,
) -> Option<MicrosandboxResult<SandboxModificationPlan>> {
    if operation.id != operation_id {
        return Some(Err(MicrosandboxError::Runtime(format!(
            "sandbox modification operation {operation_id} was answered with operation {}",
            operation.id
        ))));
    }
    match operation.status {
        CloudModificationOperationStatus::InProgress => None,
        CloudModificationOperationStatus::Succeeded => Some(operation.plan.ok_or_else(|| {
            MicrosandboxError::Runtime(format!(
                "sandbox modification operation {operation_id} succeeded without a plan"
            ))
        })),
        CloudModificationOperationStatus::Failed => {
            Some(Err(operation_failed(operation_id, operation.error)))
        }
    }
}

/// The server sanitizes `error`, so the message carries no secret value.
fn operation_failed(operation_id: &str, error: Option<CloudErrorDetails>) -> MicrosandboxError {
    let detail = error
        .into_iter()
        .flat_map(|error| [error.code, error.message])
        .flatten()
        .collect::<Vec<_>>()
        .join(": ");
    let separator = if detail.is_empty() { "" } else { ": " };
    MicrosandboxError::Runtime(format!(
        "sandbox modification operation {operation_id} failed{separator}{detail}"
    ))
}

/// A missing or non-UTF-8 variable resolves to `None`.
fn resolve_env(var: &str) -> Option<CloudSecretValue> {
    std::env::var(var).ok().map(CloudSecretValue::new)
}

/// Changes the cloud backend does not support map to [`MicrosandboxError::Unsupported`];
/// malformed patches map to [`MicrosandboxError::InvalidConfig`].
fn rejection_error(rejection: CloudModificationRejection) -> MicrosandboxError {
    match rejection {
        CloudModificationRejection::UnsupportedField { field } => MicrosandboxError::unsupported(
            Operation::SandboxModify,
            UnsupportedReason::ConfigField(field),
        ),
        CloudModificationRejection::NoSecretChange { .. }
        | CloudModificationRejection::MultipleSecrets { .. }
        | CloudModificationRejection::SecretRemoval { .. }
        | CloudModificationRejection::StoreSource { .. } => MicrosandboxError::unsupported(
            Operation::SandboxModify,
            UnsupportedReason::NotAvailable(rejection.to_string()),
        ),
        CloudModificationRejection::BlankName { .. }
        | CloudModificationRejection::InvalidName { .. }
        | CloudModificationRejection::BlankValue { .. }
        | CloudModificationRejection::ValueAndSource { .. }
        | CloudModificationRejection::InvalidPlaceholder { .. }
        | CloudModificationRejection::InvalidIdempotencyKey { .. } => {
            MicrosandboxError::InvalidConfig(rejection.to_string())
        }
        _ => MicrosandboxError::InvalidConfig(rejection.to_string()),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use microsandbox_types::{CloudIdempotencyKeyError, SecretConfigError};
    use serde_json::json;
    use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
    use tokio::net::{TcpListener, TcpStream};

    use super::*;
    use crate::backend::{Backend, SandboxBackend};
    use crate::sandbox::{
        ModificationDisposition, PlannedChange, SecretModificationPatch, SecretSource,
    };

    const SANDBOX_ID: &str = "6f1c1f7e-3b8a-4c2e-9d55-0a1b2c3d4e5f";

    #[derive(Clone)]
    enum Reply {
        Json(u16, serde_json::Value),
        /// Read the request, then close the connection without a response.
        Hangup,
    }

    #[derive(Clone)]
    struct Recorded {
        line: String,
        body: String,
    }

    /// Serves `replies` in order, one request per connection, then repeats the last.
    struct MockCloud {
        url: String,
        requests: Arc<Mutex<Vec<Recorded>>>,
    }

    impl MockCloud {
        async fn start(replies: Vec<Reply>) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let url = format!("http://{}", listener.local_addr().unwrap());
            let requests = Arc::new(Mutex::new(Vec::new()));
            let log = requests.clone();
            tokio::spawn(async move {
                let mut replies = replies.into_iter();
                let mut last = None;
                while let Ok((stream, _)) = listener.accept().await {
                    let reply = replies.next().or(last.take()).expect("mock has a reply");
                    last = Some(reply.clone());
                    let mut reader = BufReader::new(stream);
                    let request = read_request(&mut reader).await;
                    log.lock().unwrap().push(request);
                    match reply {
                        Reply::Json(status, body) => {
                            write_json(reader.get_mut(), status, &body).await;
                        }
                        Reply::Hangup => drop(reader),
                    }
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

        fn lines(&self) -> Vec<String> {
            self.requests().into_iter().map(|r| r.line).collect()
        }
    }

    async fn read_request(reader: &mut BufReader<TcpStream>) -> Recorded {
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        let mut content_length = 0;
        loop {
            let mut header = String::new();
            assert_ne!(reader.read_line(&mut header).await.unwrap(), 0);
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
        reader.read_exact(&mut body).await.unwrap();
        Recorded {
            line: line.trim_end().to_owned(),
            body: String::from_utf8(body).unwrap(),
        }
    }

    async fn write_json(stream: &mut TcpStream, status: u16, body: &serde_json::Value) {
        let body = body.to_string();
        let response = format!(
            "HTTP/1.1 {status} Mock\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
            body.len(),
        );
        stream.write_all(response.as_bytes()).await.unwrap();
    }

    fn plan_json(disposition: &str) -> serde_json::Value {
        json!({
            "sandbox": "agent-1",
            "status": "running",
            "applied": false,
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

    fn operation_json(status: &str) -> serde_json::Value {
        json!({"id": "op-1", "status": status})
    }

    fn succeeded_json(disposition: &str) -> serde_json::Value {
        json!({"id": "op-1", "status": "succeeded", "plan": plan_json(disposition)})
    }

    fn body(request: &Recorded) -> serde_json::Value {
        serde_json::from_str(&request.body).unwrap()
    }

    fn plan_line() -> String {
        format!("POST /v1/sandboxes/{SANDBOX_ID}/modifications/plan HTTP/1.1")
    }

    fn apply_line() -> String {
        format!("POST /v1/sandboxes/{SANDBOX_ID}/modifications HTTP/1.1")
    }

    fn poll_line() -> String {
        format!("GET /v1/sandboxes/{SANDBOX_ID}/modifications/op-1 HTTP/1.1")
    }

    const SHORT: SettleSchedule = SettleSchedule {
        budget: Duration::from_millis(300),
        initial_interval: Duration::from_millis(20),
        max_interval: Duration::from_millis(50),
    };

    fn secret_patch(spec: SecretModificationPatch) -> SandboxModificationPatch {
        SandboxModificationPatch {
            secrets: vec![spec],
            ..Default::default()
        }
    }

    fn secret(name: &str) -> SecretModificationPatch {
        SecretModificationPatch {
            name: name.into(),
            ..Default::default()
        }
    }

    fn value_secret(value: &str) -> SecretModificationPatch {
        SecretModificationPatch {
            value: value.to_string().into(),
            ..secret("API_KEY")
        }
    }

    fn env_secret(var: &str) -> SecretModificationPatch {
        SecretModificationPatch {
            source: Some(SecretSource::env(var)),
            ..secret("API_KEY")
        }
    }

    fn cloud_sandbox(backend: crate::CloudBackend) -> crate::sandbox::Sandbox {
        crate::sandbox::Sandbox::from_cloud_state(
            Arc::new(backend),
            crate::backend::SandboxCloudState {
                id: SANDBOX_ID.to_owned(),
                org_id: "test-org".to_owned(),
                created_at: chrono::Utc::now(),
            },
            "agent-1".to_owned(),
            crate::sandbox::SandboxConfig::default(),
        )
    }

    async fn plan(
        backend: &crate::CloudBackend,
        identity: SandboxIdentity,
        patch: SandboxModificationPatch,
    ) -> MicrosandboxResult<SandboxModificationPlan> {
        let backend_dyn: Arc<dyn Backend> = Arc::new(backend.clone());
        backend
            .plan_modification_identified(
                backend_dyn,
                "agent-1",
                identity,
                patch,
                ModificationPolicy::NoRestart,
            )
            .await
    }

    async fn apply(
        backend: &crate::CloudBackend,
        identity: SandboxIdentity,
        patch: SandboxModificationPatch,
    ) -> MicrosandboxResult<SandboxModificationPlan> {
        let backend_dyn: Arc<dyn Backend> = Arc::new(backend.clone());
        backend
            .apply_modification_identified(
                backend_dyn,
                "agent-1",
                identity,
                patch,
                ModificationPolicy::NoRestart,
            )
            .await
    }

    /// Run `test` on its own runtime with `var` set to `value`, or unset,
    /// holding the process environment lock outside any await point.
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

    fn cloud() -> SandboxIdentity {
        SandboxIdentity::Cloud(SANDBOX_ID.into())
    }

    /// Case label, a patch rejected before any request, and a check for its error.
    type RejectedPatch = (
        &'static str,
        SandboxModificationPatch,
        fn(&MicrosandboxError) -> bool,
    );

    fn rejected_patches() -> Vec<RejectedPatch> {
        fn not_available(error: &MicrosandboxError) -> bool {
            matches!(
                error,
                MicrosandboxError::Unsupported {
                    op: Operation::SandboxModify,
                    reason: UnsupportedReason::NotAvailable(_),
                }
            )
        }
        fn invalid(error: &MicrosandboxError) -> bool {
            matches!(error, MicrosandboxError::InvalidConfig(_))
        }
        fn cpus_field(error: &MicrosandboxError) -> bool {
            matches!(
                error,
                MicrosandboxError::Unsupported {
                    op: Operation::SandboxModify,
                    reason: UnsupportedReason::ConfigField("cpus"),
                }
            )
        }

        vec![
            (
                "unsupported field",
                SandboxModificationPatch {
                    cpus: Some(2),
                    ..secret_patch(env_secret("UNUSED"))
                },
                cpus_field,
            ),
            (
                "no secret change",
                SandboxModificationPatch::default(),
                not_available,
            ),
            (
                "multiple secrets",
                SandboxModificationPatch {
                    secrets: vec![env_secret("UNUSED"), secret("OTHER_KEY")],
                    ..Default::default()
                },
                not_available,
            ),
            (
                "secret removal",
                SandboxModificationPatch {
                    secrets_remove: vec!["API_KEY".into()],
                    ..secret_patch(env_secret("UNUSED"))
                },
                not_available,
            ),
            (
                "store source",
                secret_patch(SecretModificationPatch {
                    source: Some(SecretSource::Store {
                        reference: "vault://api".into(),
                    }),
                    ..secret("API_KEY")
                }),
                not_available,
            ),
            ("blank name", secret_patch(secret("  ")), invalid),
            ("invalid name", secret_patch(secret("API=KEY")), invalid),
            (
                "value and source",
                secret_patch(SecretModificationPatch {
                    value: "inline".to_string().into(),
                    ..env_secret("UNUSED")
                }),
                invalid,
            ),
            (
                "invalid placeholder",
                secret_patch(SecretModificationPatch {
                    placeholder: Some(String::new()),
                    ..secret("API_KEY")
                }),
                invalid,
            ),
        ]
    }

    #[test]
    fn dry_run_posts_a_value_free_plan_for_the_captured_sandbox() {
        const VAR: &str = "MSB_TEST_CLOUD_MODIFY_DRY_RUN_SOURCE";
        const SENTINEL: &str = "dry-run-sentinel-never-sent";

        for value in [Some(SENTINEL), None] {
            let (plan, requests) = with_env(VAR, value, async {
                let mock = MockCloud::start(vec![Reply::Json(200, plan_json("live"))]).await;
                let plan = cloud_sandbox(mock.backend())
                    .modify()
                    .secret(|secret| secret.env("API_KEY").source(SecretSource::env(VAR)))
                    .dry_run()
                    .await
                    .unwrap();
                (plan, mock.requests())
            });

            assert_eq!(serde_json::to_value(&plan).unwrap(), plan_json("live"));
            assert_eq!(requests.len(), 1);
            assert_eq!(requests[0].line, plan_line());
            assert_eq!(
                body(&requests[0]),
                json!({
                    "policy": "no_restart",
                    "secret": {"name": "API_KEY", "material": {"kind": "provided"}},
                })
            );
            assert!(!requests[0].body.contains(SENTINEL));
        }
    }

    #[tokio::test]
    async fn dry_run_rejections_map_to_typed_errors_before_any_request() {
        let mock = MockCloud::start(vec![Reply::Json(200, plan_json("live"))]).await;
        let backend = mock.backend();

        for (case, patch, expected) in rejected_patches() {
            let error = plan(&backend, cloud(), patch).await.unwrap_err();
            assert!(expected(&error), "{case}: unexpected {error:?}");
        }
        assert_eq!(mock.requests().len(), 0);
    }

    #[test]
    fn rejection_errors_keep_the_offending_field() {
        let cases = [
            CloudModificationRejection::BlankValue {
                field: "secrets.value",
            },
            CloudModificationRejection::InvalidName {
                field: "secrets.name",
                reason: SecretConfigError::EnvVarContainsEquals { secret_index: 0 },
            },
            CloudModificationRejection::InvalidIdempotencyKey {
                field: "idempotency_key",
                reason: CloudIdempotencyKeyError::Blank,
            },
        ];
        for rejection in cases {
            let error = rejection_error(rejection.clone());
            let MicrosandboxError::InvalidConfig(message) = error else {
                panic!("{rejection:?} must be invalid input, got {error:?}");
            };
            assert_eq!(message, rejection.to_string());
        }

        let error = rejection_error(CloudModificationRejection::StoreSource {
            field: "secrets.source",
        });
        assert!(error.to_string().contains("secrets.source"), "{error}");
    }

    #[tokio::test]
    async fn dry_run_not_found_is_final_and_never_looks_up_the_name() {
        let mock = MockCloud::start(vec![Reply::Json(
            404,
            json!({"error": {"code": "sandbox_not_found", "message": "sandbox missing"}}),
        )])
        .await;

        let error = plan(&mock.backend(), cloud(), secret_patch(env_secret("UNUSED")))
            .await
            .unwrap_err();

        assert!(
            matches!(error, MicrosandboxError::SandboxNotFound(_)),
            "{error:?}"
        );
        assert_eq!(mock.lines(), [plan_line()]);
    }

    #[tokio::test]
    async fn local_identity_is_refused_before_any_request() {
        let mock = MockCloud::start(vec![Reply::Json(200, plan_json("live"))]).await;
        let backend = mock.backend();
        let local = || SandboxIdentity::Local(7);

        let errors = [
            plan(&backend, local(), secret_patch(value_secret("v"))).await,
            apply(&backend, local(), secret_patch(value_secret("v"))).await,
        ];

        for error in errors {
            assert!(
                matches!(error, Err(MicrosandboxError::Runtime(_))),
                "{error:?}"
            );
        }
        assert_eq!(mock.requests().len(), 0);
    }

    #[test]
    fn plan_request_debug_is_value_free() {
        let request = CloudSandboxModificationPlanRequest::from_patch(
            &secret_patch(SecretModificationPatch {
                value: "debug-inline-secret".to_string().into(),
                ..secret("API_KEY")
            }),
            ModificationPolicy::NoRestart,
        )
        .unwrap();

        let debug = format!("{request:?}");
        assert!(!debug.contains("debug-inline-secret"), "{debug}");
        assert!(debug.contains("Provided"), "{debug}");
    }

    #[tokio::test]
    async fn apply_sends_the_value_only_in_the_body_and_returns_a_settled_plan() {
        const VALUE: &str = "inline-plaintext-4f2a";
        let mock = MockCloud::start(vec![Reply::Json(200, plan_json("live"))]).await;

        let plan = apply(&mock.backend(), cloud(), secret_patch(value_secret(VALUE)))
            .await
            .unwrap();

        assert_eq!(serde_json::to_value(&plan).unwrap(), plan_json("live"));
        let requests = mock.requests();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].line, apply_line());
        assert!(!requests[0].line.contains(VALUE));
        let body = body(&requests[0]);
        assert_eq!(
            body["secret"],
            json!({"name": "API_KEY", "value": VALUE}),
            "the secret carries only its name and the new value"
        );
        assert_eq!(body["policy"], "no_restart");
        let key = body["idempotency_key"].as_str().unwrap();
        assert_eq!(
            uuid::Uuid::parse_str(key).unwrap().get_version_num(),
            4,
            "version 4 UUID: {key}"
        );
    }

    #[test]
    fn apply_resolves_an_env_source_in_process() {
        const VAR: &str = "MSB_TEST_CLOUD_MODIFY_APPLY_SOURCE";
        const VALUE: &str = "env-plaintext-9c1e";

        let requests = with_env(VAR, Some(VALUE), async {
            let mock = MockCloud::start(vec![Reply::Json(200, plan_json("live"))]).await;
            apply(&mock.backend(), cloud(), secret_patch(env_secret(VAR)))
                .await
                .unwrap();
            mock.requests()
        });

        assert_eq!(requests.len(), 1);
        assert_eq!(body(&requests[0])["secret"]["value"], VALUE);
        assert!(!requests[0].line.contains(VALUE));
    }

    #[test]
    fn missing_or_blank_env_source_fails_before_any_request() {
        const VAR: &str = "MSB_TEST_CLOUD_MODIFY_BLANK_SOURCE";

        for value in [None, Some("   ")] {
            let (result, requests) = with_env(VAR, value, async {
                let mock = MockCloud::start(vec![Reply::Json(200, plan_json("live"))]).await;
                let result = apply(&mock.backend(), cloud(), secret_patch(env_secret(VAR))).await;
                (result, mock.requests())
            });

            assert!(
                matches!(result, Err(MicrosandboxError::InvalidConfig(ref message)) if message.contains("secrets.source")),
                "{value:?}: {result:?}"
            );
            assert_eq!(requests.len(), 0);
        }
    }

    #[tokio::test]
    async fn apply_rejections_map_to_typed_errors_before_any_request() {
        let mock = MockCloud::start(vec![Reply::Json(200, plan_json("live"))]).await;
        let backend = mock.backend();
        let mut cases = rejected_patches();
        cases.push(("blank value", secret_patch(value_secret("   ")), |error| {
            matches!(error, MicrosandboxError::InvalidConfig(_))
        }));

        for (case, patch, expected) in cases {
            let error = apply(&backend, cloud(), patch).await.unwrap_err();
            assert!(expected(&error), "{case}: unexpected {error:?}");
        }
        assert_eq!(mock.requests().len(), 0);
    }

    #[tokio::test]
    async fn accepted_apply_polls_until_it_settles_with_the_disposition_unchanged() {
        for disposition in ["live", "next start", "unconfirmed"] {
            let mock = MockCloud::start(vec![
                Reply::Json(202, operation_json("in_progress")),
                Reply::Json(200, operation_json("in_progress")),
                Reply::Json(200, succeeded_json(disposition)),
            ])
            .await;

            let plan = apply(&mock.backend(), cloud(), secret_patch(value_secret("v")))
                .await
                .unwrap();

            assert_eq!(serde_json::to_value(&plan).unwrap(), plan_json(disposition));
            assert_eq!(mock.lines(), [apply_line(), poll_line(), poll_line()]);
        }
    }

    #[tokio::test]
    async fn unknown_dispositions_from_a_newer_server_are_kept() {
        const NEWER: &str = "after migration";
        let expect_kept = |plan: SandboxModificationPlan| {
            let PlannedChange::Secret(change) = &plan.changes[0] else {
                panic!("expected a secret change: {:?}", plan.changes[0]);
            };
            assert_eq!(
                change.disposition,
                ModificationDisposition::Unknown(NEWER.into())
            );
            assert_eq!(serde_json::to_value(&plan).unwrap(), plan_json(NEWER));
        };

        let mock = MockCloud::start(vec![Reply::Json(200, plan_json(NEWER))]).await;
        expect_kept(
            plan(&mock.backend(), cloud(), secret_patch(value_secret("v")))
                .await
                .unwrap(),
        );

        let mock = MockCloud::start(vec![Reply::Json(200, plan_json(NEWER))]).await;
        expect_kept(
            apply(&mock.backend(), cloud(), secret_patch(value_secret("v")))
                .await
                .unwrap(),
        );

        let mock = MockCloud::start(vec![
            Reply::Json(202, operation_json("in_progress")),
            Reply::Json(200, succeeded_json(NEWER)),
        ])
        .await;
        expect_kept(
            apply(&mock.backend(), cloud(), secret_patch(value_secret("v")))
                .await
                .unwrap(),
        );
    }

    #[tokio::test]
    async fn failed_operation_is_a_typed_error_without_plaintext() {
        const VALUE: &str = "failed-plaintext-77d0";
        let mock = MockCloud::start(vec![
            Reply::Json(202, operation_json("in_progress")),
            Reply::Json(
                200,
                json!({
                    "id": "op-1",
                    "status": "failed",
                    "error": {"code": "secret_delivery_failed", "message": "worker refused"},
                }),
            ),
        ])
        .await;

        let error = apply(&mock.backend(), cloud(), secret_patch(value_secret(VALUE)))
            .await
            .unwrap_err();

        let MicrosandboxError::Runtime(message) = &error else {
            panic!("unexpected {error:?}");
        };
        assert_eq!(
            message,
            "sandbox modification operation op-1 failed: secret_delivery_failed: worker refused"
        );
        assert!(!format!("{error:?}").contains(VALUE));
    }

    #[tokio::test]
    async fn exhausted_budget_is_incomplete_and_keeps_the_operation_id() {
        let mock = MockCloud::start(vec![
            Reply::Json(202, operation_json("in_progress")),
            Reply::Json(200, operation_json("in_progress")),
        ])
        .await;

        let error = mock
            .backend()
            .apply_modification_within(
                cloud(),
                secret_patch(value_secret("v")),
                ModificationPolicy::NoRestart,
                SHORT,
            )
            .await
            .unwrap_err();

        assert!(
            matches!(
                error,
                MicrosandboxError::ModificationIncomplete {
                    ref operation_id,
                    budget,
                    committed: None,
                } if operation_id == "op-1" && budget == SHORT.budget
            ),
            "{error:?}"
        );
        assert!(mock.requests().len() > 2, "the operation was polled");
    }

    #[tokio::test]
    async fn poll_transport_failures_end_incomplete_with_the_operation_id() {
        let mock = MockCloud::start(vec![
            Reply::Json(202, operation_json("in_progress")),
            Reply::Hangup,
        ])
        .await;

        let error = mock
            .backend()
            .apply_modification_within(
                cloud(),
                secret_patch(value_secret("v")),
                ModificationPolicy::NoRestart,
                SHORT,
            )
            .await
            .unwrap_err();

        assert!(
            matches!(
                error,
                MicrosandboxError::ModificationIncomplete { ref operation_id, .. }
                    if operation_id == "op-1"
            ),
            "{error:?}"
        );
    }

    #[tokio::test]
    async fn transport_retry_reuses_the_idempotency_key_and_each_apply_mints_one() {
        let mock = MockCloud::start(vec![Reply::Hangup, Reply::Json(200, plan_json("live"))]).await;
        let backend = mock.backend();

        for _ in 0..2 {
            apply(&backend, cloud(), secret_patch(value_secret("v")))
                .await
                .unwrap();
        }

        let requests = mock.requests();
        let keys: Vec<_> = requests
            .iter()
            .map(|request| body(request)["idempotency_key"].clone())
            .collect();
        assert_eq!(requests.len(), 3);
        assert!(requests.iter().all(|request| request.line == apply_line()));
        assert_eq!(keys[0], keys[1], "the transport retry reuses the key");
        assert_ne!(keys[1], keys[2], "a second apply mints a new key");
    }

    #[tokio::test]
    async fn apply_not_found_is_final_and_never_looks_up_the_name() {
        let mock = MockCloud::start(vec![Reply::Json(
            404,
            json!({"error": {"code": "sandbox_not_found", "message": "sandbox missing"}}),
        )])
        .await;

        let error = apply(&mock.backend(), cloud(), secret_patch(value_secret("v")))
            .await
            .unwrap_err();

        assert!(
            matches!(error, MicrosandboxError::SandboxNotFound(_)),
            "{error:?}"
        );
        assert_eq!(mock.lines(), [apply_line()]);
    }

    #[test]
    fn apply_request_debug_redacts_the_value() {
        const VALUE: &str = "debug-apply-plaintext";
        let request = CloudSandboxModificationApplyRequest::from_patch(
            &secret_patch(value_secret(VALUE)),
            ModificationPolicy::NoRestart,
            uuid::Uuid::new_v4().to_string(),
            resolve_env,
        )
        .unwrap();

        let debug = format!("{request:?}");
        assert!(!debug.contains(VALUE), "{debug}");
        assert!(debug.contains("[REDACTED]"), "{debug}");
        assert!(!format!("{:?}", request.intent()).contains(VALUE));
    }

    #[tokio::test]
    async fn sandbox_resumes_a_modification_by_operation_id() {
        let mock = MockCloud::start(vec![Reply::Json(200, succeeded_json("unconfirmed"))]).await;

        let plan = cloud_sandbox(mock.backend())
            .resume_modification("op-1")
            .await
            .unwrap();

        assert_eq!(
            serde_json::to_value(&plan).unwrap(),
            plan_json("unconfirmed")
        );
        assert_eq!(mock.lines(), [poll_line()], "the first poll is immediate");
    }

    #[tokio::test]
    async fn handle_resume_waits_for_the_operation_to_settle() {
        let mock = MockCloud::start(vec![
            Reply::Json(200, operation_json("in_progress")),
            Reply::Json(
                200,
                json!({"id": "op-1", "status": "failed", "error": {"code": "stale_runtime"}}),
            ),
        ])
        .await;
        let handle = crate::sandbox::SandboxHandle::from_cloud(
            Arc::new(mock.backend()),
            microsandbox_types::CloudCreateSandboxResponse {
                id: SANDBOX_ID.into(),
                org_id: "test-org".into(),
                name: "agent-1".into(),
                slug: "brave-otter".into(),
                status: microsandbox_types::CloudSandboxStatus::Running,
                status_reason: None,
                spec: None,
                ephemeral: false,
                created_at: chrono::Utc::now(),
                started_at: None,
                stopped_at: None,
                last_failure_message: None,
            },
        )
        .unwrap();

        let error = handle.resume_modification("op-1").await.unwrap_err();

        assert!(
            matches!(
                error,
                MicrosandboxError::Runtime(ref message)
                    if message == "sandbox modification operation op-1 failed: stale_runtime"
            ),
            "{error:?}"
        );
        assert_eq!(mock.lines(), [poll_line(), poll_line()]);
    }

    #[tokio::test]
    async fn resume_refuses_a_local_identity_or_blank_operation_before_any_request() {
        let mock = MockCloud::start(vec![Reply::Json(200, succeeded_json("live"))]).await;
        let backend = mock.backend();
        let resume = |identity, operation_id: &str| {
            let backend_dyn: Arc<dyn Backend> = Arc::new(backend.clone());
            backend.resume_modification_identified(
                backend_dyn,
                "agent-1",
                identity,
                operation_id.to_owned(),
            )
        };

        let local = resume(SandboxIdentity::Local(7), "op-1").await;
        let blank = resume(cloud(), " ").await;

        assert!(
            matches!(local, Err(MicrosandboxError::Runtime(_))),
            "{local:?}"
        );
        assert!(
            matches!(blank, Err(MicrosandboxError::InvalidConfig(_))),
            "{blank:?}"
        );
        assert_eq!(mock.requests().len(), 0);
    }
}
