//! Cloud sandbox modification.
//!
//! Requests address the sandbox by the id captured with the builder, so a new
//! sandbox that reuses the name is never modified. Secret values are resolved in
//! this process and sent only in the apply request body. An apply is re-sent only
//! when nothing left the client, and waits while another change to the sandbox
//! holds its lock; any other failure after sending is
//! [`ModificationNotConfirmed`](crate::MicrosandboxError::ModificationNotConfirmed).

use std::hash::{BuildHasher, RandomState};
use std::str::FromStr;
use std::time::Duration;

use microsandbox_types::{
    CLOUD_MODIFICATION_FAILED, CLOUD_MODIFICATION_IN_PROGRESS, CLOUD_MODIFICATION_REFUSED,
    CLOUD_MODIFICATION_UNSUPPORTED, CloudErrorBody, CloudModificationRejection,
    CloudSandboxModificationApplyRequest, CloudSandboxModificationPlan,
    CloudSandboxModificationPlanRequest, CloudSecretValue,
};
use reqwest::Response;
use tokio::time::Instant;

use super::CloudBackend;
use super::http::{cloud_error_code, cloud_error_message, cloud_http_error, cloud_io_error};
use crate::error::{Operation, UnsupportedReason};
use crate::sandbox::{
    ModificationPolicy, SandboxModificationPatch, SandboxModificationPlan, SecretSource,
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// The apply route, as error messages name it.
const APPLY_OP: &str = "PUT /v1/sandboxes/:id";

/// One `apply()`: 180 s in all, 75 s per request. 180 s covers a crashed
/// request's 90 s lock plus one full request, with margin.
const APPLY_BUDGET: ApplyBudget = ApplyBudget {
    total: Duration::from_secs(180),
    per_request: Duration::from_secs(75),
    not_sent: Backoff {
        first: Duration::from_millis(250),
        max: Duration::from_secs(2),
        jitter: false,
    },
    in_progress: Backoff {
        first: Duration::from_secs(1),
        max: Duration::from_secs(8),
        jitter: true,
    },
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Time limits and retry delays of one apply.
#[derive(Debug, Clone, Copy)]
struct ApplyBudget {
    total: Duration,
    per_request: Duration,
    not_sent: Backoff,
    in_progress: Backoff,
}

/// A delay that doubles per retry up to `max`, optionally spread by ±20 %.
#[derive(Debug, Clone, Copy)]
struct Backoff {
    first: Duration,
    max: Duration,
    jitter: bool,
}

/// What one send produced, read to the end of the answer.
enum SendOutcome {
    /// The connection was never made, so nothing left the client.
    NotSent(reqwest::Error),
    /// The request may have reached the server, but no full answer came back.
    Lost(&'static str),
    /// The server answered.
    Answered { status: u16, body: String },
}

/// What one attempt asks the apply loop to do.
enum Attempt {
    Done(SandboxModificationPlan),
    Fail(MicrosandboxError),
    /// Nothing was written: try again, or return `at_deadline` once the budget is spent.
    Retry {
        class: RetryClass,
        at_deadline: MicrosandboxError,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RetryClass {
    /// The request never left the client.
    NotSent,
    /// Another change to the sandbox holds its lock.
    InProgress,
}

/// The error codes the modification routes answer with.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ModifyErrorCode {
    InProgress,
    Refused,
    Unsupported,
    Failed,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CloudBackend {
    /// Dry-run `patch` on the sandbox `id`. The request carries no secret value;
    /// `Env` sources are not read.
    pub(crate) async fn plan_modification(
        &self,
        id: &str,
        patch: &SandboxModificationPatch,
        policy: ModificationPolicy,
    ) -> MicrosandboxResult<SandboxModificationPlan> {
        let request = CloudSandboxModificationPlanRequest::from_patch(patch, policy)
            .map_err(|rejection| rejection_error(patch, rejection))?;
        self.post_modification_plan(id, &request).await
    }

    /// Apply `patch` to the sandbox `id`. Each `Env` source is read once, here.
    pub(crate) async fn apply_modification(
        &self,
        id: &str,
        patch: &SandboxModificationPatch,
        policy: ModificationPolicy,
    ) -> MicrosandboxResult<SandboxModificationPlan> {
        let request = CloudSandboxModificationApplyRequest::from_patch(patch, policy, resolve_env)
            .map_err(|rejection| rejection_error(patch, rejection))?;
        self.apply_with_retries(id, &request, APPLY_BUDGET).await
    }

    /// Send `request` until the server answers it, within `budget`.
    async fn apply_with_retries(
        &self,
        id: &str,
        request: &CloudSandboxModificationApplyRequest,
        budget: ApplyBudget,
    ) -> MicrosandboxResult<SandboxModificationPlan> {
        let deadline = Instant::now() + budget.total;
        let (mut not_sent, mut in_progress) = (0, 0);
        loop {
            let timeout = budget
                .per_request
                .min(deadline.saturating_duration_since(Instant::now()));
            let sent = read(self.put_modification(id, request, timeout).await).await;
            let (class, at_deadline) = match classify(sent) {
                Attempt::Done(plan) => return Ok(plan),
                Attempt::Fail(error) => return Err(error),
                Attempt::Retry { class, at_deadline } => (class, at_deadline),
            };
            let delay = match class {
                RetryClass::NotSent => budget.not_sent.delay(&mut not_sent),
                RetryClass::InProgress => budget.in_progress.delay(&mut in_progress),
            };
            if Instant::now() + delay >= deadline {
                return Err(at_deadline);
            }
            tokio::time::sleep(delay).await;
        }
    }
}

impl Backoff {
    /// The delay before retry number `*retries`, which it then counts.
    fn delay(&self, retries: &mut u32) -> Duration {
        let delay = self
            .first
            .saturating_mul(2u32.saturating_pow(*retries))
            .min(self.max);
        *retries = retries.saturating_add(1);
        if !self.jitter {
            return delay;
        }
        // A spread in [0.8, 1.2) from the process's random hasher keys.
        let spread = (RandomState::new().hash_one(Instant::now()) % 4_000) as f64 / 10_000.0;
        delay.mul_f64(0.8 + spread)
    }
}

impl FromStr for ModifyErrorCode {
    type Err = ();

    fn from_str(code: &str) -> Result<Self, Self::Err> {
        match code {
            CLOUD_MODIFICATION_IN_PROGRESS => Ok(Self::InProgress),
            CLOUD_MODIFICATION_REFUSED => Ok(Self::Refused),
            CLOUD_MODIFICATION_UNSUPPORTED => Ok(Self::Unsupported),
            CLOUD_MODIFICATION_FAILED => Ok(Self::Failed),
            _ => Err(()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Read a send's outcome to the end. A body that cannot be read is a lost answer.
async fn read(sent: Result<Response, reqwest::Error>) -> SendOutcome {
    let response = match sent {
        Ok(response) => response,
        Err(error) if error.is_connect() => return SendOutcome::NotSent(error),
        Err(error) => return SendOutcome::Lost(transport_cause(&error)),
    };
    let status = response.status().as_u16();
    match response.text().await {
        Ok(body) => SendOutcome::Answered { status, body },
        Err(error) => SendOutcome::Lost(transport_cause(&error)),
    }
}

/// A value-free description of a transport failure after the request was sent.
fn transport_cause(error: &reqwest::Error) -> &'static str {
    if error.is_timeout() {
        "no answer came before the request timed out"
    } else if error.is_body() || error.is_decode() {
        "the answer was cut off"
    } else {
        "the connection failed after the request was sent"
    }
}

/// Classify one send of the apply route.
fn classify(sent: SendOutcome) -> Attempt {
    let (status, body) = match sent {
        SendOutcome::NotSent(error) => {
            return Attempt::Retry {
                class: RetryClass::NotSent,
                at_deadline: cloud_io_error(APPLY_OP, error),
            };
        }
        SendOutcome::Lost(cause) => return Attempt::Fail(result_unknown(cause)),
        SendOutcome::Answered { status, body } => (status, body),
    };
    if status == 200 {
        return match serde_json::from_str::<CloudSandboxModificationPlan>(&body) {
            Ok(plan) => Attempt::Done(plan.into()),
            Err(_) => Attempt::Fail(result_unknown("the server's answer could not be read")),
        };
    }

    let typed: Option<CloudErrorBody> = serde_json::from_str(&body).ok();
    let raw_code = cloud_error_code(typed.as_ref());
    let code = raw_code.and_then(|code| code.parse::<ModifyErrorCode>().ok());
    let message = cloud_error_message(typed.as_ref()).unwrap_or("no message");
    match (status, code) {
        (409, Some(ModifyErrorCode::InProgress)) => Attempt::Retry {
            class: RetryClass::InProgress,
            at_deadline: cloud_http_error(status, typed.as_ref(), &body, APPLY_OP),
        },
        (409, Some(ModifyErrorCode::Refused)) => {
            Attempt::Fail(MicrosandboxError::Custom(message.to_string()))
        }
        (409, Some(ModifyErrorCode::Unsupported)) => {
            Attempt::Fail(cloud_http_error(status, typed.as_ref(), &body, APPLY_OP))
        }
        (503, Some(ModifyErrorCode::Failed)) => {
            Attempt::Fail(MicrosandboxError::ModificationNotConfirmed {
                cause: message.to_string(),
            })
        }
        (500..=599, _) => {
            let code = raw_code.map(|code| format!(" {code}")).unwrap_or_default();
            Attempt::Fail(result_unknown(format!(
                "the server answered {status}{code}: {message}"
            )))
        }
        (400..=499, _) => Attempt::Fail(cloud_http_error(status, typed.as_ref(), &body, APPLY_OP)),
        _ => Attempt::Fail(result_unknown(format!(
            "the server answered with unexpected status {status}"
        ))),
    }
}

/// A failure after sending that leaves the result unknown. The server's own
/// failure message already says whether a resend helps, so only causes the
/// client builds go through here.
fn result_unknown(cause: impl std::fmt::Display) -> MicrosandboxError {
    MicrosandboxError::ModificationNotConfirmed {
        cause: format!(
            "{cause}; the result is unknown, and sending the same change again retries it"
        ),
    }
}

/// A missing or non-UTF-8 variable resolves to `None`, which the request
/// builder refuses as an unresolved source.
fn resolve_env(var: &str) -> Option<CloudSecretValue> {
    std::env::var(var).ok().map(CloudSecretValue::new)
}

/// A patch the Cloud request cannot express. A non-secret field is
/// `Unsupported`, as the server's `modification_unsupported` is; a store
/// source is refused with the local planner's text; a name, placeholder or
/// value that sandbox creation refuses, or an unset source variable, is
/// `InvalidConfig`, as on Local;
/// anything else is the rejection's own text.
fn rejection_error(
    patch: &SandboxModificationPatch,
    rejection: CloudModificationRejection,
) -> MicrosandboxError {
    match rejection {
        CloudModificationRejection::UnsupportedField { .. } => MicrosandboxError::unsupported(
            Operation::SandboxModify,
            UnsupportedReason::NotAvailable(rejection.to_string()),
        ),
        CloudModificationRejection::StoreSource { .. } => {
            let name = patch
                .secrets
                .iter()
                .find(|spec| {
                    spec.value.is_empty() && matches!(spec.source, Some(SecretSource::Store { .. }))
                })
                .map_or("", |spec| spec.name.as_str());
            MicrosandboxError::Custom(format!(
                "cannot apply modification: secret {name}: store-backed secret sources are not supported yet"
            ))
        }
        CloudModificationRejection::BlankName { .. }
        | CloudModificationRejection::InvalidName { .. }
        | CloudModificationRejection::InvalidPlaceholder { .. }
        | CloudModificationRejection::EmptyValue { .. }
        | CloudModificationRejection::UnresolvedSource { .. } => {
            MicrosandboxError::InvalidConfig(format!("invalid secret configuration: {rejection}"))
        }
        _ => MicrosandboxError::Custom(rejection.to_string()),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests;
