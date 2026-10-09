//! Sandbox-bound job identity, control discovery, and retained output.

use std::sync::Arc;
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures::stream;
use microsandbox_protocol::jobs::{JobOperation, JobOutput, JobOutputPage, JobResponse};

use crate::backend::Backend;
#[cfg(feature = "local")]
use crate::sandbox::SandboxStatus;
use crate::sandbox::{SandboxHandle, SandboxId};

use super::{
    JobError, JobExit, JobId, JobInfo, JobLogEntry, JobLogOptions, JobLogStream, JobResult,
    JobState,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A runtime-owned command. Dropping this handle never kills it or changes sandbox ownership.
#[derive(Clone)]
pub struct Job {
    pub(super) target: Target,
    pub(super) id: JobId,
    #[cfg(feature = "local")]
    pub(super) boot_id: String,
    #[cfg(feature = "local")]
    pub(super) connection: Arc<tokio::sync::OnceCell<JobConnection>>,
}

#[derive(Clone)]
pub(super) struct Target {
    pub backend: Arc<dyn Backend>,
    pub name: String,
    pub sandbox_id: SandboxId,
}

#[cfg(feature = "local")]
pub(super) struct JobConnection {
    pub session: crate::backend::local::control::ControlSession,
    pub boot_id: String,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Target {
    pub async fn validate(&self) -> JobResult<SandboxHandle> {
        let handle = self
            .backend
            .sandboxes()
            .get(self.backend.clone(), &self.name)
            .await?;
        if handle.id() != self.sandbox_id {
            return Err(JobError::operation(
                "sandbox_replaced",
                "the sandbox name now refers to a different sandbox",
            ));
        }
        Ok(handle)
    }

    #[cfg(feature = "local")]
    pub fn store(&self) -> JobResult<microsandbox_runtime::jobs::JobStore> {
        let local = self.backend.as_local().ok_or_else(unsupported)?;
        Ok(microsandbox_runtime::jobs::JobStore::new(
            &local.sandboxes_dir().join(&self.name),
        ))
    }

    #[cfg(feature = "local")]
    pub async fn connect(&self) -> JobResult<JobConnection> {
        self.validate().await?;
        let local = self.backend.as_local().ok_or_else(unsupported)?;
        let session = local
            .control_session(&self.name)
            .await?
            .ok_or_else(unsupported)?;
        let response = session
            .job_request(&microsandbox_control_client::ManageJob(
                microsandbox_protocol::jobs::JobRequest {
                    version: microsandbox_protocol::jobs::JOB_PROTOCOL_VERSION,
                    runtime_boot_id: None,
                    operation: JobOperation::Hello,
                },
            ))
            .await
            .map_err(|error| match error.as_ref() {
                microsandbox_control_client::ControlClientError::UnsupportedMode => unsupported(),
                microsandbox_control_client::ControlClientError::Peer { error, .. }
                    if error.code == "unsupported_operation" =>
                {
                    unsupported()
                }
                _ => JobError::Sandbox(crate::MicrosandboxError::ControlClient(error)),
            })?;
        match checked(response)? {
            JobResponse::Hello {
                version,
                runtime_boot_id,
            } if version == microsandbox_protocol::jobs::JOB_PROTOCOL_VERSION => {
                Ok(JobConnection {
                    session,
                    boot_id: runtime_boot_id,
                })
            }
            _ => Err(unsupported()),
        }
    }
}

#[cfg(feature = "local")]
impl JobConnection {
    pub async fn request(&self, operation: JobOperation) -> JobResult<JobResponse> {
        let response = self
            .session
            .job_request(&microsandbox_control_client::ManageJob(
                microsandbox_protocol::jobs::JobRequest {
                    version: microsandbox_protocol::jobs::JOB_PROTOCOL_VERSION,
                    runtime_boot_id: Some(self.boot_id.clone()),
                    operation,
                },
            ))
            .await
            .map_err(crate::MicrosandboxError::ControlClient)?;
        checked(response)
    }
}

impl Job {
    #[cfg(feature = "local")]
    pub(super) fn from_info(target: Target, info: &JobInfo) -> Self {
        Self {
            target,
            id: info.id.clone(),
            boot_id: info.runtime_boot_id.clone(),
            #[cfg(feature = "local")]
            connection: Arc::new(tokio::sync::OnceCell::new()),
        }
    }

    /// Stable ID; does not perform I/O and remains valid after process exit.
    pub fn id(&self) -> &JobId {
        &self.id
    }

    /// Owning sandbox's name. Identity checks prevent reuse from redirecting this handle.
    pub fn sandbox_name(&self) -> &str {
        &self.target.name
    }

    /// Read current metadata without starting a stopped sandbox.
    pub async fn inspect(&self) -> JobResult<JobInfo> {
        let handle = self.target.validate().await?;
        #[cfg(feature = "local")]
        {
            let mut info = self
                .target
                .store()?
                .read(&self.id)
                .map_err(history_error)?
                .info;
            if info.state.is_active() {
                if matches!(
                    handle.status_snapshot(),
                    SandboxStatus::Running | SandboxStatus::Paused | SandboxStatus::Draining
                ) {
                    match self
                        .request(JobOperation::Inspect {
                            id: self.id.clone(),
                        })
                        .await
                    {
                        Ok(JobResponse::Info { info }) => return Ok(info),
                        Err(JobError::Operation { code, .. })
                            if code == "job_not_running" || code == "unsupported_feature" => {}
                        Err(error) => return Err(error),
                        _ => return Err(invalid_response()),
                    }
                }
                // An offline observation does not write over the runtime's authoritative record.
                info.state = JobState::Lost;
                info.error =
                    Some("owning runtime is no longer available; exit status is unknown".into());
            }
            Ok(info)
        }
        #[cfg(not(feature = "local"))]
        {
            let _ = handle;
            Err(unsupported())
        }
    }

    /// Wait independently of output consumption; cancelling this future does not kill the job.
    pub async fn wait(&self) -> JobResult<JobExit> {
        loop {
            let info = self.inspect().await?;
            match info.state {
                JobState::Exited => {
                    let code = info.exit_code.ok_or_else(invalid_response)?;
                    return Ok(JobExit {
                        code,
                        success: code == 0,
                        timed_out: info.timed_out,
                    });
                }
                JobState::Failed => {
                    return Err(JobError::operation(
                        "exec_failed",
                        info.failure.map_or_else(
                            || "command did not start".into(),
                            |failure| failure.message,
                        ),
                    ));
                }
                JobState::Lost => {
                    return Err(JobError::operation(
                        "job_lost",
                        info.error.unwrap_or_else(|| "job exit is unknown".into()),
                    ));
                }
                _ => tokio::time::sleep(Duration::from_millis(100)).await,
            }
        }
    }

    /// Send a Linux guest process-group signal, without waiting for process completion.
    pub async fn signal(&self, signal: i32) -> JobResult<()> {
        self.expect_ok(JobOperation::Signal {
            id: self.id.clone(),
            signal,
        })
        .await
    }

    /// Request SIGKILL. Wait separately to observe actual completion, including while paused.
    pub async fn kill(&self) -> JobResult<()> {
        self.signal(9).await
    }

    /// Permanently finish pipe input after all previously admitted bytes. PTYs reject this call.
    pub async fn eof(&self) -> JobResult<()> {
        self.expect_ok(JobOperation::Eof {
            id: self.id.clone(),
        })
        .await
    }

    /// Read retained output with filters; binary output is preserved.
    pub async fn logs(&self, options: &JobLogOptions) -> JobResult<Vec<JobLogEntry>> {
        let (items, _) = self.log_snapshot(options).await?;
        Ok(items)
    }

    /// Replay retained output and optionally follow it, using one monotonically increasing cursor.
    pub async fn log_stream(&self, options: &JobLogOptions) -> JobResult<JobLogStream> {
        let (items, cursor) = self.log_snapshot(options).await?;
        let job = self.clone();
        let options = options.clone();
        let state = (
            job,
            options,
            std::collections::VecDeque::from(items),
            cursor,
            false,
        );
        Ok(Box::pin(stream::try_unfold(
            state,
            |(job, options, mut pending, mut cursor, mut done)| async move {
                loop {
                    if let Some(item) = pending.pop_front() {
                        return Ok(Some((item, (job, options, pending, cursor, done))));
                    }
                    if done || !options.follow {
                        return Ok(None);
                    }
                    let page = job.read_page(cursor, None).await?;
                    if page.gap_before.is_some() {
                        return Err(JobError::operation(
                            "output_gap",
                            "output was pruned before the reader consumed it",
                        ));
                    }
                    cursor = page.cursor;
                    done = !page.info.state.is_active() && page.items.is_empty();
                    for record in page.items {
                        let entry = job.decode_output(record)?;
                        if matches_log(&entry, &options) {
                            pending.push_back(entry);
                        }
                    }
                    if pending.is_empty() && !done {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            },
        )))
    }

    /// Select historical output then follow without a read/subscribe gap.
    pub async fn follow_logs(&self, options: &JobLogOptions) -> JobResult<JobLogStream> {
        let mut options = options.clone();
        options.follow = true;
        self.log_stream(&options).await
    }

    async fn log_snapshot(&self, options: &JobLogOptions) -> JobResult<(Vec<JobLogEntry>, u64)> {
        self.target.validate().await?;
        if options.from_cursor.is_some() && options.since.is_some() {
            return Err(JobError::operation(
                "invalid_options",
                "from_cursor and since are mutually exclusive",
            ));
        }
        let after = options
            .from_cursor
            .as_ref()
            .map(|cursor| self.parse_cursor(cursor))
            .transpose()?
            .unwrap_or(0);
        #[cfg(feature = "local")]
        {
            let records = self.target.store()?.output(&self.id)?;
            if options.from_cursor.is_some()
                && records
                    .first()
                    .is_some_and(|record| after.saturating_add(1) < record.sequence)
            {
                return Err(JobError::operation(
                    "output_gap",
                    "requested output cursor has expired",
                ));
            }
            let cursor = records
                .last()
                .map_or(after, |record| record.sequence.max(after));
            let mut items = records
                .into_iter()
                .filter(|record| record.sequence > after)
                .map(|record| self.decode_output(record))
                .collect::<JobResult<Vec<_>>>()?;
            items.retain(|entry| matches_log(entry, options));
            if let Some(tail) = options.tail
                && items.len() > tail
            {
                items.drain(..items.len() - tail);
            }
            Ok((items, cursor))
        }
        #[cfg(not(feature = "local"))]
        {
            let _ = after;
            Err(unsupported())
        }
    }

    pub(super) async fn request(&self, operation: JobOperation) -> JobResult<JobResponse> {
        #[cfg(feature = "local")]
        {
            let connection = self
                .connection
                .get_or_try_init(|| self.target.connect())
                .await?;
            if connection.boot_id != self.boot_id {
                return Err(JobError::operation(
                    "job_not_running",
                    "job belongs to an earlier runtime generation",
                ));
            }
            connection.request(operation).await
        }
        #[cfg(not(feature = "local"))]
        {
            let _ = operation;
            Err(unsupported())
        }
    }

    pub(super) async fn expect_ok(&self, operation: JobOperation) -> JobResult<()> {
        match self.request(operation).await? {
            JobResponse::Ok => Ok(()),
            _ => Err(invalid_response()),
        }
    }

    pub(super) async fn read_page(
        &self,
        after: u64,
        attachment: Option<String>,
    ) -> JobResult<JobOutputPage> {
        // Terminal history also works after a sandbox stops. Live attachments use the fenced
        // connection; they never silently reconnect to an execution in a replacement runtime.
        if attachment.is_none() {
            let info = self.inspect().await?;
            if !info.state.is_active() {
                #[cfg(feature = "local")]
                {
                    let records = self.target.store()?.output(&self.id)?;
                    let gap_before = records
                        .first()
                        .filter(|record| after.saturating_add(1) < record.sequence)
                        .map(|record| record.sequence);
                    let items: Vec<_> = records
                        .into_iter()
                        .filter(|record| record.sequence > after)
                        .take(4)
                        .collect();
                    let cursor = items.last().map_or(after, |record| record.sequence);
                    return Ok(JobOutputPage {
                        items,
                        cursor,
                        gap_before,
                        info,
                    });
                }
            }
        }
        match self
            .request(JobOperation::Read {
                id: self.id.clone(),
                after,
                attachment,
            })
            .await?
        {
            JobResponse::Output { page } => Ok(page),
            _ => Err(invalid_response()),
        }
    }

    pub(super) fn cursor(&self, sequence: u64) -> String {
        format!("{}:{sequence}", self.id)
    }

    pub(super) fn parse_cursor(&self, cursor: &str) -> JobResult<u64> {
        let (id, sequence) = cursor
            .rsplit_once(':')
            .ok_or_else(|| JobError::operation("invalid_cursor", "invalid job output cursor"))?;
        if id != self.id.as_str() {
            return Err(JobError::operation(
                "invalid_cursor",
                "output cursor belongs to another job",
            ));
        }
        sequence
            .parse()
            .map_err(|_| JobError::operation("invalid_cursor", "invalid output sequence"))
    }

    pub(super) fn decode_output(&self, output: JobOutput) -> JobResult<JobLogEntry> {
        let data = STANDARD.decode(output.data_base64).map_err(|_| {
            JobError::operation(
                "invalid_output",
                "job output contains invalid byte encoding",
            )
        })?;
        Ok(JobLogEntry {
            timestamp: output.timestamp,
            source: output.source,
            data: data.into(),
            cursor: self.cursor(output.sequence),
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "local")]
pub(super) fn checked(response: JobResponse) -> JobResult<JobResponse> {
    match response {
        JobResponse::Error { code, message } => Err(JobError::Operation { code, message }),
        response => Ok(response),
    }
}

pub(super) fn unsupported() -> JobError {
    JobError::operation(
        "unsupported_feature",
        "managed jobs require a supporting local runtime and backend",
    )
}

pub(super) fn invalid_response() -> JobError {
    JobError::operation(
        "invalid_response",
        "runtime returned an unexpected job response",
    )
}

#[cfg(feature = "local")]
pub(super) fn history_error(error: std::io::Error) -> JobError {
    if error.kind() == std::io::ErrorKind::NotFound {
        JobError::operation("job_not_found", "job was not found or its history expired")
    } else {
        error.into()
    }
}

fn matches_log(entry: &JobLogEntry, options: &JobLogOptions) -> bool {
    options.since.is_none_or(|since| entry.timestamp >= since)
        && options.until.is_none_or(|until| entry.timestamp < until)
        && if options.sources.is_empty() {
            matches!(entry.source.as_str(), "stdout" | "stderr" | "output")
        } else {
            options.sources.contains(&entry.source)
        }
}
