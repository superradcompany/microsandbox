//! Additive sandbox methods for launching and discovering managed jobs.

#[cfg(feature = "local")]
use std::sync::Arc;
#[cfg(feature = "local")]
use std::time::Duration;

use base64::{Engine as _, engine::general_purpose::STANDARD};
#[cfg(feature = "local")]
use microsandbox_protocol::jobs::{JobOperation, JobResponse};

#[cfg(feature = "local")]
use crate::sandbox::SandboxStatus;
use crate::sandbox::exec::{ExecOptionsBuilder, StdinMode};
use crate::sandbox::{Sandbox, SandboxHandle, build_exec_request};

#[cfg(feature = "local")]
use super::JobState;
use super::client::Target;
#[cfg(not(feature = "local"))]
use super::client::unsupported;
#[cfg(feature = "local")]
use super::client::{history_error, invalid_response};
use super::{Job, JobError, JobId, JobListBuilder, JobPage, JobResult};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Start a runtime-owned command with pipe input retained for future attachments.
    pub async fn exec_detached(
        &self,
        cmd: impl Into<String>,
        args: impl IntoIterator<Item = impl Into<String>>,
    ) -> JobResult<Job> {
        self.exec_detached_with(cmd, |options| options.args(args))
            .await
    }

    /// Configure detached execution without changing the existing exec builder or return types.
    pub async fn exec_detached_with(
        &self,
        cmd: impl Into<String>,
        configure: impl FnOnce(ExecOptionsBuilder) -> ExecOptionsBuilder,
    ) -> JobResult<Job> {
        let options = configure(ExecOptionsBuilder::default().stdin_pipe()).build()?;
        let no_stdin = matches!(options.stdin, StdinMode::Null);
        if options.tty && no_stdin {
            return Err(JobError::operation(
                "invalid_options",
                "PTY execution cannot use null stdin",
            ));
        }
        let input_base64 = match &options.stdin {
            StdinMode::Bytes(bytes) => {
                if options.tty || bytes.len() > 64 * 1024 {
                    return Err(JobError::operation(
                        "invalid_options",
                        "finite detached input requires pipes and is limited to 64 KiB; use an attachment for larger input",
                    ));
                }
                Some(STANDARD.encode(bytes))
            }
            _ => None,
        };
        let request = build_exec_request(
            self.config(),
            cmd.into(),
            options.args,
            options.cwd,
            options.user,
            &options.env,
            &options.rlimits,
            options.tty,
            24,
            80,
        );
        let target = Target {
            backend: self.backend().clone(),
            name: self.name().into(),
            sandbox_id: self.id(),
        };
        #[cfg(feature = "local")]
        {
            let handle = target.validate().await?;
            if handle.status_snapshot() != SandboxStatus::Running {
                return Err(JobError::operation(
                    "sandbox_not_running",
                    "detached execution requires a running sandbox",
                ));
            }
            let connection = target.connect().await?;
            let id = JobId::parse(format!("job_{}", token()?))
                .map_err(|message| JobError::operation("invalid_id", message))?;
            let timeout_ms = options
                .timeout
                .map(|duration| {
                    // The wire uses milliseconds: round positive sub-millisecond deadlines up.
                    u64::try_from(duration.as_nanos().div_ceil(1_000_000))
                        .map_err(|_| JobError::operation("invalid_options", "timeout is too large"))
                })
                .transpose()?;
            let response = connection
                .request(JobOperation::Start {
                    id: id.clone(),
                    command: request,
                    no_stdin,
                    input_base64,
                    timeout_ms,
                })
                .await
                .map_err(|error| {
                    // A structured runtime refusal is definitive; a lost response isn't.
                    if matches!(error, JobError::Operation { .. }) {
                        error
                    } else {
                        JobError::LaunchUnconfirmed {
                            id: id.clone(),
                            message: error.to_string(),
                        }
                    }
                })?;
            let JobResponse::Info { info } = response else {
                return Err(invalid_response());
            };
            let mut job = Job::from_info(target, &info);
            job.connection = Arc::new(tokio::sync::OnceCell::new_with(Some(connection)));
            let acknowledged = async {
                loop {
                    let info =
                        job.inspect()
                            .await
                            .map_err(|error| JobError::LaunchUnconfirmed {
                                id: id.clone(),
                                message: error.to_string(),
                            })?;
                    match info.state {
                        JobState::Starting => tokio::time::sleep(Duration::from_millis(25)).await,
                        JobState::Running | JobState::Exited => return Ok(()),
                        JobState::Failed => {
                            return Err(JobError::operation(
                                "exec_failed",
                                info.failure.map_or_else(
                                    || "command did not start".into(),
                                    |failure| failure.message,
                                ),
                            ));
                        }
                        _ => {
                            return Err(JobError::LaunchUnconfirmed {
                                id: id.clone(),
                                message: info
                                    .error
                                    .unwrap_or_else(|| "job ownership was lost".into()),
                            });
                        }
                    }
                }
            };
            tokio::time::timeout(Duration::from_secs(30), acknowledged)
                .await
                .map_err(|_| JobError::LaunchUnconfirmed {
                    id,
                    message: "guest start acknowledgement timed out".into(),
                })??;
            Ok(job)
        }
        #[cfg(not(feature = "local"))]
        {
            let _ = (target, request, input_base64);
            Err(unsupported())
        }
    }

    /// Retrieve a job without creating a new process.
    pub async fn get_job(&self, id: impl AsRef<str>) -> JobResult<Job> {
        self.refresh_handle().await?.get_job(id).await
    }

    /// List active jobs in this sandbox.
    pub async fn list_jobs(&self) -> JobResult<JobPage> {
        self.list_jobs_with(|options| options).await
    }

    /// Configure a bounded job-list page.
    pub async fn list_jobs_with(
        &self,
        configure: impl FnOnce(JobListBuilder) -> JobListBuilder,
    ) -> JobResult<JobPage> {
        self.refresh_handle().await?.list_jobs_with(configure).await
    }
}

impl SandboxHandle {
    /// Retrieve a retained job while preserving this handle's sandbox identity.
    pub async fn get_job(&self, id: impl AsRef<str>) -> JobResult<Job> {
        let id = JobId::parse(id.as_ref())
            .map_err(|message| JobError::operation("invalid_id", message))?;
        let target = Target {
            backend: self.backend.clone(),
            name: self.name().into(),
            sandbox_id: self.id(),
        };
        target.validate().await?;
        #[cfg(feature = "local")]
        {
            let info = target.store()?.read(&id).map_err(history_error)?.info;
            Ok(Job::from_info(target, &info))
        }
        #[cfg(not(feature = "local"))]
        {
            let _ = id;
            Err(unsupported())
        }
    }

    /// List active jobs without starting the sandbox.
    pub async fn list_jobs(&self) -> JobResult<JobPage> {
        self.list_jobs_with(|options| options).await
    }

    /// List retained history, including after sandbox shutdown.
    pub async fn list_jobs_with(
        &self,
        configure: impl FnOnce(JobListBuilder) -> JobListBuilder,
    ) -> JobResult<JobPage> {
        let options = configure(JobListBuilder::default());
        if !(1..=100).contains(&options.limit) {
            return Err(JobError::operation(
                "invalid_options",
                "job page size must be between 1 and 100",
            ));
        }
        let target = Target {
            backend: self.backend.clone(),
            name: self.name().into(),
            sandbox_id: self.id(),
        };
        let handle = target.validate().await?;
        #[cfg(feature = "local")]
        {
            if matches!(
                handle.status_snapshot(),
                SandboxStatus::Running | SandboxStatus::Paused | SandboxStatus::Draining
            ) {
                let connection = target.connect().await?;
                return match connection
                    .request(JobOperation::List {
                        all: options.all,
                        limit: options.limit,
                        cursor: options.cursor,
                    })
                    .await?
                {
                    JobResponse::Page { page } => Ok(page),
                    _ => Err(invalid_response()),
                };
            }
            let mut items = Vec::new();
            for record in target.store()?.list()? {
                let mut info = record.info;
                if info.state.is_active() {
                    info.state = JobState::Lost;
                    info.error = Some("sandbox stopped without a confirmed process exit".into());
                }
                if (options.all || info.state.is_active())
                    && options
                        .cursor
                        .as_ref()
                        .is_none_or(|cursor| info.id > *cursor)
                {
                    items.push(info);
                }
            }
            JobPage::bounded(items, options.limit)
                .map_err(|error| JobError::operation("history_error", error.to_string()))
        }
        #[cfg(not(feature = "local"))]
        {
            let _ = handle;
            Err(unsupported())
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn token() -> JobResult<String> {
    #[cfg(feature = "local")]
    {
        use rand::Rng;
        let mut bytes = [0u8; 16];
        rand::rng().fill_bytes(&mut bytes);
        Ok(bytes.iter().map(|byte| format!("{byte:02x}")).collect())
    }
    #[cfg(not(feature = "local"))]
    {
        Err(unsupported())
    }
}
