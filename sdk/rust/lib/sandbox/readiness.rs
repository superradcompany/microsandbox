//! Lookup and prepare an existing sandbox without recreating a missing resource.

use std::sync::Arc;

use super::{
    Sandbox, SandboxRecord, SandboxStatus,
    state::{RuntimeSession, SandboxBinding},
};
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Prepare this resource for guest operations, retaining any local run it starts.
    ///
    /// Clones coordinate preparation and share ownership. An independently fetched
    /// resource connects without acquiring ownership of an already running VM.
    /// This never recreates a missing resource or starts a same-name replacement.
    pub async fn ensure_running(&self) -> MicrosandboxResult<()> {
        self.prepare_runtime().await.map(|_| ())
    }

    /// Prepare and return a local agent connection bound to the selected run.
    ///
    /// This client never follows a later restart. It retains the transport, not
    /// lifecycle ownership: retain the Sandbox while using raw guest operations.
    /// Remote contexts return Unsupported without starting a remote resource.
    pub async fn client(&self) -> MicrosandboxResult<Arc<crate::agent::AgentClient>> {
        #[cfg(feature = "local")]
        if self.backend.as_local().is_some() {
            let session = self.prepare_runtime().await?;
            if let crate::context::SandboxInner::Local(local) = &session.inner {
                return Ok(local.client.clone());
            }
        }
        Err(MicrosandboxError::local_only(
            crate::error::Operation::SandboxClient,
        ))
    }

    pub(crate) fn from_record(record: SandboxRecord) -> Self {
        let mut backend = record.backend.clone();
        if let Some(remote) = record.remote_state() {
            backend = backend
                .with_agent_identity(record.name(), &remote.id)
                .unwrap_or(backend);
        }
        Self {
            backend,
            identity: record.identity(),
            name: record.name().to_owned(),
            ephemeral: record.is_local_ephemeral(),
            binding: Arc::new(SandboxBinding::default()),
        }
    }

    /// Inspection helpers retain destination and identity without owning a run.
    pub(crate) fn observer(&self) -> Self {
        Self {
            backend: self.backend.clone(),
            identity: self.identity.clone(),
            name: self.name.clone(),
            ephemeral: self.ephemeral,
            binding: Arc::new(SandboxBinding::default()),
        }
    }

    pub(crate) fn prepared_runtime(&self) -> MicrosandboxResult<Arc<RuntimeSession>> {
        self.binding
            .current()
            .ok_or_else(|| MicrosandboxError::SandboxNotRunning(self.name.clone()))
    }

    pub(crate) async fn prepare_runtime(&self) -> MicrosandboxResult<Arc<RuntimeSession>> {
        let _preparing = self.binding.preparation.lock().await;
        loop {
            let record = self.refresh_handle().await?;
            match record.status_snapshot() {
                SandboxStatus::Running => {
                    if let Some(session) = self.binding.current()
                        && self.session_is_current(&session).await?
                    {
                        return Ok(session);
                    }
                    let connected = record
                        .connect_current_with_timeout(super::handle::DEFAULT_CONNECT_TIMEOUT)
                        .await?;
                    return self.retain_prepared(connected);
                }
                SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed => {
                    match record.start().await {
                        Ok(started) => return self.retain_prepared(started),
                        // Another receiver won startup. Reinspect instead of starting
                        // twice or taking ownership of that receiver's run.
                        Err(MicrosandboxError::SandboxStillRunning(_)) => {}
                        Err(error) => return Err(error),
                    }
                }
                SandboxStatus::Starting => {}
                SandboxStatus::Draining => {
                    return Err(MicrosandboxError::SandboxStillRunning(format!(
                        "cannot prepare '{}': shutdown is already in progress",
                        self.name
                    )));
                }
                SandboxStatus::Paused => {
                    return Err(MicrosandboxError::SandboxNotRunning(format!(
                        "'{}' is paused; resume it before guest operations",
                        self.name
                    )));
                }
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    /// Health probes may attach to a running VM, but must never boot a stopped one.
    #[cfg(feature = "local")]
    pub(crate) async fn connect_running(&self) -> MicrosandboxResult<Arc<RuntimeSession>> {
        let _preparing = self.binding.preparation.lock().await;
        let record = self.refresh_handle().await?;
        if !matches!(
            record.status_snapshot(),
            SandboxStatus::Running | SandboxStatus::Draining
        ) {
            return Err(MicrosandboxError::SandboxNotRunning(self.name.clone()));
        }
        if let Some(session) = self.binding.current()
            && self.session_is_current(&session).await?
        {
            return Ok(session);
        }
        self.retain_prepared(record.connect().await?)
    }

    async fn session_is_current(&self, session: &RuntimeSession) -> MicrosandboxResult<bool> {
        match &session.inner {
            #[cfg(feature = "local")]
            crate::context::SandboxInner::Local(local) => {
                let backend = self.backend.as_local().ok_or_else(|| {
                    MicrosandboxError::Runtime("local runtime has no local context".into())
                })?;
                let run =
                    crate::LocalContext::load_latest_run(backend.db().await?.read(), local.db_id)
                        .await?;
                Ok(local.run_id.is_some() && local.run_id == run.map(|run| run.id))
            }
            crate::context::SandboxInner::Cloud(_) => Ok(true),
            #[cfg(not(feature = "local"))]
            _ => Ok(false),
        }
    }

    fn retain_prepared(&self, prepared: Sandbox) -> MicrosandboxResult<Arc<RuntimeSession>> {
        if prepared.identity != self.identity {
            return Err(MicrosandboxError::SandboxReplaced {
                name: self.name.clone(),
                expected: self.id().to_string(),
                actual: prepared.id().to_string(),
            });
        }
        let session = prepared.binding.current().ok_or_else(|| {
            MicrosandboxError::Runtime(
                "provider returned an unprepared sandbox after startup".into(),
            )
        })?;
        // Publication is synchronous: cancellation cannot strand a successful
        // owner between returning from startup and storing it on this receiver.
        self.binding.publish(session.clone());
        Ok(session)
    }

    /// Get an existing sandbox and connect to it, starting it if stopped.
    ///
    /// Unlike [`start`](Self::start), this also succeeds when already running.
    /// Lookup captures the persisted identity before preparation, so a same-name
    /// replacement is rejected. This never creates a missing sandbox.
    ///
    /// A newly started attached local run is owned by the returned Sandbox.
    /// Connecting to an existing run acquires no lifecycle ownership; remote
    /// runtimes are independent of this object's lifetime.
    pub async fn get_running(name: &str) -> MicrosandboxResult<Self> {
        let context = crate::context::configured_context();
        Self::ctx(context.as_ref()).get_running(name).await
    }
}

#[cfg(all(test, feature = "cloud"))]
mod tests;

#[cfg(all(test, feature = "local", unix))]
mod local_tests;

impl super::SandboxPage {
    /// Converting provider records retains identity/context without any extra lookup.
    pub(crate) fn from_records(page: crate::context::sandbox::SandboxRecordPage) -> Self {
        Self {
            sandboxes: page
                .sandboxes
                .into_iter()
                .map(Sandbox::from_record)
                .collect(),
            next_cursor: page.next_cursor,
        }
    }
}
