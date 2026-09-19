//! Existing database run rows and kernel peer credentials bind every exchange.

use std::path::PathBuf;
use std::sync::Arc;

use microsandbox_control_client::{
    ClientError, ControlClientError, ControlClientResult, ErrorKind, VerifiedControlConnector,
};
use microsandbox_db::{
    DbReadConnection,
    entity::{run, sandbox},
};
use microsandbox_protocol_client::{BoxFuture, BoxTransport};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, QueryOrder};
#[cfg(windows)]
use std::os::windows::io::AsRawHandle;
use tokio::time::Instant;
#[cfg(windows)]
use windows_sys::Win32::System::Pipes::GetNamedPipeServerProcessId;

use super::super::LocalBackend;
use super::identity::{DatabaseIdentity, ProcessIdentity};
use super::registry::RuntimeKey;
use super::session::ControlSession;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

struct RuntimeOwner {
    database: Arc<DatabaseIdentity>,
    db: DbReadConnection,
    key: RuntimeKey,
    process: ProcessIdentity,
    endpoints: Vec<PathBuf>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl LocalBackend {
    pub(crate) fn invalidate_control_session(&self, sandbox_id: i32) {
        self.control_sessions.invalidate_sandbox(sandbox_id);
    }

    pub(crate) async fn control_session(
        &self,
        name: &str,
    ) -> MicrosandboxResult<Option<ControlSession>> {
        let pools = self.db().await?;
        let database = self
            .control_sessions
            .database()
            .map_err(MicrosandboxError::ControlClient)?;
        let endpoints = crate::runtime::sandbox_agent_socket_path_candidates_for(self, name)
            .iter()
            .map(|path| microsandbox_runtime::control::control_socket_path_for(path))
            .collect::<Vec<_>>();
        // Absence is the existing unsupported-feature signal for older runtimes
        // or VMs with no mutable capacity. An existing but failing peer is not.
        if !endpoints.iter().any(|path| path.exists()) {
            return Ok(None);
        }
        let model = microsandbox_db::catalog::sandbox_query(pools.read())
            .await?
            .filter(sandbox::Column::Name.eq(name))
            .one(pools.read())
            .await?
            .ok_or_else(|| MicrosandboxError::SandboxNotFound(name.into()))?;
        let run = current_run(pools.read(), model.id)
            .await
            .map_err(|error| MicrosandboxError::ControlClient(Arc::new(error)))?;
        let pid = run.pid.ok_or_else(|| {
            MicrosandboxError::ControlClient(Arc::new(ControlClientError::RuntimeChanged))
        })?;
        let process = ProcessIdentity::capture(pid)
            .map_err(|error| MicrosandboxError::ControlClient(Arc::new(error)))?;
        let key = RuntimeKey {
            sandbox_id: model.id,
            run_id: run.id,
            pid,
            start: process.start,
        };
        let owner = Arc::new(RuntimeOwner {
            database,
            db: pools.read().clone(),
            key,
            process,
            endpoints,
        });
        owner
            .verify_session(Instant::now() + std::time::Duration::from_secs(10))
            .await
            .map_err(|error| MicrosandboxError::ControlClient(Arc::new(error)))?;
        self.control_sessions
            .get(key, owner)
            .await
            .map(Some)
            .map_err(MicrosandboxError::ControlClient)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl VerifiedControlConnector for RuntimeOwner {
    fn connect(&self, deadline: Instant) -> BoxFuture<'_, ControlClientResult<BoxTransport>> {
        Box::pin(async move {
            self.verify_session(deadline).await?;
            #[cfg(unix)]
            {
                let mut last_error = None;
                for path in &self.endpoints {
                    match tokio::net::UnixStream::connect(path).await {
                        Ok(stream) => {
                            let pid = stream
                                .peer_cred()
                                .map_err(ClientError::from)?
                                .pid()
                                .ok_or_else(|| ClientError::new(ErrorKind::UnsupportedOperation))?;
                            self.process.verify_peer(pid)?;
                            self.verify_session(deadline).await?;
                            return Ok(Box::new(stream) as BoxTransport);
                        }
                        Err(error)
                            if matches!(
                                error.kind(),
                                std::io::ErrorKind::NotFound
                                    | std::io::ErrorKind::ConnectionRefused
                            ) =>
                        {
                            last_error = Some(error)
                        }
                        Err(error) => return Err(ClientError::from(error).into()),
                    }
                }
                Err(ClientError::from(
                    last_error
                        .unwrap_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound)),
                )
                .into())
            }
            #[cfg(windows)]
            {
                let path = self
                    .endpoints
                    .first()
                    .ok_or_else(|| ClientError::new(ErrorKind::InvalidOptions))?;
                loop {
                    if Instant::now() >= deadline {
                        return Err(ClientError::new(ErrorKind::Timeout).into());
                    }
                    match tokio::net::windows::named_pipe::ClientOptions::new().open(path) {
                        Ok(stream) => {
                            let mut pid = 0;
                            if unsafe {
                                GetNamedPipeServerProcessId(stream.as_raw_handle(), &mut pid)
                            } == 0
                            {
                                return Err(
                                    ClientError::from(std::io::Error::last_os_error()).into()
                                );
                            }
                            self.process.verify_peer(
                                i32::try_from(pid)
                                    .map_err(|_| ControlClientError::RuntimeChanged)?,
                            )?;
                            self.verify_session(deadline).await?;
                            return Ok(Box::new(stream) as BoxTransport);
                        }
                        Err(error) if error.raw_os_error() == Some(231) => {
                            tokio::time::sleep(std::time::Duration::from_millis(10)).await
                        }
                        Err(error) => return Err(ClientError::from(error).into()),
                    }
                }
            }
        })
    }

    fn verify_session(&self, deadline: Instant) -> BoxFuture<'_, ControlClientResult<()>> {
        Box::pin(async move {
            if Instant::now() >= deadline {
                return Err(ClientError::new(ErrorKind::Timeout).into());
            }
            self.database.verify()?;
            self.process.verify()?;
            let run = tokio::time::timeout_at(deadline, current_run(&self.db, self.key.sandbox_id))
                .await
                .map_err(|_| ClientError::new(ErrorKind::Timeout))??;
            if run.id != self.key.run_id || run.pid != Some(self.key.pid) {
                return Err(ControlClientError::RuntimeChanged);
            }
            // Catch replacement while the database read was in flight too.
            self.database.verify()?;
            self.process.verify()
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

async fn current_run(db: &DbReadConnection, sandbox_id: i32) -> ControlClientResult<run::Model> {
    run::Entity::find()
        .inner_join(sandbox::Entity)
        .filter(run::Column::SandboxId.eq(sandbox_id))
        .filter(run::Column::Status.eq(run::RunStatus::Running))
        .filter(sandbox::Column::Status.is_in([
            sandbox::SandboxStatus::Running,
            sandbox::SandboxStatus::Draining,
        ]))
        .order_by_desc(run::Column::Id)
        .one(db)
        .await
        .map_err(database_error)?
        .ok_or(ControlClientError::RuntimeChanged)
}

fn database_error(_: sea_orm::DbErr) -> ControlClientError {
    // Queries can contain runtime data. The public transport error retains the
    // failure category without exposing SQL or prepared secret material.
    ClientError::new(ErrorKind::Io(std::io::ErrorKind::Other)).into()
}
