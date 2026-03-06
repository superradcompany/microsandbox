//! Sandbox lifecycle management.
//!
//! The [`Sandbox`] struct represents a running sandbox. It is created via
//! [`Sandbox::builder`] or [`Sandbox::create`], and provides lifecycle
//! methods (stop, kill, drain, wait) and access to the [`AgentBridge`]
//! for guest communication.

mod builder;
mod config;
mod types;

use std::process::ExitStatus;
use std::sync::Arc;

use microsandbox_protocol::message::{Message, MessageType};
use sea_orm::{
    ActiveModelTrait, ColumnTrait, EntityTrait, IntoActiveModel, QueryFilter, QueryOrder, Set,
};
use sea_orm::sea_query::{Expr, OnConflict};
use tokio::sync::Mutex;

use crate::agent::AgentBridge;
use crate::db::entity::sandbox as sandbox_entity;
use crate::runtime::{SupervisorHandle, spawn_supervisor};
use crate::MicrosandboxResult;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use builder::SandboxBuilder;
pub use config::SandboxConfig;
pub use types::*;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A running sandbox.
///
/// Created via [`Sandbox::builder`] or [`Sandbox::create`]. Provides
/// lifecycle management and access to the agent bridge for guest communication.
pub struct Sandbox {
    config: SandboxConfig,
    handle: Arc<Mutex<SupervisorHandle>>,
    bridge: Arc<AgentBridge>,
}

/// Summary information about a sandbox (re-exported from entity model).
pub type SandboxInfo = sandbox_entity::Model;

//--------------------------------------------------------------------------------------------------
// Methods: Static
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Create a builder for a new sandbox.
    pub fn builder(name: impl Into<String>) -> SandboxBuilder {
        SandboxBuilder::new(name)
    }

    /// Create a sandbox from a config.
    ///
    /// Boots the VM with agentd ready to accept commands. Does not run
    /// any user workload — use `exec()`, `shell()`, etc. afterward.
    pub async fn create(config: SandboxConfig) -> MicrosandboxResult<Self> {
        // Initialize the database.
        let db = crate::db::init_global(
            Some(crate::config::config().database.max_connections),
        ).await?;

        // Upsert sandbox record.
        upsert_sandbox_record(db, &config).await?;

        // Spawn supervisor + create bridge. On failure, mark the sandbox
        // as stopped so it doesn't appear as a phantom "Running" entry.
        match Self::create_inner(&config).await {
            Ok(sandbox) => Ok(sandbox),
            Err(e) => {
                let _ = update_sandbox_status(db, &config.name, "Stopped").await;
                Err(e)
            }
        }
    }

    /// Inner create logic separated for error-cleanup wrapper.
    async fn create_inner(config: &SandboxConfig) -> MicrosandboxResult<Self> {
        let (handle, agent_host_fd) = spawn_supervisor(config).await?;
        let bridge = AgentBridge::new(agent_host_fd)?;
        bridge.wait_ready().await?;

        Ok(Self {
            config: config.clone(),
            handle: Arc::new(Mutex::new(handle)),
            bridge: Arc::new(bridge),
        })
    }

    /// Get sandbox info by name from the database.
    pub async fn get(name: &str) -> MicrosandboxResult<SandboxInfo> {
        let db = crate::db::init_global(
            Some(crate::config::config().database.max_connections),
        ).await?;

        sandbox_entity::Entity::find()
            .filter(sandbox_entity::Column::Name.eq(name))
            .one(db)
            .await?
            .ok_or_else(|| crate::MicrosandboxError::SandboxNotFound(name.into()))
    }

    /// List all sandboxes from the database.
    pub async fn list() -> MicrosandboxResult<Vec<SandboxInfo>> {
        let db = crate::db::init_global(
            Some(crate::config::config().database.max_connections),
        ).await?;

        sandbox_entity::Entity::find()
            .order_by_desc(sandbox_entity::Column::CreatedAt)
            .all(db)
            .await
            .map_err(Into::into)
    }

    /// Remove a stopped sandbox from the database.
    pub async fn remove(name: &str) -> MicrosandboxResult<()> {
        // Check if the sandbox exists and its status.
        let model = Self::get(name).await?;
        if model.status == "Running" {
            return Err(crate::MicrosandboxError::SandboxNotRunning(
                format!("cannot remove sandbox '{name}': still running"),
            ));
        }

        let db = crate::db::init_global(
            Some(crate::config::config().database.max_connections),
        ).await?;

        model.into_active_model().delete(db).await?;

        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Instance
//--------------------------------------------------------------------------------------------------

impl Sandbox {
    /// Get the sandbox name.
    pub fn name(&self) -> &str {
        &self.config.name
    }

    /// Get the sandbox configuration.
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Get the agent bridge for low-level communication with agentd.
    pub fn bridge(&self) -> &AgentBridge {
        &self.bridge
    }

    /// Stop the sandbox gracefully by sending `core.shutdown` to agentd.
    pub async fn stop(&self) -> MicrosandboxResult<()> {
        let msg = Message::new(MessageType::Shutdown, 0, Vec::new());
        self.bridge.send(&msg).await
    }

    /// Kill the sandbox immediately (SIGKILL to VM process).
    pub async fn kill(&self) -> MicrosandboxResult<()> {
        self.handle.lock().await.kill_vm()
    }

    /// Trigger a graceful drain (SIGUSR1 to supervisor).
    pub async fn drain(&self) -> MicrosandboxResult<()> {
        self.handle.lock().await.drain_supervisor()
    }

    /// Wait for the supervisor process to exit.
    ///
    /// Updates the sandbox status in the database to `Stopped` after exit.
    pub async fn wait(&self) -> MicrosandboxResult<ExitStatus> {
        let status = self.handle.lock().await.wait().await?;

        // Update the DB status now that the supervisor has exited.
        if let Ok(db) = crate::db::init_global(
            Some(crate::config::config().database.max_connections),
        ).await {
            let _ = update_sandbox_status(db, &self.config.name, "Stopped").await;
        }

        Ok(status)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

/// Update the sandbox status in the database.
async fn update_sandbox_status(
    db: &sea_orm::DatabaseConnection,
    name: &str,
    status: &str,
) -> MicrosandboxResult<()> {
    sandbox_entity::Entity::update_many()
        .col_expr(sandbox_entity::Column::Status, Expr::value(status))
        .col_expr(
            sandbox_entity::Column::UpdatedAt,
            Expr::value(chrono::Utc::now().naive_utc()),
        )
        .filter(sandbox_entity::Column::Name.eq(name))
        .exec(db)
        .await?;

    Ok(())
}

/// Insert or update the sandbox record in the database.
async fn upsert_sandbox_record(
    db: &sea_orm::DatabaseConnection,
    config: &SandboxConfig,
) -> MicrosandboxResult<()> {
    let now = chrono::Utc::now().naive_utc();
    let config_json = serde_json::to_string(config)?;

    let model = sandbox_entity::ActiveModel {
        name: Set(config.name.clone()),
        config: Set(config_json),
        status: Set("Running".to_string()),
        created_at: Set(Some(now)),
        updated_at: Set(Some(now)),
        ..Default::default()
    };

    sandbox_entity::Entity::insert(model)
        .on_conflict(
            OnConflict::column(sandbox_entity::Column::Name)
                .update_columns([
                    sandbox_entity::Column::Status,
                    sandbox_entity::Column::Config,
                    sandbox_entity::Column::UpdatedAt,
                ])
                .to_owned(),
        )
        .exec(db)
        .await?;

    Ok(())
}
