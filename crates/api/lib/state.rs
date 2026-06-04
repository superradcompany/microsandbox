//! Shared API server state.

use std::{collections::HashMap, path::PathBuf, sync::Arc};

use tokio::sync::RwLock;
use uuid::Uuid;

use crate::store::ExecutionStore;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Shared API state.
#[derive(Clone)]
pub struct ApiState {
    /// Execution store.
    pub store: ExecutionStore,

    /// Live execution controls.
    pub live: Arc<RwLock<LiveExecutionRegistry>>,
}

/// Process-local live execution registry.
#[derive(Default)]
pub struct LiveExecutionRegistry {
    controls: HashMap<(String, String), microsandbox::ExecControl>,
    stdins: HashMap<(String, String), Arc<microsandbox::sandbox::exec::ExecSink>>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ApiState {
    /// Create API state.
    pub async fn new(api_db_path: PathBuf) -> anyhow::Result<Self> {
        let store = ExecutionStore::open(api_db_path).await?;
        store.reconcile_incomplete_on_startup().await?;
        Ok(Self {
            store,
            live: Arc::new(RwLock::new(LiveExecutionRegistry::default())),
        })
    }

    /// Create test state with a temporary database.
    pub async fn for_test() -> anyhow::Result<Self> {
        Self::new(temp_db_path()).await
    }
}

impl LiveExecutionRegistry {
    /// Insert a live execution control handle.
    pub fn insert_control(
        &mut self,
        devbox_id: String,
        execution_id: String,
        control: microsandbox::ExecControl,
    ) {
        self.controls.insert((devbox_id, execution_id), control);
    }

    /// Insert a live stdin sink.
    pub fn insert_stdin(
        &mut self,
        devbox_id: String,
        execution_id: String,
        stdin: microsandbox::sandbox::exec::ExecSink,
    ) {
        self.stdins
            .insert((devbox_id, execution_id), Arc::new(stdin));
    }

    /// Return a cloneable live execution control handle.
    pub fn control(
        &self,
        devbox_id: &str,
        execution_id: &str,
    ) -> Option<microsandbox::ExecControl> {
        self.controls
            .get(&(devbox_id.to_string(), execution_id.to_string()))
            .cloned()
    }

    /// Return a live stdin sink.
    pub fn stdin(
        &self,
        devbox_id: &str,
        execution_id: &str,
    ) -> Option<Arc<microsandbox::sandbox::exec::ExecSink>> {
        self.stdins
            .get(&(devbox_id.to_string(), execution_id.to_string()))
            .cloned()
    }

    /// Remove live execution handles.
    pub fn remove(&mut self, devbox_id: &str, execution_id: &str) {
        let key = (devbox_id.to_string(), execution_id.to_string());
        self.controls.remove(&key);
        self.stdins.remove(&key);
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for ApiState {
    fn default() -> Self {
        build_default_state()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn temp_db_path() -> PathBuf {
    std::env::temp_dir().join(format!("microsandbox-api-{}.sqlite", Uuid::new_v4()))
}

fn build_default_state() -> ApiState {
    let path = temp_db_path();
    std::thread::spawn(move || {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("create API state runtime");
        runtime.block_on(ApiState::new(path))
    })
    .join()
    .expect("join API state initialization thread")
    .expect("create default API state")
}
