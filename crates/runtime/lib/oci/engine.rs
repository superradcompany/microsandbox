//! Engine boundary between OCI commands and Microsandbox VM execution.

use std::future::Future;
use std::pin::Pin;

use super::{OciBundle, OciProcess, OciResult, OciState};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Boxed future returned by OCI engine operations.
pub type OciEngineFuture<'a, T> = Pin<Box<dyn Future<Output = OciResult<T>> + Send + 'a>>;

/// Request to create a Microsandbox-backed OCI container.
#[derive(Debug, Clone)]
pub struct CreateRequest {
    /// OCI container ID.
    pub id: String,

    /// Parsed OCI bundle.
    pub bundle: OciBundle,

    /// Container-specific state directory.
    pub state_dir: std::path::PathBuf,
}

/// Response from creating a Microsandbox-backed OCI container.
#[derive(Debug, Clone)]
pub struct CreateResponse {
    /// Durable OCI state after create.
    pub state: OciState,
}

/// Response from starting an OCI init process.
#[derive(Debug, Clone)]
pub struct StartResponse {
    /// Host PID for the Microsandbox VMM/sandbox process.
    pub host_pid: i32,

    /// Guest PID for the OCI init process, if agentd reports it.
    pub guest_pid: Option<u32>,
}

/// Request to execute an additional OCI process.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    /// OCI container ID.
    pub id: String,

    /// Process descriptor supplied by Docker/containerd.
    pub process: OciProcess,
}

/// Response from executing an additional process.
#[derive(Debug, Clone)]
pub struct ExecResponse {
    /// Guest PID for the exec process.
    pub guest_pid: Option<u32>,
}

/// Request to send a signal to a container.
#[derive(Debug, Clone)]
pub struct SignalRequest {
    /// OCI container ID.
    pub id: String,

    /// POSIX signal number.
    pub signal: i32,

    /// Whether to signal all processes in the container.
    pub all: bool,
}

/// Execution engine used by the OCI runtime layer.
///
/// A standalone OCI binary should implement this trait with Microsandbox's
/// local SDK/runtime backend. A containerd shim can implement the same trait
/// while keeping task-service ownership in the shim process.
pub trait MicrosandboxOciEngine {
    /// Create the VM environment, rootfs attachments, agent channel, and durable sandbox row.
    fn create<'a>(&'a self, request: CreateRequest) -> OciEngineFuture<'a, CreateResponse>;

    /// Start the configured OCI init process inside an already-created VM environment.
    fn start<'a>(&'a self, state: &'a OciState) -> OciEngineFuture<'a, StartResponse>;

    /// Execute an additional process inside a running container.
    fn exec<'a>(&'a self, request: ExecRequest) -> OciEngineFuture<'a, ExecResponse>;

    /// Send a signal to the OCI init process or all guest processes.
    fn signal<'a>(&'a self, request: SignalRequest) -> OciEngineFuture<'a, ()>;

    /// Tear down resources created by `create`.
    fn delete<'a>(&'a self, state: &'a OciState) -> OciEngineFuture<'a, ()>;

    /// Pause the VM or guest workload.
    fn pause<'a>(&'a self, state: &'a OciState) -> OciEngineFuture<'a, ()>;

    /// Resume the VM or guest workload.
    fn resume<'a>(&'a self, state: &'a OciState) -> OciEngineFuture<'a, ()>;
}
