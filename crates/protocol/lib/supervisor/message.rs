//! Supervisor message inventory and generation availability.

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Known generation-one supervisor message names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, strum::IntoStaticStr, strum::EnumString)]
pub enum SupervisorMessageType {
    /// Opening client offer.
    #[strum(serialize = "supervisor.hello")]
    Hello,
    /// Server setup selection.
    #[strum(serialize = "supervisor.welcome")]
    Welcome,
    /// Structured setup or operation failure.
    #[strum(serialize = "supervisor.error")]
    Error,
    /// Supervisor health query.
    #[strum(serialize = "supervisor.status")]
    Status,
    /// Supervisor health result.
    #[strum(serialize = "supervisor.status.result")]
    StatusResult,
    /// Facility query.
    #[strum(serialize = "supervisor.capabilities")]
    Capabilities,
    /// Facility result.
    #[strum(serialize = "supervisor.capabilities.result")]
    CapabilitiesResult,
    /// Durable catalog watch.
    #[strum(serialize = "supervisor.watch")]
    Watch,
    /// Ordered durable catalog event.
    #[strum(serialize = "supervisor.event")]
    Event,
    /// Terminal catalog watch record.
    #[strum(serialize = "supervisor.watch.end")]
    WatchEnd,
    /// Idempotent request lookup.
    #[strum(serialize = "request.get")]
    RequestGet,
    /// Idempotent request lookup result.
    #[strum(serialize = "request.get.result")]
    RequestGetResult,
    /// Sandbox creation mutation.
    #[strum(serialize = "sandbox.create")]
    SandboxCreate,
    /// Sandbox start mutation.
    #[strum(serialize = "sandbox.start")]
    SandboxStart,
    /// Sandbox graceful-stop mutation.
    #[strum(serialize = "sandbox.stop")]
    SandboxStop,
    /// Sandbox forced-stop mutation.
    #[strum(serialize = "sandbox.kill")]
    SandboxKill,
    /// Sandbox restart mutation.
    #[strum(serialize = "sandbox.restart")]
    SandboxRestart,
    /// Sandbox removal mutation.
    #[strum(serialize = "sandbox.remove")]
    SandboxRemove,
    /// Sandbox modification mutation.
    #[strum(serialize = "sandbox.modify")]
    SandboxModify,
    /// Sandbox inspection query.
    #[strum(serialize = "sandbox.inspect")]
    SandboxInspect,
    /// Sandbox inspection result.
    #[strum(serialize = "sandbox.inspect.result")]
    SandboxInspectResult,
    /// Paginated sandbox list query.
    #[strum(serialize = "sandbox.list")]
    SandboxList,
    /// Paginated sandbox list result.
    #[strum(serialize = "sandbox.list.result")]
    SandboxListResult,
    /// Accepted mutation result.
    #[strum(serialize = "operation.accepted")]
    OperationAccepted,
    /// Operation lookup.
    #[strum(serialize = "operation.get")]
    OperationGet,
    /// Operation lookup result.
    #[strum(serialize = "operation.get.result")]
    OperationGetResult,
    /// Operation watch.
    #[strum(serialize = "operation.watch")]
    OperationWatch,
    /// Operation watch event.
    #[strum(serialize = "operation.event")]
    OperationEvent,
    /// Terminal operation watch record.
    #[strum(serialize = "operation.watch.end")]
    OperationWatchEnd,
    /// Operation cancellation request.
    #[strum(serialize = "operation.cancel")]
    OperationCancel,
    /// Operation retry request.
    #[strum(serialize = "operation.retry")]
    OperationRetry,
    /// Cancel or retry result.
    #[strum(serialize = "operation.action.result")]
    OperationActionResult,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SupervisorMessageType {
    /// Stable wire spelling.
    pub fn as_str(self) -> &'static str {
        self.into()
    }

    /// Resolve a known spelling while leaving extension names open.
    pub fn from_wire_str(name: &str) -> Option<Self> {
        name.parse().ok()
    }
}

/// Generation in which a known supervisor message first became available.
pub fn supervisor_message_min_generation(name: &str) -> Option<u8> {
    SupervisorMessageType::from_wire_str(name).map(|_| 1)
}
