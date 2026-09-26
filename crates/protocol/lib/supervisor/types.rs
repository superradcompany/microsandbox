//! Stable supervisor identifiers and operation records.

use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer, de};

//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------

macro_rules! fixed_bytes {
    ($(#[$meta:meta])* $name:ident, $size:expr) => {
        $(#[$meta])*
        #[derive(Clone, Copy, PartialEq, Eq, Hash)]
        pub struct $name(pub [u8; $size]);

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.debug_tuple(stringify!($name)).field(&self.0).finish()
            }
        }

        impl Serialize for $name {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_bytes(&self.0)
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let bytes: serde_bytes::ByteBuf = Deserialize::deserialize(deserializer)?;
                let value: [u8; $size] = bytes
                    .as_ref()
                    .try_into()
                    .map_err(|_| de::Error::invalid_length(bytes.len(), &$size.to_string().as_str()))?;
                Ok(Self(value))
            }
        }
    };
}

//--------------------------------------------------------------------------------------------------
// Types: Identities
//--------------------------------------------------------------------------------------------------

fixed_bytes!(/// One SDK or CLI process participating in setup diagnostics.
    ClientInstanceId, 16);
fixed_bytes!(/// One running supervisor process, replaced on every restart.
    SupervisorInstanceId, 16);
fixed_bytes!(/// Stable lineage identity retained across runtime restarts.
    SandboxLineageId, 16);
fixed_bytes!(/// Identity of one concrete runtime boot.
    RuntimeBootId, 16);
fixed_bytes!(/// Idempotency identity of one mutating supervisor request.
    SupervisorRequestId, 16);
fixed_bytes!(/// Durable asynchronous supervisor operation identity.
    OperationId, 16);
fixed_bytes!(/// Digest of one canonical microsandbox home path.
    HomeDigest, 32);

/// Empty map payload used by parameterless requests.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Empty {}

/// Versioned canonical CBOR document owned by a higher-level SDK schema.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionedDocument {
    /// Schema generation understood by the producer.
    pub schema_generation: u32,
    /// Canonical CBOR bytes; the supervisor stores and hashes these bytes exactly.
    #[serde(with = "serde_bytes")]
    pub cbor: Vec<u8>,
}

/// Stable sandbox selector with an explicit, extensible discriminator.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SandboxLocator {
    /// Select by preferred immutable lineage identity.
    Lineage {
        /// Stable lineage identity.
        lineage_id: SandboxLineageId,
    },
    /// Select by a human-readable name within the canonical home.
    Name {
        /// Cataloged sandbox name.
        name: String,
    },
}

/// Idempotent mutation wrapper shared by lifecycle operations.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Mutation<T> {
    /// UUIDv7 request identity retained for request lookup and replay detection.
    pub supervisor_request_id: SupervisorRequestId,
    /// Optional optimistic-concurrency guard over the durable catalog.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expected_catalog_revision: Option<u64>,
    /// Canonical intent whose fingerprint must remain stable for this request ID.
    pub intent: T,
}

/// Requested durable sandbox state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DesiredSandboxState {
    /// The sandbox should not have a running runtime.
    Stopped,
    /// The sandbox should have a running runtime.
    Running,
    /// The sandbox and its owned state should be removed.
    Removed,
}

/// Last supervisor observation of a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ObservedSandboxState {
    /// No durable or runtime state exists.
    Absent,
    /// Durable sandbox creation is underway.
    Creating,
    /// Runtime launch is underway.
    Starting,
    /// A runtime is alive and controllable.
    Running,
    /// Graceful shutdown is underway.
    Stopping,
    /// Durable state exists without a running runtime.
    Stopped,
    /// Reconciliation stopped after a durable failure.
    Failed,
    /// Durable removal is underway.
    Removing,
}

/// Durable asynchronous operation state.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationState {
    /// Accepted but not yet executing.
    Pending,
    /// Execution or reconciliation is underway.
    Running,
    /// The requested durable outcome was reached.
    Succeeded,
    /// Execution ended with a durable failure record.
    Failed,
    /// Cancellation was accepted before successful completion.
    Cancelled,
}

/// Retry classification attached to structured supervisor failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RetryClass {
    /// Repeating the request cannot fix the condition.
    Never,
    /// The same idempotent request may succeed after a delay.
    Transient,
    /// Caller action or changed input is required.
    AfterCorrection,
}

/// Structured supervisor failure returned during setup or an operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorError {
    /// Stable machine-readable code.
    pub code: String,
    /// Sanitized human-readable diagnostic.
    pub message: String,
    /// Whether and how the same request may be attempted again.
    pub retry_class: RetryClass,
    /// Optional canonical CBOR details for code-specific diagnostics.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "serde_bytes")]
    pub details: Vec<u8>,
}

/// Supervisor health and durable catalog position.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorStatus {
    /// Identity of this running process.
    pub supervisor_instance_id: SupervisorInstanceId,
    /// Current committed catalog revision.
    pub catalog_revision: u64,
    /// Number of cataloged sandboxes.
    pub sandbox_count: u64,
    /// Number of runtime processes currently observed alive.
    pub running_count: u64,
    /// Whether startup reconciliation has completed.
    pub reconciled: bool,
}

/// Facilities implemented by the connected supervisor generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorCapabilities {
    /// Durable idempotent lifecycle operations are supported.
    pub lifecycle_operations: bool,
    /// Catalog and operation watch streams are supported.
    pub watches: bool,
    /// Sandbox modification is supported.
    pub sandbox_modify: bool,
    /// Per-sandbox jail launch is supported.
    pub jailer: bool,
}

/// One sandbox projection returned by inspect, list, and events.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxRecord {
    /// Stable lineage identity.
    pub lineage_id: SandboxLineageId,
    /// Name within the canonical home.
    pub name: String,
    /// Requested durable state.
    pub desired_state: DesiredSandboxState,
    /// Last observed state.
    pub observed_state: ObservedSandboxState,
    /// Current runtime boot, when one is alive or still being reconciled.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_boot_id: Option<RuntimeBootId>,
    /// Catalog revision that last changed this record.
    pub catalog_revision: u64,
}

/// One asynchronous operation projection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationRecord {
    /// Stable operation identity.
    pub operation_id: OperationId,
    /// Idempotency identity of the originating request.
    pub supervisor_request_id: SupervisorRequestId,
    /// Current durable state.
    pub state: OperationState,
    /// Target sandbox, when the operation is sandbox-scoped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxLineageId>,
    /// Failure retained when the operation ended unsuccessfully.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<SupervisorError>,
    /// Catalog revision containing this projection.
    pub catalog_revision: u64,
}

/// Durable lookup result for an idempotent request.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RequestRecord {
    /// Queried request identity.
    pub supervisor_request_id: SupervisorRequestId,
    /// Canonical intent fingerprint used to reject mismatched reuse.
    #[serde(with = "serde_bytes")]
    pub intent_fingerprint: Vec<u8>,
    /// Operation created by the request.
    pub operation: OperationRecord,
}

/// Acceptance response returned before asynchronous convergence.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationAccepted {
    /// Existing or newly created durable operation identity.
    pub operation_id: OperationId,
    /// Request identity used for idempotent lookup.
    pub supervisor_request_id: SupervisorRequestId,
    /// Catalog revision that committed acceptance.
    pub catalog_revision: u64,
    /// True when an identical earlier request was replayed.
    pub replayed: bool,
}

/// Sandbox creation intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateSandboxIntent {
    /// Name to reserve within the canonical home.
    pub name: String,
    /// Portable SDK-owned sandbox specification.
    pub spec: VersionedDocument,
    /// Named launch isolation profile.
    pub isolation_profile: String,
}

/// Sandbox lifecycle intent for start, stop, kill, restart, or remove.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxActionIntent {
    /// Target sandbox.
    pub sandbox: SandboxLocator,
}

/// Sandbox modification intent.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModifySandboxIntent {
    /// Target sandbox.
    pub sandbox: SandboxLocator,
    /// Portable SDK-owned modification patch.
    pub patch: VersionedDocument,
}

/// Request lookup parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct GetRequest {
    /// Idempotency identity to query.
    pub supervisor_request_id: SupervisorRequestId,
}

/// Sandbox inspection parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InspectSandbox {
    /// Target sandbox.
    pub sandbox: SandboxLocator,
}

/// Paginated sandbox list parameters.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListSandboxes {
    /// Maximum records requested from this page.
    pub limit: u32,
    /// Opaque cursor from a prior page.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "serde_bytes")]
    pub cursor: Vec<u8>,
}

/// Paginated sandbox list result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxList {
    /// Snapshot revision shared by this page.
    pub catalog_revision: u64,
    /// Sandbox projections.
    pub sandboxes: Vec<SandboxRecord>,
    /// Opaque next cursor; empty means the page is final.
    #[serde(default, skip_serializing_if = "Vec::is_empty", with = "serde_bytes")]
    pub next_cursor: Vec<u8>,
}

/// Operation lookup, watch, cancel, or retry parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperationSelector {
    /// Durable operation identity.
    pub operation_id: OperationId,
}

/// Catalog watch parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchCatalog {
    /// First revision the client has not consumed.
    pub from_revision: u64,
}

/// One ordered catalog event.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CatalogEvent {
    /// Strictly increasing catalog revision.
    pub catalog_revision: u64,
    /// Changed sandbox projection, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox: Option<SandboxRecord>,
    /// Changed operation projection, when applicable.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operation: Option<OperationRecord>,
}

/// Terminal reason for a catalog or operation watch.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WatchEnd {
    /// Stable reason such as `caught_up`, `compacted`, or `shutdown`.
    pub reason: String,
    /// Last revision emitted before termination.
    pub last_catalog_revision: u64,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SupervisorRequestId {
    /// Whether the bytes carry an RFC 9562 UUIDv7 version and variant.
    pub fn is_uuid_v7(self) -> bool {
        self.0[6] >> 4 == 7 && self.0[8] >> 6 == 2
    }
}

impl<T> Mutation<T> {
    /// Validate invariants shared by every mutating supervisor request.
    pub fn validate(&self) -> bool {
        self.supervisor_request_id.is_uuid_v7()
    }
}
