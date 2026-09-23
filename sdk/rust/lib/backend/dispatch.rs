//! Backend dispatch contract.

use std::{sync::Arc, time::Duration};

use futures::future::BoxFuture;

#[cfg(feature = "local")]
use super::LocalBackend;
use super::{
    BackendInfo, BackendKind, BackendSelectionSource, SandboxBackend, SnapshotBackend,
    VolumeBackend,
};
use crate::{
    MicrosandboxResult,
    error::{Operation, UnsupportedReason},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Top-level routing trait for SDK dispatch. Implementations route to
/// resource-specific sub-traits (sandboxes, volumes, snapshots) via accessor
/// methods.
///
/// Object-safe — handles hold an `Arc<dyn Backend>`. Every implementation must
/// explicitly provide each resource-specific backend so that missing
/// capabilities are caught at compile time.
pub trait Backend: Send + Sync + 'static {
    /// Return the kind of backend this is (`Local` or `Cloud`).
    fn kind(&self) -> BackendKind;

    /// Return a secret-safe description of this backend.
    fn info(&self) -> BackendInfo {
        BackendInfo {
            kind: self.kind(),
            api_url: None,
            source: BackendSelectionSource::Programmatic,
            profile: None,
        }
    }

    /// Return the sandbox lifecycle backend.
    fn sandboxes(&self) -> &dyn SandboxBackend;

    /// Return the volume lifecycle backend.
    fn volumes(&self) -> &dyn VolumeBackend;

    /// Return the snapshot lifecycle backend.
    fn snapshots(&self) -> &dyn SnapshotBackend;

    /// Try downcast to a concrete `&LocalBackend` when in a local context.
    ///
    /// Used by helpers that need access to local-only state (DB pool, config
    /// paths) without keeping a separate `Arc<LocalBackend>` alongside the
    /// `Arc<dyn Backend>`. Returns `None` for cloud backends.
    #[cfg(feature = "local")]
    fn as_local(&self) -> Option<&LocalBackend> {
        None
    }

    /// Borrow a cloud backend and its captured device settings.
    #[cfg(feature = "cloud")]
    fn as_cloud(&self) -> Option<&super::CloudBackend> {
        None
    }

    /// Bind agent connections to the sandbox identity captured by a cloud object.
    /// Backends without cloud identities leave the backend unchanged.
    #[doc(hidden)]
    fn with_agent_identity(&self, _name: &str, _id: &str) -> Option<Arc<dyn Backend>> {
        None
    }

    /// Open a fresh agent connection to the named sandbox with an explicit
    /// handshake timeout. Local dials the relay socket; cloud dials the
    /// sandbox's agent WebSocket route.
    /// Exec, attach, and guest-filesystem operations route through this
    /// connection. The default errors as unsupported for backends that
    /// cannot reach a sandbox agent.
    fn dial_agent<'a>(
        &'a self,
        _name: &'a str,
        _timeout: Duration,
    ) -> BoxFuture<'a, MicrosandboxResult<crate::agent::AgentClient>> {
        Box::pin(async {
            Err(crate::MicrosandboxError::unsupported(
                Operation::AgentConnect,
                UnsupportedReason::NotAvailable(
                    "this backend does not provide agent connectivity".into(),
                ),
            ))
        })
    }
}
