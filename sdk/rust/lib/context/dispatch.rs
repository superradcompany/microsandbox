//! Context dispatch contract.

use std::{sync::Arc, time::Duration};

use futures::future::BoxFuture;

#[cfg(feature = "local")]
use super::LocalContext;
use super::{
    ContextInfo, ContextKind, ContextSelectionSource, SandboxOps, ServiceOps, SnapshotOps,
    VolumeOps,
};
use crate::{
    MicrosandboxResult,
    error::{Operation, UnsupportedReason},
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Top-level routing trait for SDK dispatch. Implementations route to
/// resource-specific sub-traits (sandboxes, volumes, snapshots, services) via
/// accessor methods.
///
/// Object-safe — handles hold an `Arc<dyn Context>`. Every implementation must
/// explicitly provide each resource-specific backend so that missing
/// capabilities are caught at compile time.
pub trait Context: Send + Sync + 'static {
    /// Retain this destination and its shared implementation state.
    /// Cloning must not re-resolve configuration or open an independent catalog.
    fn clone_shared(&self) -> Arc<dyn Context>;

    /// Bind sandbox operations to this context without performing I/O.
    fn sandboxes(&self) -> super::Sandboxes {
        super::Sandboxes {
            context: self.clone_shared(),
        }
    }

    /// Bind volume operations to this context without performing I/O.
    fn volumes(&self) -> super::Volumes {
        super::Volumes {
            context: self.clone_shared(),
        }
    }

    /// Bind snapshot operations to this context without performing I/O.
    fn snapshots(&self) -> super::Snapshots {
        super::Snapshots {
            context: self.clone_shared(),
        }
    }

    /// Bind individual checkpoint operations to this context without performing I/O.
    fn checkpoints(&self) -> super::Checkpoints {
        super::Checkpoints {
            context: self.clone_shared(),
        }
    }

    /// Return the kind of backend this is (`Local` or `Remote`).
    fn kind(&self) -> ContextKind;

    /// Return a secret-safe description of this backend.
    /// Returns an error if backend resolution failed, rather than reporting a usable backend.
    fn info(&self) -> crate::MicrosandboxResult<ContextInfo> {
        Ok(ContextInfo {
            kind: self.kind(),
            api_url: None,
            source: ContextSelectionSource::Programmatic,
            profile: None,
        })
    }

    /// Return the sandbox lifecycle backend.
    fn sandbox_ops(&self) -> &dyn SandboxOps;

    /// Return the volume lifecycle backend.
    fn volume_ops(&self) -> &dyn VolumeOps;

    /// Return the snapshot lifecycle backend.
    fn snapshot_ops(&self) -> &dyn SnapshotOps;

    /// Operations for Services in this destination.
    fn service_ops(&self) -> &dyn ServiceOps;

    /// Try downcast to a concrete `&LocalContext` when in a local context.
    ///
    /// Used by helpers that need access to local-only state (DB pool, config
    /// paths) without keeping a separate `Arc<LocalContext>` alongside the
    /// `Arc<dyn Context>`. Returns `None` for cloud backends.
    #[cfg(feature = "local")]
    fn as_local(&self) -> Option<&LocalContext> {
        None
    }

    /// Borrow a cloud backend and its captured device settings.
    #[cfg(feature = "cloud")]
    fn as_cloud(&self) -> Option<&super::RemoteContext> {
        None
    }

    /// Bind agent connections to the sandbox identity captured by a cloud object.
    /// Backends without cloud identities leave the backend unchanged.
    #[doc(hidden)]
    fn with_agent_identity(&self, _name: &str, _id: &str) -> Option<Arc<dyn Context>> {
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
