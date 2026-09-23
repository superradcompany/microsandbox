//! Identity continuity is supplied by the runtime owner, never inferred from a path.

use std::sync::Arc;

use microsandbox_protocol_client::{BoxFuture, BoxTransport, Connector};
use tokio::time::Instant;

use crate::ControlClientResult;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// A connector that binds every returned stream to one verified runtime.
///
/// Implementations must verify the connected peer's process identity and stable
/// OS birth token on every dial, not merely check a PID or endpoint path. The
/// backend owns database/run identity and keeps any required OS process handles.
pub trait VerifiedControlConnector: Send + Sync {
    /// Open a stream and verify its connected peer before returning ownership.
    /// Peer replacement is `RuntimeChanged`, distinct from a transport failure.
    fn connect(&self, deadline: Instant) -> BoxFuture<'_, ControlClientResult<BoxTransport>>;

    /// Recheck the active run and process identity immediately before admitting
    /// an operation. Return `RuntimeChanged` if continuity no longer holds.
    fn verify_session(&self, deadline: Instant) -> BoxFuture<'_, ControlClientResult<()>>;
}

#[derive(Clone)]
pub(crate) enum Dialer {
    Unverified(Arc<dyn Connector>),
    Verified(Arc<dyn VerifiedControlConnector>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Dialer {
    pub(crate) fn verified(&self) -> bool {
        matches!(self, Self::Verified(_))
    }

    pub(crate) async fn connect(&self, deadline: Instant) -> ControlClientResult<BoxTransport> {
        Ok(match self {
            Self::Unverified(connector) => connector.connect(deadline).await?,
            Self::Verified(connector) => connector.connect(deadline).await?,
        })
    }

    pub(crate) async fn verify(&self, deadline: Instant) -> ControlClientResult<()> {
        match self {
            Self::Unverified(_) => Ok(()),
            Self::Verified(connector) => connector.verify_session(deadline).await,
        }
    }
}
