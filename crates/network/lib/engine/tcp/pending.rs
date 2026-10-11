//! Cancelable host TCP dial held by a paused guest socket.

use std::io;
use std::sync::Arc;

use tokio::net::TcpStream;
use tokio::sync::oneshot;
use tokio::task::JoinHandle;

use super::upstream::UpstreamTcpTarget;
use crate::netstack::shared::SharedState;
use crate::proxy::ResolvedOutboundProxy;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Owns a host dial; dropping it cancels the task and releases any returned socket.
pub(crate) struct PendingConnect {
    /// Completed socket or dial error, transferred once to the connection tracker.
    result: oneshot::Receiver<io::Result<TcpStream>>,
    task: JoinHandle<()>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PendingConnect {
    /// Dial the policy-approved `target` on `runtime`, then wake the network loop.
    /// `proxy` selects an outbound tunnel; `None` uses a direct host connection.
    pub(crate) fn start(
        target: UpstreamTcpTarget,
        proxy: Option<Arc<ResolvedOutboundProxy>>,
        shared: Arc<SharedState>,
        runtime: &tokio::runtime::Handle,
    ) -> Self {
        let (sender, result) = oneshot::channel();
        let task = runtime.spawn(async move {
            let result = target.open(proxy.as_deref()).await;
            let _ = sender.send(result);
            shared.proxy_wake.wake();
        });
        Self { result, task }
    }

    /// Take the dial outcome without blocking; `None` means it is still pending.
    pub(crate) fn take_result(&mut self) -> Option<io::Result<TcpStream>> {
        match self.result.try_recv() {
            Ok(result) => Some(result),
            Err(oneshot::error::TryRecvError::Empty) => None,
            Err(oneshot::error::TryRecvError::Closed) => {
                Some(Err(io::Error::other("upstream connect task exited")))
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for PendingConnect {
    fn drop(&mut self) {
        self.task.abort();
    }
}
