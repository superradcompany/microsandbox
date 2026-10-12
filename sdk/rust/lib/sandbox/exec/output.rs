//! Return output capacity when the caller consumes an event, independently of stdin.

use std::sync::Weak;

use microsandbox_protocol::{
    exec::{EXEC_OUTPUT_EVENT_OVERHEAD, ExecOutputCredit},
    message::MessageType,
};
use tokio::sync::{mpsc, watch};

use crate::{MicrosandboxResult, agent::AgentClient, backend::Backend, config::ExecConfig};

use super::ExecEvent;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) struct EventReceiver {
    events: mpsc::UnboundedReceiver<ExecEvent>,
    consumed: Option<watch::Sender<u64>>,
}

pub(super) struct OutputCredits {
    pub(super) consumed: watch::Sender<u64>,
    pub(super) updates: watch::Receiver<u64>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl EventReceiver {
    pub(crate) async fn recv(&mut self) -> Option<ExecEvent> {
        let event = self.events.recv().await?;
        if let Some(consumed) = &self.consumed {
            consume(consumed, &event);
        }
        Some(event)
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Drop for EventReceiver {
    fn drop(&mut self) {
        // Stop new deliveries before returning capacity for every queued event.
        self.events.close();
        if let Some(consumed) = &self.consumed {
            while let Ok(event) = self.events.try_recv() {
                consume(consumed, &event);
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn configuration(backend: &dyn Backend) -> MicrosandboxResult<ExecConfig> {
    #[cfg(feature = "local")]
    if let Some(local) = backend.as_local() {
        let config = local.config().exec.clone();
        config.validate()?;
        return Ok(config);
    }
    #[cfg(feature = "cloud")]
    if let Some(cloud) = backend.as_cloud() {
        let config = cloud.config_sources().resolved_config().exec.clone();
        config.validate()?;
        return Ok(config);
    }
    let _ = backend;
    Ok(ExecConfig::default())
}

pub(super) fn receiver(
    events: mpsc::UnboundedReceiver<ExecEvent>,
    controlled: bool,
) -> (EventReceiver, Option<OutputCredits>) {
    let (consumed, credits) = if controlled {
        let (tx, rx) = watch::channel(0);
        (
            Some(tx.clone()),
            Some(OutputCredits {
                consumed: tx,
                updates: rx,
            }),
        )
    } else {
        (None, None)
    };
    (EventReceiver { events, consumed }, credits)
}

/// Return capacity for output read by the caller or discarded after its reader is dropped.
pub(super) fn consume(consumed: &watch::Sender<u64>, event: &ExecEvent) {
    let bytes = match event {
        ExecEvent::Stdout(data) | ExecEvent::Stderr(data) => {
            data.len() as u64 + u64::from(EXEC_OUTPUT_EVENT_OVERHEAD)
        }
        _ => 0,
    };
    if bytes != 0 {
        consumed.send_modify(|offset| *offset += bytes);
    }
}

/// Coalesce read notifications into cumulative credit; never enqueue one task per chunk.
pub(super) async fn return_credit(
    credits: Option<watch::Receiver<u64>>,
    client: Weak<AgentClient>,
    id: u32,
) -> Result<(), String> {
    let Some(mut credits) = credits else {
        return std::future::pending().await;
    };
    while credits.changed().await.is_ok() {
        let consumed = *credits.borrow_and_update();
        let client = client.upgrade().ok_or("exec connection closed")?;
        client
            .send(
                id,
                MessageType::ExecOutputCredit,
                &ExecOutputCredit { consumed },
            )
            .await
            .map_err(|error| error.to_string())?;
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    #[tokio::test]
    async fn unread_output_returns_no_credit_and_reads_coalesce() {
        let (tx, rx) = mpsc::unbounded_channel();
        let (mut events, credits) = receiver(rx, true);
        let mut credits = credits.unwrap().updates;
        tx.send(ExecEvent::Started { pid: 1 }).unwrap();
        tx.send(ExecEvent::Stdout(Bytes::from_static(b"abc")))
            .unwrap();
        tx.send(ExecEvent::Stderr(Bytes::from_static(b"defg")))
            .unwrap();
        assert!(!credits.has_changed().unwrap());
        events.recv().await.unwrap();
        assert!(!credits.has_changed().unwrap());
        events.recv().await.unwrap();
        events.recv().await.unwrap();
        assert_eq!(
            *credits.borrow_and_update(),
            7 + 2 * u64::from(EXEC_OUTPUT_EVENT_OVERHEAD)
        );
        tx.send(ExecEvent::Stdout(Bytes::from_static(b"unread")))
            .unwrap();
        drop(events);
        assert!(tx.is_closed());
        assert_eq!(
            *credits.borrow(),
            13 + 3 * u64::from(EXEC_OUTPUT_EVENT_OVERHEAD)
        );
    }
}
