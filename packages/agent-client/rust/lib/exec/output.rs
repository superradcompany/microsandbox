//! Coalesced acknowledgements for consumed execution output.

use std::future::Future;

use microsandbox_protocol::exec::ExecOutputAck;
use tokio::sync::watch;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Keeps the latest consumed output total for one execution.
///
/// Run the sender in its own task so yielding gives readers a chance to advance the counter.
/// Dropping all consumption senders flushes the last update before the sender finishes.
pub struct OutputAcknowledgements {
    /// Consumption updates from readers and discarded output.
    pub consumed: watch::Sender<ExecOutputAck>,
    /// Latest consumption not yet handed to the transport.
    updates: watch::Receiver<ExecOutputAck>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl OutputAcknowledgements {
    /// Send the latest cumulative total after giving other ready tasks a chance to run.
    ///
    /// There is no timer or minimum batch size. A single consumed chunk is enough to wake the
    /// sender. Updates arriving during a send are coalesced into the next acknowledgement.
    pub async fn run<F, Fut, E>(self, mut send: F) -> Result<(), E>
    where
        F: FnMut(ExecOutputAck) -> Fut,
        Fut: Future<Output = Result<(), E>>,
    {
        let Self {
            consumed,
            mut updates,
        } = self;
        drop(consumed);

        while updates.changed().await.is_ok() {
            tokio::task::yield_now().await;
            let acknowledgement = updates.borrow_and_update().clone();
            send(acknowledgement).await?;
        }
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for OutputAcknowledgements {
    fn default() -> Self {
        let (consumed, updates) = watch::channel(ExecOutputAck::default());
        Self { consumed, updates }
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use microsandbox_protocol::exec::EXEC_OUTPUT_EVENT_OVERHEAD;
    use tokio::sync::{Semaphore, mpsc};

    use super::*;

    #[tokio::test]
    async fn pending_consumption_coalesces_and_closing_flushes_the_tail() {
        let acknowledgements = OutputAcknowledgements::default();
        let consumed = acknowledgements.consumed.clone();
        let (sent, mut received) = mpsc::unbounded_channel();
        let capacity = Arc::new(Semaphore::new(0));
        let sender_capacity = capacity.clone();
        let worker = tokio::spawn(acknowledgements.run(move |ack| {
            let sent = sent.clone();
            let capacity = sender_capacity.clone();
            async move {
                sent.send(ack).unwrap();
                capacity.acquire().await.unwrap().forget();
                Ok::<_, ()>(())
            }
        }));

        consumed.send_modify(|ack| ack.consume(1).unwrap());
        let first = tokio::time::timeout(Duration::from_secs(1), received.recv())
            .await
            .expect("a one-byte tail must not wait for more output")
            .unwrap();
        assert_eq!(first.consumed, 1 + u64::from(EXEC_OUTPUT_EVENT_OVERHEAD));

        // While delivery is blocked, retain only the latest cumulative total.
        consumed.send_modify(|ack| ack.consume(10).unwrap());
        consumed.send_modify(|ack| ack.consume(11).unwrap());
        drop(consumed);
        capacity.add_permits(2);

        tokio::time::timeout(Duration::from_secs(1), worker)
            .await
            .expect("closing must flush pending consumption")
            .unwrap()
            .unwrap();
        let final_ack = received.recv().await.unwrap();
        assert_eq!(
            final_ack.consumed,
            22 + 3 * u64::from(EXEC_OUTPUT_EVENT_OVERHEAD)
        );
        assert!(received.recv().await.is_none());
    }
}
