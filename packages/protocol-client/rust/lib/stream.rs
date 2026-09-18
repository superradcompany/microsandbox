//! Owned subscriptions, split senders, and one consuming receiver per ID.

use std::sync::{Arc, atomic::Ordering};

use tokio::sync::mpsc;

use crate::router::{Lease, QueuedFrame};
use crate::{Client, ClientResult, Delivery, IntoOutboundMessage, Message, Protocol, RawFrame};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Opaque frame stream whose lifetime retains its connection and ID lease.
pub struct RawStream<P: Protocol> {
    sender: RawStreamSender<P>,
    pub(crate) receiver: RawStreamReceiver<P>,
}

/// Cloneable send permission bound to one specific lease, not merely its number.
pub struct RawStreamSender<P: Protocol> {
    client: Client<P>,
    lease: Arc<Lease>,
}

/// Sole consuming raw receiver. Dropping it disables sends and starts draining.
pub struct RawStreamReceiver<P: Protocol> {
    client: Client<P>,
    pub(crate) lease: Arc<Lease>,
    receiver: mpsc::Receiver<QueuedFrame>,
    done: bool,
}

/// Decoded message stream over the same opaque router and lease.
pub struct Stream<P: Protocol> {
    raw: RawStream<P>,
}

/// Cloneable native-message sender bound to an owned stream lease.
pub struct StreamSender<P: Protocol> {
    raw: RawStreamSender<P>,
}

/// Sole decoded receiver; no competing reader is created by conversion/split.
pub struct StreamReceiver<P: Protocol> {
    raw: RawStreamReceiver<P>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<P: Protocol> RawStream<P> {
    pub(crate) fn new(
        client: Client<P>,
        lease: Arc<Lease>,
        receiver: mpsc::Receiver<QueuedFrame>,
    ) -> Self {
        Self {
            sender: RawStreamSender {
                client: client.clone(),
                lease: Arc::clone(&lease),
            },
            receiver: RawStreamReceiver {
                client,
                lease,
                receiver,
                done: false,
            },
        }
    }

    /// Current stream's correlation ID.
    pub fn id(&self) -> u32 {
        self.sender.id()
    }

    /// Send a follow-up opaque frame; local close never sends a protocol signal.
    pub async fn send(&self, flags: u8, body: &[u8]) -> ClientResult<()> {
        self.sender.send(flags, body).await
    }

    /// Receive each frame, terminal included, then clean exhaustion or an error.
    pub async fn recv(&mut self) -> ClientResult<Option<RawFrame>> {
        self.receiver.recv().await
    }

    /// Abandon local consumption and retain bounded drain state until terminal.
    pub fn close(&mut self) {
        self.receiver.close();
    }

    /// Move ownership into a cloneable sender and one consuming receiver.
    pub fn into_parts(self) -> (RawStreamSender<P>, RawStreamReceiver<P>) {
        (self.sender, self.receiver)
    }
}

impl<P: Protocol> RawStreamSender<P> {
    /// Correlation ID associated with this specific lease.
    pub fn id(&self) -> u32 {
        self.lease.id
    }

    /// Send while this lease remains live; a reused numeric ID gives no authority.
    pub async fn send(&self, flags: u8, body: &[u8]) -> ClientResult<()> {
        self.client.send_raw_owned(&self.lease, flags, body).await
    }
}

impl<P: Protocol> RawStreamReceiver<P> {
    /// Correlation ID whose frames this receiver alone consumes.
    pub fn id(&self) -> u32 {
        self.lease.id
    }

    /// Receive the next frame. EOF before terminal is an error exactly once.
    pub async fn recv(&mut self) -> ClientResult<Option<RawFrame>> {
        if self.done {
            return Ok(None);
        }
        match self.receiver.recv().await {
            Some(queued) => {
                if queued.frame.flags & microsandbox_protocol::message::FLAG_TERMINAL != 0 {
                    self.done = true;
                }
                Ok(Some(queued.frame))
            }
            None => {
                self.done = true;
                if self.lease.terminal.load(Ordering::Acquire) {
                    Ok(None)
                } else {
                    Err(self
                        .client
                        .inner
                        .state
                        .error()
                        .with_delivery(self.lease.delivery()))
                }
            }
        }
    }

    /// Stop local consumption and disable sends without canceling remote work.
    pub fn close(&mut self) {
        self.client.inner.state.abandon(&self.lease);
        self.receiver.close();
        while self.receiver.try_recv().is_ok() {}
        self.done = true;
    }
}

impl<P: Protocol> Stream<P> {
    pub(crate) fn from_raw(raw: RawStream<P>) -> Self {
        Self { raw }
    }

    /// Correlation ID of the owned stream.
    pub fn id(&self) -> u32 {
        self.raw.id()
    }

    /// Send a native or already-encoded payload using the selected codec.
    pub async fn send<M: IntoOutboundMessage<P>>(&self, message: M) -> ClientResult<()> {
        self.raw
            .sender
            .client
            .send_owned(&self.raw.sender.lease, message)
            .await
    }

    /// Receive an inspectable message, including unknown names and peer errors.
    pub async fn recv(&mut self) -> ClientResult<Option<Message>> {
        self.raw
            .recv()
            .await?
            .map(|frame| {
                self.raw
                    .sender
                    .client
                    .inner
                    .codec
                    .decode(frame)
                    .map_err(|error| error.with_delivery(Delivery::Unknown))
            })
            .transpose()
    }

    /// Abandon consumption; no domain-specific cancellation or EOF is sent.
    pub fn close(&mut self) {
        self.raw.close();
    }

    /// Split into owned handles while preserving one receiver and the ID lease.
    pub fn into_parts(self) -> (StreamSender<P>, StreamReceiver<P>) {
        let (sender, receiver) = self.raw.into_parts();
        (
            StreamSender { raw: sender },
            StreamReceiver { raw: receiver },
        )
    }
}

impl<P: Protocol> StreamSender<P> {
    /// Correlation ID of this lease.
    pub fn id(&self) -> u32 {
        self.raw.id()
    }

    /// Send on this lease, rejecting stale senders even after numeric ID reuse.
    pub async fn send<M: IntoOutboundMessage<P>>(&self, message: M) -> ClientResult<()> {
        self.raw.client.send_owned(&self.raw.lease, message).await
    }
}

impl<P: Protocol> StreamReceiver<P> {
    /// Correlation ID consumed by this receiver.
    pub fn id(&self) -> u32 {
        self.raw.id()
    }

    /// Receive messages on the sole raw receiver, decoding only on demand.
    pub async fn recv(&mut self) -> ClientResult<Option<Message>> {
        self.raw
            .recv()
            .await?
            .map(|frame| {
                self.raw
                    .client
                    .inner
                    .codec
                    .decode(frame)
                    .map_err(|error| error.with_delivery(Delivery::Unknown))
            })
            .transpose()
    }

    /// Disable further sends and drain until terminal completion.
    pub fn close(&mut self) {
        self.raw.close();
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<P: Protocol> Clone for RawStreamSender<P> {
    fn clone(&self) -> Self {
        Self {
            client: self.client.clone(),
            lease: Arc::clone(&self.lease),
        }
    }
}

impl<P: Protocol> Clone for StreamSender<P> {
    fn clone(&self) -> Self {
        Self {
            raw: self.raw.clone(),
        }
    }
}

impl<P: Protocol> Drop for RawStreamReceiver<P> {
    fn drop(&mut self) {
        self.client.inner.state.abandon(&self.lease);
    }
}
