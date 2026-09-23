//! Shared framed connection; protocol setup and application behavior stay outside.

use std::path::Path;
use std::sync::Arc;

use microsandbox_protocol::codec;
use tokio::sync::{mpsc, oneshot};
use tokio::task::JoinHandle;
use tokio::time::Instant;
use zeroize::{Zeroize, Zeroizing};

use crate::router::{self, Lease, State, WriteCommand};
use crate::{
    ByteTransport, ClientError, ClientResult, ConnectOptions, Connector, Delivery, ErrorKind,
    Established, IntoOutboundMessage, LocalConnector, Message, Protocol, RawFrame, RawStream,
    Request, RequestOptions, Stream,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Cheap shared handle to one reader, writer, allocator, and set of subscriptions.
pub struct Client<P: Protocol> {
    pub(crate) inner: Arc<Owner<P>>,
}

pub(crate) struct Owner<P: Protocol> {
    pub(crate) state: Arc<State>,
    pub(crate) ready: P::Ready,
    pub(crate) codec: Arc<dyn crate::EnvelopeCodec>,
    writer: mpsc::Sender<WriteCommand>,
    handles: Vec<JoinHandle<()>>,
}

enum Packet {
    Frame(RawFrame),
    Exact(Zeroizing<Vec<u8>>),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl<P: Protocol> Client<P> {
    /// Connect a native endpoint with a single total setup deadline.
    pub async fn connect(path: impl AsRef<Path>) -> ClientResult<Self> {
        Self::connect_with(path, |options| options).await
    }

    /// Configure a native connection without modifying its endpoint name.
    pub async fn connect_with(
        path: impl AsRef<Path>,
        configure: impl FnOnce(ConnectOptions) -> ConnectOptions,
    ) -> ClientResult<Self> {
        Self::connect_connector_with(&LocalConnector::new(path), configure).await
    }

    /// Connect through a supplied repeatable dialer.
    pub async fn connect_connector(connector: &dyn Connector) -> ClientResult<Self> {
        Self::connect_connector_with(connector, |options| options).await
    }

    /// Configure one deadline covering both dial and protocol establishment.
    pub async fn connect_connector_with(
        connector: &dyn Connector,
        configure: impl FnOnce(ConnectOptions) -> ConnectOptions,
    ) -> ClientResult<Self> {
        let options = configure(ConnectOptions::default());
        options.limits.validate()?;
        let deadline = crate::options::checked_deadline(options.setup_timeout)?;
        if deadline <= Instant::now() {
            return Err(ClientError::new(ErrorKind::Timeout));
        }
        tokio::time::timeout_at(deadline, async {
            let stream = connector.connect(deadline).await?;
            let established = P::establish(stream, options).await?;
            Self::from_established(established).await
        })
        .await
        .map_err(|_| ClientError::new(ErrorKind::Timeout))?
    }

    /// Establish the protocol on an exclusively owned caller transport.
    pub async fn connect_stream(stream: impl ByteTransport) -> ClientResult<Self> {
        Self::connect_stream_with(stream, |options| options).await
    }

    /// Configure setup for an already-dialed owned transport.
    pub async fn connect_stream_with(
        stream: impl ByteTransport,
        configure: impl FnOnce(ConnectOptions) -> ConnectOptions,
    ) -> ClientResult<Self> {
        let options = configure(ConnectOptions::default());
        options.limits.validate()?;
        let deadline = crate::options::checked_deadline(options.setup_timeout)?;
        if deadline <= Instant::now() {
            return Err(ClientError::new(ErrorKind::Timeout));
        }
        tokio::time::timeout_at(deadline, async {
            let established = P::establish(Box::new(stream), options).await?;
            Self::from_established(established).await
        })
        .await
        .map_err(|_| ClientError::new(ErrorKind::Timeout))?
    }

    /// Start routing after external protocol setup, validating ranges and limits.
    pub async fn from_established(established: Established<P::Ready>) -> ClientResult<Self> {
        established.ids.validate()?;
        established.limits.validate()?;
        let state = State::new(established.ids, established.limits, P::REUSE_IDS);
        let (reader, writer) = tokio::io::split(established.transport);
        let (sender, queue) = mpsc::channel(state.limits.queued_writes);
        // Tasks own State, never Owner. Thus the last client/stream owner really
        // closes the transport instead of forming a task/connection cycle.
        let handles = vec![
            tokio::spawn(router::reader_loop(reader, Arc::clone(&state))),
            tokio::spawn(router::writer_loop(writer, queue, Arc::clone(&state))),
        ];
        Ok(Self {
            inner: Arc::new(Owner {
                state,
                ready: established.ready,
                codec: established.codec,
                writer: sender,
                handles,
            }),
        })
    }

    /// Shared immutable ready/welcome metadata.
    pub fn ready(&self) -> &P::Ready {
        &self.inner.ready
    }

    /// Whether the shared connection has terminated.
    pub fn is_closed(&self) -> bool {
        self.inner.state.is_closed()
    }

    /// Wait for shared closure, including an idle peer disconnect. Cancellation
    /// of this wait does not close the connection or affect other callers.
    pub async fn closed(&self) {
        self.inner.state.cancelled().await;
    }

    /// Close all shared handles and wake every waiter; never reconnect implicitly.
    pub async fn close(&self) {
        self.inner.state.close(ErrorKind::Closed);
        for handle in &self.inner.handles {
            handle.abort();
        }
    }

    /// Return the first response and retain drain state if it is nonterminal.
    pub async fn request<M: IntoOutboundMessage<P>>(&self, message: M) -> ClientResult<Message> {
        self.request_with(message, |options| options).await
    }

    /// Configure a local unary wait without imposing application success rules.
    pub async fn request_with<M: IntoOutboundMessage<P>>(
        &self,
        message: M,
        configure: impl FnOnce(RequestOptions) -> RequestOptions,
    ) -> ClientResult<Message> {
        let outbound = message.into_outbound(self.ready(), self.inner.codec.as_ref())?;
        let frame = self
            .request_raw_with(outbound.flags, outbound.body, configure)
            .await?;
        self.inner
            .codec
            .decode(frame)
            .map_err(|error| error.with_delivery(Delivery::Unknown))
    }

    /// Execute a borrowed prepared request with optional checked result decoding.
    pub async fn request_typed<R: Request<P>>(&self, request: &R) -> Result<R::Response, R::Error> {
        self.request_typed_with(request, |options| options).await
    }

    /// Configure one checked unary attempt; unexpected streaming is an error.
    pub async fn request_typed_with<R: Request<P>>(
        &self,
        request: &R,
        configure: impl FnOnce(RequestOptions) -> RequestOptions,
    ) -> Result<R::Response, R::Error> {
        let message = self.request_with(request.message()?, configure).await?;
        if message.flags & microsandbox_protocol::message::FLAG_TERMINAL == 0 {
            return Err(ClientError::new(ErrorKind::InvalidData)
                .with_delivery(Delivery::Unknown)
                .into());
        }
        request.decode(message)
    }

    /// Open a message stream on an owned correlation ID.
    pub async fn stream<M: IntoOutboundMessage<P>>(&self, message: M) -> ClientResult<Stream<P>> {
        self.stream_with(message, |options| options).await
    }

    /// Configure the stream-opening wait; subsequent receives own their lifetime.
    pub async fn stream_with<M: IntoOutboundMessage<P>>(
        &self,
        message: M,
        configure: impl FnOnce(RequestOptions) -> RequestOptions,
    ) -> ClientResult<Stream<P>> {
        let outbound = message.into_outbound(self.ready(), self.inner.codec.as_ref())?;
        Ok(Stream::from_raw(
            self.stream_raw_with(outbound.flags, outbound.body, configure)
                .await?,
        ))
    }

    /// Return one raw frame without decoding or normalizing its envelope.
    pub async fn request_raw(&self, flags: u8, body: Vec<u8>) -> ClientResult<RawFrame> {
        self.request_raw_with(flags, body, |options| options).await
    }

    /// Set a deadline covering queue admission, write completion, and reply wait.
    pub async fn request_raw_with(
        &self,
        flags: u8,
        body: Vec<u8>,
        configure: impl FnOnce(RequestOptions) -> RequestOptions,
    ) -> ClientResult<RawFrame> {
        let packet = self.packet(0, flags, body)?;
        let mut stream = self.reserve_stream()?;
        let lease = Arc::clone(&stream.receiver.lease);
        let options = configure(RequestOptions::default());
        self.attempt(&lease, options, async {
            self.write_opening(&lease, packet).await?;
            stream
                .recv()
                .await?
                .ok_or_else(|| ClientError::new(ErrorKind::PeerClosed))
        })
        .await
        // The owned receiver drops on every return/cancellation path. It keeps
        // admitted, nonterminal IDs draining rather than immediately reusing them.
    }

    /// Open an opaque stream with the same ID lease as native message streams.
    pub async fn stream_raw(&self, flags: u8, body: Vec<u8>) -> ClientResult<RawStream<P>> {
        self.stream_raw_with(flags, body, |options| options).await
    }

    /// Configure opaque stream opening without inspecting its envelope.
    pub async fn stream_raw_with(
        &self,
        flags: u8,
        body: Vec<u8>,
        configure: impl FnOnce(RequestOptions) -> RequestOptions,
    ) -> ClientResult<RawStream<P>> {
        let packet = self.packet(0, flags, body)?;
        let stream = self.reserve_stream()?;
        let lease = Arc::clone(&stream.receiver.lease);
        let options = configure(RequestOptions::default());
        self.attempt(&lease, options, self.write_opening(&lease, packet))
            .await?;
        Ok(stream)
    }

    /// Send a native or encoded payload on a currently live owned ID.
    pub async fn send<M: IntoOutboundMessage<P>>(&self, id: u32, message: M) -> ClientResult<()> {
        let lease = self.inner.state.owned(id)?;
        self.send_owned(&lease, message).await
    }

    /// Send an opaque envelope on a currently live owned ID.
    pub async fn send_raw(&self, id: u32, flags: u8, body: &[u8]) -> ClientResult<()> {
        let lease = self.inner.state.owned(id)?;
        self.send_raw_owned(&lease, flags, body).await
    }

    /// Serialize exact packet bytes without allocating an ID or subscription.
    /// The caller owns packet semantics; byte limits and shared close still apply.
    pub async fn write_unchecked(&self, packet: Vec<u8>) -> ClientResult<()> {
        if packet.len() > self.inner.state.limits.buffered_bytes as usize {
            return Err(ClientError::new(ErrorKind::Capacity));
        }
        self.write_packet(None, Packet::Exact(Zeroizing::new(packet)))
            .await
    }

    pub(crate) async fn send_owned<M: IntoOutboundMessage<P>>(
        &self,
        lease: &Arc<Lease>,
        message: M,
    ) -> ClientResult<()> {
        let outbound = message.into_outbound(self.ready(), self.inner.codec.as_ref())?;
        self.write_packet(
            Some(lease),
            self.packet(lease.id, outbound.flags, outbound.body)?,
        )
        .await
    }

    pub(crate) async fn send_raw_owned(
        &self,
        lease: &Arc<Lease>,
        flags: u8,
        body: &[u8],
    ) -> ClientResult<()> {
        self.write_packet(Some(lease), self.packet(lease.id, flags, body.to_vec())?)
            .await
    }

    fn reserve_stream(&self) -> ClientResult<RawStream<P>> {
        let (lease, receiver) = self.inner.state.reserve()?;
        Ok(RawStream::new(self.clone(), lease, receiver))
    }

    fn packet(&self, id: u32, flags: u8, body: Vec<u8>) -> ClientResult<Packet> {
        if body.len() > self.inner.state.limits.max_frame_size as usize - 5 {
            return Err(ClientError::new(ErrorKind::Capacity));
        }
        Ok(Packet::Frame(RawFrame { id, flags, body }))
    }

    async fn write_opening(&self, lease: &Arc<Lease>, mut packet: Packet) -> ClientResult<()> {
        let Packet::Frame(frame) = &mut packet else {
            unreachable!()
        };
        frame.id = lease.id;
        self.write_packet(Some(lease), packet).await
    }

    async fn write_packet(&self, lease: Option<&Arc<Lease>>, packet: Packet) -> ClientResult<()> {
        let bytes = Arc::clone(&self.inner.state.budget)
            .acquire_many_owned(packet.len() as u32)
            .await
            .map_err(|_| self.inner.state.error())?;
        let permit = self
            .inner
            .writer
            .reserve()
            .await
            .map_err(|_| self.inner.state.error())?;
        // Allocate the framed packet only after reserving queue bytes and an
        // item slot. Waiting callers retain their input, not an extra packet
        // copy outside the transport's buffer budget.
        let packet = packet.encode()?;
        let (ack, written) = oneshot::channel();
        self.inner.state.admit(
            lease,
            permit,
            WriteCommand {
                packet,
                ack,
                _bytes: bytes,
            },
        )?;
        written
            .await
            .map_err(|_| self.inner.state.error().with_delivery(Delivery::Unknown))?
    }

    async fn attempt<T>(
        &self,
        lease: &Lease,
        options: RequestOptions,
        future: impl std::future::Future<Output = ClientResult<T>>,
    ) -> ClientResult<T> {
        let result = match options
            .request_timeout
            .or(self.inner.state.limits.request_timeout)
        {
            Some(timeout) => {
                let deadline = crate::options::checked_deadline(timeout)?;
                // A zero/expired local wait must not poll a ready writer first:
                // Tokio timeouts otherwise allow an immediately ready future
                // to run even when the timer is already due.
                if deadline <= Instant::now() {
                    Err(ClientError::new(ErrorKind::Timeout))
                } else {
                    tokio::time::timeout_at(deadline, future)
                        .await
                        .unwrap_or_else(|_| Err(ClientError::new(ErrorKind::Timeout)))
                }
            }
            None => future.await,
        };
        result.map_err(|error| error.with_delivery(lease.delivery()))
    }
}

impl Packet {
    fn len(&self) -> usize {
        match self {
            Self::Frame(frame) => frame.body.len() + 9,
            Self::Exact(packet) => packet.len(),
        }
    }

    fn encode(self) -> ClientResult<Zeroizing<Vec<u8>>> {
        match self {
            Self::Exact(packet) => Ok(packet),
            Self::Frame(mut frame) => {
                let mut packet = Zeroizing::new(Vec::with_capacity(frame.body.len() + 9));
                let result = codec::encode_raw_to_buf(&frame, &mut packet);
                frame.body.zeroize();
                result.map_err(|_| ClientError::new(ErrorKind::InvalidData))?;
                Ok(packet)
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<P: Protocol> Clone for Client<P> {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl<P: Protocol> Drop for Owner<P> {
    fn drop(&mut self) {
        self.state.close(ErrorKind::Closed);
        for handle in &self.handles {
            handle.abort();
        }
    }
}
