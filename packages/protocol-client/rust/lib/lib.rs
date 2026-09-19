//! Low-level framed connections, independent of the application protocol.
#![warn(missing_docs)]

mod client;
mod error;
mod message;
mod options;
mod protocol;
mod request;
mod router;
mod stream;
mod transport;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use client::Client;
pub use error::{ClientError, ClientResult, Delivery, ErrorKind};
pub use message::{EncodedMessage, IntoOutboundMessage, Message, OutboundMessage, TypedMessage};
pub use microsandbox_protocol::codec::RawFrame;
pub use options::{ClientLimits, ConnectOptions, RequestOptions};
pub use protocol::{
    CborEnvelopeCodec, EnvelopeCodec, Established, IdRange, Protocol, SendMetadata,
};
pub use request::Request;
pub use stream::{
    RawStream, RawStreamReceiver, RawStreamSender, Stream, StreamReceiver, StreamSender,
};
pub use transport::{BoxFuture, BoxTransport, ByteTransport, Connector, LocalConnector};
