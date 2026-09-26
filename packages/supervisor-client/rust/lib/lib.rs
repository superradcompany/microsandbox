#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

mod client;
mod error;
mod protocol;
mod request;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use client::{SupervisorClient, SupervisorClientConfig};
pub use error::{SupervisorClientError, SupervisorClientResult};
pub use microsandbox_protocol::supervisor::*;
pub use microsandbox_protocol_client::{
    ClientError, ConnectOptions, Connector, Delivery, EncodedMessage, ErrorKind, Message, Request,
    RequestOptions, Stream,
};
pub use protocol::{SupervisorProtocol, SupervisorReady};
pub use request::*;
