#![doc = include_str!("../README.md")]
#![warn(missing_docs)]

mod compat_message;
mod connection;
mod dialer;
mod error;
mod json_client;
mod json_reply;
mod json_value;
mod protocol;
mod request;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use compat_message::{CheckedControlRequest, IntoControlMessage};
pub use connection::{ControlConnection, ControlMode, ControlReply};
pub use dialer::VerifiedControlConnector;
pub use error::{ControlClientError, ControlClientResult};
pub use json_client::{JsonControlClient, MAX_DISCOVERY_RESPONSE_SIZE};
pub use json_reply::JsonReply;
pub use json_value::{JsonNumber, JsonValue};
pub use microsandbox_protocol::control::*;
pub use microsandbox_protocol_client::{
    Client, ClientError, ConnectOptions, Connector, Delivery, EncodedMessage, ErrorKind, Message,
    RawFrame, Request, RequestOptions, TypedMessage,
};
pub use microsandbox_utils::size;
pub use protocol::{ControlClient, ControlProtocol, ControlReady};
pub use request::{
    GetCapabilities, GetCpuState, GetMemoryState, SetCpuTarget, SetMemoryTarget, UpdateSecrets,
};
