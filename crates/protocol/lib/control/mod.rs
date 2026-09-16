//! Host-only control protocol, independent of the guest agent's generation.

mod handshake;
mod message;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use handshake::*;
pub use message::*;
pub use types::*;
