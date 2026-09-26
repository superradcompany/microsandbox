//! Local supervisor protocol shared by native clients and the supervisor process.
//!
//! The `MSBS` preamble selects this protocol before the ordinary framed setup.
//! Every subsequent record uses the common `{v,t,p}` CBOR envelope.

mod handshake;
mod message;
mod types;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use handshake::*;
pub use message::*;
pub use types::*;
