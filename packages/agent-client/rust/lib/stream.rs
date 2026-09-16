//! Agent streams backed by the actual shared router.

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use microsandbox_protocol_client::{
    RawStream, RawStreamReceiver, RawStreamSender, Stream, StreamReceiver, StreamSender,
};

/// Owned decoded agent stream.
pub type AgentStream = Stream<crate::AgentProtocol>;
/// Owned raw agent stream.
pub type RawAgentStream = RawStream<crate::AgentProtocol>;
