//! Optional checked unary operations layered over the message API.

use crate::{ClientError, EncodedMessage, Message, Protocol};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Pair a prepared protocol request with checked terminal-response decoding.
///
/// Application errors belong to the implementation, so they can retain an
/// original peer error or legacy JSON response rather than flattening it into
/// a generic transport error. Implementations borrow prepared inputs.
pub trait Request<P: Protocol> {
    /// Checked operation result, independent of SDK domain behavior.
    type Response;
    /// Application error that can also retain a local transport failure.
    type Error: From<ClientError>;

    /// Encode the prepared request without performing I/O.
    fn message(&self) -> Result<EncodedMessage, Self::Error>;

    /// Check the expected terminal response name, generation, and payload.
    fn decode(&self, message: Message) -> Result<Self::Response, Self::Error>;
}
