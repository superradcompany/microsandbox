//! Sidecar index for layer acceleration.
//!
//! Provides wire format types, a zero-copy mmap reader, and a builder/writer
//! for the binary per-layer index generated at OCI extraction time.

mod reader;
mod types;
mod writer;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use reader::*;
pub use types::*;
pub use writer::*;
