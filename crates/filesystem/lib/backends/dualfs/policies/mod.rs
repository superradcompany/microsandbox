//! Built-in dispatch policies for DualFs.

mod backend_a_fallback_to_backend_b;
mod backend_a_only;
mod merge_reads;
mod read_backend_b_write_backend_a;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use backend_a_fallback_to_backend_b::BackendAFallbackToBackendBRead;
pub use backend_a_only::BackendAOnly;
pub use merge_reads::MergeReadsBackendAPrecedence;
pub use read_backend_b_write_backend_a::ReadBackendBWriteBackendA;
