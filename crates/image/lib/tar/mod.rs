mod ingest;
mod pax;
mod records;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use ingest::{Compression, IngestError, IngestResult, ingest_compressed_tar, ingest_tar};
