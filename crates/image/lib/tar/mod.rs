mod ingest;
mod pax;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use ingest::{Compression, IngestError, IngestResult, ingest_compressed_tar, ingest_tar};

pub(crate) use ingest::hash_compressed_tar;
