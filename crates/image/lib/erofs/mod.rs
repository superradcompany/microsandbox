pub(crate) mod format;
pub mod fsmeta;
pub mod reader;
pub(crate) mod writer;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use fsmeta::write_fsmeta;
pub use reader::{
    ErofsEntryInfo, ErofsEntryKind, ErofsReader, entry_info_from_erofs, read_file_from_erofs,
};
pub use writer::{ErofsDataMap, ErofsError, write_erofs};
