mod format;
pub mod reader;
mod writer;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use reader::{
    ErofsEntryInfo, ErofsEntryKind, ErofsReader, entry_info_from_erofs, read_file_from_erofs,
};
pub use writer::{ErofsError, write_erofs};
