//! Persistent named volumes with retained destination and identity.

pub mod fs;
mod identity;
mod inspection;
mod resource;

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------

pub use fs::{VolumeFs, VolumeFsReadStream, VolumeFsWriteSink};
pub use identity::VolumeId;
pub use inspection::VolumeInfo;
pub use microsandbox_types::{VolumeKind, VolumeSpec, VolumeSpec as VolumeConfig};
pub use resource::{Volume, VolumeBuilder};
#[cfg(feature = "local")]
pub(crate) use resource::{
    create_local, destroy_local, get_local, list_local, lock_volume_name, provision_volume_path,
    provision_volume_path_sync, remove_local,
};
pub(crate) use resource::{validate_volume_config, validate_volume_name};
