//! Typed-bootstrap launch format introduced in v0.6.10.

use microsandbox_types::compat::field::Field;

use crate::client::compat::launch;
use crate::client::launch::LaunchConfig;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Decode a launch with an explicitly supplied typed bootstrap.
pub(in crate::client::compat) fn decode(bytes: &[u8]) -> Result<LaunchConfig, String> {
    let mut launch = launch::decode_previous(bytes)?;
    let Field::Present(bootstrap) = std::mem::take(&mut launch.bootstrap) else {
        return Err("missing bootstrap".into());
    };
    launch.into_current(bootstrap, false)
}
