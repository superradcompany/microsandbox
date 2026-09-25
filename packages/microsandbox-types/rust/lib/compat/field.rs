//! Distinguish an omitted field from an explicitly supplied null at wire boundaries.

use serde::{Deserialize, Deserializer};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Presence of a wire field, including null when the payload type permits it.
#[derive(Default)]
pub enum Field<T> {
    /// The field was omitted.
    #[default]
    Missing,
    /// The field was supplied, possibly as null.
    Present(T),
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'de, T: Deserialize<'de>> Deserialize<'de> for Field<T> {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        T::deserialize(deserializer).map(Self::Present)
    }
}
