//! Byte-preserving representation shared by native SDK bindings.

use base64::{Engine as _, engine::general_purpose::STANDARD};
use bytes::Bytes;
use serde::{Deserialize, Deserializer, Serializer};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn serialize<S: Serializer>(data: &Bytes, serializer: S) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(&STANDARD.encode(data))
}

pub(super) fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Bytes, D::Error> {
    let encoded = String::deserialize(deserializer)?;
    STANDARD
        .decode(encoded)
        .map(Bytes::from)
        .map_err(serde::de::Error::custom)
}
