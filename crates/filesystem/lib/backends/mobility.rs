//! Bounded framing helpers for filesystem backend state.

use std::io;

use bincode::config;
use serde::{Serialize, de::DeserializeOwned};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SCHEMA: u16 = 1;
const HEADER_BYTES: usize = 10;
pub(crate) const MAX_BACKEND_STATE_BYTES: usize = 4 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn encode<T: Serialize>(kind: &[u8; 8], state: &T) -> io::Result<Vec<u8>> {
    let config = config::standard()
        .with_little_endian()
        .with_fixed_int_encoding()
        .with_limit::<MAX_BACKEND_STATE_BYTES>();
    let payload = bincode::serde::encode_to_vec(state, config).map_err(invalid_data)?;
    let total = HEADER_BYTES
        .checked_add(payload.len())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "backend state is too large"))?;
    if total > MAX_BACKEND_STATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "backend state exceeds 4 MiB",
        ));
    }

    let mut bytes = Vec::with_capacity(total);
    bytes.extend_from_slice(kind);
    bytes.extend_from_slice(&SCHEMA.to_le_bytes());
    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

pub(crate) fn decode<T: DeserializeOwned>(kind: &[u8; 8], bytes: &[u8]) -> io::Result<T> {
    if bytes.len() < HEADER_BYTES || bytes.len() > MAX_BACKEND_STATE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid backend state length",
        ));
    }
    if &bytes[..8] != kind || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != SCHEMA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported backend state format",
        ));
    }

    let config = config::standard()
        .with_little_endian()
        .with_fixed_int_encoding()
        .with_limit::<MAX_BACKEND_STATE_BYTES>();
    let (state, consumed) =
        bincode::serde::decode_from_slice(&bytes[HEADER_BYTES..], config).map_err(invalid_data)?;
    if HEADER_BYTES + consumed != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing backend state bytes",
        ));
    }
    Ok(state)
}

fn invalid_data(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use serde::{Deserialize, Serialize};

    use super::*;

    const KIND: &[u8; 8] = b"MSBTEST\0";

    #[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
    struct State {
        value: u64,
    }

    #[test]
    fn framed_state_round_trips_and_rejects_trailing_bytes() {
        let encoded = encode(KIND, &State { value: 42 }).unwrap();
        assert_eq!(decode::<State>(KIND, &encoded).unwrap().value, 42);

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode::<State>(KIND, &trailing).is_err());
    }
}
