//! Bounded framing helpers for filesystem backend state.

use std::io;

use bincode::config;
use serde::{Serialize, de::DeserializeOwned};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SCHEMA: u16 = 1;
const HEADER_BYTES: usize = 10;
const MIB: usize = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Output buffer that refuses to grow past the state budget.
struct BoundedWriter {
    bytes: Vec<u8>,
    limit: usize,
    exceeded: bool,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl io::Write for BoundedWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        if self.bytes.len().saturating_add(buf.len()) > self.limit {
            self.exceeded = true;
            return Err(io::Error::new(
                io::ErrorKind::FileTooLarge,
                "backend state exceeds its budget",
            ));
        }
        self.bytes.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn encode<T: Serialize>(kind: &[u8; 8], state: &T, limit: usize) -> io::Result<Vec<u8>> {
    let config = config::standard()
        .with_little_endian()
        .with_fixed_int_encoding();
    let mut writer = BoundedWriter {
        bytes: Vec::with_capacity(HEADER_BYTES),
        limit,
        exceeded: false,
    };
    writer.bytes.extend_from_slice(kind);
    writer.bytes.extend_from_slice(&SCHEMA.to_le_bytes());
    if let Err(error) = bincode::serde::encode_into_std_write(state, &mut writer, config) {
        if writer.exceeded {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "filesystem state exceeds the {} MiB budget; raise snapshots.max_filesystem_state_mib \
                     (a running sandbox keeps the budget it started with)",
                    limit / MIB
                ),
            ));
        }
        return Err(invalid_data(error));
    }
    Ok(writer.bytes)
}

pub(crate) fn decode<T: DeserializeOwned>(
    kind: &[u8; 8],
    bytes: &[u8],
    limit: usize,
) -> io::Result<T> {
    if bytes.len() < HEADER_BYTES || bytes.len() > limit {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid backend state length",
        ));
    }
    if &bytes[..8] != kind || u16::from_le_bytes(bytes[8..10].try_into().unwrap()) != SCHEMA {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported snapshot filesystem format; if this snapshot was created with a newer microsandbox runtime, upgrade to that version or newer to restore it",
        ));
    }

    let payload = &bytes[HEADER_BYTES..];
    let (state, consumed) = match limit {
        limit if limit <= MIB => decode_tier::<{ MIB }, T>(payload),
        limit if limit <= 2 * MIB => decode_tier::<{ 2 * MIB }, T>(payload),
        limit if limit <= 4 * MIB => decode_tier::<{ 4 * MIB }, T>(payload),
        limit if limit <= 8 * MIB => decode_tier::<{ 8 * MIB }, T>(payload),
        limit if limit <= 16 * MIB => decode_tier::<{ 16 * MIB }, T>(payload),
        limit if limit <= 32 * MIB => decode_tier::<{ 32 * MIB }, T>(payload),
        limit if limit <= 64 * MIB => decode_tier::<{ 64 * MIB }, T>(payload),
        limit if limit <= 128 * MIB => decode_tier::<{ 128 * MIB }, T>(payload),
        limit if limit <= 256 * MIB => decode_tier::<{ 256 * MIB }, T>(payload),
        limit if limit <= 512 * MIB => decode_tier::<{ 512 * MIB }, T>(payload),
        limit if limit <= 1024 * MIB => decode_tier::<{ 1024 * MIB }, T>(payload),
        limit if limit <= 2048 * MIB => decode_tier::<{ 2048 * MIB }, T>(payload),
        _ => decode_tier::<{ 4095 * MIB }, T>(payload),
    }?;
    if HEADER_BYTES + consumed != bytes.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "trailing backend state bytes",
        ));
    }
    Ok(state)
}

/// Decodes with a compile-time allocation bound, which bincode only accepts as a const generic.
fn decode_tier<const L: usize, T: DeserializeOwned>(bytes: &[u8]) -> io::Result<(T, usize)> {
    let config = config::standard()
        .with_little_endian()
        .with_fixed_int_encoding()
        .with_limit::<L>();
    bincode::serde::decode_from_slice(bytes, config).map_err(invalid_data)
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

    const DEFAULT_LIMIT: usize = 4 * MIB;

    #[test]
    fn framed_state_round_trips_and_rejects_trailing_bytes() {
        let encoded = encode(KIND, &State { value: 42 }, DEFAULT_LIMIT).unwrap();
        assert_eq!(
            decode::<State>(KIND, &encoded, DEFAULT_LIMIT)
                .unwrap()
                .value,
            42
        );

        let mut trailing = encoded;
        trailing.push(0);
        assert!(decode::<State>(KIND, &trailing, DEFAULT_LIMIT).is_err());
    }

    #[test]
    fn state_size_follows_the_budget() {
        let state = vec![7u8; 5 * MIB];

        let error = encode(KIND, &state, DEFAULT_LIMIT).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("snapshots.max_filesystem_state_mib")
        );

        for limit in [8 * MIB, 4095 * MIB] {
            let encoded = encode(KIND, &state, limit).unwrap();
            assert_eq!(decode::<Vec<u8>>(KIND, &encoded, limit).unwrap(), state);
        }

        let encoded = encode(KIND, &state, 8 * MIB).unwrap();
        assert!(decode::<Vec<u8>>(KIND, &encoded, DEFAULT_LIMIT).is_err());
        assert!(decode::<Vec<u8>>(KIND, &encoded, encoded.len() - 1).is_err());
        assert!(decode::<Vec<u8>>(KIND, &encoded, encoded.len()).is_ok());
    }

    #[test]
    fn state_below_the_default_budget_is_bounded() {
        let state = vec![7u8; 2 * MIB];
        assert!(encode(KIND, &state, MIB).is_err());
        let encoded = encode(KIND, &state, 3 * MIB).unwrap();
        assert!(decode::<Vec<u8>>(KIND, &encoded, MIB).is_err());
        assert!(decode::<Vec<u8>>(KIND, &encoded, 3 * MIB).is_ok());
    }

    #[test]
    fn encoding_stops_at_the_budget() {
        use std::io::Write;

        let mut writer = BoundedWriter {
            bytes: Vec::new(),
            limit: 8,
            exceeded: false,
        };
        writer.write_all(&[1; 8]).unwrap();
        assert!(writer.write_all(&[1]).is_err());
        assert!(writer.exceeded);
        assert_eq!(writer.bytes.len(), 8);
    }

    #[test]
    fn malformed_length_prefix_does_not_allocate_beyond_the_budget() {
        for limit in [MIB, 4 * MIB, 64 * MIB, 4095 * MIB] {
            let mut malformed = Vec::from(&KIND[..]);
            malformed.extend_from_slice(&SCHEMA.to_le_bytes());
            malformed.extend_from_slice(&u64::MAX.to_le_bytes());
            assert!(decode::<Vec<u8>>(KIND, &malformed, limit).is_err());
        }
    }
}
