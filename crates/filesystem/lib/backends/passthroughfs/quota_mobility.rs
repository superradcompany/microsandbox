//! Versioned quota envelope shared by all passthrough snapshot variants.

use super::quota::{FileChargeState, QuotaState};
use crate::backends::mobility;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{collections::BTreeSet, io};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const INCREMENTAL_SCHEMA: u16 = 2;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

pub(crate) trait QuotaSnapshot {
    fn quota(&self) -> &Option<QuotaState>;
    fn quota_mut(&mut self) -> &mut Option<QuotaState>;
    fn quota_inodes(&self) -> BTreeSet<u64>;
}

#[derive(Serialize, Deserialize)]
struct IncrementalState<T, Charges = Vec<FileChargeState>> {
    backend: T,
    charges: Charges,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn encode<T: Serialize + QuotaSnapshot>(
    kind: &[u8; 8],
    state: &T,
    limit: usize,
) -> io::Result<Vec<u8>> {
    if let Some(files) = state.quota().as_ref().and_then(|q| q.files.as_ref()) {
        mobility::encode_schema(
            kind,
            INCREMENTAL_SCHEMA,
            &IncrementalState {
                backend: state,
                charges: files,
            },
            limit,
        )
    } else {
        // Quota-free mounts and restored old snapshots retain their original bytes.
        mobility::encode(kind, state, limit)
    }
}

pub(crate) fn decode<T: DeserializeOwned + QuotaSnapshot>(
    kind: &[u8; 8],
    bytes: &[u8],
    limit: usize,
) -> io::Result<T> {
    let state: T = if bytes.get(8..10) == Some(&INCREMENTAL_SCHEMA.to_le_bytes()) {
        let mut envelope: IncrementalState<T> =
            mobility::decode_schema(kind, INCREMENTAL_SCHEMA, bytes, limit)?;
        let quota = envelope
            .backend
            .quota_mut()
            .as_mut()
            .ok_or_else(|| invalid("incremental snapshot has no quota"))?;
        quota.files = Some(envelope.charges);
        envelope.backend
    } else {
        mobility::decode(kind, bytes, limit)?
    };
    if let Some(quota) = state.quota() {
        quota.validate()?;
        if let Some(files) = &quota.files {
            let inodes = state.quota_inodes();
            if files.iter().any(|file| !inodes.contains(&file.inode)) {
                return Err(invalid("quota charge references an uncaptured inode"));
            }
        }
    }
    Ok(state)
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backends::passthroughfs::quota::DirQuota;

    const KIND: &[u8; 8] = b"MSBQTST\0";
    const LIMIT: usize = 4096;

    #[derive(Debug, Deserialize, Serialize)]
    struct State {
        quota: Option<QuotaState>,
        marker: u64,
    }

    impl QuotaSnapshot for State {
        fn quota(&self) -> &Option<QuotaState> {
            &self.quota
        }
        fn quota_mut(&mut self) -> &mut Option<QuotaState> {
            &mut self.quota
        }
        fn quota_inodes(&self) -> BTreeSet<u64> {
            BTreeSet::from([3])
        }
    }

    #[test]
    fn frozen_schema_one_quota_bytes_restore_and_reencode_unchanged() {
        // Schema-one layout at c8c6cfe3: Option<QuotaState { baseline:
        // Option<u64>, used: u64 }>, followed by another backend field.
        let fixture =
            hex::decode("4d5342515453540001000101640000000000000007000000000000002a00000000000000")
                .unwrap();
        let state: State = decode(KIND, &fixture, LIMIT).unwrap();
        assert_eq!(state.marker, 42);
        let saved = state.quota.as_ref().unwrap();
        assert_eq!(
            (saved.baseline, saved.used, saved.files.as_ref()),
            (Some(100), 7, None)
        );
        let quota = DirQuota::new("/nonexistent-quota-root".into(), 10);
        quota.restore_state(saved).unwrap();
        assert_eq!(quota.capture_state(), *saved);
        assert_eq!(quota.baseline(), 100);
        assert_eq!(encode(KIND, &state, LIMIT).unwrap(), fixture);
    }

    #[test]
    fn incremental_state_round_trips_and_old_readers_refuse() {
        let state = State {
            quota: Some(QuotaState {
                baseline: None,
                used: 20,
                files: Some(vec![FileChargeState {
                    inode: 3,
                    ranges: vec![(100, 120)],
                }]),
            }),
            marker: 42,
        };
        let bytes = encode(KIND, &state, LIMIT).unwrap();
        assert_eq!(&bytes[8..10], &2u16.to_le_bytes());
        let restored: State = decode(KIND, &bytes, LIMIT).unwrap();
        assert_eq!(restored.quota, state.quota);
        assert_eq!(restored.marker, 42);
        assert!(
            mobility::decode::<State>(KIND, &bytes, LIMIT)
                .unwrap_err()
                .to_string()
                .contains("upgrade")
        );
        assert!(decode::<State>(KIND, &bytes, bytes.len() - 1).is_err());
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert!(decode::<State>(KIND, &trailing, LIMIT).is_err());
    }

    #[test]
    fn incremental_state_rejects_an_unknown_inode() {
        let state = State {
            quota: Some(QuotaState {
                baseline: None,
                used: 20,
                files: Some(vec![FileChargeState {
                    inode: 4,
                    ranges: vec![(0, 20)],
                }]),
            }),
            marker: 42,
        };
        let bytes = encode(KIND, &state, LIMIT).unwrap();
        assert!(decode::<State>(KIND, &bytes, LIMIT).is_err());
    }
}
