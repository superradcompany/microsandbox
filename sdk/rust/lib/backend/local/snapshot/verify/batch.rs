//! Verify physical payloads once per algorithm while keeping descriptor use bounded.
//!
//! The caller owns the selected members' reader leases. Buckets are only a scheduling hint:
//! every alias is reopened and compared with the live representative after hashing. A retained
//! representative prevents inode reuse from turning a replaced path into a cached success.

use std::collections::BTreeMap;
use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

use microsandbox_image::checkpoint::{
    CheckpointPayloadCheck, CheckpointPayloadIntegrity, sparse_file_integrity_from_file,
};
use microsandbox_image::snapshot::UpperIntegrity;
use sha2::{Digest, Sha256};

use crate::snapshot::UpperVerifyStatus;

use super::super::file_identity::{Key as FileKey, key as file_key};

use super::{
    ensure_verification_source_unchanged, legacy_sparse_integrity_from_file,
    merkle_integrity_from_file, open_verification_source, verification_source_identity,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub(super) struct PayloadCheckFailure {
    pub kind: PayloadFailureKind,
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PayloadFailureKind {
    Missing,
    Invalid,
    Unavailable,
    Changed,
}

pub(super) struct BatchVerification {
    /// One outcome per supplied binding, including every alias of a shared physical file.
    pub outcomes: Vec<Result<UpperVerifyStatus, PayloadCheckFailure>>,
    /// Actual hash passes, counted once per physical file and required algorithm.
    pub hashes: usize,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn verify_payloads(checks: &[CheckpointPayloadCheck]) -> BatchVerification {
    verify_with_observer(checks, |_| {})
}

fn verify_with_observer(
    checks: &[CheckpointPayloadCheck],
    mut after_hash: impl FnMut(&Path),
) -> BatchVerification {
    let mut outcomes = vec![None; checks.len()];
    let mut buckets: BTreeMap<FileKey, Vec<usize>> = BTreeMap::new();
    let mut hashes = 0;
    for (index, check) in checks.iter().enumerate() {
        match open(check).and_then(|file| file_key(&file).map_err(io_failure)) {
            Ok(key) => buckets.entry(key).or_default().push(index),
            Err(error) => outcomes[index] = Some(Err(error)),
        }
    }

    for (key, indices) in buckets {
        // An alias may disappear after enumeration. Keep reporting the remaining aliases;
        // never omit the missing binding or infer its contents from another member's name.
        let representative = indices
            .iter()
            .find_map(|&index| match open(&checks[index]) {
                Ok(file) => match file_key(&file) {
                    Ok(current) if current == key => Some((index, file)),
                    Ok(_) => {
                        outcomes[index] =
                            Some(Err(changed("payload replaced before verification")));
                        None
                    }
                    Err(error) => {
                        outcomes[index] = Some(Err(io_failure(error)));
                        None
                    }
                },
                Err(error) => {
                    outcomes[index] = Some(Err(error));
                    None
                }
            });
        let Some((representative_index, mut file)) = representative else {
            continue;
        };
        let path = &checks[representative_index].path;
        let before = match file.metadata() {
            Ok(metadata) => verification_source_identity(&metadata),
            Err(error) => {
                fail_all(&mut outcomes, &indices, io_failure(error));
                continue;
            }
        };
        let mut actual = BTreeMap::new();
        let mut metadata_bytes = None;
        let retain_metadata = indices
            .iter()
            .any(|&index| checks[index].metadata_bytes.is_some());
        for &index in &indices {
            let Some(expected) = &checks[index].integrity else {
                continue;
            };
            if actual.contains_key(expected.algorithm()) {
                continue;
            }
            hashes += 1;
            let result = (|| -> io::Result<CheckpointPayloadIntegrity> {
                file.seek(SeekFrom::Start(0))?;
                match expected {
                    CheckpointPayloadIntegrity::Snapshot(UpperIntegrity::Sha256 { .. }) => {
                        let (digest, bytes) = sha256(&mut file, retain_metadata)?;
                        metadata_bytes = bytes;
                        Ok(digest.into())
                    }
                    CheckpointPayloadIntegrity::Snapshot(UpperIntegrity::SparseSha256V1 {
                        ..
                    }) => legacy_sparse_integrity_from_file(file.try_clone()?).map(Into::into),
                    CheckpointPayloadIntegrity::Snapshot(UpperIntegrity::FileMerkleBlake3V1 {
                        ..
                    }) => merkle_integrity_from_file(file.try_clone()?).map(Into::into),
                    CheckpointPayloadIntegrity::CheckpointFileV1(_) => {
                        sparse_file_integrity_from_file(&mut file)
                            .map(CheckpointPayloadIntegrity::CheckpointFileV1)
                            .map_err(io::Error::other)
                    }
                }
            })()
            .map_err(io_failure);
            actual.insert(expected.algorithm(), result);
        }
        after_hash(path);

        for &index in &indices {
            if outcomes[index].is_some() {
                continue;
            }
            let check = &checks[index];
            let result = (|| {
                let alias = open(check)?;
                if file_key(&alias).map_err(io_failure)? != key
                    || verification_source_identity(&alias.metadata().map_err(io_failure)?)
                        != before
                {
                    return Err(changed("payload alias changed during verification"));
                }
                if let Some(planned) = &check.metadata_bytes
                    && metadata_bytes.as_ref() != Some(planned)
                {
                    return Err(changed(
                        "metadata bytes differ from the decoded verification plan",
                    ));
                }
                let Some(expected) = &check.integrity else {
                    return Ok(UpperVerifyStatus::NotRecorded);
                };
                let verified = actual
                    .get(expected.algorithm())
                    .expect("every required algorithm is scheduled")
                    .as_ref()
                    .map_err(Clone::clone)?;
                if verified != expected {
                    return Err(PayloadCheckFailure {
                        kind: PayloadFailureKind::Invalid,
                        detail: format!(
                            "payload integrity mismatch: expected={}, actual={}",
                            expected.value(),
                            verified.value()
                        ),
                    });
                }
                Ok(UpperVerifyStatus::Verified {
                    algorithm: expected.algorithm().into(),
                    digest: verified.value().into(),
                })
            })();
            outcomes[index] = Some(result);
        }
        // Recheck after processing every alias. If the representative changed while outcomes
        // were assembled, invalidate earlier successes too. At most two payload handles are
        // retained between hashes, independent of the group's number of RAM/disk objects.
        if let Err(error) = ensure_verification_source_unchanged(&file, path, &before) {
            fail_all(&mut outcomes, &indices, changed(error.to_string()));
        }
    }
    BatchVerification {
        outcomes: outcomes
            .into_iter()
            .map(|outcome| outcome.expect("every payload binding is visited"))
            .collect(),
        hashes,
    }
}

fn open(check: &CheckpointPayloadCheck) -> Result<File, PayloadCheckFailure> {
    let file = open_verification_source(&check.path).map_err(|error| match error {
        crate::MicrosandboxError::Io(error) => io_failure(error),
        other => PayloadCheckFailure {
            kind: PayloadFailureKind::Invalid,
            detail: other.to_string(),
        },
    })?;
    if file.metadata().map_err(io_failure)?.len() != check.length {
        return Err(PayloadCheckFailure {
            kind: PayloadFailureKind::Invalid,
            detail: "payload length differs from verification inventory".into(),
        });
    }
    Ok(file)
}

fn sha256(file: &mut File, retain: bool) -> io::Result<(UpperIntegrity, Option<Vec<u8>>)> {
    let length = file.metadata()?.len();
    let mut reader = (&mut *file).take(length);
    let mut hasher = Sha256::new();
    let mut retained = retain.then(Vec::new);
    let mut buffer = vec![0u8; 1024 * 1024];
    let mut read = 0;
    loop {
        let count = reader.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
        read += count as u64;
        if let Some(bytes) = &mut retained {
            bytes.extend_from_slice(&buffer[..count]);
        }
    }
    if read != length || file.read(&mut [0u8; 1])? != 0 {
        return Err(io::Error::other(
            "payload length changed during verification",
        ));
    }
    Ok((
        UpperIntegrity::Sha256 {
            digest: format!("sha256:{}", hex::encode(hasher.finalize())),
        },
        retained,
    ))
}

fn fail_all(
    outcomes: &mut [Option<Result<UpperVerifyStatus, PayloadCheckFailure>>],
    indices: &[usize],
    error: PayloadCheckFailure,
) {
    for &index in indices {
        outcomes[index] = Some(Err(error.clone()));
    }
}

fn changed(detail: impl Into<String>) -> PayloadCheckFailure {
    PayloadCheckFailure {
        kind: PayloadFailureKind::Changed,
        detail: detail.into(),
    }
}

fn io_failure(error: io::Error) -> PayloadCheckFailure {
    PayloadCheckFailure {
        kind: if error.kind() == io::ErrorKind::NotFound {
            PayloadFailureKind::Missing
        } else {
            PayloadFailureKind::Unavailable
        },
        detail: error.to_string(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn check(path: &Path, bytes: &[u8]) -> CheckpointPayloadCheck {
        CheckpointPayloadCheck {
            path: path.into(),
            length: bytes.len() as u64,
            integrity: Some(
                UpperIntegrity::Sha256 {
                    digest: format!("sha256:{}", hex::encode(Sha256::digest(bytes))),
                }
                .into(),
            ),
            metadata_bytes: None,
        }
    }

    #[test]
    fn hardlinks_share_hashing_but_each_binding_must_match() {
        let root = tempfile::tempdir().unwrap();
        let a = root.path().join("a");
        let b = root.path().join("b");
        std::fs::write(&a, b"valid").unwrap();
        std::fs::hard_link(&a, &b).unwrap();
        let result = verify_payloads(&[check(&a, b"valid"), check(&b, b"wrong")]);
        assert_eq!(result.hashes, 1);
        assert!(result.outcomes[0].is_ok());
        assert_eq!(
            result.outcomes[1].as_ref().unwrap_err().kind,
            PayloadFailureKind::Invalid
        );
    }

    #[test]
    fn equal_expected_digests_do_not_hide_a_corrupt_independent_copy() {
        let root = tempfile::tempdir().unwrap();
        let a = root.path().join("a");
        let b = root.path().join("b");
        std::fs::write(&a, b"valid").unwrap();
        std::fs::write(&b, b"wrong").unwrap();
        let result = verify_payloads(&[check(&a, b"valid"), check(&b, b"valid")]);
        assert_eq!(result.hashes, 2);
        assert!(result.outcomes[0].is_ok());
        assert_eq!(
            result.outcomes[1].as_ref().unwrap_err().kind,
            PayloadFailureKind::Invalid
        );
    }

    #[test]
    fn shared_payload_supports_multiple_algorithms_and_unrecorded_aliases() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("payload");
        std::fs::write(&path, b"valid").unwrap();
        let sha = check(&path, b"valid");
        let mut merkle = sha.clone();
        merkle.integrity = Some(
            merkle_integrity_from_file(File::open(&path).unwrap())
                .unwrap()
                .into(),
        );
        let mut checkpoint = sha.clone();
        checkpoint.integrity = Some(CheckpointPayloadIntegrity::CheckpointFileV1(
            microsandbox_image::checkpoint::sparse_file_integrity(&path).unwrap(),
        ));
        assert_ne!(
            merkle.integrity.as_ref().unwrap().value(),
            checkpoint.integrity.as_ref().unwrap().value()
        );
        let mut unrecorded = sha.clone();
        unrecorded.integrity = None;
        let result = verify_payloads(&[sha, merkle, checkpoint, unrecorded]);
        assert_eq!(result.hashes, 3);
        assert!(result.outcomes.iter().all(Result::is_ok));
        assert!(matches!(
            result.outcomes[3],
            Ok(UpperVerifyStatus::NotRecorded)
        ));
    }

    #[test]
    fn checkpoint_integrity_rejects_snapshot_merkle_roots_and_corrupt_aliases() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("disk");
        let alias = root.path().join("alias");
        std::fs::write(&path, b"valid").unwrap();
        std::fs::hard_link(&path, &alias).unwrap();
        let integrity = microsandbox_image::checkpoint::sparse_file_integrity(&path).unwrap();
        let mut valid = check(&path, b"valid");
        valid.integrity = Some(CheckpointPayloadIntegrity::CheckpointFileV1(
            integrity.clone(),
        ));
        let mut wrong = valid.clone();
        wrong.path = alias;
        wrong.integrity = Some(CheckpointPayloadIntegrity::CheckpointFileV1(
            microsandbox_image::checkpoint::SparseFileIntegrity {
                root: merkle_integrity_from_file(File::open(&path).unwrap())
                    .unwrap()
                    .value()
                    .into(),
                ..integrity
            },
        ));
        let result = verify_payloads(&[valid.clone(), wrong]);
        assert_eq!(result.hashes, 1);
        assert!(
            matches!(&result.outcomes[0], Ok(UpperVerifyStatus::Verified { algorithm, .. }) if algorithm == "microsandbox.checkpoint-file/1")
        );
        assert_eq!(
            result.outcomes[1].as_ref().unwrap_err().kind,
            PayloadFailureKind::Invalid
        );
        std::fs::write(&path, b"wrong").unwrap();
        let result = verify_payloads(&[valid]);
        assert_eq!(
            result.outcomes[0].as_ref().unwrap_err().kind,
            PayloadFailureKind::Invalid
        );
    }

    #[test]
    fn changed_decoded_metadata_cannot_be_authenticated_by_later_bytes() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("metadata");
        std::fs::write(&path, b"valid").unwrap();
        let mut binding = check(&path, b"valid");
        binding.metadata_bytes = Some(b"older".to_vec());
        let result = verify_payloads(&[binding]);
        assert_eq!(
            result.outcomes[0].as_ref().unwrap_err().kind,
            PayloadFailureKind::Changed
        );
    }

    #[test]
    fn replacement_or_mutation_after_hashing_invalidates_results() {
        for replace in [false, true] {
            let root = tempfile::tempdir().unwrap();
            let a = root.path().join("a");
            let b = root.path().join("b");
            std::fs::write(&a, b"valid").unwrap();
            std::fs::hard_link(&a, &b).unwrap();
            let result = verify_with_observer(&[check(&a, b"valid"), check(&b, b"valid")], |_| {
                if replace {
                    std::fs::remove_file(&b).unwrap();
                }
                std::fs::write(&b, b"wrong").unwrap();
            });
            assert_eq!(
                result.outcomes[1].as_ref().unwrap_err().kind,
                PayloadFailureKind::Changed
            );
            if !replace {
                assert!(result.outcomes.iter().all(Result::is_err));
            }
        }
    }

    #[test]
    fn missing_and_wrong_length_bindings_are_not_omitted() {
        let root = tempfile::tempdir().unwrap();
        let missing = root.path().join("missing");
        let short = root.path().join("short");
        std::fs::write(&short, b"x").unwrap();
        let result = verify_payloads(&[check(&missing, b"valid"), check(&short, b"valid")]);
        assert_eq!(result.hashes, 0);
        assert_eq!(
            result.outcomes[0].as_ref().unwrap_err().kind,
            PayloadFailureKind::Missing
        );
        assert_eq!(
            result.outcomes[1].as_ref().unwrap_err().kind,
            PayloadFailureKind::Invalid
        );
    }

    #[cfg(unix)]
    #[test]
    fn many_objects_keep_open_file_count_bounded() {
        const CHILD: &str = "MSB_TEST_BATCH_VERIFY_LOW_FD";
        if std::env::var_os(CHILD).is_none() {
            use std::os::unix::process::CommandExt;
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child.args(["--exact", "backend::local::snapshot::verify::batch::tests::many_objects_keep_open_file_count_bounded", "--nocapture"]).env(CHILD, "1");
            // Only an async-signal-safe resource-limit call executes between fork and exec.
            unsafe {
                child.pre_exec(|| {
                    let limit = libc::rlimit {
                        rlim_cur: 64,
                        rlim_max: 64,
                    };
                    if libc::setrlimit(libc::RLIMIT_NOFILE, &limit) != 0 {
                        return Err(io::Error::last_os_error());
                    }
                    Ok(())
                });
            }
            let output = child.output().unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("611 objects checked"));
            return;
        }
        let root = tempfile::tempdir().unwrap();
        let checks: Vec<_> = (0..611)
            .map(|index| {
                let path = root.path().join(index.to_string());
                std::fs::write(&path, b"valid").unwrap();
                check(&path, b"valid")
            })
            .collect();
        let result = verify_payloads(&checks);
        assert_eq!(result.hashes, 611);
        assert!(result.outcomes.iter().all(Result::is_ok));
        println!("611 objects checked");
    }
}
