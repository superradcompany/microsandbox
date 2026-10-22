//! Private configuration receipts tied to one immutable checkpoint, never archive members.

use std::{
    fs,
    io::{self, Read},
    path::{Path, PathBuf},
};

#[cfg(any(feature = "runner", test))]
use std::io::Write;

#[cfg(feature = "runner")]
use microsandbox_db::DbWriteConnection;
use microsandbox_protocol::control::ConfigurationCaptureReceipt;
use microsandbox_protocol::init_observation::InitObservation;
use microsandbox_types::ExecLimits;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::MountedStorageEvidence;
use super::script_backing::ScriptBackingEvidence;
#[cfg(feature = "runner")]
use super::script_backing::ScriptBackingObservation;
#[cfg(feature = "runner")]
use super::{LiveConfigurationSelection, RetentionJournal, read_retained_init};
use super::{RetainedConfiguration, invalid};
#[cfg(any(feature = "runner", test))]
use super::{private_directory, sync_directory};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_CAPTURE_BYTES: u64 = 16 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Borrowed executor authority, used only after the checkpoint coordinator pauses the VM.
#[cfg(feature = "runner")]
pub(crate) struct ConfigurationCaptureContext<'a> {
    journal: &'a RetentionJournal,
    db: &'a DbWriteConnection,
    runtime_script_root: Option<&'a fs::File>,
    storage: Option<&'a MountedStorageEvidence>,
    exec_limits: Option<ExecLimits>,
}

#[cfg(feature = "runner")]
pub(crate) struct ConfigurationCaptureObservation<'a> {
    sandbox_directory: &'a Path,
    selected: Option<LiveConfigurationSelection<'a>>,
    scripts: ScriptBackingObservation,
    init: Option<InitObservation>,
    storage: Option<MountedStorageEvidence>,
    exec_limits: Option<ExecLimits>,
}

/// Host-private evidence from the checkpoint's paused configuration boundary.
/// Raw source values require portable projection before they may be exported.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CapturedConfiguration {
    schema: u32,
    checkpoint_id: String,
    capture_root: String,
    source: Option<RetainedConfiguration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    scripts: Option<ScriptBackingEvidence>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    init: Option<InitObservation>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    storage: Option<MountedStorageEvidence>,
    // ExecLimits has serde defaults for launch compatibility. Evidence must instead be
    // complete: a partial object cannot certify omitted values as observed defaults.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_exec_limits"
    )]
    exec_limits: Option<ExecLimits>,
}

/// Remove an unpublished receipt on error; only checkpoint publication transfers ownership.
#[cfg(any(feature = "runner", test))]
pub(crate) struct PreparedConfigurationReceipt {
    path: PathBuf,
    receipt: ConfigurationCaptureReceipt,
    published: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "runner")]
impl<'a> ConfigurationCaptureContext<'a> {
    pub(crate) fn new(
        journal: &'a RetentionJournal,
        db: &'a DbWriteConnection,
        runtime_script_root: Option<&'a fs::File>,
        storage: Option<&'a MountedStorageEvidence>,
        exec_limits: Option<ExecLimits>,
    ) -> Self {
        Self {
            journal,
            db,
            runtime_script_root,
            storage,
            exec_limits,
        }
    }

    pub(crate) async fn observe(&self) -> io::Result<ConfigurationCaptureObservation<'a>> {
        let selected = self.journal.select_live_configuration(self.db).await?;
        let scripts = ScriptBackingObservation::observe(
            self.runtime_script_root,
            selected
                .as_ref()
                .and_then(|selected| selected.configuration().source.as_ref()),
        );
        let sandbox_directory = self
            .journal
            .directory
            .parent()
            .ok_or_else(|| invalid("missing capture source directory"))?;
        let init = selected
            .as_ref()
            .map(|selected| read_retained_init(sandbox_directory, selected.configuration()))
            .transpose()?
            .flatten();
        Ok(ConfigurationCaptureObservation {
            storage: self.storage.cloned(),
            exec_limits: self.exec_limits,
            init,
            scripts,
            sandbox_directory,
            selected,
        })
    }
}

#[cfg(feature = "runner")]
impl ConfigurationCaptureObservation<'_> {
    pub(crate) async fn prepare(
        self,
        checkpoint_id: &str,
        capture_root: &str,
    ) -> io::Result<PreparedConfigurationReceipt> {
        if let Some(selected) = &self.selected
            && !selected.revalidate().await?
        {
            return Err(invalid("configuration changed during checkpoint capture"));
        }
        PreparedConfigurationReceipt::prepare_with_evidence(
            self.sandbox_directory,
            checkpoint_id,
            capture_root,
            self.selected
                .as_ref()
                .map(LiveConfigurationSelection::configuration),
            self.selected
                .as_ref()
                .and_then(LiveConfigurationSelection::pending_configuration),
            Some(self.scripts.finish()),
            self.init,
            self.storage,
            self.exec_limits,
        )
    }
}

impl CapturedConfiguration {
    /// Effective guest limits observed for this capture; absent evidence remains unknown.
    pub fn exec_limits(&self) -> Option<ExecLimits> {
        self.exec_limits
    }

    /// Negotiated observations from actual mounted backends. Older receipts return None.
    pub fn storage(&self) -> Option<&MountedStorageEvidence> {
        self.storage.as_ref()
    }

    /// Private next-start intent selected at the capture boundary, never active evidence.
    /// Older receipts omit it; do not replace that absence with current catalog settings.
    pub fn pending_configuration(&self) -> Option<&serde_json::Value> {
        self.pending.as_ref()
    }

    /// Guest boot selection bound to this capture, not a portable init default or health check.
    pub fn init(&self) -> Option<&InitObservation> {
        self.init.as_ref()
    }

    /// Actual registered-file evidence, distinct from declared scripts in the source config.
    /// This private record is not portable config or proof of full-state handle compatibility.
    pub fn scripts(&self) -> Option<&ScriptBackingEvidence> {
        self.scripts.as_ref()
    }

    /// Consume private evidence without cloning script bodies for the SDK capture pipeline.
    pub fn into_parts(self) -> (Option<RetainedConfiguration>, Option<ScriptBackingEvidence>) {
        (self.source, self.scripts)
    }

    /// Local source at capture, or explicit unavailability. This is never a default config.
    pub fn source(&self) -> Option<&RetainedConfiguration> {
        self.source.as_ref()
    }

    /// Read the exact receipt from the independently selected source sandbox and capture.
    /// The caller must verify the immutable checkpoint first and supply its expected root.
    pub fn read(
        sandbox_directory: &Path,
        checkpoint_id: &str,
        capture_root: &str,
        receipt: &ConfigurationCaptureReceipt,
    ) -> io::Result<Self> {
        let path = receipt_path(sandbox_directory, checkpoint_id)?;
        require_directory(path.parent().expect("receipt parent"))?;
        require_directory(&sandbox_directory.join("last-active"))?;
        let mut options = fs::OpenOptions::new();
        options.read(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        }
        #[cfg(windows)]
        {
            use std::os::windows::fs::OpenOptionsExt;
            options.custom_flags(
                windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT,
            );
        }
        let file = options.open(&path)?;
        if !file.metadata()?.is_file() || file.metadata()?.len() > MAX_CAPTURE_BYTES {
            return Err(invalid("invalid configuration capture file"));
        }
        let mut bytes = Vec::new();
        file.take(MAX_CAPTURE_BYTES + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_CAPTURE_BYTES
            || hex::encode(Sha256::digest(&bytes)) != receipt.sha256
        {
            return Err(invalid("configuration capture digest mismatch"));
        }
        let record: Self = serde_json::from_slice(&bytes)
            .map_err(|_| invalid("invalid configuration capture document"))?;
        if record.schema != 1
            || record.checkpoint_id != checkpoint_id
            || record.capture_root != capture_root
        {
            return Err(invalid("configuration capture identity mismatch"));
        }
        if let Some(storage) = &record.storage {
            storage.validate()?;
        }
        Ok(record)
    }
}

#[cfg(any(feature = "runner", test))]
impl PreparedConfigurationReceipt {
    /// Persist before the checkpoint root becomes visible. The caller owns capture authority.
    #[cfg(test)]
    pub(crate) fn prepare(
        sandbox_directory: &Path,
        checkpoint_id: &str,
        capture_root: &str,
        source: Option<&RetainedConfiguration>,
        pending: Option<&serde_json::Value>,
        scripts: Option<ScriptBackingEvidence>,
        init: Option<InitObservation>,
    ) -> io::Result<Self> {
        Self::prepare_with_storage(
            sandbox_directory,
            checkpoint_id,
            capture_root,
            source,
            pending,
            scripts,
            init,
            None,
        )
    }

    // Identity, source and backing are selected together under capture authority.
    #[allow(clippy::too_many_arguments)]
    #[cfg(test)]
    pub(crate) fn prepare_with_storage(
        sandbox_directory: &Path,
        checkpoint_id: &str,
        capture_root: &str,
        source: Option<&RetainedConfiguration>,
        pending: Option<&serde_json::Value>,
        scripts: Option<ScriptBackingEvidence>,
        init: Option<InitObservation>,
        storage: Option<MountedStorageEvidence>,
    ) -> io::Result<Self> {
        Self::prepare_with_evidence(
            sandbox_directory,
            checkpoint_id,
            capture_root,
            source,
            pending,
            scripts,
            init,
            storage,
            None,
        )
    }

    // All evidence is selected under one runtime capture authority; no desired defaults enter here.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn prepare_with_evidence(
        sandbox_directory: &Path,
        checkpoint_id: &str,
        capture_root: &str,
        source: Option<&RetainedConfiguration>,
        pending: Option<&serde_json::Value>,
        scripts: Option<ScriptBackingEvidence>,
        init: Option<InitObservation>,
        storage: Option<MountedStorageEvidence>,
        exec_limits: Option<ExecLimits>,
    ) -> io::Result<Self> {
        if let Some(storage) = &storage {
            storage.validate()?;
        }
        if let Some(limits) = exec_limits {
            limits.validate().map_err(invalid)?;
        }
        let path = receipt_path(sandbox_directory, checkpoint_id)?;
        let parent = sandbox_directory.join("last-active");
        private_directory(&parent)?;
        let directory = path.parent().expect("receipt parent").to_path_buf();
        private_directory(&directory)?;
        sync_directory(&parent)?;
        let mut record = CapturedConfiguration {
            schema: 1,
            checkpoint_id: checkpoint_id.into(),
            capture_root: capture_root.into(),
            source: source.cloned(),
            pending: pending.cloned(),
            scripts,
            init,
            storage,
            exec_limits,
        };
        let mut bytes = serde_json::to_vec(&record)
            .map_err(|_| invalid("could not encode configuration capture"))?;
        // Optional observations must not make an otherwise fitting capture fail. Omission
        // means unknown, never an empty inventory or permission to infer storage settings.
        if bytes.len() as u64 > MAX_CAPTURE_BYTES && record.exec_limits.take().is_some() {
            bytes = serde_json::to_vec(&record)
                .map_err(|_| invalid("could not encode configuration capture"))?;
        }
        if bytes.len() as u64 > MAX_CAPTURE_BYTES && record.storage.take().is_some() {
            bytes = serde_json::to_vec(&record)
                .map_err(|_| invalid("could not encode configuration capture"))?;
        }
        if bytes.len() as u64 > MAX_CAPTURE_BYTES {
            // Ordinary checkpoint capture requests this evidence automatically. A valid
            // workload (for example a large registered script) must remain capturable even
            // when its optional configuration cannot fit. Drop the complete observation,
            // not individual settings that a consumer might mistake for known defaults.
            record.source = None;
            record.pending = None;
            record.scripts = None;
            record.init = None;
            record.storage = None;
            record.exec_limits = None;
            bytes = serde_json::to_vec(&record)
                .map_err(|_| invalid("could not encode configuration capture"))?;
        }
        if bytes.len() as u64 > MAX_CAPTURE_BYTES {
            return Err(invalid("configuration capture exceeds size limit"));
        }
        let receipt = ConfigurationCaptureReceipt {
            sha256: hex::encode(Sha256::digest(&bytes)),
        };
        let mut temporary = tempfile::NamedTempFile::new_in(&directory)?;
        temporary.write_all(&bytes)?;
        temporary.flush()?;
        temporary.as_file().sync_all()?;
        // Never replace another capture's evidence, even on retry after an uncertain outcome.
        temporary
            .persist_noclobber(&path)
            .map_err(|error| error.error)?;
        let prepared = Self {
            path,
            receipt,
            published: false,
        };
        sync_directory(&directory)?;
        Ok(prepared)
    }

    /// The immutable checkpoint is published; keep its private receipt for local recovery.
    pub(crate) fn publish(mut self) -> ConfigurationCaptureReceipt {
        self.published = true;
        self.receipt.clone()
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[cfg(any(feature = "runner", test))]
impl Drop for PreparedConfigurationReceipt {
    fn drop(&mut self) {
        if !self.published
            && let Err(error) = fs::remove_file(&self.path)
        {
            tracing::warn!(%error, "unpublished configuration receipt cleanup failed");
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

// Validate the evidence shape before using the legacy defaultable execution-policy type.
fn deserialize_exec_limits<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> Result<Option<ExecLimits>, D::Error> {
    let value = Option::<serde_json::Value>::deserialize(deserializer)?;
    let Some(value) = value else {
        return Ok(None);
    };
    let fields = [
        "max_executions",
        "input_limit",
        "output_limit",
        "stdin_chunk_size",
        "output_chunk_size",
    ];
    if !value.as_object().is_some_and(|object| {
        object.len() == fields.len() && fields.iter().all(|field| object.contains_key(*field))
    }) {
        return Err(serde::de::Error::custom(
            "incomplete execution-limit evidence",
        ));
    }
    let limits: ExecLimits = serde_json::from_value(value).map_err(serde::de::Error::custom)?;
    limits.validate().map_err(serde::de::Error::custom)?;
    Ok(Some(limits))
}

/// Stable private receipt binding for a disk-only root, distinct from full checkpoint roots.
pub fn disk_configuration_root(
    disk: &microsandbox_image::checkpoint::DiskGenerationManifest,
) -> io::Result<String> {
    let bytes =
        serde_json::to_vec(disk).map_err(|_| invalid("could not fingerprint captured disk"))?;
    Ok(format!("disk:{}", hex::encode(Sha256::digest(bytes))))
}

fn receipt_path(sandbox_directory: &Path, checkpoint_id: &str) -> io::Result<PathBuf> {
    if checkpoint_id.is_empty()
        || checkpoint_id.len() > 128
        || !checkpoint_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
    {
        return Err(invalid("invalid configuration capture identity"));
    }
    Ok(sandbox_directory
        .join("last-active/captures")
        .join(format!("{checkpoint_id}.json")))
}

fn require_directory(path: &Path) -> io::Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err(invalid(
            "configuration capture parent is not a real directory",
        ));
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::retention::{
        CapturedScriptBacking, CapturedScriptDirectory, MountedFilesystem, MountedFilesystemKind,
        RetentionOwner,
    };

    fn source() -> RetainedConfiguration {
        RetainedConfiguration {
            owner: RetentionOwner {
                catalog_file: [1, 2],
                sandbox_id: 1,
                sandbox_created_at: Some("created".into()),
                run_id: 2,
                run_started_at: "started".into(),
                runtime_boot_id: "boot".into(),
            },
            generation: 3,
            source: Some(serde_json::json!({"env": "PRIVATE_SOURCE_VALUE"})),
        }
    }

    #[test]
    fn optional_storage_preserves_exactly_fitting_configuration() {
        let home = tempfile::tempdir().unwrap();
        let mut source = source();
        source.source = Some(serde_json::Value::String(String::new()));
        let base = CapturedConfiguration {
            schema: 1,
            checkpoint_id: "boundary".into(),
            capture_root: "root".into(),
            source: Some(source.clone()),
            pending: None,
            scripts: None,
            init: None,
            storage: None,
            exec_limits: None,
        };
        let available = MAX_CAPTURE_BYTES as usize - serde_json::to_vec(&base).unwrap().len();
        source.source = Some(serde_json::Value::String("x".repeat(available)));
        let receipt = PreparedConfigurationReceipt::prepare_with_evidence(
            home.path(),
            "boundary",
            "root",
            Some(&source),
            None,
            None,
            None,
            Some(MountedStorageEvidence::default()),
            Some(ExecLimits::default()),
        )
        .unwrap()
        .publish();
        let path = receipt_path(home.path(), "boundary").unwrap();
        assert_eq!(fs::metadata(&path).unwrap().len(), MAX_CAPTURE_BYTES);
        let captured =
            CapturedConfiguration::read(home.path(), "boundary", "root", &receipt).unwrap();
        assert!(captured.storage().is_none());
        assert!(captured.exec_limits().is_none());
        assert_eq!(captured.source().unwrap().source, source.source);
    }

    #[test]
    fn oversized_configuration_becomes_bounded_digest_bound_unknown_evidence() {
        let home = tempfile::tempdir().unwrap();
        let mut source = source();
        source.source = Some(serde_json::json!({"scripts":{"large":"x".repeat(9 * 1024 * 1024)}}));
        let receipt = PreparedConfigurationReceipt::prepare_with_evidence(
            home.path(),
            "oversized",
            "root",
            Some(&source),
            source.source.as_ref(),
            Some(ScriptBackingEvidence::Unknown {
                reason: super::super::ScriptBackingUnknown::Unreadable,
            }),
            Some(InitObservation::Builtin),
            Some(MountedStorageEvidence::default()),
            Some(ExecLimits::default()),
        )
        .unwrap()
        .publish();
        let path = receipt_path(home.path(), "oversized").unwrap();
        let bytes = fs::read(&path).unwrap();
        assert!(bytes.len() < 1024);
        let captured =
            CapturedConfiguration::read(home.path(), "oversized", "root", &receipt).unwrap();
        assert!(captured.source().is_none());
        assert!(captured.pending_configuration().is_none());
        assert!(captured.scripts().is_none());
        assert!(captured.init().is_none());
        assert!(captured.storage().is_none());
        assert!(captured.exec_limits().is_none());
        assert!(
            CapturedConfiguration::read(home.path(), "oversized", "other_root", &receipt).is_err()
        );
        let mut forged: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        forged["source"] = serde_json::to_value(&source).unwrap();
        fs::write(path, serde_json::to_vec(&forged).unwrap()).unwrap();
        assert!(CapturedConfiguration::read(home.path(), "oversized", "root", &receipt).is_err());
    }

    #[test]
    fn unknown_receipt_still_obeys_size_limit_before_publication() {
        let home = tempfile::tempdir().unwrap();
        assert!(
            PreparedConfigurationReceipt::prepare(
                home.path(),
                "oversized_root",
                &"x".repeat(MAX_CAPTURE_BYTES as usize),
                None,
                None,
                None,
                None,
            )
            .is_err()
        );
        assert!(
            !receipt_path(home.path(), "oversized_root")
                .unwrap()
                .exists()
        );
    }

    #[test]
    fn execution_limit_evidence_is_optional_complete_validated_and_digest_bound() {
        let home = tempfile::tempdir().unwrap();
        let limits = ExecLimits {
            max_executions: 7,
            ..ExecLimits::default()
        };
        for requested in [false, true] {
            let id = if requested {
                "exec-extended"
            } else {
                "exec-old"
            };
            let receipt = PreparedConfigurationReceipt::prepare_with_evidence(
                home.path(),
                id,
                "root",
                None,
                None,
                None,
                None,
                None,
                requested.then_some(limits),
            )
            .unwrap()
            .publish();
            let path = receipt_path(home.path(), id).unwrap();
            let mut json: serde_json::Value =
                serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
            assert_eq!(json.get("exec_limits").is_some(), requested);
            let read = CapturedConfiguration::read(home.path(), id, "root", &receipt).unwrap();
            assert_eq!(read.exec_limits(), requested.then_some(limits));
            if requested {
                json["exec_limits"]["max_executions"] = 8.into();
                fs::write(&path, serde_json::to_vec(&json).unwrap()).unwrap();
                assert!(CapturedConfiguration::read(home.path(), id, "root", &receipt).is_err());
            } else {
                // A strict pre-extension decoder sees no new field at all.
                assert_eq!(json.as_object().unwrap().len(), 4);
            }
        }
        let base =
            serde_json::json!({"schema":1,"checkpoint_id":"x","capture_root":"root","source":null});
        assert!(
            serde_json::from_value::<CapturedConfiguration>(base.clone())
                .unwrap()
                .exec_limits()
                .is_none()
        );
        for evidence in [
            serde_json::json!({}),
            serde_json::json!({"max_executions":7}),
            serde_json::json!({"max_executions":0,"input_limit":65536,"output_limit":1048576,"stdin_chunk_size":16384,"output_chunk_size":16384}),
            serde_json::json!({"max_executions":7,"input_limit":65536,"output_limit":1048576,"stdin_chunk_size":16384,"output_chunk_size":16384,"unknown":1}),
        ] {
            let mut json = base.clone();
            json["exec_limits"] = evidence;
            assert!(serde_json::from_value::<CapturedConfiguration>(json).is_err());
        }
    }

    #[test]
    fn negotiated_storage_is_digest_bound_and_unrequested_receipts_keep_the_old_shape() {
        let home = tempfile::tempdir().unwrap();
        let mut storage = MountedStorageEvidence::default();
        storage.0.insert(
            "/data".into(),
            MountedFilesystem {
                kind: MountedFilesystemKind::Directory,
                quota_bytes: Some(0),
            },
        );
        storage.0.insert(
            "/file".into(),
            MountedFilesystem {
                kind: MountedFilesystemKind::File,
                quota_bytes: None,
            },
        );
        for requested in [false, true] {
            let id = if requested { "extended" } else { "original" };
            let receipt = PreparedConfigurationReceipt::prepare_with_storage(
                home.path(),
                id,
                "root",
                None,
                None,
                None,
                None,
                requested.then(|| storage.clone()),
            )
            .unwrap()
            .publish();
            let path = receipt_path(home.path(), id).unwrap();
            let bytes = fs::read(&path).unwrap();
            let mut json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(json.get("storage").is_some(), requested);
            let captured = CapturedConfiguration::read(home.path(), id, "root", &receipt).unwrap();
            if requested {
                let observed = captured.storage().unwrap();
                assert_eq!(observed.get("/data").unwrap().quota_bytes, Some(0));
                assert_eq!(observed.get("/file").unwrap().quota_bytes, None);
                assert!(observed.get("/unknown").is_none());
                json["storage"]["/data"]["quota_bytes"] = serde_json::Value::Null;
                fs::write(path, serde_json::to_vec(&json).unwrap()).unwrap();
                assert!(CapturedConfiguration::read(home.path(), id, "root", &receipt).is_err());
            } else {
                assert!(captured.storage().is_none());
                // These are exactly the required fields emitted by the previous schema.
                let keys: std::collections::BTreeSet<_> = json
                    .as_object()
                    .unwrap()
                    .keys()
                    .map(String::as_str)
                    .collect();
                assert_eq!(
                    keys,
                    ["schema", "checkpoint_id", "capture_root", "source"]
                        .into_iter()
                        .collect()
                );
            }
        }
    }

    #[test]
    fn receipt_is_private_bound_and_never_overwrites_an_existing_capture() {
        let home = tempfile::tempdir().unwrap();
        let source = source();
        let prepared = PreparedConfigurationReceipt::prepare(
            home.path(),
            "checkpoint_one",
            "full:root",
            Some(&source),
            None,
            None,
            Some(InitObservation::Builtin),
        )
        .unwrap();
        let receipt = prepared.publish();
        let read =
            CapturedConfiguration::read(home.path(), "checkpoint_one", "full:root", &receipt)
                .unwrap();
        assert_eq!(read.source().unwrap().generation, 3);
        assert_eq!(read.init(), Some(&InitObservation::Builtin));
        // Later mutable runtime state cannot replace evidence sealed into this capture digest.
        std::fs::write(home.path().join("last-active/init.json"), b"new runtime").unwrap();
        assert_eq!(
            CapturedConfiguration::read(home.path(), "checkpoint_one", "full:root", &receipt)
                .unwrap()
                .init(),
            Some(&InitObservation::Builtin)
        );
        assert!(
            CapturedConfiguration::read(home.path(), "checkpoint_one", "other:root", &receipt)
                .is_err()
        );
        assert!(
            PreparedConfigurationReceipt::prepare(
                home.path(),
                "checkpoint_one",
                "other:root",
                None,
                None,
                None,
                None,
            )
            .is_err()
        );
        assert!(
            CapturedConfiguration::read(home.path(), "checkpoint_one", "full:root", &receipt)
                .is_ok()
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let path = receipt_path(home.path(), "checkpoint_one").unwrap();
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                fs::metadata(home.path().join("last-active/captures"))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
    }

    #[test]
    fn pending_intent_is_digest_bound_and_missing_legacy_evidence_stays_unknown() {
        let home = tempfile::tempdir().unwrap();
        let pending = serde_json::json!({"runtime":{"user":"PRIVATE_PENDING_USER"}});
        let receipt = PreparedConfigurationReceipt::prepare(
            home.path(),
            "pending",
            "disk:root",
            Some(&source()),
            Some(&pending),
            None,
            None,
        )
        .unwrap()
        .publish();
        let captured =
            CapturedConfiguration::read(home.path(), "pending", "disk:root", &receipt).unwrap();
        assert_eq!(captured.pending_configuration(), Some(&pending));
        assert!(
            captured
                .source()
                .unwrap()
                .source
                .as_ref()
                .unwrap()
                .get("runtime")
                .is_none()
        );
        let path = receipt_path(home.path(), "pending").unwrap();
        let mut value: serde_json::Value =
            serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
        value["pending"]["runtime"]["user"] = "OTHER_PRIVATE_USER".into();
        fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
        let error = CapturedConfiguration::read(home.path(), "pending", "disk:root", &receipt)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("digest mismatch"));
        assert!(!error.contains("PRIVATE_USER"));
        value.as_object_mut().unwrap().remove("pending");
        let bytes = serde_json::to_vec(&value).unwrap();
        fs::write(&path, &bytes).unwrap();
        let legacy = ConfigurationCaptureReceipt {
            sha256: hex::encode(Sha256::digest(&bytes)),
        };
        assert!(
            CapturedConfiguration::read(home.path(), "pending", "disk:root", &legacy)
                .unwrap()
                .pending_configuration()
                .is_none()
        );
    }

    #[test]
    fn private_receipt_digest_binds_actual_script_evidence() {
        let home = tempfile::tempdir().unwrap();
        let scripts = ScriptBackingEvidence::Observed {
            runtime_directory: CapturedScriptDirectory {
                uid: 0,
                gid: 0,
                mode: 0o755,
            },
            scripts_directory: CapturedScriptDirectory {
                uid: 44,
                gid: 45,
                mode: 0o710,
            },
            files: BTreeMap::from([(
                "task".into(),
                CapturedScriptBacking {
                    content: "ACTUAL_PRIVATE_SCRIPT".into(),
                    uid: 42,
                    gid: 43,
                    mode: 0o640,
                },
            )]),
        };
        let receipt = PreparedConfigurationReceipt::prepare(
            home.path(),
            "with_scripts",
            "full:root",
            Some(&source()),
            None,
            Some(scripts),
            None,
        )
        .unwrap()
        .publish();
        let captured =
            CapturedConfiguration::read(home.path(), "with_scripts", "full:root", &receipt)
                .unwrap();
        let Some(ScriptBackingEvidence::Observed { files, .. }) = captured.scripts() else {
            panic!("missing script evidence")
        };
        assert_eq!(files["task"].content, "ACTUAL_PRIVATE_SCRIPT");
        assert_eq!(
            (files["task"].uid, files["task"].gid, files["task"].mode),
            (42, 43, 0o640)
        );
        let path = receipt_path(home.path(), "with_scripts").unwrap();
        let bytes = fs::read_to_string(&path)
            .unwrap()
            .replace("ACTUAL_PRIVATE_SCRIPT", "FORGED_PRIVATE_SCRIPT");
        fs::write(path, bytes).unwrap();
        let error = CapturedConfiguration::read(home.path(), "with_scripts", "full:root", &receipt)
            .err()
            .unwrap()
            .to_string();
        assert!(error.contains("digest mismatch"));
        assert!(!error.contains("PRIVATE_SCRIPT"));
    }

    #[test]
    fn unpublished_receipt_rolls_back_and_unavailable_source_stays_unknown() {
        let home = tempfile::tempdir().unwrap();
        drop(
            PreparedConfigurationReceipt::prepare(
                home.path(),
                "checkpoint_one",
                "disk:root",
                None,
                None,
                None,
                None,
            )
            .unwrap(),
        );
        assert!(
            !receipt_path(home.path(), "checkpoint_one")
                .unwrap()
                .exists()
        );
        let receipt = PreparedConfigurationReceipt::prepare(
            home.path(),
            "checkpoint_one",
            "disk:root",
            None,
            None,
            None,
            None,
        )
        .unwrap()
        .publish();
        assert!(
            CapturedConfiguration::read(home.path(), "checkpoint_one", "disk:root", &receipt)
                .unwrap()
                .source()
                .is_none(),
        );
        for id in ["", "..", "../state", "a/b", "a\\b"] {
            assert!(
                PreparedConfigurationReceipt::prepare(
                    home.path(),
                    id,
                    "root",
                    None,
                    None,
                    None,
                    None
                )
                .is_err()
            );
        }
    }

    #[test]
    fn changed_and_malformed_receipts_never_expose_source_values() {
        let home = tempfile::tempdir().unwrap();
        let receipt = PreparedConfigurationReceipt::prepare(
            home.path(),
            "checkpoint_one",
            "root",
            Some(&source()),
            None,
            None,
            None,
        )
        .unwrap()
        .publish();
        let path = receipt_path(home.path(), "checkpoint_one").unwrap();
        let bytes = fs::read(&path).unwrap();
        fs::write(&path, b"PRIVATE_BAD_DOCUMENT").unwrap();
        let error = CapturedConfiguration::read(home.path(), "checkpoint_one", "root", &receipt)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("PRIVATE"));
        let wrong = ConfigurationCaptureReceipt {
            sha256: hex::encode(Sha256::digest(b"PRIVATE_BAD_DOCUMENT")),
        };
        let error = CapturedConfiguration::read(home.path(), "checkpoint_one", "root", &wrong)
            .err()
            .unwrap()
            .to_string();
        assert!(!error.contains("PRIVATE"));
        // The bound is enforced before allocation, including a sparse oversized local file.
        let file = fs::OpenOptions::new().write(true).open(&path).unwrap();
        file.set_len(MAX_CAPTURE_BYTES + 1).unwrap();
        assert!(
            CapturedConfiguration::read(home.path(), "checkpoint_one", "root", &receipt).is_err()
        );
        drop(file);
        fs::write(&path, bytes).unwrap();
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(
                &path,
                receipt_path(home.path(), "checkpoint_alias").unwrap(),
            )
            .unwrap();
            assert!(
                CapturedConfiguration::read(home.path(), "checkpoint_alias", "root", &receipt)
                    .is_err()
            );
        }
    }
}
