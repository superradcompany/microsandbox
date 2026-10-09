//! Portable snapshot metadata and execution defaults, excluding host resource authorization.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use typed_path::Utf8UnixPath;

use super::Manifest;
use crate::domain::{
    EnvVar, HandoffInit, MountOptions, RlimitResource, SecurityProfile, TransparentHugePagePolicy,
};
use crate::error::{SnapshotManifestError, SnapshotManifestResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Must-understand key for the sandbox defaults retained by a snapshot.
pub const RESTORE_DEFAULTS_EXTENSION: &str = "microsandbox.restore-defaults";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Portable restore defaults; the user applies to new commands, never captured process credentials.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RestoreDefaults {
    /// Effective sandbox-level user, not a one-command exec override.
    pub user: Option<String>,
    /// Captured guest settings, absent in released user-only payloads.
    /// Absence inherits legacy defaults; present empty values remain authoritative.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<SnapshotMetadataV1>,
}

/// Durable guest settings, excluding host bindings, destination policy and one-shot launch intent.
/// Stored in the `config` field of the existing `restore-defaults` extension.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SnapshotMetadataV1 {
    /// Effective guest environment, including image defaults.
    pub env: Vec<EnvVar>,
    /// Default directory for new executions.
    pub workdir: Option<String>,
    /// Default guest shell.
    pub shell: Option<String>,
    /// Materialized script bodies, including their interpreter lines.
    pub scripts: BTreeMap<String, String>,
    /// Durable workload entrypoint; capture does not authorize executing it on restore.
    pub entrypoint: Option<Vec<String>>,
    /// Durable workload arguments; capture does not authorize executing them on restore.
    pub cmd: Option<Vec<String>>,
    /// Explicit guest hostname, or destination-derived hostname when absent.
    pub hostname: Option<String>,
    /// PID 1 handoff, without arguments appended for a one-shot workload.
    pub init: Option<HandoffInit>,
    /// Sandbox-wide guest resource limits.
    pub rlimits: Vec<GuestRlimitV1>,
    /// In-guest security policy, retained for later cold starts too.
    pub security: SecurityProfile,
    /// Guest transparent huge-page boot policy.
    pub thp: TransparentHugePagePolicy,
    /// Guest-memory mount declarations. Cold boot creates empty filesystems.
    pub tmpfs: Vec<GuestTmpfsV1>,
}

/// A portable resource limit. Decimal strings preserve all 64 bits in canonical JSON.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestRlimitV1 {
    /// POSIX resource to limit.
    pub resource: RlimitResource,
    /// Soft limit, including `u64::MAX` for unlimited.
    #[serde(with = "decimal_limit")]
    pub soft: u64,
    /// Hard limit, including `u64::MAX` for unlimited.
    #[serde(with = "decimal_limit")]
    pub hard: u64,
}

/// A tmpfs declaration that cannot encode a host path or named resource.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GuestTmpfsV1 {
    /// Absolute guest mount path.
    pub guest: String,
    /// Size limit in MiB, or the guest kernel default.
    pub size_mib: Option<u32>,
    /// Guest mount flags and ownership.
    pub options: MountOptions,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Manifest {
    /// Record portable restore settings without embedding source host bindings or credentials.
    pub fn set_restore_defaults(
        &mut self,
        defaults: RestoreDefaults,
    ) -> SnapshotManifestResult<()> {
        validate_defaults(&defaults)?;
        // Preserve the released empty-payload behavior. Captured configuration must remain
        // present even without a user override, because empty settings are authoritative.
        if defaults.user.is_none() && defaults.config.is_none() {
            self.extensions.remove(RESTORE_DEFAULTS_EXTENSION);
            self.requires
                .retain(|key| key != RESTORE_DEFAULTS_EXTENSION);
            return Ok(());
        }
        self.extensions.insert(
            RESTORE_DEFAULTS_EXTENSION.into(),
            serde_json::to_value(defaults)
                .map_err(|error| SnapshotManifestError::ManifestParse(error.to_string()))?,
        );
        // Readers must understand these defaults rather than silently changing restored behavior.
        self.requires.push(RESTORE_DEFAULTS_EXTENSION.into());
        self.requires.sort();
        self.requires.dedup();
        Ok(())
    }

    /// Read bounded, typed defaults; released snapshots without the extension use image defaults.
    pub fn restore_defaults(&self) -> SnapshotManifestResult<RestoreDefaults> {
        let Some(value) = self.extensions.get(RESTORE_DEFAULTS_EXTENSION) else {
            return Ok(RestoreDefaults::default());
        };
        let defaults: RestoreDefaults = serde_json::from_value(value.clone()).map_err(|error| {
            SnapshotManifestError::ManifestParse(format!("invalid restore defaults: {error}"))
        })?;
        validate_defaults(&defaults)?;
        if defaults.config.is_some()
            && !self
                .requires
                .iter()
                .any(|key| key == RESTORE_DEFAULTS_EXTENSION)
        {
            return invalid("captured restore configuration must be a required extension");
        }
        Ok(defaults)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_defaults(defaults: &RestoreDefaults) -> SnapshotManifestResult<()> {
    if defaults
        .user
        .as_ref()
        .is_some_and(|user| user.is_empty() || user.len() > 4096 || user.contains('\0'))
    {
        return Err(SnapshotManifestError::ManifestParse(
            "invalid snapshot default exec user".into(),
        ));
    }
    if let Some(config) = &defaults.config {
        validate(config)?;
    }
    Ok(())
}

fn invalid<T>(message: &str) -> SnapshotManifestResult<T> {
    Err(SnapshotManifestError::ManifestParse(message.into()))
}

fn validate(config: &SnapshotMetadataV1) -> SnapshotManifestResult<()> {
    // Strings become process arguments, environment entries, or filesystem paths.
    let value = serde_json::to_value(config)
        .map_err(|error| SnapshotManifestError::ManifestParse(error.to_string()))?;

    fn contains_nul(value: &serde_json::Value) -> bool {
        match value {
            serde_json::Value::String(value) => value.contains('\0'),
            serde_json::Value::Array(values) => values.iter().any(contains_nul),
            serde_json::Value::Object(values) => values
                .iter()
                .any(|(key, value)| key.contains('\0') || contains_nul(value)),
            _ => false,
        }
    }

    if contains_nul(&value) {
        return invalid("NUL in snapshot guest configuration");
    }

    if config
        .env
        .iter()
        .any(|env| env.key.is_empty() || env.key.contains('='))
    {
        return invalid("invalid snapshot guest environment key");
    }

    if config
        .scripts
        .keys()
        .any(|name| Utf8UnixPath::new(name).file_name() != Some(name.as_str()))
    {
        return invalid("snapshot script name must be a single filename");
    }

    if let Some(init) = &config.init
        && ((init.cmd != "auto" && !init.cmd.starts_with('/'))
            || init.cmd.contains('\\')
            || init
                .env
                .iter()
                .any(|(key, _)| key.is_empty() || key.contains('=')))
    {
        return invalid("invalid snapshot handoff init");
    }

    if config.rlimits.iter().any(|limit| limit.soft > limit.hard) {
        return invalid("snapshot resource limit soft value exceeds hard value");
    }

    let mut paths = BTreeSet::new();
    for mount in &config.tmpfs {
        if !mount.guest.starts_with('/')
            || mount.guest == "/"
            || mount.guest.contains([':', ';', ','])
            || mount.guest[1..]
                .split('/')
                .any(|part| part.is_empty() || part == "." || part == "..")
            || !paths.insert(&mount.guest)
            || mount.options.override_uid.is_some() != mount.options.override_gid.is_some()
        {
            return invalid("invalid or duplicate snapshot tmpfs declaration");
        }
    }
    Ok(())
}

mod decimal_limit {
    use serde::{Deserialize, Deserializer, Serializer};

    //--------------------------------------------------------------------------------------------------
    // Functions
    //--------------------------------------------------------------------------------------------------

    pub fn serialize<S: Serializer>(value: &u64, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_str(&value.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<u64, D::Error> {
        let value = String::deserialize(deserializer)?;
        let number = value.parse::<u64>().map_err(serde::de::Error::custom)?;
        if number.to_string() != value {
            return Err(serde::de::Error::custom(
                "resource limit must be a canonical decimal string",
            ));
        }
        Ok(number)
    }
}
