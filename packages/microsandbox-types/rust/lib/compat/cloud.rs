//! Version-neutral deserialization for current and previous cloud requests.
//!
//! Serialization always emits the canonical source-tagged union. This module
//! additionally accepts the legacy untagged `image` and `disk_snapshot_ref`
//! shapes and previous secret fields. Current payloads are read directly;
//! previous field conversion is delegated to the corresponding version module.

use std::path::PathBuf;

use serde::{Deserialize, Deserializer};

use crate::cloud::{
    CloudCreateSandboxRequest, CloudDiskImageFormat, CloudHostPattern, CloudPatch, CloudPullPolicy,
    CloudSandboxResources, CloudSandboxSpec, CloudSecretEntry, CloudSecretSource,
    CloudSecretsConfig, CloudSnapshotLocation, CloudViolationAction,
};
use crate::compat::field::Field;
use crate::compat::v0_5_0::local::secrets::SecretInjection;
use crate::compat::v0_6_7::cloud::secrets;
use crate::{SecretSubstitution, compat};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
struct SecretsConfig {
    #[serde(default)]
    entries: Vec<CloudSecretEntry>,
    #[serde(default)]
    passthrough_hosts: Field<Option<Vec<CloudHostPattern>>>,
    #[serde(default)]
    violation_action: Field<CloudViolationAction>,
    #[serde(default)]
    on_violation: Field<secrets::ViolationAction>,
}

#[derive(Deserialize)]
struct SecretEntry {
    env_var: String,
    #[serde(default)]
    value: String,
    source: Option<CloudSecretSource>,
    placeholder: String,
    #[serde(default)]
    allowed_hosts: Vec<CloudHostPattern>,
    #[serde(default)]
    substitution: Field<SecretSubstitution>,
    #[serde(default)]
    injection: Field<SecretInjection>,
    #[serde(default)]
    passthrough_hosts: Field<Vec<CloudHostPattern>>,
    #[serde(default)]
    violation_action: Field<Option<CloudViolationAction>>,
    #[serde(default)]
    on_violation: Field<Option<secrets::ViolationAction>>,
    #[serde(default = "default_true")]
    require_tls_identity: bool,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum CreateRequest {
    Tagged(TaggedRequest),
    PreviousImage(PreviousImageRequest),
    PreviousSnapshot(PreviousSnapshotRequest),
}

#[derive(Deserialize)]
#[serde(tag = "source", rename_all = "snake_case")]
enum TaggedRequest {
    Oci {
        #[serde(flatten)]
        sandbox: CloudSandboxSpec,
        reference: String,
        #[serde(default)]
        resources: CloudSandboxResources,
        #[serde(default)]
        patches: Vec<CloudPatch>,
        #[serde(default)]
        pull_policy: CloudPullPolicy,
    },
    Bind {
        #[serde(flatten)]
        sandbox: CloudSandboxSpec,
        path: PathBuf,
        #[serde(default)]
        resources: CloudSandboxResources,
        #[serde(default)]
        patches: Vec<CloudPatch>,
    },
    DiskImage {
        #[serde(flatten)]
        sandbox: CloudSandboxSpec,
        path: PathBuf,
        format: CloudDiskImageFormat,
        fstype: Option<String>,
        #[serde(default)]
        resources: CloudSandboxResources,
        #[serde(default)]
        patches: Vec<CloudPatch>,
    },
    DiskSnapshot {
        #[serde(flatten)]
        sandbox: CloudSandboxSpec,
        disk_snapshot_ref: CloudSnapshotLocation,
        #[serde(default)]
        resources: CloudSandboxResources,
        #[serde(default)]
        pull_policy: CloudPullPolicy,
    },
}

#[derive(Deserialize)]
struct PreviousImageRequest {
    #[serde(default)]
    source: Field<serde::de::IgnoredAny>,
    #[serde(default)]
    disk_snapshot_ref: Field<serde::de::IgnoredAny>,
    #[serde(flatten)]
    request: compat::v0_6_5::cloud::create::CreateRequest,
}

#[derive(Deserialize)]
struct PreviousSnapshotRequest {
    #[serde(default)]
    source: Field<serde::de::IgnoredAny>,
    #[serde(default)]
    image: Field<serde::de::IgnoredAny>,
    disk_snapshot_ref: CloudSnapshotLocation,
    #[serde(default)]
    resources: CloudSandboxResources,
    #[serde(default)]
    pull_policy: CloudPullPolicy,
    #[serde(flatten)]
    sandbox: CloudSandboxSpec,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl CreateRequest {
    fn into_current(self) -> Result<CloudCreateSandboxRequest, String> {
        let tagged = match self {
            Self::Tagged(request) => request,
            Self::PreviousImage(request) => {
                reject_tagged_fallback(request.source)?;
                if matches!(request.disk_snapshot_ref, Field::Present(_)) {
                    return Err("image and disk_snapshot_ref are mutually exclusive".into());
                }
                return request.request.try_into();
            }
            Self::PreviousSnapshot(request) => {
                reject_tagged_fallback(request.source)?;
                if matches!(request.image, Field::Present(_)) {
                    return Err("image and disk_snapshot_ref are mutually exclusive".into());
                }
                TaggedRequest::DiskSnapshot {
                    sandbox: request.sandbox,
                    disk_snapshot_ref: request.disk_snapshot_ref,
                    resources: request.resources,
                    pull_policy: request.pull_policy,
                }
            }
        };
        Ok(match tagged {
            TaggedRequest::Oci {
                sandbox,
                reference,
                resources,
                patches,
                pull_policy,
            } => CloudCreateSandboxRequest::Oci {
                sandbox,
                reference,
                resources,
                patches,
                pull_policy,
            },
            TaggedRequest::Bind {
                sandbox,
                path,
                resources,
                patches,
            } => {
                reject_disk_size(&resources)?;
                CloudCreateSandboxRequest::Bind {
                    sandbox,
                    path,
                    resources: resources.into(),
                    patches,
                }
            }
            TaggedRequest::DiskImage {
                sandbox,
                path,
                format,
                fstype,
                resources,
                patches,
            } => {
                reject_disk_size(&resources)?;
                CloudCreateSandboxRequest::DiskImage {
                    sandbox,
                    path,
                    format,
                    fstype,
                    resources: resources.into(),
                    patches,
                }
            }
            TaggedRequest::DiskSnapshot {
                sandbox,
                disk_snapshot_ref,
                resources,
                pull_policy,
            } => {
                reject_disk_size(&resources)?;
                CloudCreateSandboxRequest::DiskSnapshot {
                    sandbox,
                    disk_snapshot_ref,
                    resources: resources.into(),
                    pull_policy,
                }
            }
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl<'de> Deserialize<'de> for CloudCreateSandboxRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        CreateRequest::deserialize(deserializer)?
            .into_current()
            .map_err(serde::de::Error::custom)
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn deserialize_secrets_config<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<CloudSecretsConfig, D::Error> {
    let config = SecretsConfig::deserialize(deserializer).map_err(secret_error)?;
    let (violation_action, on_violation_hosts) =
        match (config.violation_action, config.on_violation) {
            (Field::Present(_), Field::Present(_)) => {
                return Err(secret_error("conflicting policies"));
            }
            (Field::Present(action), Field::Missing) => (Some(action), None),
            (Field::Missing, Field::Present(action)) => action.into_current(),
            (Field::Missing, Field::Missing) => (None, None),
        };
    let passthrough_hosts = match (config.passthrough_hosts, on_violation_hosts) {
        (Field::Present(_), Some(_)) => return Err(secret_error("conflicting passthrough")),
        (Field::Present(hosts), None) => hosts,
        (Field::Missing, hosts) => hosts,
    };
    Ok(CloudSecretsConfig {
        entries: config.entries,
        passthrough_hosts,
        violation_action: violation_action.unwrap_or_default(),
    })
}

pub(crate) fn deserialize_secret_entry<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<CloudSecretEntry, D::Error> {
    let entry = SecretEntry::deserialize(deserializer).map_err(secret_error)?;
    let substitution = match (entry.substitution, entry.injection) {
        (Field::Present(_), Field::Present(_)) => return Err(secret_error("conflicting scopes")),
        (Field::Present(scopes), Field::Missing) => scopes,
        (Field::Missing, Field::Present(scopes)) => scopes.into(),
        (Field::Missing, Field::Missing) => SecretSubstitution::default(),
    };
    let (violation_action, on_violation_hosts) = match (entry.violation_action, entry.on_violation)
    {
        (Field::Present(_), Field::Present(_)) => return Err(secret_error("conflicting policies")),
        (Field::Present(action), Field::Missing) => (action, None),
        (Field::Missing, Field::Present(Some(action))) => action.into_current(),
        (Field::Missing, Field::Present(None) | Field::Missing) => (None, None),
    };
    let passthrough_hosts = match (entry.passthrough_hosts, on_violation_hosts) {
        (Field::Present(_), Some(_)) => return Err(secret_error("conflicting passthrough")),
        (Field::Present(hosts), None) => hosts,
        (Field::Missing, hosts) => hosts.unwrap_or_default(),
    };
    Ok(CloudSecretEntry {
        env_var: entry.env_var,
        value: entry.value,
        source: entry.source,
        placeholder: entry.placeholder,
        allowed_hosts: entry.allowed_hosts,
        substitution,
        passthrough_hosts,
        violation_action,
        require_tls_identity: entry.require_tls_identity,
    })
}

fn default_true() -> bool {
    true
}

// Keep diagnostics independent of secret-bearing caller input.
fn secret_error<E: serde::de::Error>(_: impl std::fmt::Display) -> E {
    E::custom("invalid cloud secret configuration")
}

fn reject_disk_size(resources: &CloudSandboxResources) -> Result<(), String> {
    if resources.disk_size_mib.is_some() {
        return Err("resources.disk_size_mib is only valid for OCI source".into());
    }
    Ok(())
}

fn reject_tagged_fallback(source: Field<serde::de::IgnoredAny>) -> Result<(), String> {
    if matches!(source, Field::Present(_)) {
        return Err("invalid tagged cloud create request".into());
    }
    Ok(())
}
