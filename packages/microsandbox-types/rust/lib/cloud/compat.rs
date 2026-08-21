//! Backward-compatible deserialization for cloud sandbox creation.
//!
//! Serialization always emits the canonical source-tagged union. This module
//! additionally accepts the legacy untagged `image` and `disk_snapshot_ref`
//! shapes without mixing migration mechanics into the main contract module.

use serde::Deserialize;
use serde::de::DeserializeOwned;

use super::{
    CloudCreateSandboxRequest, CloudPullPolicy, CloudRootfsSource, CloudSandboxResources,
    CloudSandboxSpec,
};

type CompatResult<T> = Result<T, String>;

impl<'de> Deserialize<'de> for CloudCreateSandboxRequest {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let value = serde_json::Value::deserialize(deserializer)?;
        deserialize_request(value).map_err(serde::de::Error::custom)
    }
}

fn deserialize_request(value: serde_json::Value) -> CompatResult<CloudCreateSandboxRequest> {
    let object = value
        .as_object()
        .ok_or_else(|| "cloud sandbox create request must be an object".to_owned())?;
    let has_image = object.contains_key("image");
    let has_disk_snapshot = object.contains_key("disk_snapshot_ref");

    if let Some(source) = object.get("source") {
        let source = source
            .as_str()
            .ok_or_else(|| "cloud sandbox create source must be a string".to_owned())?
            .to_owned();
        let mut value = value;
        request_object_mut(&mut value)?.remove("source");
        return deserialize_tagged_request(value, &source);
    }

    match (has_image, has_disk_snapshot) {
        (true, false) => deserialize_legacy_image_request(value),
        (false, true) => deserialize_tagged_request(value, "disk_snapshot"),
        (true, true) => Err("image and disk_snapshot_ref are mutually exclusive".to_owned()),
        (false, false) => Err("exactly one of image and disk_snapshot_ref is required".to_owned()),
    }
}

fn deserialize_tagged_request(
    value: serde_json::Value,
    source: &str,
) -> CompatResult<CloudCreateSandboxRequest> {
    match source {
        "oci" => deserialize_oci_request(value),
        "bind" => deserialize_bind_request(value),
        "disk_image" => deserialize_disk_image_request(value),
        "disk_snapshot" => deserialize_disk_snapshot_request(value),
        unknown => Err(format!(
            "unknown variant `{unknown}`, expected one of `oci`, `bind`, `disk_image`, `disk_snapshot`"
        )),
    }
}

fn deserialize_oci_request(
    mut value: serde_json::Value,
) -> CompatResult<CloudCreateSandboxRequest> {
    let object = request_object_mut(&mut value)?;
    let reference = take_required_field(object, "reference")?;
    let resources = take_default_field(object, "resources")?;
    let patches = take_default_field(object, "patches")?;
    let pull_policy = take_default_field(object, "pull_policy")?;
    let sandbox = deserialize_common_spec(value)?;

    Ok(CloudCreateSandboxRequest::Oci {
        sandbox,
        reference,
        resources,
        patches,
        pull_policy,
    })
}

fn deserialize_bind_request(
    mut value: serde_json::Value,
) -> CompatResult<CloudCreateSandboxRequest> {
    let object = request_object_mut(&mut value)?;
    let path = take_required_field(object, "path")?;
    let resources = take_default_field(object, "resources")?;
    let patches = take_default_field(object, "patches")?;
    let sandbox = deserialize_common_spec(value)?;

    Ok(CloudCreateSandboxRequest::Bind {
        sandbox,
        path,
        resources,
        patches,
    })
}

fn deserialize_disk_image_request(
    mut value: serde_json::Value,
) -> CompatResult<CloudCreateSandboxRequest> {
    let object = request_object_mut(&mut value)?;
    let path = take_required_field(object, "path")?;
    let format = take_required_field(object, "format")?;
    let fstype = take_default_field(object, "fstype")?;
    let resources = take_default_field(object, "resources")?;
    let patches = take_default_field(object, "patches")?;
    let sandbox = deserialize_common_spec(value)?;

    Ok(CloudCreateSandboxRequest::DiskImage {
        sandbox,
        path,
        format,
        fstype,
        resources,
        patches,
    })
}

fn deserialize_disk_snapshot_request(
    mut value: serde_json::Value,
) -> CompatResult<CloudCreateSandboxRequest> {
    let object = request_object_mut(&mut value)?;
    let disk_snapshot_ref = take_required_field(object, "disk_snapshot_ref")?;
    let resources = take_default_field(object, "resources")?;
    let pull_policy = take_default_field(object, "pull_policy")?;
    let sandbox = deserialize_common_spec(value)?;

    Ok(CloudCreateSandboxRequest::DiskSnapshot {
        sandbox,
        disk_snapshot_ref,
        resources,
        pull_policy,
    })
}

fn deserialize_legacy_image_request(
    mut value: serde_json::Value,
) -> CompatResult<CloudCreateSandboxRequest> {
    let object = request_object_mut(&mut value)?;
    let image: CloudRootfsSource = take_required_field(object, "image")?;
    let resources: CloudSandboxResources = take_default_field(object, "resources")?;
    let patches = take_default_field(object, "patches")?;
    let pull_policy: CloudPullPolicy = take_default_field(object, "pull_policy")?;
    let sandbox = deserialize_common_spec(value)?;

    match image {
        CloudRootfsSource::Oci { reference } => Ok(CloudCreateSandboxRequest::Oci {
            sandbox,
            reference,
            resources,
            patches,
            pull_policy,
        }),
        CloudRootfsSource::Bind { path } => {
            reject_non_oci_legacy_options(&resources, pull_policy)?;
            Ok(CloudCreateSandboxRequest::Bind {
                sandbox,
                path,
                resources: resources.into(),
                patches,
            })
        }
        CloudRootfsSource::DiskImage {
            path,
            format,
            fstype,
        } => {
            reject_non_oci_legacy_options(&resources, pull_policy)?;
            Ok(CloudCreateSandboxRequest::DiskImage {
                sandbox,
                path,
                format,
                fstype,
                resources: resources.into(),
                patches,
            })
        }
    }
}

fn reject_non_oci_legacy_options(
    resources: &CloudSandboxResources,
    pull_policy: CloudPullPolicy,
) -> CompatResult<()> {
    if resources.disk_size_mib.is_some() {
        return Err("resources.disk_size_mib is only valid for OCI source".to_owned());
    }
    if pull_policy != CloudPullPolicy::default() {
        return Err("pull_policy is only valid for OCI and disk_snapshot sources".to_owned());
    }
    Ok(())
}

fn request_object_mut(
    value: &mut serde_json::Value,
) -> CompatResult<&mut serde_json::Map<String, serde_json::Value>> {
    value
        .as_object_mut()
        .ok_or_else(|| "cloud sandbox create request must be an object".to_owned())
}

fn take_required_field<T: DeserializeOwned>(
    object: &mut serde_json::Map<String, serde_json::Value>,
    name: &'static str,
) -> CompatResult<T> {
    let value = object
        .remove(name)
        .ok_or_else(|| format!("missing field `{name}`"))?;
    serde_json::from_value(value).map_err(|error| error.to_string())
}

fn take_default_field<T: Default + DeserializeOwned>(
    object: &mut serde_json::Map<String, serde_json::Value>,
    name: &'static str,
) -> CompatResult<T> {
    object
        .remove(name)
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| error.to_string())
        .map(Option::unwrap_or_default)
}

fn deserialize_common_spec(value: serde_json::Value) -> CompatResult<CloudSandboxSpec> {
    serde_json::from_value(value).map_err(|error| error.to_string())
}
