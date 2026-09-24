//! Untagged image-based cloud creation introduced in v0.6.5.

use serde::Deserialize;

use crate::cloud::{
    CloudCreateSandboxRequest, CloudPatch, CloudPullPolicy, CloudRootfsSource,
    CloudSandboxResources, CloudSandboxSpec,
};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Deserialize)]
pub(crate) struct CreateRequest {
    pub(crate) image: CloudRootfsSource,
    #[serde(default)]
    pub(crate) resources: CloudSandboxResources,
    #[serde(default)]
    pub(crate) patches: Vec<CloudPatch>,
    #[serde(default)]
    pub(crate) pull_policy: CloudPullPolicy,
    #[serde(flatten)]
    pub(crate) sandbox: CloudSandboxSpec,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl TryFrom<CreateRequest> for CloudCreateSandboxRequest {
    type Error = String;

    fn try_from(request: CreateRequest) -> Result<Self, Self::Error> {
        let CreateRequest {
            image,
            resources,
            patches,
            pull_policy,
            sandbox,
        } = request;
        match image {
            CloudRootfsSource::Oci { reference } => Ok(Self::Oci {
                sandbox,
                reference,
                resources,
                patches,
                pull_policy,
            }),
            CloudRootfsSource::Bind { path } => {
                reject_non_oci_options(&resources, pull_policy)?;
                Ok(Self::Bind {
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
                reject_non_oci_options(&resources, pull_policy)?;
                Ok(Self::DiskImage {
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
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn reject_non_oci_options(
    resources: &CloudSandboxResources,
    pull_policy: CloudPullPolicy,
) -> Result<(), String> {
    if resources.disk_size_mib.is_some() {
        return Err("resources.disk_size_mib is only valid for OCI source".to_owned());
    }
    if pull_policy != CloudPullPolicy::default() {
        return Err("pull_policy is only valid for OCI and disk_snapshot sources".to_owned());
    }
    Ok(())
}
