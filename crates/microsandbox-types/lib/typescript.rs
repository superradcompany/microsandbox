//! TypeScript binding generation helpers.

use ts_rs::TS;

use crate::{
    CloudCreateSandboxRequest, CloudErrorBody, CloudErrorDetails, CloudMessageResponse,
    CloudPaginated, CloudSandbox, CloudSandboxStatus, DiskImageFormat, HostPermissions, LogSource,
    MountOptions, OciRootfsSource, Rlimit, RlimitResource, RootfsSource, SandboxPolicy,
    SecurityProfile, StatVirtualization,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return the checked-in TypeScript bindings for the shared microsandbox contracts.
pub fn bindings() -> &'static str {
    include_str!("../bindings/typescript/index.ts")
}

/// Render raw `ts-rs` declarations for the shared microsandbox contracts.
pub fn declarations() -> Vec<String> {
    let cfg = ts_rs::Config::new().with_large_int("number");

    vec![
        DiskImageFormat::decl(&cfg),
        OciRootfsSource::decl(&cfg),
        RootfsSource::decl(&cfg),
        StatVirtualization::decl(&cfg),
        HostPermissions::decl(&cfg),
        SecurityProfile::decl(&cfg),
        MountOptions::decl(&cfg),
        SandboxPolicy::decl(&cfg),
        RlimitResource::decl(&cfg),
        Rlimit::decl(&cfg),
        LogSource::decl(&cfg),
        CloudCreateSandboxRequest::decl(&cfg),
        CloudSandbox::decl(&cfg),
        CloudSandboxStatus::decl(&cfg),
        CloudPaginated::<CloudSandbox>::decl(&cfg),
        CloudMessageResponse::decl(&cfg),
        CloudErrorBody::decl(&cfg),
        CloudErrorDetails::decl(&cfg),
    ]
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn checked_in_bindings_include_cloud_contracts() {
        let bindings = bindings();

        for name in [
            "DiskImageFormat",
            "OciRootfsSource",
            "RootfsSource",
            "StatVirtualization",
            "HostPermissions",
            "SecurityProfile",
            "MountOptions",
            "SandboxPolicy",
            "RlimitResource",
            "Rlimit",
            "LogSource",
            "CloudCreateSandboxRequest",
            "CloudSandbox",
            "CloudSandboxStatus",
            "CloudPaginated",
            "CloudMessageResponse",
            "CloudErrorBody",
            "CloudErrorDetails",
        ] {
            assert!(bindings.contains(name), "missing {name}");
        }
    }

    #[test]
    fn ts_rs_renders_cloud_contract_declarations() {
        let declarations = declarations();

        assert_eq!(declarations.len(), 18);
        assert!(
            declarations
                .iter()
                .any(|decl| decl.contains("RootfsSource"))
        );
        assert!(declarations.iter().any(|decl| decl.contains("Rlimit")));
        assert!(
            declarations
                .iter()
                .any(|decl| decl.contains("CloudCreateSandboxRequest"))
        );
        assert!(
            declarations
                .iter()
                .any(|decl| decl.contains("CloudSandboxStatus"))
        );
    }
}
