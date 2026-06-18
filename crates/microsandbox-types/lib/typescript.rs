//! TypeScript binding generation helpers.

use ts_rs::TS;

use crate::{
    CloudCreateSandboxRequest, CloudErrorBody, CloudErrorDetails, CloudMessageResponse,
    CloudPaginated, CloudSandbox, CloudSandboxStatus,
};

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Return the checked-in TypeScript bindings for the shared microsandbox contracts.
pub fn bindings() -> &'static str {
    include_str!("../bindings/typescript/index.ts")
}

/// Render raw `ts-rs` declarations for the shared cloud contracts.
pub fn declarations() -> Vec<String> {
    let cfg = ts_rs::Config::new().with_large_int("number");

    vec![
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

        assert_eq!(declarations.len(), 7);
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
