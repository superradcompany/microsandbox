//! Mapping of OCI process security to guest execution settings.

use anyhow::Result;
use microsandbox_protocol::exec::ExecSecurity;
use oci_spec::runtime::Process;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

pub(crate) const SECURITY_LABEL: &str = "oci.microsandbox.process_security";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn process_security(process: &Process) -> Result<ExecSecurity> {
    Ok(ExecSecurity {
        no_new_privileges: process.no_new_privileges().unwrap_or(false),
        capabilities: process
            .capabilities()
            .as_ref()
            .map(|caps| serde_json::from_value(serde_json::to_value(caps)?))
            .transpose()?,
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_explicit_empty_capabilities_and_no_new_privileges() {
        let process: Process = serde_json::from_value(serde_json::json!({
            "user": {"uid": 0, "gid": 0}, "cwd": "/",
            "noNewPrivileges": true, "capabilities": {}
        }))
        .unwrap();
        let policy = process_security(&process).unwrap();
        assert!(policy.no_new_privileges);
        assert_eq!(policy.capabilities, Some(Default::default()));
    }

    #[test]
    fn preserves_capability_names_and_absent_policy() {
        let mut value = serde_json::json!({"user": {"uid": 0, "gid": 0}, "cwd": "/"});
        let process: Process = serde_json::from_value(value.clone()).unwrap();
        assert_eq!(process_security(&process).unwrap(), ExecSecurity::default());
        value["capabilities"] = serde_json::json!({"bounding": ["CAP_CHOWN"]});
        let process: Process = serde_json::from_value(value).unwrap();
        assert_eq!(
            process_security(&process)
                .unwrap()
                .capabilities
                .unwrap()
                .bounding,
            ["CAP_CHOWN"]
        );
    }
}
