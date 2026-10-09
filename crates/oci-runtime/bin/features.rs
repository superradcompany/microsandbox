//! OCI runtime feature reporting.

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn oci_features_json() -> serde_json::Value {
    serde_json::json!({
        "ociVersionMin": "1.0.0",
        "ociVersionMax": "1.2.0",
        "hooks": [],
        "mountOptions": [],
        "linux": {
            "namespaces": [],
            "capabilities": microsandbox_protocol::exec::EXEC_CAPABILITY_NAMES,
            "cgroup": {
                "v1": false,
                "v2": false,
                "systemd": false,
                "systemdUser": false,
                "rdma": false
            },
            "seccomp": {
                "enabled": false
            },
            "apparmor": {
                "enabled": false
            },
            "selinux": {
                "enabled": false
            }
        },
        "annotations": {
            "org.opencontainers.runmsb.version": env!("CARGO_PKG_VERSION")
        },
        "potentiallyUnsafeConfigAnnotations": []
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn features_reports_required_oci_probe_fields() {
        let features = oci_features_json();

        assert_eq!(features["ociVersionMin"], "1.0.0");
        assert_eq!(features["ociVersionMax"], "1.2.0");
        assert!(features["hooks"].is_array());
        assert!(features["mountOptions"].as_array().unwrap().is_empty());
        assert_eq!(features["linux"]["seccomp"]["enabled"], false);
        assert!(
            features["linux"]["capabilities"]
                .as_array()
                .unwrap()
                .iter()
                .any(|cap| cap == "CAP_CHOWN")
        );
        assert_eq!(
            features["annotations"]["org.opencontainers.runmsb.version"],
            env!("CARGO_PKG_VERSION")
        );
    }
}
