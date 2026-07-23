//! OCI runtime feature reporting.

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn oci_features_json() -> serde_json::Value {
    serde_json::json!({
        "ociVersionMin": "1.0.0",
        "ociVersionMax": "1.2.0",
        "hooks": [],
        "mountOptions": [
            "bind",
            "rbind",
            "ro",
            "rw",
            "nosuid",
            "nodev",
            "noexec"
        ],
        "linux": {
            "namespaces": [],
            "capabilities": [],
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
            "org.opencontainers.microsandbox-runtime.version": env!("CARGO_PKG_VERSION")
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
        assert!(
            features["mountOptions"]
                .as_array()
                .unwrap()
                .contains(&serde_json::Value::String("rbind".to_string()))
        );
        assert_eq!(features["linux"]["seccomp"]["enabled"], false);
        assert_eq!(
            features["annotations"]["org.opencontainers.microsandbox-runtime.version"],
            env!("CARGO_PKG_VERSION")
        );
    }
}
