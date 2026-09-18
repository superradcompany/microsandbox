use std::path::Path;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use microsandbox_protocol::bootstrap::*;
use microsandbox_types::CpuPlacement;
use serde_json::{Value, json};

use super::LaunchConfig;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn historical(env: Vec<String>) -> Value {
    // Required fields from the v0.6.0 LaunchConfig contract. Keep this fixture
    // independent of current serialization so new required fields are detected.
    json!({"db_path":"/home/db/msb.db","db_connect_timeout_secs":5,
        "log_dir":"/home/logs","runtime_dir":"/home/sandboxes/test/runtime",
        "sandboxes_dir":"/home/sandboxes","agent_sock":"/home/run/agent/test.sock",
        "libkrunfw_path":"/home/lib/libkrunfw.so.5","startup":null,
        "lifecycle":{"max_duration_secs":null,"idle_timeout_secs":null},
        "metrics":{"sample_interval_ms":1000,"disabled":true,"slot":null},
        "rootfs":{"path":null,"disk":"/home/root.vmdk","disk_format":"vmdk","disk_readonly":true,"upper":"/home/upper.ext4"},
        "mounts":[],"disks":[],"init_path":null,"env":env,"workdir":"/tmp",
        "exec_path":null,"exec_args":[],"network":null,"sandbox_slot":1})
}

fn decode(value: &Value) -> Result<LaunchConfig, String> {
    LaunchConfig::from_json(&serde_json::to_vec(value).unwrap())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[test]
fn legacy_bootstrap_preserves_every_setting_and_derives_lease_paths() {
    let args = vec!["", "a b", "semi;colon", "=", "雪"];
    let handoff_env = vec![("A", "  value=;:雪  ")];
    let env = vec![
        "APP=  value=;:雪  ".into(),
        "MSB_BLOCK_ROOT=kind=oci-erofs,lower=/dev/vda,upper=/dev/vdb,upper_fstype=ext4".into(),
        "MSB_DIR_MOUNTS=files:/files:ro,noexec,nosuid,nodev".into(),
        "MSB_FILE_MOUNTS=config:app.json:/etc/app.json:ro".into(),
        "MSB_DISK_MOUNTS=data:/data:fstype=ext4,nosuid,nodev".into(),
        "MSB_TMPFS=/scratch:size=64,mode=1770,noexec".into(),
        "MSB_SECURITY_PROFILE=restricted".into(),
        "MSB_USER=1000:1000".into(),
        "MSB_HOSTNAME=  guest-name  ".into(),
        "MSB_HOST_ALIAS=host.test".into(),
        "MSB_RLIMITS=nofile=512:1024;core=0".into(),
        "MSB_NET=iface=eth0,mac=02:00:00:00:00:01,mtu=1400".into(),
        "MSB_NET_IPV4=addr=172.16.0.2/30,gw=172.16.0.1,dns=172.16.0.1".into(),
        "MSB_NET_IPV6=addr=fd42::2/64,gw=fd42::1,dns=fd42::1".into(),
        "MSB_HANDOFF_INIT=/sbin/init".into(),
        "MSB_HANDOFF_INIT_CWD=/work space".into(),
        format!(
            "MSB_HANDOFF_INIT_ARGS={}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&args).unwrap())
        ),
        format!(
            "MSB_HANDOFF_INIT_ENV={}",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&handoff_env).unwrap())
        ),
    ];
    let config = decode(&historical(env.clone())).unwrap();
    assert_eq!(config.cpu_placement, CpuPlacement::Inherit);
    assert_eq!(config.cpu_lease_dir, Path::new("/home/run/cpu-leases"));
    assert_eq!(
        config.writeback_lease_dir,
        Path::new("/home/run/writeback-leases")
    );
    let b = config.bootstrap;
    assert_eq!(b.default_cwd.as_deref(), Some("/tmp"));
    assert_eq!(
        b.default_env
            .iter()
            .map(|e| format!("{}={}", e.key, e.value))
            .collect::<Vec<_>>(),
        env
    );
    assert_eq!(
        b.block_root,
        Some(BootstrapBlockRoot::OciErofs {
            lower: "/dev/vda".into(),
            upper: BootstrapBlockRootUpper::Device {
                device: "/dev/vdb".into(),
                fstype: "ext4".into()
            }
        })
    );
    assert_eq!(
        b.dir_mounts,
        vec![BootstrapDirMount {
            tag: "files".into(),
            guest_path: "/files".into(),
            flags: BootstrapMountFlags {
                readonly: true,
                noexec: true,
                nosuid: true,
                nodev: true
            }
        }]
    );
    assert_eq!(b.file_mounts[0].filename, "app.json");
    assert!(b.file_mounts[0].flags.readonly);
    assert_eq!(b.disk_mounts[0].fstype.as_deref(), Some("ext4"));
    assert!(b.disk_mounts[0].flags.nosuid && b.disk_mounts[0].flags.nodev);
    assert_eq!(b.tmpfs_mounts[0].size_mib, Some(64));
    assert_eq!(b.tmpfs_mounts[0].mode, Some(0o1770));
    assert!(b.tmpfs_mounts[0].flags.noexec);
    assert_eq!(b.security_profile, BootstrapSecurityProfile::Restricted);
    assert_eq!(b.hostname.as_deref(), Some("guest-name"));
    assert_eq!(b.user.as_deref(), Some("1000:1000"));
    assert_eq!(b.host_alias.as_deref(), Some("host.test"));
    assert_eq!(b.rlimits.len(), 2);
    assert_eq!(b.rlimits[0].soft, 512);
    assert_eq!(b.rlimits[0].hard, 1024);
    let network = b.network.unwrap();
    assert_eq!(network.mtu, 1400);
    assert_eq!(network.mac, [2, 0, 0, 0, 0, 1]);
    assert_eq!(network.ipv4.unwrap().prefix_len, 30);
    assert_eq!(network.ipv6.unwrap().prefix_len, 64);
    let handoff = b.handoff_init.unwrap();
    assert_eq!(handoff.args, args);
    assert_eq!(handoff.cwd.as_deref(), Some("/work space"));
    assert_eq!(handoff.env[0].value, handoff_env[0].1);
}

#[test]
fn explicit_bootstrap_remains_authoritative_and_modern_fields_stay_required() {
    let mut value = serde_json::to_value(LaunchConfig::default()).unwrap();
    value.as_object_mut().unwrap().remove("execution");
    value["env"] = json!(["MSB_SECURITY_PROFILE=restricted", "SECRET=old"]);
    value["workdir"] = json!("/old");
    assert_eq!(decode(&value).unwrap().bootstrap, GuestBootstrap::default());
    value["bootstrap"] = Value::Null;
    assert!(decode(&value).is_err());
    value["bootstrap"] = json!({});
    value.as_object_mut().unwrap().remove("cpu_lease_dir");
    assert!(decode(&value).is_err());
}

#[test]
fn incomplete_lease_group_is_not_defaulted_and_legacy_root_is_required() {
    let mut value = historical(vec![]);
    value["cpu_placement"] = json!("inherit");
    assert!(decode(&value).is_err());
    let mut value = historical(vec![]);
    value["agent_sock"] = json!("endpoint");
    value["sandboxes_dir"] = json!("sandboxes");
    assert!(decode(&value).is_err());
    value["sandboxes_dir"] = json!("/other/sandboxes");
    assert_eq!(
        decode(&value).unwrap().cpu_lease_dir,
        Path::new("/other/run/cpu-leases")
    );
    value["run_dir"] = json!("/explicit/run");
    assert_eq!(
        decode(&value).unwrap().cpu_lease_dir,
        Path::new("/explicit/run/cpu-leases")
    );
}

#[test]
fn invalid_legacy_input_fails_without_echoing_values() {
    for entry in [
        "secret-marker",
        "=secret-marker",
        "A=secret-marker\0",
        "MSB_SECURITY_PROFILE=secret-marker",
        "MSB_BLOCK_ROOT=kind=secret-marker",
        "MSB_DIR_MOUNTS=x:secret-marker",
        "MSB_DIR_MOUNTS=x:/ok:ro,rw",
        "MSB_FILE_MOUNTS=x:f:/ok:fstype=ext4",
        "MSB_TMPFS=/x:mode=secret-marker",
        "MSB_RLIMITS=nofile=20:10",
        "MSB_RLIMITS=nofile=1;nofile=2",
        "MSB_NET=iface=eth0,mac=secret-marker",
        "MSB_HANDOFF_INIT=secret-marker",
    ] {
        let err = decode(&historical(vec![entry.into()])).unwrap_err();
        assert!(!err.contains("secret-marker"), "{err}");
    }
}

#[test]
fn repeated_environment_keys_and_empty_metadata_follow_legacy_behavior() {
    let config = decode(&historical(vec![
        "MSB_HOSTNAME=old".into(),
        "MSB_HOSTNAME= new ".into(),
        "MSB_USER=  ".into(),
        "MSB_BLOCK_ROOT=kind=oci-erofs,lower=/dev/vda,upper=tmpfs,upper_size_mib=128".into(),
    ]))
    .unwrap();
    assert_eq!(config.bootstrap.hostname.as_deref(), Some("new"));
    assert!(config.bootstrap.user.is_none());
    assert!(matches!(
        config.bootstrap.block_root,
        Some(BootstrapBlockRoot::OciErofs {
            upper: BootstrapBlockRootUpper::Tmpfs {
                size_mib: Some(128)
            },
            ..
        })
    ));
}

#[test]
fn duplicate_json_policy_keys_are_rejected() {
    for bytes in [
        br#"{"env":[],"env":[]}"#.as_slice(),
        br#"{"bootstrap":{"security_profile":"restricted","security_profile":"default"}}"#,
    ] {
        assert!(
            LaunchConfig::from_json(bytes)
                .unwrap_err()
                .contains("duplicate")
        );
    }
}

#[cfg(feature = "net")]
#[test]
fn legacy_connection_limits_keep_historical_budgets_and_refuse_ambiguous_zero() {
    use microsandbox_network::config::ConnectionLimit;

    // Include real released producer records, not only current serializers. The
    // v0.6.0 fixture covers the older environment-based launch shape as well.
    let inputs = [
        historical(vec![]),
        serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/launch-v0.6.10.json"
        ))
        .unwrap(),
        serde_json::from_slice(include_bytes!(
            "../../../tests/fixtures/launch-v0.6.18.json"
        ))
        .unwrap(),
    ];
    for input in inputs {
        for profile in ["single_tenant", "multi_tenant"] {
            for requested in [None, Some(1), Some(256), Some(257), Some(4096)] {
                let mut value = input.clone();
                value["deployment_profile"] = json!(profile);
                // Preserve each historical producer's flat/resolved shape.
                let resolved = value["network"].get("config").is_some();
                let network = json!({"max_connections": requested});
                value["network"] = if resolved {
                    json!({"config": network, "outbound_proxy": null})
                } else {
                    network
                };
                let launch = decode(&value).unwrap();
                let expected = requested.unwrap_or(256);
                let expected = if profile == "multi_tenant" {
                    expected.min(256)
                } else {
                    expected
                };
                let network = launch.network.unwrap();
                assert_eq!(
                    network.config().max_tcp_connections,
                    Some(ConnectionLimit::from(expected)),
                );
                assert_eq!(network.config().max_udp_connections, Some(256.into()));
            }
        }
        for requested in [json!(0), json!(4097), json!(-1), json!("unlimited")] {
            let mut value = input.clone();
            value["network"] = json!({"max_connections": requested});
            assert!(decode(&value).is_err(), "{requested}");
        }
        for requested in [0, 1, 256] {
            let mut value = input.clone();
            value["network"] = json!({"max_udp_connections": requested});
            assert!(
                decode(&value)
                    .unwrap_err()
                    .contains("UDP connection limits")
            );
        }
    }
}

#[cfg(feature = "net")]
#[test]
fn current_launch_keeps_new_connection_limit_semantics() {
    use microsandbox_network::config::ConnectionLimit;

    for requested in [None, Some(0), Some(4097)] {
        let mut value = serde_json::to_value(LaunchConfig::default()).unwrap();
        value["network"] = json!({"config": {
            "max_connections": requested, "max_udp_connections": requested
        }, "outbound_proxy": null});
        let launch = decode(&value).unwrap();
        let network = launch.network.unwrap();
        assert_eq!(
            network.config().max_tcp_connections,
            requested.map(ConnectionLimit::from),
        );
        assert_eq!(
            network.config().max_udp_connections,
            requested.map(ConnectionLimit::from)
        );
    }
}

#[cfg(feature = "net")]
#[test]
fn resolved_network_preserves_policy_and_refuses_unavailable_features() {
    let mut value = historical(vec![]);
    value["network"] =
        json!({"config":{"enabled":false,"max_connections":12},"outbound_proxy":null});
    let net = decode(&value).unwrap().network.unwrap();
    assert!(!net.config().enabled);
    assert_eq!(net.config().max_tcp_connections, Some(12.into()));
    value["network"]["outbound_proxy"] = json!({"secret":"secret-marker"});
    let err = decode(&value).unwrap_err();
    assert!(!err.contains("secret-marker"));
    value["network"] = json!({"strict":true});
    assert!(decode(&value).unwrap().network.unwrap().config().strict);
}

#[test]
fn isolated_host_file_mounts_are_not_silently_discarded() {
    let mut value = historical(vec![]);
    value["file_mounts"] = json!([]);
    assert!(decode(&value).is_ok());
    value["file_mounts"] = json!([{"mount":"file:/private/input","filename":"input"}]);
    assert_eq!(decode(&value).unwrap().file_mounts.len(), 1);
}

#[cfg(feature = "net")]
#[test]
fn historical_secret_policies_survive_launch_decoding() {
    let mut value = historical(vec![]);
    value["network"] =
        serde_json::to_value(microsandbox_network::config::NetworkConfig::default()).unwrap();
    value["network"]["secrets"] = json!({"on_violation":"block-and-terminate", "secrets":[{
        "env_var":"API_KEY", "value":"test-secret", "placeholder":"$MSB_test",
        "allowed_hosts":[], "injection":{"headers":false,"body":true},
        "on_violation":"block-and-log"
    }]});
    let launch = decode(&value).unwrap();
    let config = serde_json::to_value(launch.network.unwrap()).unwrap();
    assert_eq!(
        config["config"]["secrets"]["violation_action"],
        "block-and-terminate"
    );
    assert_eq!(
        config["config"]["secrets"]["secrets"][0]["violation_action"],
        "block-and-log"
    );
    assert_eq!(
        config["config"]["secrets"]["secrets"][0]["substitution"]["body"],
        true
    );
    value["network"]["secrets"]["violation_action"] = json!("block-and-log");
    assert!(decode(&value).unwrap_err().contains("conflicting"));
}
