//! Encode the selected historical process-launch contract without exposing secrets on argv.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use microsandbox_protocol::bootstrap::*;
use microsandbox_runtime::launch::LaunchConfig;
use microsandbox_types::{CpuPlacement, TransparentHugePagePolicy};
use serde_json::{Value, json};

use super::launch_contract::LaunchContract;
use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const RESERVED: &[&str] = &[
    "MSB_BLOCK_ROOT",
    "MSB_DIR_MOUNTS",
    "MSB_FILE_MOUNTS",
    "MSB_DISK_MOUNTS",
    "MSB_TMPFS",
    "MSB_HOSTNAME",
    "MSB_HOST_ALIAS",
    "MSB_USER",
    "MSB_SECURITY_PROFILE",
    "MSB_RLIMITS",
    "MSB_NET",
    "MSB_NET_IPV4",
    "MSB_NET_IPV6",
    "MSB_HANDOFF_INIT",
    "MSB_HANDOFF_INIT_ARGS",
    "MSB_HANDOFF_INIT_CWD",
    "MSB_HANDOFF_INIT_ENV",
];

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(super) fn encode(launch: &LaunchConfig, contract: LaunchContract) -> MicrosandboxResult<Value> {
    if contract.machine {
        return Ok(serde_json::to_value(launch)?);
    }
    if launch.execution != microsandbox_runtime::launch::ExecutionIntent::Boot {
        return unsupported("execution restore");
    }
    #[cfg(feature = "net")]
    if launch
        .network
        .as_ref()
        .is_some_and(|network| network.config().max_udp_connections.is_some())
    {
        // Older runtimes ignore this field and impose their own fixed UDP budget.
        // Refuse explicit intent before launch instead of silently changing its meaning.
        return unsupported("UDP connection limits");
    }
    #[cfg(feature = "net")]
    if let Some(limit) = launch
        .network
        .as_ref()
        .and_then(|network| network.config().max_tcp_connections)
    {
        // Historical engines treat zero as a closed admission budget, reject caps over
        // 4096, and clamp multi-tenant budgets to 256. Preserve explicit intent instead
        // of serializing the new meaning into an older, numerically identical field.
        let Some(cap) = limit.cap() else {
            return unsupported("unlimited network connections");
        };
        if cap.get() > 4096 {
            return unsupported("network connection limits above 4096");
        }
        if launch.deployment_profile == microsandbox_types::DeploymentProfile::MultiTenant
            && cap.get() > 256
        {
            return unsupported("multi-tenant network connection limits above 256");
        }
    }
    if !launch.owned_volumes.is_empty() {
        return unsupported("sandbox-owned volumes");
    }
    if !launch.file_mounts.is_empty() {
        return unsupported("isolated file mounts");
    }
    #[cfg(feature = "net")]
    if contract.patch >= 16 && u64::from(launch.sandbox_slot) > u64::from(u16::MAX) {
        return unsupported("network slot outside the historical 16-bit range");
    }
    if !launch.rootfs.disk_layers.is_empty() || !launch.rootfs.upper_layers.is_empty() {
        return unsupported("layered execution restore");
    }
    #[cfg(feature = "net")]
    if contract.patch < 18
        && launch
            .network
            .as_ref()
            .is_some_and(|net| net.config().strict)
    {
        return unsupported("strict network authority");
    }
    let mut value = serde_json::to_value(launch)?;
    if contract.legacy_env() {
        if contract.patch < 9 {
            if launch.cpu_placement != CpuPlacement::Inherit
                || launch.placement_profile_name.is_some()
                || launch.placement_profile.is_some()
            {
                return unsupported("CPU placement");
            }
            if launch.thp != TransparentHugePagePolicy::Madvise {
                return unsupported("transparent huge-page policy");
            }
            if !launch.vsock.is_empty() {
                return unsupported("host socket forwarding");
            }
            if launch.rootfs.upper_format.is_some() {
                return unsupported("custom root-disk format");
            }
            if matches!(
                launch.bootstrap.block_root,
                Some(BootstrapBlockRoot::OciErofs {
                    upper: BootstrapBlockRootUpper::Tmpfs { .. },
                    ..
                })
            ) {
                return unsupported("RAM-backed root disk");
            }
            #[cfg(feature = "net")]
            if launch.deployment_profile != microsandbox_types::DeploymentProfile::default() {
                return unsupported("deployment profile");
            }
        }
        let env = legacy_env(&launch.bootstrap)?;
        value["env"] = json!(env);
        value["workdir"] = json!(launch.bootstrap.default_cwd);
        // Keep the typed input too: a compatible future entry point can consume
        // it without reintroducing delimiter constraints into its guest transport.
    }
    #[cfg(feature = "net")]
    if !contract.resolved_network() && !value["network"].is_null() {
        if !value["network"]["outbound_proxy"].is_null() {
            return unsupported("outbound proxy");
        }
        value["network"] = value["network"]["config"].take();
    }
    #[cfg(feature = "net")]
    if !value["network"].is_null() {
        // Historical releases used the previous secret-policy field names.
        let network = if contract.resolved_network() {
            &mut value["network"]["config"]
        } else {
            &mut value["network"]
        };
        // Explicit UDP values were rejected above; omit the new optional key
        // entirely when encoding a historical producer's network object.
        if let Some(fields) = network.as_object_mut() {
            fields.remove("max_udp_connections");
        }
        // Pin the historical default at the boundary; omission on the current contract
        // intentionally has a different meaning and must not broaden an old launch.
        if network["max_connections"].is_null() {
            network["max_connections"] = json!(256);
        }
        if let Some(secrets) = network.get_mut("secrets").and_then(Value::as_object_mut) {
            if let Some(action) = secrets.remove("violation_action") {
                secrets.insert("on_violation".into(), action);
            }
            if let Some(entries) = secrets.get_mut("secrets").and_then(Value::as_array_mut) {
                for entry in entries {
                    if let Some(fields) = entry.as_object_mut() {
                        if fields
                            .get("passthrough_hosts")
                            .and_then(Value::as_array)
                            .is_some_and(|hosts| !hosts.is_empty())
                        {
                            return unsupported("secret passthrough hosts");
                        }
                        fields.remove("passthrough_hosts");
                        for (current, legacy) in [
                            ("substitution", "injection"),
                            ("violation_action", "on_violation"),
                        ] {
                            if let Some(value) = fields.remove(current) {
                                fields.insert(legacy.into(), value);
                            }
                        }
                    }
                }
            }
        }
    }
    Ok(value)
}

fn legacy_env(bootstrap: &GuestBootstrap) -> MicrosandboxResult<Vec<String>> {
    if bootstrap.default_env.iter().any(|entry| {
        entry.key.is_empty() || entry.key.contains(['=', '\0']) || entry.value.contains('\0')
    }) {
        return unsupported("invalid environment entry");
    }
    if bootstrap.default_cwd.as_deref().is_some_and(|cwd| {
        cwd.bytes()
            .any(|b| !(0x20..=0x7e).contains(&b) || b == b'"')
    }) {
        return unsupported("working directory requiring the typed transport");
    }
    let mut env: Vec<String> = bootstrap
        .default_env
        .iter()
        .map(|e| format!("{}={}", e.key, e.value))
        .collect();
    // Reserved metadata cannot also be a workload variable with a conflicting
    // value. The typed transport has separate namespaces; the old one did not.
    if bootstrap
        .default_env
        .iter()
        .any(|e| RESERVED.contains(&e.key.as_str()))
    {
        return unsupported("reserved bootstrap environment variable");
    }
    let mut push = |key: &str, value: String| env.push(format!("{key}={value}"));
    if let Some(root) = &bootstrap.block_root {
        let value = match root {
            BootstrapBlockRoot::DiskImage { device, fstype } => {
                let mut value = format!("kind=disk-image,device={device}");
                if let Some(fstype) = fstype {
                    value.push_str(&format!(",fstype={fstype}"));
                }
                value
            }
            BootstrapBlockRoot::OciErofs { lower, upper } => {
                let upper = match upper {
                    BootstrapBlockRootUpper::Device { device, fstype } => {
                        format!("upper={device},upper_fstype={fstype}")
                    }
                    BootstrapBlockRootUpper::Tmpfs { size_mib } => match size_mib {
                        Some(size) => format!("upper=tmpfs,upper_size_mib={size}"),
                        None => "upper=tmpfs".into(),
                    },
                };
                format!("kind=oci-erofs,lower={lower},{upper}")
            }
        };
        push("MSB_BLOCK_ROOT", value);
    }
    if !bootstrap.dir_mounts.is_empty() {
        push(
            "MSB_DIR_MOUNTS",
            bootstrap
                .dir_mounts
                .iter()
                .map(|m| options(format!("{}:{}", m.tag, m.guest_path), m.flags, vec![]))
                .collect::<Vec<_>>()
                .join(";"),
        );
    }
    if !bootstrap.file_mounts.is_empty() {
        push(
            "MSB_FILE_MOUNTS",
            bootstrap
                .file_mounts
                .iter()
                .map(|m| {
                    options(
                        format!("{}:{}:{}", m.tag, m.filename, m.guest_path),
                        m.flags,
                        vec![],
                    )
                })
                .collect::<Vec<_>>()
                .join(";"),
        );
    }
    if !bootstrap.disk_mounts.is_empty() {
        push(
            "MSB_DISK_MOUNTS",
            bootstrap
                .disk_mounts
                .iter()
                .map(|m| {
                    options(
                        format!("{}:{}", m.id, m.guest_path),
                        m.flags,
                        m.fstype
                            .as_ref()
                            .map(|v| format!("fstype={v}"))
                            .into_iter()
                            .collect(),
                    )
                })
                .collect::<Vec<_>>()
                .join(";"),
        );
    }
    if !bootstrap.tmpfs_mounts.is_empty() {
        push(
            "MSB_TMPFS",
            bootstrap
                .tmpfs_mounts
                .iter()
                .map(|m| {
                    let mut opts = Vec::new();
                    if let Some(size) = m.size_mib {
                        opts.push(format!("size={size}"));
                    }
                    if let Some(mode) = m.mode {
                        opts.push(format!("mode={mode:o}"));
                    }
                    options(m.path.clone(), m.flags, opts)
                })
                .collect::<Vec<_>>()
                .join(";"),
        );
    }
    for (key, value) in [
        ("MSB_HOSTNAME", &bootstrap.hostname),
        ("MSB_HOST_ALIAS", &bootstrap.host_alias),
        ("MSB_USER", &bootstrap.user),
    ] {
        if let Some(value) = value {
            push(key, value.clone());
        }
    }
    push(
        "MSB_SECURITY_PROFILE",
        match bootstrap.security_profile {
            BootstrapSecurityProfile::Default => "default",
            BootstrapSecurityProfile::Restricted => "restricted",
        }
        .into(),
    );
    if !bootstrap.rlimits.is_empty() {
        push(
            "MSB_RLIMITS",
            bootstrap
                .rlimits
                .iter()
                .map(|r| format!("{}={}:{}", r.resource, r.soft, r.hard))
                .collect::<Vec<_>>()
                .join(";"),
        );
    }
    if let Some(network) = &bootstrap.network {
        push(
            "MSB_NET",
            format!(
                "iface={},mac={},mtu={}",
                network.interface,
                network
                    .mac
                    .iter()
                    .map(|b| format!("{b:02x}"))
                    .collect::<Vec<_>>()
                    .join(":"),
                network.mtu
            ),
        );
        if let Some(ip) = network.ipv4 {
            let mut v = format!("addr={}/{},gw={}", ip.address, ip.prefix_len, ip.gateway);
            if let Some(dns) = ip.dns {
                v.push_str(&format!(",dns={dns}"));
            }
            push("MSB_NET_IPV4", v);
        }
        if let Some(ip) = network.ipv6 {
            let mut v = format!("addr={}/{},gw={}", ip.address, ip.prefix_len, ip.gateway);
            if let Some(dns) = ip.dns {
                v.push_str(&format!(",dns={dns}"));
            }
            push("MSB_NET_IPV6", v);
        }
    }
    if let Some(handoff) = &bootstrap.handoff_init {
        push("MSB_HANDOFF_INIT", handoff.cmd.clone());
        push(
            "MSB_HANDOFF_INIT_ARGS",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(&handoff.args)?),
        );
        push(
            "MSB_HANDOFF_INIT_ENV",
            URL_SAFE_NO_PAD.encode(serde_json::to_vec(
                &handoff
                    .env
                    .iter()
                    .map(|e| (&e.key, &e.value))
                    .collect::<Vec<_>>(),
            )?),
        );
        if let Some(cwd) = &handoff.cwd {
            push("MSB_HANDOFF_INIT_CWD", cwd.clone());
        }
    }
    // Old runtimes put these strings on the guest kernel command line. Reject
    // values that its quoted transport cannot carry, before starting a process.
    if env.iter().any(|value| {
        value
            .bytes()
            .any(|b| !(0x20..=0x7e).contains(&b) || b == b'"')
    }) {
        return unsupported("environment value requiring the typed guest transport");
    }
    // Independently decode the generated legacy grammar to detect delimiter
    // collisions rather than trying to escape a format that has no escaping.
    let mut check = serde_json::to_value(LaunchConfig::default())?;
    check
        .as_object_mut()
        .expect("LaunchConfig is an object")
        .remove("bootstrap");
    check.as_object_mut().unwrap().remove("execution");
    check["env"] = json!(env);
    check["workdir"] = json!(bootstrap.default_cwd);
    let mut decoded = LaunchConfig::from_json(&serde_json::to_vec(&check)?)
        .map_err(|_| {
            MicrosandboxError::Runtime(
                "guest configuration cannot be represented by the legacy launch contract".into(),
            )
        })?
        .bootstrap;
    decoded.default_env = bootstrap.default_env.clone();
    if decoded != *bootstrap {
        return unsupported("guest configuration requiring the typed transport");
    }
    Ok(env)
}

fn options(mut base: String, flags: BootstrapMountFlags, mut values: Vec<String>) -> String {
    for (enabled, name) in [
        (flags.readonly, "ro"),
        (flags.noexec, "noexec"),
        (flags.nosuid, "nosuid"),
        (flags.nodev, "nodev"),
    ] {
        if enabled {
            values.push(name.into());
        }
    }
    if !values.is_empty() {
        base.push(':');
        base.push_str(&values.join(","));
    }
    base
}

fn unsupported<T>(feature: &str) -> MicrosandboxResult<T> {
    Err(MicrosandboxError::Runtime(format!(
        "{feature} requires a newer runtime launch contract"
    )))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "net")]
    #[test]
    fn udp_limits_require_current_launch_contract() {
        use microsandbox_network::config::{EnvNetworkSecretResolver, NetworkConfig};

        for requested in [None, Some(0), Some(1), Some(256), Some(4097)] {
            let network: NetworkConfig = serde_json::from_value(json!({
                "max_connections": 8,
                "max_udp_connections": requested,
            }))
            .unwrap();
            let launch = LaunchConfig {
                network: Some(network.resolve(&EnvNetworkSecretResolver).unwrap()),
                ..Default::default()
            };
            let current = encode(
                &launch,
                LaunchContract {
                    patch: 18,
                    machine: true,
                },
            )
            .unwrap();
            assert_eq!(current["network"]["config"]["max_connections"], 8);
            assert_eq!(
                current["network"]["config"]["max_udp_connections"],
                json!(requested)
            );
            assert!(
                current["network"]["config"]
                    .get("max_tcp_connections")
                    .is_none()
            );
            for patch in 0..=18 {
                let result = encode(
                    &launch,
                    LaunchContract {
                        patch,
                        machine: false,
                    },
                );
                if requested.is_some() {
                    assert!(
                        result
                            .unwrap_err()
                            .to_string()
                            .contains("UDP connection limits")
                    );
                } else {
                    let value = result.unwrap();
                    let network = if patch >= 17 {
                        &value["network"]["config"]
                    } else {
                        &value["network"]
                    };
                    assert_eq!(network["max_connections"], 8);
                    assert!(network.get("max_udp_connections").is_none());
                }
            }
        }
    }

    #[cfg(feature = "net")]
    #[test]
    fn legacy_network_limits_reject_changed_meanings_before_launch() {
        use microsandbox_network::config::{EnvNetworkSecretResolver, NetworkConfig};
        use microsandbox_types::DeploymentProfile;

        for profile in [
            DeploymentProfile::SingleTenant,
            DeploymentProfile::MultiTenant,
        ] {
            for requested in [
                None,
                Some(0),
                Some(1),
                Some(256),
                Some(257),
                Some(4096),
                Some(4097),
            ] {
                let network: NetworkConfig =
                    serde_json::from_value(json!({"max_connections": requested})).unwrap();
                let launch = LaunchConfig {
                    network: Some(network.resolve(&EnvNetworkSecretResolver).unwrap()),
                    deployment_profile: profile,
                    ..Default::default()
                };
                // Current runtimes implement every explicit value, including zero/unlimited.
                assert_eq!(
                    encode(
                        &launch,
                        LaunchContract {
                            patch: 18,
                            machine: true
                        }
                    )
                    .unwrap(),
                    serde_json::to_value(&launch).unwrap(),
                );

                for patch in 0..=18 {
                    if profile == DeploymentProfile::MultiTenant && patch < 9 {
                        // Those releases predate deployment profiles entirely.
                        continue;
                    }
                    let result = encode(
                        &launch,
                        LaunchContract {
                            patch,
                            machine: false,
                        },
                    );
                    let unsupported = requested.is_some_and(|limit| {
                        limit == 0
                            || limit > 4096
                            || (profile == DeploymentProfile::MultiTenant && limit > 256)
                    });
                    if unsupported {
                        let error = result.unwrap_err().to_string();
                        assert!(error.contains("network connection"), "{error}");
                        assert!(error.contains("newer runtime launch contract"), "{error}");
                    } else {
                        let value = result.unwrap();
                        let network = if patch >= 17 {
                            &value["network"]["config"]
                        } else {
                            &value["network"]
                        };
                        // Omission pins the historical default. Representable explicit
                        // budgets must survive the historical launch transformation.
                        assert_eq!(network["max_connections"], json!(requested.unwrap_or(256)));
                    }
                }
            }
        }
    }

    #[test]
    fn owned_storage_is_never_silently_dropped_for_released_runtimes() {
        let launch = LaunchConfig {
            owned_volumes: vec![microsandbox_types::VolumeMount::Owned {
                guest: "/data".into(),
                storage: microsandbox_types::OwnedVolumeStorage::Directory { quota_mib: None },
                options: Default::default(),
                stat_virtualization: microsandbox_types::StatVirtualization::Strict,
                host_permissions: microsandbox_types::HostPermissions::Private,
            }],
            ..Default::default()
        };
        for patch in 0..=18 {
            assert!(
                encode(
                    &launch,
                    LaunchContract {
                        patch,
                        machine: false
                    }
                )
                .unwrap_err()
                .to_string()
                .contains("sandbox-owned volumes")
            );
        }
        assert_eq!(
            encode(
                &launch,
                LaunchContract {
                    patch: 18,
                    machine: true
                }
            )
            .unwrap(),
            serde_json::to_value(&launch).unwrap()
        );
    }

    #[test]
    fn legacy_input_retains_guest_root_mounts_environment_and_cwd() {
        let mut launch = LaunchConfig::default();
        launch.bootstrap = GuestBootstrap {
            block_root: Some(BootstrapBlockRoot::OciErofs {
                lower: "/dev/vda".into(),
                upper: BootstrapBlockRootUpper::Device {
                    device: "/dev/vdb".into(),
                    fstype: "ext4".into(),
                },
            }),
            dir_mounts: vec![BootstrapDirMount {
                tag: "work".into(),
                guest_path: "/work".into(),
                flags: BootstrapMountFlags {
                    readonly: true,
                    noexec: true,
                    ..Default::default()
                },
            }],
            default_env: vec![BootstrapEnvVar {
                key: "APP".into(),
                value: "value=with spaces".into(),
            }],
            default_cwd: Some("/work".into()),
            security_profile: BootstrapSecurityProfile::Restricted,
            ..Default::default()
        };
        for patch in [0, 4, 8, 9] {
            let value = encode(
                &launch,
                LaunchContract {
                    patch,
                    machine: false,
                },
            )
            .unwrap();
            let env: Vec<String> = serde_json::from_value(value["env"].clone()).unwrap();
            assert!(env.contains(&"MSB_BLOCK_ROOT=kind=oci-erofs,lower=/dev/vda,upper=/dev/vdb,upper_fstype=ext4".into()));
            assert!(env.contains(&"MSB_DIR_MOUNTS=work:/work:ro,noexec".into()));
            assert!(env.contains(&"APP=value=with spaces".into()));
            assert!(env.contains(&"MSB_SECURITY_PROFILE=restricted".into()));
            assert_eq!(value["workdir"], "/work");
        }
    }

    #[test]
    fn typed_values_are_preserved_and_legacy_delimiter_collisions_fail() {
        let mut launch = LaunchConfig::default();
        launch.bootstrap.dir_mounts.push(BootstrapDirMount {
            tag: "x".into(),
            guest_path: "/data:ro;injected:/x".into(),
            flags: Default::default(),
        });
        assert!(
            encode(
                &launch,
                LaunchContract {
                    patch: 4,
                    machine: false
                }
            )
            .is_err()
        );
        assert_eq!(
            encode(
                &launch,
                LaunchContract {
                    patch: 10,
                    machine: false
                }
            )
            .unwrap(),
            serde_json::to_value(&launch).unwrap()
        );
        launch.bootstrap.dir_mounts.clear();
        for value in ["non-ascii-雪", "a\"b", "a\nb"] {
            launch.bootstrap.default_env = vec![BootstrapEnvVar {
                key: "APP".into(),
                value: value.into(),
            }];
            let error = encode(
                &launch,
                LaunchContract {
                    patch: 9,
                    machine: false,
                },
            )
            .unwrap_err()
            .to_string();
            assert!(!error.contains(value));
        }
    }

    #[cfg(feature = "net")]
    #[test]
    fn newer_resolved_network_shape_keeps_the_original_policy() {
        let launch = LaunchConfig {
            network: Some(
                microsandbox_network::config::NetworkConfig::default()
                    .resolve(&microsandbox_network::config::EnvNetworkSecretResolver)
                    .unwrap(),
            ),
            ..Default::default()
        };
        let expected = serde_json::to_value(&launch.network).unwrap();
        for patch in [17, 18] {
            let value = encode(
                &launch,
                LaunchContract {
                    patch,
                    machine: false,
                },
            )
            .unwrap();
            let mut expected = expected.clone();
            expected["config"]["max_connections"] = json!(256);
            expected["config"]
                .as_object_mut()
                .unwrap()
                .remove("max_udp_connections");
            if let Some(secrets) = expected["config"]
                .get_mut("secrets")
                .and_then(Value::as_object_mut)
            {
                if let Some(action) = secrets.remove("violation_action") {
                    secrets.insert("on_violation".into(), action);
                }
            }
            assert_eq!(value["network"], expected);
            assert!(value["network"]["outbound_proxy"].is_null());
        }
    }
}
