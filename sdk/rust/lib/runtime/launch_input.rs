//! Helpers for encoding the previous environment-based launch transport.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use microsandbox_protocol::bootstrap::*;
use microsandbox_runtime::launch::LaunchConfig;
use serde_json::json;

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

/// Encode the environment-based launch transport used through v0.6.9.
pub(super) fn legacy_env(bootstrap: &GuestBootstrap) -> MicrosandboxResult<Vec<String>> {
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

pub(super) fn unsupported<T>(feature: &str) -> MicrosandboxResult<T> {
    Err(MicrosandboxError::Runtime(format!(
        "{feature} requires a newer runtime launch contract"
    )))
}
