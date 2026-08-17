//! Typed host-to-guest configuration delivered before agent initialization.

use std::net::{Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::exec::ExecRlimit;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Complete one-shot configuration consumed by agentd during guest boot.
///
/// The runtime preloads this payload into the agent console before the VM
/// starts. The surrounding protocol envelope supplies the schema generation.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuestBootstrap {
    /// Block-backed root filesystem assembly, when required.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_root: Option<BootstrapBlockRoot>,

    /// Virtiofs directory mounts installed inside the guest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub dir_mounts: Vec<BootstrapDirMount>,

    /// Virtiofs file mounts installed inside the guest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub file_mounts: Vec<BootstrapFileMount>,

    /// Additional block-device mounts installed inside the guest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub disk_mounts: Vec<BootstrapDiskMount>,

    /// Tmpfs mounts installed inside the guest.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tmpfs_mounts: Vec<BootstrapTmpfsMount>,

    /// Guest hostname.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// Host alias written into the guest's hosts file.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub host_alias: Option<String>,

    /// Guest network interface and address configuration.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<BootstrapNetwork>,

    /// Sandbox-wide resource limits inherited by guest workloads.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rlimits: Vec<ExecRlimit>,

    /// Default guest user for command execution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// Default working directory for requests that omit one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_cwd: Option<String>,

    /// Environment inherited by requests that do not override a key.
    ///
    /// Secret entries contain guest-visible placeholders, never host secret
    /// values. Explicit exec and handoff environment entries take precedence.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub default_env: Vec<BootstrapEnvVar>,

    /// In-guest security policy.
    #[serde(default)]
    pub security_profile: BootstrapSecurityProfile,

    /// Optional PID 1 handoff after agentd finishes guest initialization.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handoff_init: Option<BootstrapHandoffInit>,
}

/// Block-backed root filesystem configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BootstrapBlockRoot {
    /// A single filesystem image mounted as the guest root.
    DiskImage {
        /// Guest block-device path.
        device: String,

        /// Filesystem type, or `None` to probe inside the guest.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        fstype: Option<String>,
    },

    /// An EROFS lower filesystem combined with a writable overlay upper.
    OciErofs {
        /// Read-only EROFS block-device path.
        lower: String,

        /// Writable overlay backing.
        upper: BootstrapBlockRootUpper,
    },
}

/// Writable backing for an OCI EROFS root.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum BootstrapBlockRootUpper {
    /// Writable filesystem supplied by a guest block device.
    Device {
        /// Guest block-device path.
        device: String,

        /// Filesystem type on the device.
        fstype: String,
    },

    /// RAM-backed writable upper.
    Tmpfs {
        /// Optional maximum size in MiB.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        size_mib: Option<u32>,
    },
}

/// Common guest mount flags.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapMountFlags {
    /// Mount read-only.
    #[serde(default)]
    pub readonly: bool,

    /// Disallow execution from the mount.
    #[serde(default)]
    pub noexec: bool,

    /// Ignore set-user-ID and set-group-ID bits.
    #[serde(default)]
    pub nosuid: bool,

    /// Disallow device nodes.
    #[serde(default)]
    pub nodev: bool,
}

/// Guest-side virtiofs directory mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapDirMount {
    /// Virtiofs device tag.
    pub tag: String,

    /// Absolute guest mount path.
    pub guest_path: String,

    /// Guest mount flags.
    #[serde(default)]
    pub flags: BootstrapMountFlags,
}

/// Guest-side virtiofs file mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapFileMount {
    /// Virtiofs device tag.
    pub tag: String,

    /// Filename inside the staged virtiofs directory.
    pub filename: String,

    /// Absolute guest file path.
    pub guest_path: String,

    /// Guest mount flags.
    #[serde(default)]
    pub flags: BootstrapMountFlags,
}

/// Guest-side block-device mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapDiskMount {
    /// Virtio block-device identifier.
    pub id: String,

    /// Absolute guest mount path.
    pub guest_path: String,

    /// Filesystem type, or `None` to probe inside the guest.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fstype: Option<String>,

    /// Guest mount flags.
    #[serde(default)]
    pub flags: BootstrapMountFlags,
}

/// Guest-side tmpfs mount.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapTmpfsMount {
    /// Absolute guest mount path.
    pub path: String,

    /// Optional maximum size in MiB.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub size_mib: Option<u32>,

    /// Optional Unix mode applied to the tmpfs root.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,

    /// Guest mount flags.
    #[serde(default)]
    pub flags: BootstrapMountFlags,
}

/// Guest network interface and address configuration.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapNetwork {
    /// Guest interface name.
    pub interface: String,

    /// Guest interface MAC address.
    pub mac: [u8; 6],

    /// Guest interface MTU.
    pub mtu: u16,

    /// IPv4 address configuration when IPv4 is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4: Option<BootstrapIpv4>,

    /// IPv6 address configuration when IPv6 is active.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6: Option<BootstrapIpv6>,
}

/// Guest IPv4 address configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapIpv4 {
    /// Guest IPv4 address.
    pub address: Ipv4Addr,

    /// CIDR prefix length.
    pub prefix_len: u8,

    /// Default gateway.
    pub gateway: Ipv4Addr,

    /// DNS resolver address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Ipv4Addr>,
}

/// Guest IPv6 address configuration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapIpv6 {
    /// Guest IPv6 address.
    pub address: Ipv6Addr,

    /// CIDR prefix length.
    pub prefix_len: u8,

    /// Default gateway.
    pub gateway: Ipv6Addr,

    /// DNS resolver address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dns: Option<Ipv6Addr>,
}

/// A baseline guest environment entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapEnvVar {
    /// Environment variable name.
    pub key: String,

    /// Environment variable value.
    pub value: String,
}

/// In-guest security profile selected for a sandbox.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BootstrapSecurityProfile {
    /// Preserve normal guest-root behavior.
    #[default]
    Default,

    /// Restrict mount and process privileges inside the guest.
    Restricted,
}

/// Optional PID 1 handoff after agentd completes initialization.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BootstrapHandoffInit {
    /// Absolute init path inside the guest, or the `auto` sentinel.
    pub cmd: String,

    /// Arguments following `argv[0]`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub args: Vec<String>,

    /// Working directory entered before the handoff.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,

    /// Environment merged over the inherited runtime environment.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub env: Vec<BootstrapEnvVar>,
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        codec,
        message::{Message, MessageType, PROTOCOL_VERSION},
    };

    #[test]
    fn guest_bootstrap_round_trips_transport_sensitive_values() {
        let bootstrap = GuestBootstrap {
            block_root: Some(BootstrapBlockRoot::OciErofs {
                lower: "/dev/vda".to_string(),
                upper: BootstrapBlockRootUpper::Tmpfs {
                    size_mib: Some(512),
                },
            }),
            dir_mounts: vec![BootstrapDirMount {
                tag: "workspace".to_string(),
                guest_path: "/workspace:with separators".to_string(),
                flags: BootstrapMountFlags {
                    noexec: true,
                    ..BootstrapMountFlags::default()
                },
            }],
            file_mounts: vec![BootstrapFileMount {
                tag: "config".to_string(),
                filename: "app.json".to_string(),
                guest_path: "/etc/app.json".to_string(),
                flags: BootstrapMountFlags {
                    readonly: true,
                    ..BootstrapMountFlags::default()
                },
            }],
            disk_mounts: vec![BootstrapDiskMount {
                id: "data".to_string(),
                guest_path: "/data".to_string(),
                fstype: Some("ext4".to_string()),
                flags: BootstrapMountFlags::default(),
            }],
            tmpfs_mounts: vec![BootstrapTmpfsMount {
                path: "/tmp".to_string(),
                size_mib: Some(64),
                mode: Some(0o1777),
                flags: BootstrapMountFlags::default(),
            }],
            hostname: Some("quoted-env-test".to_string()),
            host_alias: Some("host.microsandbox.internal".to_string()),
            network: Some(BootstrapNetwork {
                interface: "eth0".to_string(),
                mac: [0x02, 0x00, 0x00, 0x00, 0x00, 0x02],
                mtu: 1500,
                ipv4: Some(BootstrapIpv4 {
                    address: "172.16.0.2".parse().unwrap(),
                    prefix_len: 30,
                    gateway: "172.16.0.1".parse().unwrap(),
                    dns: Some("172.16.0.1".parse().unwrap()),
                }),
                ipv6: Some(BootstrapIpv6 {
                    address: "fd42:6d73:62::2".parse().unwrap(),
                    prefix_len: 64,
                    gateway: "fd42:6d73:62::1".parse().unwrap(),
                    dns: Some("fd42:6d73:62::1".parse().unwrap()),
                }),
            }),
            rlimits: vec![ExecRlimit {
                resource: "nofile".to_string(),
                soft: 1024,
                hard: 4096,
            }],
            user: Some("1000:1000".to_string()),
            default_cwd: Some("/workspace with spaces".to_string()),
            default_env: vec![
                BootstrapEnvVar {
                    key: "APP_CONFIG".to_string(),
                    value: "{\"message\":\"hello\"}".to_string(),
                },
                BootstrapEnvVar {
                    key: "UNICODE".to_string(),
                    value: "snowman: \u{2603}\nnext\tcolumn".to_string(),
                },
                BootstrapEnvVar {
                    key: "EMPTY".to_string(),
                    value: String::new(),
                },
            ],
            security_profile: BootstrapSecurityProfile::Restricted,
            handoff_init: Some(BootstrapHandoffInit {
                cmd: "/sbin/init".to_string(),
                args: vec!["--unit=multi user.target".to_string()],
                cwd: Some("/workspace with spaces".to_string()),
                env: vec![BootstrapEnvVar {
                    key: "HANDOFF_JSON".to_string(),
                    value: "{\"enabled\":true}".to_string(),
                }],
            }),
        };

        let message = Message::with_payload(MessageType::Bootstrap, 0, &bootstrap).unwrap();
        assert_eq!(message.v, PROTOCOL_VERSION);
        let mut frame = Vec::new();
        codec::encode_to_buf(&message, &mut frame).unwrap();
        let decoded = codec::decode_message_frame(&frame).unwrap();
        assert_eq!(decoded.payload::<GuestBootstrap>().unwrap(), bootstrap);
    }
}
