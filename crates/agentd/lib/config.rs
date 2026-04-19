//! Agentd configuration, read once from environment variables at startup.
//!
//! [`AgentdConfig::from_env`] reads all `MSB_*` environment variables and
//! parses them into their respective types in a single step. Downstream
//! functions receive the config by reference, avoiding repeated env var reads
//! and repeated parsing.

use std::env;
use std::net::{Ipv4Addr, Ipv6Addr};

use microsandbox_protocol::{
    ENV_BLOCK_ROOT, ENV_DIR_MOUNTS, ENV_FILE_MOUNTS, ENV_HOSTNAME, ENV_NET, ENV_NET_IPV4,
    ENV_NET_IPV6, ENV_RLIMITS, ENV_TMPFS, ENV_USER, exec::ExecRlimit,
};

use crate::error::{AgentdError, AgentdResult};
use crate::rlimit;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Parsed configuration for agentd.
///
/// All `MSB_*` environment variables are read and parsed into their respective
/// types during construction via [`AgentdConfig::from_env`].
#[derive(Debug)]
pub struct AgentdConfig {
    /// Parsed `MSB_BLOCK_ROOT` — block device for rootfs switch.
    pub(crate) block_root: Option<BlockRootSpec>,

    /// Parsed `MSB_DIR_MOUNTS` — virtiofs directory mount specs (empty when unset).
    pub(crate) dir_mounts: Vec<DirMountSpec>,

    /// Parsed `MSB_FILE_MOUNTS` — virtiofs file mount specs (empty when unset).
    pub(crate) file_mounts: Vec<FileMountSpec>,

    /// Parsed `MSB_TMPFS` — tmpfs mount specs (empty when unset).
    pub(crate) tmpfs: Vec<TmpfsSpec>,

    /// `MSB_HOSTNAME` — guest hostname.
    pub(crate) hostname: Option<String>,

    /// Parsed `MSB_NET` — network interface config.
    pub(crate) net: Option<NetSpec>,

    /// Parsed `MSB_NET_IPV4` — IPv4 config.
    pub(crate) net_ipv4: Option<NetIpv4Spec>,

    /// Parsed `MSB_NET_IPV6` — IPv6 config.
    pub(crate) net_ipv6: Option<NetIpv6Spec>,

    /// `MSB_USER` — default guest user for exec sessions.
    ///
    /// Captured at startup; changes to `MSB_USER` afterward are not observed.
    pub(crate) user: Option<String>,

    /// Parsed `MSB_RLIMITS` — sandbox-wide resource limits applied to PID 1
    /// so every guest process inherits the raised baseline (empty when unset).
    pub(crate) rlimits: Vec<ExecRlimit>,
}

/// Parsed tmpfs mount specification.
#[derive(Debug)]
pub(crate) struct TmpfsSpec {
    pub path: String,
    pub size_mib: Option<u32>,
    pub mode: Option<u32>,
    pub noexec: bool,
}

/// Parsed block-device root specification with kind-based dispatch.
#[derive(Debug)]
pub(crate) enum BlockRootSpec {
    /// Single disk image.
    DiskImage {
        device: String,
        fstype: Option<String>,
    },
    /// OCI EROFS: merged EROFS lower + writable upper + guest overlayfs.
    OciErofs {
        lower: String,
        upper: String,
        upper_fstype: String,
    },
}

/// Parsed virtiofs directory volume mount specification.
#[derive(Debug)]
pub(crate) struct DirMountSpec {
    pub tag: String,
    pub guest_path: String,
    pub readonly: bool,
}

/// Parsed virtiofs file volume mount specification.
#[derive(Debug)]
pub(crate) struct FileMountSpec {
    pub tag: String,
    pub filename: String,
    pub guest_path: String,
    pub readonly: bool,
}

/// Parsed `MSB_NET` specification.
#[derive(Debug)]
pub(crate) struct NetSpec {
    pub iface: String,
    pub mac: [u8; 6],
    pub mtu: u16,
}

/// Parsed `MSB_NET_IPV4` specification.
#[derive(Debug)]
pub(crate) struct NetIpv4Spec {
    pub address: Ipv4Addr,
    pub prefix_len: u8,
    pub gateway: Ipv4Addr,
    pub dns: Option<Ipv4Addr>,
}

/// Parsed `MSB_NET_IPV6` specification.
#[derive(Debug)]
pub(crate) struct NetIpv6Spec {
    pub address: Ipv6Addr,
    pub prefix_len: u8,
    pub gateway: Ipv6Addr,
    pub dns: Option<Ipv6Addr>,
}

/// Bundled network configuration: interface + IPv4 + IPv6.
///
/// Borrows the three `MSB_NET*` specs so they can travel as one parameter.
#[derive(Debug)]
pub(crate) struct NetConfig<'a> {
    pub net: Option<&'a NetSpec>,
    pub ipv4: Option<&'a NetIpv4Spec>,
    pub ipv6: Option<&'a NetIpv6Spec>,
}

//--------------------------------------------------------------------------------------------------
// Implementations
//--------------------------------------------------------------------------------------------------

impl AgentdConfig {
    /// Reads all `MSB_*` environment variables and parses them into the config.
    ///
    /// Empty or whitespace-only values are treated as absent (`None`).
    /// Returns an error if any present value fails to parse.
    pub fn from_env() -> AgentdResult<Self> {
        Ok(Self {
            block_root: read_env(ENV_BLOCK_ROOT)
                .map(|v| parse_block_root(&v))
                .transpose()?,
            dir_mounts: read_env(ENV_DIR_MOUNTS)
                .map(|v| parse_dir_mounts(&v))
                .transpose()?
                .unwrap_or_default(),
            file_mounts: read_env(ENV_FILE_MOUNTS)
                .map(|v| parse_file_mounts(&v))
                .transpose()?
                .unwrap_or_default(),
            tmpfs: read_env(ENV_TMPFS)
                .map(|v| parse_tmpfs_mounts(&v))
                .transpose()?
                .unwrap_or_default(),
            hostname: read_env(ENV_HOSTNAME),
            net: read_env(ENV_NET).map(|v| parse_net(&v)).transpose()?,
            net_ipv4: read_env(ENV_NET_IPV4)
                .map(|v| parse_net_ipv4(&v))
                .transpose()?,
            net_ipv6: read_env(ENV_NET_IPV6)
                .map(|v| parse_net_ipv6(&v))
                .transpose()?,
            user: read_env(ENV_USER),
            rlimits: read_env(ENV_RLIMITS)
                .map(|v| parse_rlimits(&v))
                .transpose()?
                .unwrap_or_default(),
        })
    }

    /// Borrows the three `MSB_NET*` specs as a single bundle.
    pub(crate) fn network(&self) -> NetConfig<'_> {
        NetConfig {
            net: self.net.as_ref(),
            ipv4: self.net_ipv4.as_ref(),
            ipv6: self.net_ipv6.as_ref(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Parse Functions: Block Root / Volume Mounts / Tmpfs
//--------------------------------------------------------------------------------------------------

/// Parses `MSB_BLOCK_ROOT` into a kind-based spec.
///
/// Supports:
/// - `kind=disk-image,device=/dev/vda[,fstype=ext4]`
/// - `kind=oci-erofs,lower=/dev/vdb,upper=/dev/vdc,upper_fstype=ext4`
fn parse_block_root(val: &str) -> AgentdResult<BlockRootSpec> {
    let mut kv: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for part in val.split(',') {
        let Some((k, v)) = part.split_once('=') else {
            continue;
        };
        if kv.insert(k, v).is_some() {
            return Err(AgentdError::Config(format!(
                "MSB_BLOCK_ROOT duplicate key '{k}'"
            )));
        }
    }

    let get = |key: &str| -> AgentdResult<String> {
        kv.get(key)
            .filter(|v| !v.is_empty())
            .map(|v| v.to_string())
            .ok_or_else(|| AgentdError::Config(format!("MSB_BLOCK_ROOT missing '{key}'")))
    };

    match kv.get("kind").copied() {
        Some("disk-image") => {
            let device = get("device")?;
            let fstype = kv
                .get("fstype")
                .filter(|v| !v.is_empty())
                .map(|v| v.to_string());
            Ok(BlockRootSpec::DiskImage { device, fstype })
        }
        Some("oci-erofs") => {
            let lower = get("lower")?;
            let upper = get("upper")?;
            let upper_fstype = get("upper_fstype")?;
            Ok(BlockRootSpec::OciErofs {
                lower,
                upper,
                upper_fstype,
            })
        }
        Some(other) => Err(AgentdError::Config(format!(
            "MSB_BLOCK_ROOT unknown kind: {other}"
        ))),
        None => Err(AgentdError::Config(
            "MSB_BLOCK_ROOT missing 'kind' key".into(),
        )),
    }
}

/// Parses semicolon-separated directory mount entries.
fn parse_dir_mounts(val: &str) -> AgentdResult<Vec<DirMountSpec>> {
    val.split(';')
        .filter(|e| !e.is_empty())
        .map(parse_dir_mount_entry)
        .collect()
}

/// Parses a single virtiofs directory volume mount entry: `tag:guest_path[:ro]`
fn parse_dir_mount_entry(entry: &str) -> AgentdResult<DirMountSpec> {
    let parts: Vec<&str> = entry.split(':').collect();
    if parts.len() < 2 {
        return Err(AgentdError::Config(format!(
            "MSB_DIR_MOUNTS entry must be tag:path[:ro], got: {entry}"
        )));
    }

    let tag = parts[0];
    let guest_path = parts[1];
    let readonly = match parts.get(2) {
        Some(&"ro") => true,
        None => false,
        Some(flag) => {
            return Err(AgentdError::Config(format!(
                "MSB_DIR_MOUNTS unknown flag '{flag}' (expected 'ro')"
            )));
        }
    };

    if parts.len() > 3 {
        return Err(AgentdError::Config(format!(
            "MSB_DIR_MOUNTS entry has too many parts: {entry}"
        )));
    }

    if tag.is_empty() {
        return Err(AgentdError::Config(
            "MSB_DIR_MOUNTS entry has empty tag".into(),
        ));
    }
    if guest_path.is_empty() || !guest_path.starts_with('/') {
        return Err(AgentdError::Config(format!(
            "MSB_DIR_MOUNTS guest path must be absolute: {guest_path}"
        )));
    }

    Ok(DirMountSpec {
        tag: tag.to_string(),
        guest_path: guest_path.to_string(),
        readonly,
    })
}

/// Parses semicolon-separated file mount entries.
fn parse_file_mounts(val: &str) -> AgentdResult<Vec<FileMountSpec>> {
    val.split(';')
        .filter(|e| !e.is_empty())
        .map(parse_file_mount_entry)
        .collect()
}

/// Parses a single virtiofs file volume mount entry: `tag:filename:guest_path[:ro]`
fn parse_file_mount_entry(entry: &str) -> AgentdResult<FileMountSpec> {
    let parts: Vec<&str> = entry.split(':').collect();
    if parts.len() < 3 {
        return Err(AgentdError::Config(format!(
            "MSB_FILE_MOUNTS entry must be tag:filename:path[:ro], got: {entry}"
        )));
    }

    let tag = parts[0];
    let filename = parts[1];
    let guest_path = parts[2];
    let readonly = match parts.get(3) {
        Some(&"ro") => true,
        None => false,
        Some(flag) => {
            return Err(AgentdError::Config(format!(
                "MSB_FILE_MOUNTS unknown flag '{flag}' (expected 'ro')"
            )));
        }
    };

    if parts.len() > 4 {
        return Err(AgentdError::Config(format!(
            "MSB_FILE_MOUNTS entry has too many parts: {entry}"
        )));
    }

    if tag.is_empty() {
        return Err(AgentdError::Config(
            "MSB_FILE_MOUNTS entry has empty tag".into(),
        ));
    }
    if filename.is_empty() {
        return Err(AgentdError::Config(
            "MSB_FILE_MOUNTS entry has empty filename".into(),
        ));
    }
    if guest_path.is_empty() || !guest_path.starts_with('/') {
        return Err(AgentdError::Config(format!(
            "MSB_FILE_MOUNTS guest path must be absolute: {guest_path}"
        )));
    }

    Ok(FileMountSpec {
        tag: tag.to_string(),
        filename: filename.to_string(),
        guest_path: guest_path.to_string(),
        readonly,
    })
}

/// Parses semicolon-separated tmpfs mount entries.
fn parse_tmpfs_mounts(val: &str) -> AgentdResult<Vec<TmpfsSpec>> {
    val.split(';')
        .filter(|e| !e.is_empty())
        .map(parse_tmpfs_entry)
        .collect()
}

/// Parses a single tmpfs entry: `path[,size=N][,mode=N][,noexec]`
///
/// Mode is parsed as octal (e.g. `mode=1777`).
fn parse_tmpfs_entry(entry: &str) -> AgentdResult<TmpfsSpec> {
    let mut parts = entry.split(',');
    let path = parts.next().unwrap(); // always at least one element
    if path.is_empty() {
        return Err(AgentdError::Config("tmpfs entry has empty path".into()));
    }

    let mut size_mib = None;
    let mut mode = None;
    let mut noexec = false;

    for opt in parts {
        if opt == "noexec" {
            noexec = true;
        } else if let Some(val) = opt.strip_prefix("size=") {
            size_mib = Some(
                val.parse::<u32>()
                    .map_err(|_| AgentdError::Config(format!("invalid tmpfs size: {val}")))?,
            );
        } else if let Some(val) = opt.strip_prefix("mode=") {
            mode =
                Some(u32::from_str_radix(val, 8).map_err(|_| {
                    AgentdError::Config(format!("invalid octal tmpfs mode: {val}"))
                })?);
        } else {
            return Err(AgentdError::Config(format!("unknown tmpfs option: {opt}")));
        }
    }

    Ok(TmpfsSpec {
        path: path.to_string(),
        size_mib,
        mode,
        noexec,
    })
}

//--------------------------------------------------------------------------------------------------
// Parse Functions: Rlimits
//--------------------------------------------------------------------------------------------------

/// Parses `MSB_RLIMITS` value: semicolon-separated `resource=soft[:hard]` entries.
///
/// Rejects unknown resource names and duplicate resources at startup so
/// misspellings and overrides fail loud rather than silently last-winning
/// during PID 1 init.
fn parse_rlimits(val: &str) -> AgentdResult<Vec<ExecRlimit>> {
    let mut seen: Vec<String> = Vec::new();
    val.split(';')
        .filter(|entry| !entry.is_empty())
        .map(|entry| {
            let rlimit = entry.parse::<ExecRlimit>().map_err(|err| {
                AgentdError::Config(format!("{ENV_RLIMITS} entry {entry}: {err}"))
            })?;
            if rlimit::parse_rlimit_resource(&rlimit.resource).is_none() {
                return Err(AgentdError::Config(format!(
                    "{ENV_RLIMITS} unknown resource: {}",
                    rlimit.resource
                )));
            }
            if seen.iter().any(|name| name == &rlimit.resource) {
                return Err(AgentdError::Config(format!(
                    "{ENV_RLIMITS} duplicate resource: {}",
                    rlimit.resource
                )));
            }
            seen.push(rlimit.resource.clone());
            Ok(rlimit)
        })
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Parse Functions: Network
//--------------------------------------------------------------------------------------------------

/// Parses `MSB_NET` value: `iface=NAME,mac=AA:BB:CC:DD:EE:FF,mtu=N`
fn parse_net(val: &str) -> AgentdResult<NetSpec> {
    let mut iface = None;
    let mut mac = None;
    let mut mtu = 1500u16;

    for part in val.split(',') {
        if let Some(v) = part.strip_prefix("iface=") {
            iface = Some(v.to_string());
        } else if let Some(v) = part.strip_prefix("mac=") {
            mac = Some(parse_mac(v)?);
        } else if let Some(v) = part.strip_prefix("mtu=") {
            mtu = v
                .parse()
                .map_err(|_| AgentdError::Config(format!("invalid MTU: {v}")))?;
        } else {
            return Err(AgentdError::Config(format!(
                "unknown MSB_NET option: {part}"
            )));
        }
    }

    let iface = iface.ok_or_else(|| AgentdError::Config("MSB_NET missing iface=".into()))?;
    let mac = mac.ok_or_else(|| AgentdError::Config("MSB_NET missing mac=".into()))?;

    Ok(NetSpec { iface, mac, mtu })
}

/// Parses `MSB_NET_IPV4` value: `addr=A.B.C.D/N,gw=A.B.C.D[,dns=A.B.C.D]`
fn parse_net_ipv4(val: &str) -> AgentdResult<NetIpv4Spec> {
    let mut address = None;
    let mut prefix_len = None;
    let mut gateway = None;
    let mut dns = None;

    for part in val.split(',') {
        if let Some(v) = part.strip_prefix("addr=") {
            let (addr, prefix) = parse_cidr_v4(v)?;
            address = Some(addr);
            prefix_len = Some(prefix);
        } else if let Some(v) = part.strip_prefix("gw=") {
            gateway = Some(
                v.parse::<Ipv4Addr>()
                    .map_err(|_| AgentdError::Config(format!("invalid IPv4 gateway: {v}")))?,
            );
        } else if let Some(v) = part.strip_prefix("dns=") {
            dns = Some(
                v.parse::<Ipv4Addr>()
                    .map_err(|_| AgentdError::Config(format!("invalid IPv4 DNS: {v}")))?,
            );
        } else {
            return Err(AgentdError::Config(format!(
                "unknown MSB_NET_IPV4 option: {part}"
            )));
        }
    }

    let address =
        address.ok_or_else(|| AgentdError::Config("MSB_NET_IPV4 missing addr=".into()))?;
    let prefix_len =
        prefix_len.ok_or_else(|| AgentdError::Config("MSB_NET_IPV4 missing addr=".into()))?;
    let gateway = gateway.ok_or_else(|| AgentdError::Config("MSB_NET_IPV4 missing gw=".into()))?;

    Ok(NetIpv4Spec {
        address,
        prefix_len,
        gateway,
        dns,
    })
}

/// Parses `MSB_NET_IPV6` value: `addr=ADDR/N,gw=ADDR[,dns=ADDR]`
fn parse_net_ipv6(val: &str) -> AgentdResult<NetIpv6Spec> {
    let mut address = None;
    let mut prefix_len = None;
    let mut gateway = None;
    let mut dns = None;

    for part in val.split(',') {
        if let Some(v) = part.strip_prefix("addr=") {
            let (addr, prefix) = parse_cidr_v6(v)?;
            address = Some(addr);
            prefix_len = Some(prefix);
        } else if let Some(v) = part.strip_prefix("gw=") {
            gateway = Some(
                v.parse::<Ipv6Addr>()
                    .map_err(|_| AgentdError::Config(format!("invalid IPv6 gateway: {v}")))?,
            );
        } else if let Some(v) = part.strip_prefix("dns=") {
            dns = Some(
                v.parse::<Ipv6Addr>()
                    .map_err(|_| AgentdError::Config(format!("invalid IPv6 DNS: {v}")))?,
            );
        } else {
            return Err(AgentdError::Config(format!(
                "unknown MSB_NET_IPV6 option: {part}"
            )));
        }
    }

    let address =
        address.ok_or_else(|| AgentdError::Config("MSB_NET_IPV6 missing addr=".into()))?;
    let prefix_len =
        prefix_len.ok_or_else(|| AgentdError::Config("MSB_NET_IPV6 missing addr=".into()))?;
    let gateway = gateway.ok_or_else(|| AgentdError::Config("MSB_NET_IPV6 missing gw=".into()))?;

    Ok(NetIpv6Spec {
        address,
        prefix_len,
        gateway,
        dns,
    })
}

/// Parses a MAC address string like `02:5a:7b:13:01:02`.
fn parse_mac(s: &str) -> AgentdResult<[u8; 6]> {
    let mut mac = [0u8; 6];
    let mut len = 0usize;
    for (i, part) in s.split(':').enumerate() {
        if i >= 6 {
            return Err(AgentdError::Config(format!("invalid MAC address: {s}")));
        }
        mac[i] = u8::from_str_radix(part, 16)
            .map_err(|_| AgentdError::Config(format!("invalid MAC octet: {part}")))?;
        len = i + 1;
    }
    if len != 6 {
        return Err(AgentdError::Config(format!("invalid MAC address: {s}")));
    }
    Ok(mac)
}

/// Parses an IPv4 CIDR like `100.96.1.2/30`.
fn parse_cidr_v4(s: &str) -> AgentdResult<(Ipv4Addr, u8)> {
    let (addr_str, prefix_str) = s
        .split_once('/')
        .ok_or_else(|| AgentdError::Config(format!("invalid IPv4 CIDR (missing /): {s}")))?;
    let addr = addr_str
        .parse::<Ipv4Addr>()
        .map_err(|_| AgentdError::Config(format!("invalid IPv4 address: {addr_str}")))?;
    let prefix = prefix_str
        .parse::<u8>()
        .map_err(|_| AgentdError::Config(format!("invalid IPv4 prefix length: {prefix_str}")))?;
    if prefix > 32 {
        return Err(AgentdError::Config(format!(
            "IPv4 prefix length out of range (0-32): {prefix}"
        )));
    }
    Ok((addr, prefix))
}

/// Parses an IPv6 CIDR like `fd42:6d73:62:2a::2/64`.
fn parse_cidr_v6(s: &str) -> AgentdResult<(Ipv6Addr, u8)> {
    let (addr_str, prefix_str) = s
        .rsplit_once('/')
        .ok_or_else(|| AgentdError::Config(format!("invalid IPv6 CIDR (missing /): {s}")))?;
    let addr = addr_str
        .parse::<Ipv6Addr>()
        .map_err(|_| AgentdError::Config(format!("invalid IPv6 address: {addr_str}")))?;
    let prefix = prefix_str
        .parse::<u8>()
        .map_err(|_| AgentdError::Config(format!("invalid IPv6 prefix length: {prefix_str}")))?;
    if prefix > 128 {
        return Err(AgentdError::Config(format!(
            "IPv6 prefix length out of range (0-128): {prefix}"
        )));
    }
    Ok((addr, prefix))
}

//--------------------------------------------------------------------------------------------------
// Helper Functions
//--------------------------------------------------------------------------------------------------

/// Reads a single environment variable, returning `None` for missing or empty values.
fn read_env(key: &str) -> Option<String> {
    env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // ── Block Root ────────────────────────────────────────────────────

    #[test]
    fn test_parse_block_root_disk_image() {
        let spec = parse_block_root("kind=disk-image,device=/dev/vda,fstype=ext4").unwrap();
        let BlockRootSpec::DiskImage { device, fstype } = spec else {
            panic!("expected DiskImage");
        };
        assert_eq!(device, "/dev/vda");
        assert_eq!(fstype.as_deref(), Some("ext4"));
    }

    #[test]
    fn test_parse_block_root_disk_image_no_fstype() {
        let spec = parse_block_root("kind=disk-image,device=/dev/vda").unwrap();
        let BlockRootSpec::DiskImage { device, fstype } = spec else {
            panic!("expected DiskImage");
        };
        assert_eq!(device, "/dev/vda");
        assert_eq!(fstype, None);
    }

    #[test]
    fn test_parse_block_root_oci_erofs() {
        let spec =
            parse_block_root("kind=oci-erofs,lower=/dev/vda,upper=/dev/vdb,upper_fstype=ext4")
                .unwrap();
        let BlockRootSpec::OciErofs {
            lower,
            upper,
            upper_fstype,
        } = spec
        else {
            panic!("expected OciErofs");
        };
        assert_eq!(lower, "/dev/vda");
        assert_eq!(upper, "/dev/vdb");
        assert_eq!(upper_fstype, "ext4");
    }

    #[test]
    fn test_parse_block_root_unknown_kind_errors() {
        let err = parse_block_root("kind=bogus,device=/dev/vda").unwrap_err();
        assert!(err.to_string().contains("unknown kind"));
    }

    #[test]
    fn test_parse_block_root_missing_kind_errors() {
        let err = parse_block_root("/dev/vda").unwrap_err();
        assert!(err.to_string().contains("missing 'kind' key"));
    }

    #[test]
    fn test_parse_block_root_disk_image_missing_device_errors() {
        let err = parse_block_root("kind=disk-image").unwrap_err();
        assert!(err.to_string().contains("missing 'device'"));
    }

    #[test]
    fn test_parse_block_root_oci_erofs_missing_upper_errors() {
        let err = parse_block_root("kind=oci-erofs,lower=/dev/vda,upper_fstype=ext4").unwrap_err();
        assert!(err.to_string().contains("missing 'upper'"));
    }

    #[test]
    fn test_parse_block_root_duplicate_key_errors() {
        let err = parse_block_root("kind=disk-image,device=/dev/vda,device=/dev/vdb").unwrap_err();
        assert!(err.to_string().contains("duplicate key 'device'"));
    }

    // ── File Mounts ────────────────────────────────────────────────────

    #[test]
    fn test_parse_file_mount_entry_basic() {
        let spec = parse_file_mount_entry("fm_config:app.conf:/etc/app.conf").unwrap();
        assert_eq!(spec.tag, "fm_config");
        assert_eq!(spec.filename, "app.conf");
        assert_eq!(spec.guest_path, "/etc/app.conf");
        assert!(!spec.readonly);
    }

    #[test]
    fn test_parse_file_mount_entry_readonly() {
        let spec = parse_file_mount_entry("fm_config:app.conf:/etc/app.conf:ro").unwrap();
        assert!(spec.readonly);
    }

    #[test]
    fn test_parse_file_mount_entry_too_few_parts() {
        assert!(parse_file_mount_entry("fm_config:/etc/app.conf").is_err());
    }

    #[test]
    fn test_parse_file_mount_entry_empty_filename() {
        assert!(parse_file_mount_entry("fm_config::/etc/app.conf").is_err());
    }

    #[test]
    fn test_parse_file_mount_entry_relative_path() {
        assert!(parse_file_mount_entry("fm_config:app.conf:relative/path").is_err());
    }

    #[test]
    fn test_parse_file_mount_entry_too_many_parts() {
        assert!(parse_file_mount_entry("fm_config:app.conf:/etc/app.conf:ro:extra").is_err());
    }

    #[test]
    fn test_parse_file_mount_entry_unknown_flag() {
        assert!(parse_file_mount_entry("fm_config:app.conf:/etc/app.conf:rw").is_err());
    }

    #[test]
    fn test_parse_file_mount_entry_empty_tag() {
        assert!(parse_file_mount_entry(":app.conf:/etc/app.conf").is_err());
    }

    // ── Tmpfs ─────────────────────────────────────────────────────────

    #[test]
    fn test_parse_path_only() {
        let spec = parse_tmpfs_entry("/tmp").unwrap();
        assert_eq!(spec.path, "/tmp");
        assert_eq!(spec.size_mib, None);
        assert_eq!(spec.mode, None);
        assert!(!spec.noexec);
    }

    #[test]
    fn test_parse_with_size() {
        let spec = parse_tmpfs_entry("/tmp,size=256").unwrap();
        assert_eq!(spec.path, "/tmp");
        assert_eq!(spec.size_mib, Some(256));
    }

    #[test]
    fn test_parse_with_noexec() {
        let spec = parse_tmpfs_entry("/tmp,noexec").unwrap();
        assert_eq!(spec.path, "/tmp");
        assert!(spec.noexec);
    }

    #[test]
    fn test_parse_with_octal_mode() {
        let spec = parse_tmpfs_entry("/tmp,mode=1777").unwrap();
        assert_eq!(spec.mode, Some(0o1777));

        let spec = parse_tmpfs_entry("/data,mode=755").unwrap();
        assert_eq!(spec.mode, Some(0o755));
    }

    #[test]
    fn test_parse_multi_options() {
        let spec = parse_tmpfs_entry("/tmp,size=256,mode=1777,noexec").unwrap();
        assert_eq!(spec.path, "/tmp");
        assert_eq!(spec.size_mib, Some(256));
        assert_eq!(spec.mode, Some(0o1777));
        assert!(spec.noexec);
    }

    #[test]
    fn test_parse_unknown_option_errors() {
        let err = parse_tmpfs_entry("/tmp,bogus=42").unwrap_err();
        assert!(err.to_string().contains("unknown tmpfs option"));
    }

    #[test]
    fn test_parse_invalid_size_errors() {
        let err = parse_tmpfs_entry("/tmp,size=abc").unwrap_err();
        assert!(err.to_string().contains("invalid tmpfs size"));
    }

    #[test]
    fn test_parse_invalid_mode_errors() {
        let err = parse_tmpfs_entry("/tmp,mode=zzz").unwrap_err();
        assert!(err.to_string().contains("invalid octal tmpfs mode"));
    }

    #[test]
    fn test_parse_empty_path_errors() {
        let err = parse_tmpfs_entry(",size=256").unwrap_err();
        assert!(err.to_string().contains("empty path"));
    }

    // ── Network ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_net_full() {
        let spec = parse_net("iface=eth0,mac=02:5a:7b:13:01:02,mtu=1500").unwrap();
        assert_eq!(spec.iface, "eth0");
        assert_eq!(spec.mac, [0x02, 0x5a, 0x7b, 0x13, 0x01, 0x02]);
        assert_eq!(spec.mtu, 1500);
    }

    #[test]
    fn test_parse_net_default_mtu() {
        let spec = parse_net("iface=eth0,mac=02:00:00:00:00:01").unwrap();
        assert_eq!(spec.mtu, 1500);
    }

    #[test]
    fn test_parse_net_missing_iface() {
        assert!(parse_net("mac=02:00:00:00:00:01").is_err());
    }

    #[test]
    fn test_parse_net_missing_mac() {
        assert!(parse_net("iface=eth0").is_err());
    }

    #[test]
    fn test_parse_net_unknown_option() {
        assert!(parse_net("iface=eth0,mac=02:00:00:00:00:01,bogus=42").is_err());
    }

    #[test]
    fn test_parse_net_ipv4() {
        let spec = parse_net_ipv4("addr=100.96.1.2/30,gw=100.96.1.1,dns=100.96.1.1").unwrap();
        assert_eq!(spec.address, Ipv4Addr::new(100, 96, 1, 2));
        assert_eq!(spec.prefix_len, 30);
        assert_eq!(spec.gateway, Ipv4Addr::new(100, 96, 1, 1));
        assert_eq!(spec.dns, Some(Ipv4Addr::new(100, 96, 1, 1)));
    }

    #[test]
    fn test_parse_net_ipv4_no_dns() {
        let spec = parse_net_ipv4("addr=10.0.0.2/24,gw=10.0.0.1").unwrap();
        assert_eq!(spec.dns, None);
    }

    #[test]
    fn test_parse_net_ipv4_missing_addr() {
        assert!(parse_net_ipv4("gw=10.0.0.1").is_err());
    }

    #[test]
    fn test_parse_net_ipv6() {
        let spec = parse_net_ipv6(
            "addr=fd42:6d73:62:2a::2/64,gw=fd42:6d73:62:2a::1,dns=fd42:6d73:62:2a::1",
        )
        .unwrap();
        assert_eq!(
            spec.address,
            "fd42:6d73:62:2a::2".parse::<Ipv6Addr>().unwrap()
        );
        assert_eq!(spec.prefix_len, 64);
        assert_eq!(
            spec.gateway,
            "fd42:6d73:62:2a::1".parse::<Ipv6Addr>().unwrap()
        );
        assert!(spec.dns.is_some());
    }

    #[test]
    fn test_parse_mac_valid() {
        let mac = parse_mac("02:5a:7b:13:01:02").unwrap();
        assert_eq!(mac, [0x02, 0x5a, 0x7b, 0x13, 0x01, 0x02]);
    }

    #[test]
    fn test_parse_mac_invalid() {
        assert!(parse_mac("02:5a:7b").is_err());
        assert!(parse_mac("zz:00:00:00:00:00").is_err());
    }

    #[test]
    fn test_parse_cidr_v4() {
        let (addr, prefix) = parse_cidr_v4("100.96.1.2/30").unwrap();
        assert_eq!(addr, Ipv4Addr::new(100, 96, 1, 2));
        assert_eq!(prefix, 30);
    }

    #[test]
    fn test_parse_cidr_v6() {
        let (addr, prefix) = parse_cidr_v6("fd42:6d73:62:2a::2/64").unwrap();
        assert_eq!(addr, "fd42:6d73:62:2a::2".parse::<Ipv6Addr>().unwrap());
        assert_eq!(prefix, 64);
    }

    // ── Rlimits ───────────────────────────────────────────────────────

    #[test]
    fn test_parse_rlimits_happy_path() {
        let rlimits = parse_rlimits("nofile=65535;nproc=4096:8192").unwrap();
        assert_eq!(rlimits.len(), 2);
        assert_eq!(rlimits[0].resource, "nofile");
        assert_eq!(rlimits[0].soft, 65535);
        assert_eq!(rlimits[0].hard, 65535);
        assert_eq!(rlimits[1].resource, "nproc");
        assert_eq!(rlimits[1].soft, 4096);
        assert_eq!(rlimits[1].hard, 8192);
    }

    #[test]
    fn test_parse_rlimits_ignores_empty_entries() {
        let rlimits = parse_rlimits("nofile=1024;").unwrap();
        assert_eq!(rlimits.len(), 1);
        assert_eq!(rlimits[0].resource, "nofile");
    }

    #[test]
    fn test_parse_rlimits_rejects_unknown_resource() {
        let err = parse_rlimits("bogus=1024").unwrap_err();
        assert!(
            matches!(err, AgentdError::Config(msg) if msg.contains("unknown resource: bogus")),
            "unexpected error shape"
        );
    }

    #[test]
    fn test_parse_rlimits_rejects_duplicate_resource() {
        let err = parse_rlimits("nofile=1024;nofile=65535").unwrap_err();
        assert!(
            matches!(err, AgentdError::Config(msg) if msg.contains("duplicate resource: nofile")),
            "unexpected error shape"
        );
    }

    #[test]
    fn test_parse_rlimits_rejects_malformed_entry() {
        assert!(parse_rlimits("nofile").is_err());
        assert!(parse_rlimits("nofile=abc").is_err());
        assert!(parse_rlimits("nofile=65535:1024").is_err()); // soft > hard
    }
}
