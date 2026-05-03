//! Agentd configuration, read once from environment variables at startup.
//!
//! Split into two structs with different lifetimes:
//!
//! - [`BootParams`] — one-shot MSB_* env vars consumed by [`init::init`] and
//!   dropped once init completes.
//! - [`AgentdConfig`] — runtime config that outlives init (currently just
//!   the default guest user), passed by reference to the agent loop.
//!
//! Each struct owns its own [`from_env`](BootParams::from_env) constructor
//! so reading is centralised and validation failures abort boot with a
//! single clean error before any side effects begin.
//!
//! [`init::init`]: crate::init::init

use std::env;
use std::ffi::OsString;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::path::PathBuf;

use microsandbox_protocol::{
    ENV_BLOCK_ROOT, ENV_DIR_MOUNTS, ENV_DISK_MOUNTS, ENV_FILE_MOUNTS, ENV_HANDOFF_INIT,
    ENV_HANDOFF_INIT_ARGS, ENV_HANDOFF_INIT_ENV, ENV_HOST_ALIAS, ENV_HOSTNAME, ENV_NET,
    ENV_NET_IPV4, ENV_NET_IPV6, ENV_RLIMITS, ENV_TMPFS, ENV_USER, HANDOFF_INIT_SEP,
    exec::ExecRlimit,
};

use crate::error::{AgentdError, AgentdResult};
use crate::rlimit;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// One-shot MSB_* env vars consumed by [`init::init`] and dropped afterward.
///
/// Moved by value into init; owning the data (rather than borrowing) makes
/// the "consumed once" lifetime explicit in the signature and prevents
/// accidental reads after init completes.
///
/// [`init::init`]: crate::init::init
#[derive(Debug)]
pub struct BootParams {
    /// Parsed `MSB_BLOCK_ROOT` — block device for rootfs switch.
    pub(crate) block_root: Option<BlockRootSpec>,

    /// Parsed `MSB_DIR_MOUNTS` — virtiofs directory mount specs (empty when unset).
    pub(crate) dir_mounts: Vec<DirMountSpec>,

    /// Parsed `MSB_FILE_MOUNTS` — virtiofs file mount specs (empty when unset).
    pub(crate) file_mounts: Vec<FileMountSpec>,

    /// Parsed `MSB_DISK_MOUNTS` — disk-image mount specs (empty when unset).
    pub(crate) disk_mounts: Vec<DiskMountSpec>,

    /// Parsed `MSB_TMPFS` — tmpfs mount specs (empty when unset).
    pub(crate) tmpfs: Vec<TmpfsSpec>,

    /// `MSB_HOSTNAME` — guest hostname.
    pub(crate) hostname: Option<String>,

    /// `MSB_HOST_ALIAS` — DNS name (e.g. `host.microsandbox.internal`)
    /// the guest uses to reach the sandbox host. Written into
    /// `/etc/hosts` pointing at the gateway IPs.
    pub(crate) host_alias: Option<String>,

    /// Parsed `MSB_NET` — network interface config.
    pub(crate) net: Option<NetSpec>,

    /// Parsed `MSB_NET_IPV4` — IPv4 config.
    pub(crate) net_ipv4: Option<NetIpv4Spec>,

    /// Parsed `MSB_NET_IPV6` — IPv6 config.
    pub(crate) net_ipv6: Option<NetIpv6Spec>,

    /// Parsed `MSB_RLIMITS` — sandbox-wide resource limits applied to PID 1
    /// so every guest process inherits the raised baseline (empty when unset).
    pub(crate) rlimits: Vec<ExecRlimit>,

    /// Parsed `MSB_HANDOFF_INIT[_ARGS|_ENV]` — guest init binary to which
    /// agentd hands off PID 1 after `init::init()`. `None` means agentd
    /// remains PID 1 (the default).
    pub(crate) handoff_init: Option<HandoffInit>,
}

/// Parsed handoff-init specification.
///
/// When present in [`BootParams`], agentd performs setup, forks, the
/// parent execs `program` (becoming the new PID 1), and the child
/// continues as the agent loop.
#[derive(Debug)]
pub struct HandoffInit {
    /// Absolute path inside the guest rootfs.
    pub(crate) program: PathBuf,

    /// argv past `argv[0]` — i.e., the supplemental arguments. Empty
    /// means the init is exec'd with `argv = [program]`.
    pub(crate) argv: Vec<OsString>,

    /// Extra env vars merged on top of the inherited env. Empty means
    /// inherit-only.
    pub(crate) env: Vec<(OsString, OsString)>,
}

/// Runtime configuration surviving past init; referenced by the agent loop.
///
/// Currently holds only the default guest user used when an exec request
/// does not specify its own.
#[derive(Debug)]
pub struct AgentdConfig {
    /// `MSB_USER` — default guest user for exec sessions.
    ///
    /// Captured at startup; changes to `MSB_USER` afterward are not observed.
    pub(crate) user: Option<String>,
}

/// Parsed tmpfs mount specification.
#[derive(Debug)]
pub(crate) struct TmpfsSpec {
    pub path: String,
    pub size_mib: Option<u32>,
    pub mode: Option<u32>,
    pub noexec: bool,
    pub readonly: bool,
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

/// Parsed disk-image volume mount specification.
///
/// Each entry corresponds to one extra virtio-blk device attached by the
/// VMM. Agentd resolves the device node from `id` via
/// `/dev/disk/by-id/virtio-<id>` and mounts it at `guest_path`.
#[derive(Debug)]
pub(crate) struct DiskMountSpec {
    pub id: String,
    pub guest_path: String,
    /// Inner filesystem type. `None` triggers an autodetect walk over
    /// `/proc/filesystems` in agentd's init path.
    pub fstype: Option<String>,
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

impl BootParams {
    /// Reads and parses the boot-time `MSB_*` environment variables.
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
            disk_mounts: read_env(ENV_DISK_MOUNTS)
                .map(|v| parse_disk_mounts(&v))
                .transpose()?
                .unwrap_or_default(),
            tmpfs: read_env(ENV_TMPFS)
                .map(|v| parse_tmpfs_mounts(&v))
                .transpose()?
                .unwrap_or_default(),
            hostname: read_env(ENV_HOSTNAME),
            host_alias: read_env(ENV_HOST_ALIAS),
            net: read_env(ENV_NET).map(|v| parse_net(&v)).transpose()?,
            net_ipv4: read_env(ENV_NET_IPV4)
                .map(|v| parse_net_ipv4(&v))
                .transpose()?,
            net_ipv6: read_env(ENV_NET_IPV6)
                .map(|v| parse_net_ipv6(&v))
                .transpose()?,
            rlimits: read_env(ENV_RLIMITS)
                .map(|v| parse_rlimits(&v))
                .transpose()?
                .unwrap_or_default(),
            handoff_init: parse_handoff_init()?,
        })
    }

    /// Take the handoff-init spec out of the boot params.
    ///
    /// Used by `bin/main.rs` before `init::init` consumes `BootParams`
    /// by value, since the handoff hook fires after init returns.
    pub fn take_handoff_init(&mut self) -> Option<HandoffInit> {
        self.handoff_init.take()
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

impl AgentdConfig {
    /// Reads the runtime-config `MSB_*` environment variables.
    ///
    /// Empty or whitespace-only values are treated as absent (`None`).
    pub fn from_env() -> AgentdResult<Self> {
        Ok(Self {
            user: read_env(ENV_USER),
        })
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

/// Parses semicolon-separated disk-image mount entries.
fn parse_disk_mounts(val: &str) -> AgentdResult<Vec<DiskMountSpec>> {
    val.split(';')
        .filter(|e| !e.is_empty())
        .map(parse_disk_mount_entry)
        .collect()
}

/// Parses a single disk-image mount entry: `id:guest_path[:fstype][:ro]`.
///
/// `fstype` may be empty (treated as autodetect). `ro` is the optional
/// final token.
fn parse_disk_mount_entry(entry: &str) -> AgentdResult<DiskMountSpec> {
    let parts: Vec<&str> = entry.split(':').collect();
    if parts.len() < 2 {
        return Err(AgentdError::Config(format!(
            "MSB_DISK_MOUNTS entry must be id:guest_path[:fstype][:ro], got: {entry}"
        )));
    }

    let id = parts[0];
    let guest_path = parts[1];
    let mut fstype: Option<String> = None;
    let mut readonly = false;

    if let Some(third) = parts.get(2)
        && !third.is_empty()
    {
        fstype = Some((*third).to_string());
    }
    if let Some(fourth) = parts.get(3) {
        match *fourth {
            "ro" => readonly = true,
            other => {
                return Err(AgentdError::Config(format!(
                    "MSB_DISK_MOUNTS unknown flag '{other}' (expected 'ro')"
                )));
            }
        }
    }
    if parts.len() > 4 {
        return Err(AgentdError::Config(format!(
            "MSB_DISK_MOUNTS entry has too many parts: {entry}"
        )));
    }

    if id.is_empty() {
        return Err(AgentdError::Config(
            "MSB_DISK_MOUNTS entry has empty id".into(),
        ));
    }
    if guest_path.is_empty() || !guest_path.starts_with('/') {
        return Err(AgentdError::Config(format!(
            "MSB_DISK_MOUNTS guest path must be absolute: {guest_path}"
        )));
    }

    Ok(DiskMountSpec {
        id: id.to_string(),
        guest_path: guest_path.to_string(),
        fstype,
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
    let mut readonly = false;

    for opt in parts {
        if opt == "noexec" {
            noexec = true;
        } else if opt == "ro" {
            readonly = true;
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
        readonly,
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
// Parse Functions: Handoff Init
//--------------------------------------------------------------------------------------------------

/// Reads `MSB_HANDOFF_INIT[_ARGS|_ENV]` and assembles a [`HandoffInit`].
///
/// Returns `Ok(None)` when `MSB_HANDOFF_INIT` is unset/empty (the
/// default no-handoff path). Returns `Err` when the program path is
/// not absolute, or when `MSB_HANDOFF_INIT_ENV` contains an entry
/// without an `=`.
fn parse_handoff_init() -> AgentdResult<Option<HandoffInit>> {
    let Some(program_str) = read_env_raw(ENV_HANDOFF_INIT) else {
        return Ok(None);
    };
    if program_str.trim().is_empty() {
        return Ok(None);
    }

    let program = PathBuf::from(&program_str);
    if !program.is_absolute() {
        return Err(AgentdError::Config(format!(
            "{ENV_HANDOFF_INIT} must be an absolute path, got: {program_str}"
        )));
    }

    let argv = match read_env_raw(ENV_HANDOFF_INIT_ARGS) {
        Some(val) if !val.is_empty() => val.split(HANDOFF_INIT_SEP).map(OsString::from).collect(),
        _ => Vec::new(),
    };

    let env = match read_env_raw(ENV_HANDOFF_INIT_ENV) {
        Some(val) if !val.is_empty() => val
            .split(HANDOFF_INIT_SEP)
            .map(|entry| {
                let (k, v) = entry.split_once('=').ok_or_else(|| {
                    AgentdError::Config(format!(
                        "{ENV_HANDOFF_INIT_ENV} entry missing '=': {entry}"
                    ))
                })?;
                if k.is_empty() {
                    return Err(AgentdError::Config(format!(
                        "{ENV_HANDOFF_INIT_ENV} entry has empty key: {entry}"
                    )));
                }
                Ok((OsString::from(k), OsString::from(v)))
            })
            .collect::<AgentdResult<Vec<_>>>()?,
        _ => Vec::new(),
    };

    Ok(Some(HandoffInit { program, argv, env }))
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

/// Reads a single environment variable without trimming whitespace.
///
/// Used for the handoff-init vars where the `\x1f` separator and argv
/// content are sensitive to byte-exact preservation.
fn read_env_raw(key: &str) -> Option<String> {
    env::var(key).ok().filter(|v| !v.is_empty())
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

    // ── Disk Mounts ───────────────────────────────────────────────────

    #[test]
    fn test_parse_disk_mount_entry_basic() {
        let spec = parse_disk_mount_entry("data_abc:/data:ext4").unwrap();
        assert_eq!(spec.id, "data_abc");
        assert_eq!(spec.guest_path, "/data");
        assert_eq!(spec.fstype.as_deref(), Some("ext4"));
        assert!(!spec.readonly);
    }

    #[test]
    fn test_parse_disk_mount_entry_readonly() {
        let spec = parse_disk_mount_entry("seed_7f:/seed:ext4:ro").unwrap();
        assert!(spec.readonly);
        assert_eq!(spec.fstype.as_deref(), Some("ext4"));
    }

    #[test]
    fn test_parse_disk_mount_entry_empty_fstype_means_autodetect() {
        let spec = parse_disk_mount_entry("probe_1:/data::ro").unwrap();
        assert!(spec.fstype.is_none());
        assert!(spec.readonly);
    }

    #[test]
    fn test_parse_disk_mount_entry_autodetect_no_ro() {
        let spec = parse_disk_mount_entry("probe_1:/data").unwrap();
        assert!(spec.fstype.is_none());
        assert!(!spec.readonly);
    }

    #[test]
    fn test_parse_disk_mount_entry_rejects_unknown_flag() {
        let err = parse_disk_mount_entry("id:/data:ext4:rw").unwrap_err();
        assert!(err.to_string().contains("unknown flag"));
    }

    #[test]
    fn test_parse_disk_mount_entry_rejects_relative_path() {
        assert!(parse_disk_mount_entry("id:relative").is_err());
    }

    #[test]
    fn test_parse_disk_mount_entry_rejects_empty_id() {
        assert!(parse_disk_mount_entry(":/data:ext4").is_err());
    }

    #[test]
    fn test_parse_disk_mount_entry_rejects_too_many_parts() {
        assert!(parse_disk_mount_entry("id:/data:ext4:ro:extra").is_err());
    }

    #[test]
    fn test_parse_disk_mounts_multiple_entries() {
        let specs = parse_disk_mounts("data_1:/data:ext4;seed_2:/seed::ro;probe_3:/p").unwrap();
        assert_eq!(specs.len(), 3);
        assert_eq!(specs[0].guest_path, "/data");
        assert!(specs[1].readonly);
        assert!(specs[2].fstype.is_none());
    }

    #[test]
    fn test_parse_with_ro() {
        let spec = parse_tmpfs_entry("/seed,size=64,ro").unwrap();
        assert_eq!(spec.path, "/seed");
        assert_eq!(spec.size_mib, Some(64));
        assert!(spec.readonly);
        assert!(!spec.noexec);
    }

    #[test]
    fn test_parse_ro_defaults_to_false_when_absent() {
        let spec = parse_tmpfs_entry("/tmp,size=256").unwrap();
        assert!(!spec.readonly);
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

    // ── Handoff Init ──────────────────────────────────────────────────

    /// Mutex serialising tests that touch `MSB_HANDOFF_INIT*` env vars,
    /// since `parse_handoff_init` reads them from the process env.
    static HANDOFF_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_handoff_env<R>(
        program: Option<&str>,
        args: Option<&str>,
        env_var: Option<&str>,
        f: impl FnOnce() -> R,
    ) -> R {
        let _guard = HANDOFF_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        unsafe {
            match program {
                Some(v) => env::set_var(ENV_HANDOFF_INIT, v),
                None => env::remove_var(ENV_HANDOFF_INIT),
            }
            match args {
                Some(v) => env::set_var(ENV_HANDOFF_INIT_ARGS, v),
                None => env::remove_var(ENV_HANDOFF_INIT_ARGS),
            }
            match env_var {
                Some(v) => env::set_var(ENV_HANDOFF_INIT_ENV, v),
                None => env::remove_var(ENV_HANDOFF_INIT_ENV),
            }
        }
        let out = f();
        unsafe {
            env::remove_var(ENV_HANDOFF_INIT);
            env::remove_var(ENV_HANDOFF_INIT_ARGS);
            env::remove_var(ENV_HANDOFF_INIT_ENV);
        }
        out
    }

    #[test]
    fn test_parse_handoff_init_unset_returns_none() {
        let res = with_handoff_env(None, None, None, parse_handoff_init).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn test_parse_handoff_init_empty_returns_none() {
        let res = with_handoff_env(Some(""), None, None, parse_handoff_init).unwrap();
        assert!(res.is_none());
    }

    #[test]
    fn test_parse_handoff_init_program_only() {
        let res = with_handoff_env(Some("/lib/systemd/systemd"), None, None, parse_handoff_init)
            .unwrap()
            .unwrap();
        assert_eq!(res.program, PathBuf::from("/lib/systemd/systemd"));
        assert!(res.argv.is_empty());
        assert!(res.env.is_empty());
    }

    #[test]
    fn test_parse_handoff_init_with_argv() {
        let argv = format!("--unit=multi-user.target{HANDOFF_INIT_SEP}--log-level=warning");
        let res = with_handoff_env(
            Some("/lib/systemd/systemd"),
            Some(&argv),
            None,
            parse_handoff_init,
        )
        .unwrap()
        .unwrap();
        assert_eq!(
            res.argv,
            vec![
                OsString::from("--unit=multi-user.target"),
                OsString::from("--log-level=warning"),
            ]
        );
    }

    #[test]
    fn test_parse_handoff_init_with_env() {
        let envs = format!("container=microsandbox{HANDOFF_INIT_SEP}LANG=C.UTF-8");
        let res = with_handoff_env(Some("/sbin/init"), None, Some(&envs), parse_handoff_init)
            .unwrap()
            .unwrap();
        assert_eq!(
            res.env,
            vec![
                (OsString::from("container"), OsString::from("microsandbox")),
                (OsString::from("LANG"), OsString::from("C.UTF-8")),
            ]
        );
    }

    #[test]
    fn test_parse_handoff_init_argv_with_spaces_preserved() {
        // Argv entries can contain any characters except '\x1f' and NUL.
        let argv = format!("--label=hello world{HANDOFF_INIT_SEP}--config=/etc/foo;bar");
        let res = with_handoff_env(Some("/sbin/init"), Some(&argv), None, parse_handoff_init)
            .unwrap()
            .unwrap();
        assert_eq!(
            res.argv,
            vec![
                OsString::from("--label=hello world"),
                OsString::from("--config=/etc/foo;bar"),
            ]
        );
    }

    #[test]
    fn test_parse_handoff_init_rejects_relative_path() {
        let err = with_handoff_env(Some("sbin/init"), None, None, parse_handoff_init).unwrap_err();
        assert!(err.to_string().contains("absolute path"));
    }

    #[test]
    fn test_parse_handoff_init_env_entry_missing_equals() {
        let envs = format!("KEY=value{HANDOFF_INIT_SEP}NOEQUALS");
        let err = with_handoff_env(Some("/sbin/init"), None, Some(&envs), parse_handoff_init)
            .unwrap_err();
        assert!(err.to_string().contains("missing '='"));
    }

    #[test]
    fn test_parse_handoff_init_env_entry_empty_key_rejected() {
        // `=value` (empty key) used to silently produce a nameless env entry.
        let envs = "=value".to_string();
        let err = with_handoff_env(Some("/sbin/init"), None, Some(&envs), parse_handoff_init)
            .unwrap_err();
        assert!(err.to_string().contains("empty key"));
    }

    #[test]
    fn test_parse_handoff_init_env_value_with_equals_is_value() {
        // Only the first '=' splits; the rest is part of the value.
        let envs = "PATH=/a:/b=/c".to_string();
        let res = with_handoff_env(Some("/sbin/init"), None, Some(&envs), parse_handoff_init)
            .unwrap()
            .unwrap();
        assert_eq!(
            res.env,
            vec![(OsString::from("PATH"), OsString::from("/a:/b=/c"))]
        );
    }
}
