//! Config-FD environment transport introduced in v0.5.9, reused through v0.6.9.

use std::collections::BTreeMap;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use microsandbox_protocol::{bootstrap::*, exec::ExecRlimit};
use microsandbox_types::{RlimitResource, compat::field::Field};
use serde::de::DeserializeOwned;

use crate::client::compat::launch;
use crate::client::launch::LaunchConfig;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

type ParseResult<T> = Result<T, ()>;

#[derive(Default)]
struct MountOptions {
    flags: BootstrapMountFlags,
    fstype: Option<String>,
    size_mib: Option<u32>,
    mode: Option<u32>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Decode a launch using the environment-based bootstrap.
pub(in crate::client::compat) fn decode(bytes: &[u8]) -> Result<LaunchConfig, String> {
    let mut launch = launch::decode_previous(bytes)?;
    let Field::Present(env) = std::mem::take(&mut launch.env) else {
        return Err("missing bootstrap or legacy env".into());
    };
    let bootstrap = to_current(env, launch.workdir.take())
        .map_err(|field| format!("invalid legacy launch field: {field}"))?;
    launch.into_current(bootstrap, true)
}

/// Translate only the legacy representation. Typed bootstrap takes precedence at the caller.
pub(in crate::client::compat) fn to_current(
    env: Vec<String>,
    workdir: Option<String>,
) -> Result<GuestBootstrap, &'static str> {
    let mut values = BTreeMap::new();
    let mut default_env = Vec::with_capacity(env.len());
    for entry in env {
        let (key, value) = entry.split_once('=').ok_or("env")?;
        validate_env(key, value).map_err(|_| "env")?;
        // Preserve launch order when installing guest variables. The legacy
        // kernel-command-line transport gives the final assignment precedence.
        values.insert(key.to_owned(), value.to_owned());
        default_env.push(BootstrapEnvVar {
            key: key.to_owned(),
            value: value.to_owned(),
        });
    }
    let read = |key: &str| values.get(key).map(|s| s.trim()).filter(|s| !s.is_empty());
    let parse = |key: &'static str, f: fn(&str) -> ParseResult<_>| {
        read(key).map(f).transpose().map_err(|_| key)
    };
    let mut bootstrap = GuestBootstrap {
        default_env,
        default_cwd: workdir.filter(|v| !v.is_empty()),
        hostname: read("MSB_HOSTNAME").map(str::to_owned),
        host_alias: read("MSB_HOST_ALIAS").map(str::to_owned),
        user: read("MSB_USER").map(str::to_owned),
        block_root: parse("MSB_BLOCK_ROOT", block_root)?,
        ..GuestBootstrap::default()
    };
    if bootstrap
        .default_cwd
        .as_deref()
        .is_some_and(|v| v.contains('\0'))
    {
        return Err("workdir");
    }
    for entry in read("MSB_DIR_MOUNTS")
        .into_iter()
        .flat_map(|v| v.split(';'))
        .filter(|v| !v.is_empty())
    {
        let (parts, options) = mount(entry, 2, "directory").map_err(|_| "MSB_DIR_MOUNTS")?;
        bootstrap.dir_mounts.push(BootstrapDirMount {
            tag: parts[0].into(),
            guest_path: parts[1].into(),
            flags: options.flags,
        });
    }
    for entry in read("MSB_FILE_MOUNTS")
        .into_iter()
        .flat_map(|v| v.split(';'))
        .filter(|v| !v.is_empty())
    {
        let (parts, options) = mount(entry, 3, "file").map_err(|_| "MSB_FILE_MOUNTS")?;
        bootstrap.file_mounts.push(BootstrapFileMount {
            tag: parts[0].into(),
            filename: parts[1].into(),
            guest_path: parts[2].into(),
            flags: options.flags,
        });
    }
    for entry in read("MSB_DISK_MOUNTS")
        .into_iter()
        .flat_map(|v| v.split(';'))
        .filter(|v| !v.is_empty())
    {
        let (parts, options) = mount(entry, 2, "disk").map_err(|_| "MSB_DISK_MOUNTS")?;
        bootstrap.disk_mounts.push(BootstrapDiskMount {
            id: parts[0].into(),
            guest_path: parts[1].into(),
            fstype: options.fstype,
            flags: options.flags,
        });
    }
    for entry in read("MSB_TMPFS")
        .into_iter()
        .flat_map(|v| v.split(';'))
        .filter(|v| !v.is_empty())
    {
        let (parts, options) = mount(entry, 1, "tmpfs").map_err(|_| "MSB_TMPFS")?;
        bootstrap.tmpfs_mounts.push(BootstrapTmpfsMount {
            path: parts[0].into(),
            size_mib: options.size_mib,
            mode: options.mode,
            flags: options.flags,
        });
    }
    if let Some(value) = read("MSB_SECURITY_PROFILE") {
        bootstrap.security_profile = match value {
            "default" => BootstrapSecurityProfile::Default,
            "restricted" => BootstrapSecurityProfile::Restricted,
            _ => return Err("MSB_SECURITY_PROFILE"),
        };
    }
    if let Some(value) = read("MSB_RLIMITS") {
        for entry in value.split(';').filter(|v| !v.is_empty()) {
            let limit: ExecRlimit = entry.parse().map_err(|_| "MSB_RLIMITS")?;
            if RlimitResource::try_from(limit.resource.as_str()).is_err()
                || limit.soft > limit.hard
                || bootstrap
                    .rlimits
                    .iter()
                    .any(|other| other.resource == limit.resource)
            {
                return Err("MSB_RLIMITS");
            }
            bootstrap.rlimits.push(limit);
        }
    }
    if let Some(value) = read("MSB_NET") {
        bootstrap.network = Some(
            network(value, read("MSB_NET_IPV4"), read("MSB_NET_IPV6")).map_err(|_| "MSB_NET")?,
        );
    } else if read("MSB_NET_IPV4").is_some() || read("MSB_NET_IPV6").is_some() {
        return Err("MSB_NET");
    }
    // Handoff strings intentionally bypass trimming: argv, environment and paths
    // may contain significant whitespace. Paths refer to Linux even on Windows.
    if let Some(cmd) = values
        .get("MSB_HANDOFF_INIT")
        .filter(|v| !v.trim().is_empty())
    {
        if cmd != "auto" {
            absolute(cmd).map_err(|_| "MSB_HANDOFF_INIT")?;
        }
        let args: Vec<String> = decode_json(values.get("MSB_HANDOFF_INIT_ARGS"))
            .map_err(|_| "MSB_HANDOFF_INIT_ARGS")?;
        if args.iter().any(|v| v.contains('\0')) {
            return Err("MSB_HANDOFF_INIT_ARGS");
        }
        let env: Vec<(String, String)> =
            decode_json(values.get("MSB_HANDOFF_INIT_ENV")).map_err(|_| "MSB_HANDOFF_INIT_ENV")?;
        for (key, value) in &env {
            validate_env(key, value).map_err(|_| "MSB_HANDOFF_INIT_ENV")?;
        }
        let cwd = values
            .get("MSB_HANDOFF_INIT_CWD")
            .filter(|v| !v.is_empty())
            .cloned();
        if let Some(cwd) = &cwd {
            absolute(cwd).map_err(|_| "MSB_HANDOFF_INIT_CWD")?;
        }
        bootstrap.handoff_init = Some(BootstrapHandoffInit {
            cmd: cmd.clone(),
            args,
            cwd,
            env: env
                .into_iter()
                .map(|(key, value)| BootstrapEnvVar { key, value })
                .collect(),
        });
    }
    Ok(bootstrap)
}

fn block_root(value: &str) -> ParseResult<BootstrapBlockRoot> {
    let fields = pairs(value)?;
    let get = |key| required(&fields, key).map(str::to_owned);
    match required(&fields, "kind")? {
        "disk-image" => {
            let device = get("device")?;
            absolute(&device)?;
            Ok(BootstrapBlockRoot::DiskImage {
                device,
                fstype: fields
                    .get("fstype")
                    .filter(|v| !v.is_empty())
                    .map(|v| (*v).into()),
            })
        }
        "oci-erofs" => {
            let lower = get("lower")?;
            absolute(&lower)?;
            let upper = if required(&fields, "upper")? == "tmpfs" {
                if fields.contains_key("upper_fstype") {
                    return Err(());
                }
                BootstrapBlockRootUpper::Tmpfs {
                    size_mib: fields
                        .get("upper_size_mib")
                        .map(|v| v.parse())
                        .transpose()
                        .map_err(|_| ())?,
                }
            } else {
                let device = get("upper")?;
                absolute(&device)?;
                BootstrapBlockRootUpper::Device {
                    device,
                    fstype: get("upper_fstype")?,
                }
            };
            Ok(BootstrapBlockRoot::OciErofs { lower, upper })
        }
        _ => Err(()),
    }
}

/// The final positional field is always a Linux guest path; keyed options vary by mount kind.
fn mount<'a>(
    entry: &'a str,
    count: usize,
    kind: &str,
) -> ParseResult<(Vec<&'a str>, MountOptions)> {
    let mut parts = entry.splitn(count + 1, ':');
    let fields: Vec<_> = parts.by_ref().take(count).collect();
    if fields.len() != count || fields.iter().any(|s| s.is_empty()) {
        return Err(());
    }
    absolute(fields[count - 1])?;
    let mut options = MountOptions::default();
    let mut seen = Vec::new();
    for option in parts
        .next()
        .into_iter()
        .flat_map(|v| v.split(','))
        .map(str::trim)
        .filter(|v| !v.is_empty())
    {
        let (key, value) = option.split_once('=').unwrap_or((option, ""));
        let identity = if matches!(key, "ro" | "rw") {
            "access"
        } else {
            key
        };
        if seen.contains(&identity) {
            return Err(());
        }
        seen.push(identity);
        match (key, value) {
            ("ro", "") => options.flags.readonly = true,
            ("rw", "") => options.flags.readonly = false,
            ("noexec", "") => options.flags.noexec = true,
            ("nosuid", "") => options.flags.nosuid = true,
            ("nodev", "") => options.flags.nodev = true,
            ("fstype", value)
                if kind == "disk" && !value.is_empty() && !value.contains([':', ';', '=']) =>
            {
                options.fstype = Some(value.into())
            }
            ("size", value) if kind == "tmpfs" => {
                options.size_mib = Some(value.parse().map_err(|_| ())?)
            }
            ("mode", value) if kind == "tmpfs" => {
                options.mode = Some(u32::from_str_radix(value, 8).map_err(|_| ())?)
            }
            _ => return Err(()),
        }
    }
    Ok((fields, options))
}

fn network(value: &str, ipv4: Option<&str>, ipv6: Option<&str>) -> ParseResult<BootstrapNetwork> {
    let fields = pairs(value)?;
    if fields
        .keys()
        .any(|key| !matches!(*key, "iface" | "mac" | "mtu"))
    {
        return Err(());
    }
    let mac: Vec<u8> = required(&fields, "mac")?
        .split(':')
        .map(|v| u8::from_str_radix(v, 16).map_err(|_| ()))
        .collect::<ParseResult<_>>()?;
    Ok(BootstrapNetwork {
        interface: required(&fields, "iface")?.into(),
        mac: mac.try_into().map_err(|_| ())?,
        mtu: fields
            .get("mtu")
            .map(|v| v.parse())
            .transpose()
            .map_err(|_| ())?
            .unwrap_or(1500),
        ipv4: ipv4
            .map(|v| {
                let f = pairs(v)?;
                let (address, prefix_len) = ip_address(&f, 32)?;
                Ok::<_, ()>(BootstrapIpv4 {
                    address: address.parse().map_err(|_| ())?,
                    prefix_len,
                    gateway: required(&f, "gw")?.parse().map_err(|_| ())?,
                    dns: f
                        .get("dns")
                        .map(|v| v.parse())
                        .transpose()
                        .map_err(|_| ())?,
                })
            })
            .transpose()?,
        ipv6: ipv6
            .map(|v| {
                let f = pairs(v)?;
                let (address, prefix_len) = ip_address(&f, 128)?;
                Ok::<_, ()>(BootstrapIpv6 {
                    address: address.parse().map_err(|_| ())?,
                    prefix_len,
                    gateway: required(&f, "gw")?.parse().map_err(|_| ())?,
                    dns: f
                        .get("dns")
                        .map(|v| v.parse())
                        .transpose()
                        .map_err(|_| ())?,
                })
            })
            .transpose()?,
    })
}

fn ip_address<'a>(fields: &BTreeMap<&str, &'a str>, max: u8) -> ParseResult<(&'a str, u8)> {
    if fields
        .keys()
        .any(|key| !matches!(*key, "addr" | "gw" | "dns"))
    {
        return Err(());
    }
    let (address, prefix) = required(fields, "addr")?.rsplit_once('/').ok_or(())?;
    let prefix = prefix.parse::<u8>().map_err(|_| ())?;
    if prefix > max {
        return Err(());
    }
    Ok((address, prefix))
}

fn pairs(value: &str) -> ParseResult<BTreeMap<&str, &str>> {
    let mut fields = BTreeMap::new();
    for entry in value.split(',') {
        let (key, value) = entry.split_once('=').ok_or(())?;
        if fields.insert(key, value).is_some() {
            return Err(());
        }
    }
    Ok(fields)
}

fn required<'a>(fields: &BTreeMap<&str, &'a str>, key: &str) -> ParseResult<&'a str> {
    fields.get(key).copied().filter(|v| !v.is_empty()).ok_or(())
}

fn absolute(value: &str) -> ParseResult<()> {
    if value.starts_with('/') && !value.contains('\0') {
        Ok(())
    } else {
        Err(())
    }
}

fn validate_env(key: &str, value: &str) -> ParseResult<()> {
    if key.is_empty() || key.contains(['=', '\0']) || value.contains('\0') {
        Err(())
    } else {
        Ok(())
    }
}

fn decode_json<T: DeserializeOwned + Default>(value: Option<&String>) -> ParseResult<T> {
    match value.filter(|v| !v.is_empty()) {
        Some(value) => {
            serde_json::from_slice(&URL_SAFE_NO_PAD.decode(value).map_err(|_| ())?).map_err(|_| ())
        }
        None => Ok(T::default()),
    }
}
