use microsandbox::sandbox::{NetworkPolicy, Patch, PullPolicy, SandboxConfig};
use microsandbox::{LogLevel, RegistryAuth};
use microsandbox_network::dns::Nameserver;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

use crate::error::to_py_err;

//--------------------------------------------------------------------------------------------------
// Functions: Config Conversion
//--------------------------------------------------------------------------------------------------

/// Build a `SandboxConfig` from Python kwargs.
pub fn build_config_from_kwargs(
    name: String,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<SandboxConfig> {
    let Some(kwargs) = kwargs else {
        return Err(pyo3::exceptions::PyValueError::new_err("image is required"));
    };

    let image_obj = kwargs
        .get_item("image")?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("image is required"))?;

    // Accept str, PathLike, or ImageSource (with _to_image_str method).
    let image_str: String = if let Ok(s) = image_obj.extract::<String>() {
        s
    } else if let Ok(method) = image_obj.getattr("_to_image_str") {
        method.call0()?.extract()?
    } else if let Ok(fspath) = image_obj.call_method0("__fspath__") {
        fspath.extract()?
    } else {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "image must be str, os.PathLike, or ImageSource",
        ));
    };

    let mut builder = microsandbox::Sandbox::builder(name);

    // Handle disk image with fstype if ImageSource has those attributes.
    if let Ok(fstype_attr) = image_obj.getattr("_fstype") {
        if !fstype_attr.is_none() {
            let fstype: String = fstype_attr.extract()?;
            builder = builder.image_with(|i| i.disk(&image_str).fstype(&fstype));
        } else {
            builder = builder.image(image_str.as_str());
        }
    } else {
        builder = builder.image(image_str.as_str());
    };

    if let Some(memory) = extract_opt::<u32>(kwargs, "memory")? {
        builder = builder.memory(memory);
    }
    if let Some(cpus) = extract_opt::<u8>(kwargs, "cpus")? {
        builder = builder.cpus(cpus);
    }
    if let Some(workdir) = extract_opt::<String>(kwargs, "workdir")? {
        builder = builder.workdir(workdir);
    }
    if let Some(shell) = extract_opt::<String>(kwargs, "shell")? {
        builder = builder.shell(shell);
    }
    if let Some(hostname) = extract_opt::<String>(kwargs, "hostname")? {
        builder = builder.hostname(hostname);
    }
    if let Some(libkrunfw_path) = extract_opt::<String>(kwargs, "libkrunfw_path")? {
        builder = builder.libkrunfw_path(libkrunfw_path);
    }
    if let Some(user) = extract_opt::<String>(kwargs, "user")? {
        builder = builder.user(user);
    }
    if let Some(entrypoint) = extract_opt::<Vec<String>>(kwargs, "entrypoint")? {
        builder = builder.entrypoint(entrypoint);
    }
    if let Some(init_obj) = kwargs.get_item("init")?
        && !init_obj.is_none()
    {
        let (program, args, env) = parse_init_kwarg(&init_obj)?;
        builder = builder.init_with(program, |i| i.args(args).envs(env));
    }
    if let Some(replace) = extract_opt::<bool>(kwargs, "replace")?
        && replace
    {
        builder = builder.replace();
    }
    if let Some(max_duration) = extract_opt::<f64>(kwargs, "max_duration")? {
        if max_duration < 0.0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "max_duration must be non-negative",
            ));
        }
        builder = builder.max_duration(max_duration as u64);
    }
    if let Some(idle_timeout) = extract_opt::<f64>(kwargs, "idle_timeout")? {
        if idle_timeout < 0.0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "idle_timeout must be non-negative",
            ));
        }
        builder = builder.idle_timeout(idle_timeout as u64);
    }
    let stop_signal_val = extract_opt::<String>(kwargs, "stop_signal")?;

    // Environment variables.
    if let Some(env) = kwargs.get_item("env")? {
        let env_dict: &Bound<'_, PyDict> = env.downcast()?;
        for (k, v) in env_dict.iter() {
            let key: String = k.extract()?;
            let val: String = v.extract()?;
            builder = builder.env(key, val);
        }
    }

    // Scripts.
    if let Some(scripts) = kwargs.get_item("scripts")? {
        let scripts_dict: &Bound<'_, PyDict> = scripts.downcast()?;
        for (k, v) in scripts_dict.iter() {
            let key: String = k.extract()?;
            let val: String = v.extract()?;
            builder = builder.script(key, val);
        }
    }

    // Pull policy.
    if let Some(pp) = extract_opt::<String>(kwargs, "pull_policy")? {
        let policy = match pp.as_str() {
            "always" => PullPolicy::Always,
            "if-missing" | "if_missing" | "IF_MISSING" => PullPolicy::IfMissing,
            "never" => PullPolicy::Never,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "invalid pull_policy: {pp}. Expected: always, if-missing, never"
                )));
            }
        };
        builder = builder.pull_policy(policy);
    }

    // Log level.
    if let Some(ll) = extract_opt::<String>(kwargs, "log_level")? {
        let level = match ll.as_str() {
            "trace" | "TRACE" => LogLevel::Trace,
            "debug" | "DEBUG" => LogLevel::Debug,
            "info" | "INFO" => LogLevel::Info,
            "warn" | "WARN" => LogLevel::Warn,
            "error" | "ERROR" => LogLevel::Error,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "invalid log_level: {ll}"
                )));
            }
        };
        builder = builder.log_level(level);
    }

    // Registry auth.
    if let Some(auth) = kwargs.get_item("registry_auth")? {
        let auth_dict = as_dict(&auth)?;
        let auth_dict = &auth_dict;
        let username: String = auth_dict
            .get_item("username")?
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("registry_auth.username required")
            })?
            .extract()?;
        let password: String = auth_dict
            .get_item("password")?
            .ok_or_else(|| {
                pyo3::exceptions::PyValueError::new_err("registry_auth.password required")
            })?
            .extract()?;
        builder = builder.registry(|r| r.auth(RegistryAuth::Basic { username, password }));
    }

    // Volumes.
    if let Some(volumes) = kwargs.get_item("volumes")? {
        let vol_dict: &Bound<'_, PyDict> = volumes.downcast()?;
        for (guest_path_obj, mount_obj) in vol_dict.iter() {
            let guest_path: String = guest_path_obj.extract()?;
            let mount_dict = as_dict(&mount_obj)?;
            builder = apply_mount(builder, guest_path, &mount_dict)?;
        }
    }

    // Patches.
    if let Some(patches) = kwargs.get_item("patches")? {
        let patches_list: &Bound<'_, PyList> = patches.downcast()?;
        for patch_obj in patches_list.iter() {
            let patch_dict = as_dict(&patch_obj)?;
            builder = apply_patch(builder, &patch_dict)?;
        }
    }

    // Ports.
    if let Some(ports) = kwargs.get_item("ports")? {
        let ports_dict: &Bound<'_, PyDict> = ports.downcast()?;
        for (host_obj, guest_obj) in ports_dict.iter() {
            let host_port: u16 = host_obj.extract()?;
            let guest_port: u16 = guest_obj.extract()?;
            builder = builder.port(host_port, guest_port);
        }
    }

    // Network.
    if let Some(network) = kwargs.get_item("network")? {
        let net_dict = as_dict(&network)?;
        builder = apply_network(builder, &net_dict)?;
    }

    // Secrets.
    if let Some(secrets) = kwargs.get_item("secrets")? {
        let secrets_list: &Bound<'_, PyList> = secrets.downcast()?;
        for secret_obj in secrets_list.iter() {
            let secret_dict = as_dict(&secret_obj)?;
            builder = apply_secret(builder, &secret_dict)?;
        }
    }

    // Secret violation action (top-level kwarg).
    if let Some(violation) = extract_opt::<String>(kwargs, "on_secret_violation")? {
        let action = parse_violation_action(&violation)?;
        builder = builder.network(|n| n.on_secret_violation(action));
    }

    let mut config = builder.build().map_err(to_py_err)?;
    if let Some(sig) = stop_signal_val {
        config.stop_signal = Some(sig);
    }
    Ok(config)
}

//--------------------------------------------------------------------------------------------------
// Functions: Init
//--------------------------------------------------------------------------------------------------

/// Tuple returned by [`parse_init_kwarg`]: `(program, args, env)`.
type ParsedInit = (String, Vec<String>, Vec<(String, String)>);

/// Parse the `init=` kwarg into `(program, args, env)`.
///
/// Accepted forms:
/// - `"/sbin/init"` — bare string, no args/env
/// - `("/sbin/init", ["arg1", "arg2"])` — tuple of (path, args)
/// - `("/sbin/init", {"args": [...], "env": {...}})` — tuple of
///   (path, options dict)
/// - `{"program": "/sbin/init", "args": [...], "env": {...}}` — dict
/// - `InitConfig(...)` (any object with `_to_dict()` returning the dict
///   form above)
fn parse_init_kwarg(obj: &Bound<'_, PyAny>) -> PyResult<ParsedInit> {
    // Bare string.
    if let Ok(s) = obj.extract::<String>() {
        return Ok((s, Vec::new(), Vec::new()));
    }

    // 2-element tuple of (program, args_or_options). Lists are NOT
    // accepted to avoid `init=["arg1", "arg2"]` parsing as
    // `program="arg1", args=["arg2"]`.
    if let Ok(seq) = obj.downcast::<pyo3::types::PyTuple>() {
        return parse_init_pair(seq.as_any());
    }

    // Dict form, or any object exposing `_to_dict()` (e.g. InitConfig).
    let dict_owned = if let Ok(d) = obj.downcast::<PyDict>() {
        Some(d.clone())
    } else if let Ok(method) = obj.getattr("_to_dict") {
        let returned = method.call0()?;
        Some(
            returned
                .downcast::<PyDict>()
                .map_err(|_| {
                    pyo3::exceptions::PyTypeError::new_err("init._to_dict() must return a dict")
                })?
                .clone(),
        )
    } else {
        None
    };
    if let Some(dict) = dict_owned {
        let program: String = dict
            .get_item("program")?
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("init dict requires 'program'"))?
            .extract()?;
        let (args, env) = parse_args_env(&dict)?;
        return Ok((program, args, env));
    }

    Err(pyo3::exceptions::PyTypeError::new_err(
        "init must be str, 2-tuple of (path, args_or_options), dict, or InitConfig",
    ))
}

/// Parse the `(program, args_or_options)` 2-element tuple form.
fn parse_init_pair(seq: &Bound<'_, PyAny>) -> PyResult<ParsedInit> {
    let len: usize = seq.len()?;
    if len != 2 {
        return Err(pyo3::exceptions::PyValueError::new_err(format!(
            "init tuple must have exactly 2 elements (path, args_or_options); got {len}"
        )));
    }
    let program: String = seq.get_item(0)?.extract()?;
    let second = seq.get_item(1)?;
    if second.is_none() {
        return Ok((program, Vec::new(), Vec::new()));
    }
    // Second element is either a list of args or a dict of options.
    if let Ok(args) = second.extract::<Vec<String>>() {
        return Ok((program, args, Vec::new()));
    }
    let dict: &Bound<'_, PyDict> = second.downcast().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err("init second element must be list[str] or dict")
    })?;
    let (args, env) = parse_args_env(dict)?;
    Ok((program, args, env))
}

/// `(args, env)` pair extracted from a Python init-options dict.
type ArgsEnv = (Vec<String>, Vec<(String, String)>);

/// Pull `args: list[str]` and `env: dict[str, str]` from a dict that
/// also carries `program` (or just the args/env keys, for the
/// 2-tuple-options form). Both keys are optional.
fn parse_args_env(dict: &Bound<'_, PyDict>) -> PyResult<ArgsEnv> {
    let args = dict
        .get_item("args")?
        .filter(|v| !v.is_none())
        .map(|v| v.extract::<Vec<String>>())
        .transpose()?
        .unwrap_or_default();
    let env = match dict.get_item("env")? {
        Some(env_obj) if !env_obj.is_none() => {
            let env_dict: &Bound<'_, PyDict> = env_obj.downcast()?;
            env_dict
                .iter()
                .map(|(k, v)| Ok::<_, PyErr>((k.extract::<String>()?, v.extract::<String>()?)))
                .collect::<Result<Vec<_>, _>>()?
        }
        _ => Vec::new(),
    };
    Ok((args, env))
}

//--------------------------------------------------------------------------------------------------
// Functions: Mount
//--------------------------------------------------------------------------------------------------

fn apply_mount(
    builder: microsandbox::sandbox::SandboxBuilder,
    guest_path: String,
    mount: &Bound<'_, PyDict>,
) -> PyResult<microsandbox::sandbox::SandboxBuilder> {
    let readonly = extract_opt::<bool>(mount, "readonly")?.unwrap_or(false);

    if let Some(bind_path) = extract_opt::<String>(mount, "bind")? {
        Ok(builder.volume(&guest_path, |v| {
            let m = v.bind(&bind_path);
            if readonly { m.readonly() } else { m }
        }))
    } else if let Some(vol_name) = extract_opt::<String>(mount, "named")? {
        Ok(builder.volume(&guest_path, |v| {
            let m = v.named(&vol_name);
            if readonly { m.readonly() } else { m }
        }))
    } else if extract_opt::<bool>(mount, "tmpfs")?.unwrap_or(false) {
        let size_mib = extract_opt::<u32>(mount, "size_mib")?;
        Ok(builder.volume(&guest_path, |v| {
            let mut m = v.tmpfs();
            if let Some(size) = size_mib {
                m = m.size(size);
            }
            if readonly { m.readonly() } else { m }
        }))
    } else if let Some(disk_path) = extract_opt::<String>(mount, "disk")? {
        let format_str = extract_opt::<String>(mount, "format")?;
        let fstype = extract_opt::<String>(mount, "fstype")?;
        let format = format_str
            .as_deref()
            .map(|s| {
                s.parse::<microsandbox::sandbox::DiskImageFormat>()
                    .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
            })
            .transpose()?;
        Ok(builder.volume(&guest_path, |v| {
            let mut m = v.disk(&disk_path);
            if let Some(format) = format {
                m = m.format(format);
            }
            if let Some(fstype) = fstype {
                m = m.fstype(fstype);
            }
            if readonly { m.readonly() } else { m }
        }))
    } else {
        Err(pyo3::exceptions::PyValueError::new_err(
            "mount must have one of: bind, named, tmpfs, disk",
        ))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Patch
//--------------------------------------------------------------------------------------------------

fn apply_patch(
    builder: microsandbox::sandbox::SandboxBuilder,
    patch: &Bound<'_, PyDict>,
) -> PyResult<microsandbox::sandbox::SandboxBuilder> {
    let kind: String = patch
        .get_item("kind")?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("patch.kind required"))?
        .extract()?;

    let mode = extract_opt::<u32>(patch, "mode")?;
    let replace = extract_opt::<bool>(patch, "replace")?.unwrap_or(false);

    match kind.as_str() {
        "text" => {
            let path: String = extract_required(patch, "path")?;
            let content: String = extract_required(patch, "content")?;
            Ok(builder.add_patch(Patch::Text {
                path,
                content,
                mode,
                replace,
            }))
        }
        "append" => {
            let path: String = extract_required(patch, "path")?;
            let content: String = extract_required(patch, "content")?;
            Ok(builder.add_patch(Patch::Append { path, content }))
        }
        "copy_file" => {
            let src: String = extract_required(patch, "src")?;
            let dst: String = extract_required(patch, "dst")?;
            Ok(builder.add_patch(Patch::CopyFile {
                src: src.into(),
                dst,
                mode,
                replace,
            }))
        }
        "copy_dir" => {
            let src: String = extract_required(patch, "src")?;
            let dst: String = extract_required(patch, "dst")?;
            Ok(builder.add_patch(Patch::CopyDir {
                src: src.into(),
                dst,
                replace,
            }))
        }
        "symlink" => {
            let target: String = extract_required(patch, "target")?;
            let link: String = extract_required(patch, "link")?;
            Ok(builder.add_patch(Patch::Symlink {
                target,
                link,
                replace,
            }))
        }
        "mkdir" => {
            let path: String = extract_required(patch, "path")?;
            Ok(builder.add_patch(Patch::Mkdir { path, mode }))
        }
        "remove" => {
            let path: String = extract_required(patch, "path")?;
            Ok(builder.add_patch(Patch::Remove { path }))
        }
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown patch kind: {kind}"
        ))),
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Network
//--------------------------------------------------------------------------------------------------

fn apply_network(
    mut builder: microsandbox::sandbox::SandboxBuilder,
    net: &Bound<'_, PyDict>,
) -> PyResult<microsandbox::sandbox::SandboxBuilder> {
    // Parse bulk deny-Domain rules up-front so PyValueError propagates
    // cleanly rather than being swallowed inside the builder closure.
    let mut bulk_deny_rules: Vec<microsandbox_network::policy::Rule> = Vec::new();

    if let Some(domains) = extract_opt::<Vec<String>>(net, "deny_domains")? {
        for d in domains {
            let domain = d.parse().map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("deny_domains[{d:?}]: {e}"))
            })?;
            bulk_deny_rules.push(microsandbox_network::policy::Rule::deny_egress(
                microsandbox_network::policy::Destination::Domain(domain),
            ));
        }
    }
    if let Some(suffixes) = extract_opt::<Vec<String>>(net, "deny_domain_suffixes")? {
        for s in suffixes {
            let suffix = s.parse().map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("deny_domain_suffixes[{s:?}]: {e}"))
            })?;
            bulk_deny_rules.push(microsandbox_network::policy::Rule::deny_egress(
                microsandbox_network::policy::Destination::DomainSuffix(suffix),
            ));
        }
    }
    let mut policy_set = false;

    // Check for preset policy string.
    if let Some(policy_str) = extract_opt::<String>(net, "policy")? {
        let mut policy = match policy_str.as_str() {
            "none" => NetworkPolicy::none(),
            "public_only" | "public-only" => NetworkPolicy::public_only(),
            "allow_all" | "allow-all" => NetworkPolicy::allow_all(),
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "unknown network policy preset: {policy_str}"
                )));
            }
        };
        let mut combined = bulk_deny_rules.clone();
        combined.extend(policy.rules);
        policy.rules = combined;
        builder = builder.network(|n| n.policy(policy));
        policy_set = true;
    }

    // Check for custom policy object.
    if let Some(custom) = net.get_item("custom_policy")?
        && !custom.is_none()
    {
        let cp_dict = as_dict(&custom)?;
        let parse_action_field = |field: &str,
                                  default: microsandbox_network::policy::Action|
         -> PyResult<microsandbox_network::policy::Action> {
            let s: Option<String> = extract_opt(&cp_dict, field)?;
            match s.as_deref() {
                None => Ok(default),
                Some("allow") => Ok(microsandbox_network::policy::Action::Allow),
                Some("deny") => Ok(microsandbox_network::policy::Action::Deny),
                Some(other) => Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "unknown {field}: {other}"
                ))),
            }
        };
        // Asymmetric defaults match the rest of the stack: egress falls
        // through to Deny (preserves today's `public_only` reachability
        // when paired with an implicit allow-public rule); ingress falls
        // through to Allow (preserves today's unfiltered published-port
        // behavior).
        let default_egress =
            parse_action_field("default_egress", microsandbox_network::policy::Action::Deny)?;
        let default_ingress = parse_action_field(
            "default_ingress",
            microsandbox_network::policy::Action::Allow,
        )?;

        let mut rules: Vec<microsandbox_network::policy::Rule> = Vec::new();
        if let Some(rules_obj) = cp_dict.get_item("rules")?
            && !rules_obj.is_none()
        {
            let rules_list: &Bound<'_, PyList> = rules_obj.downcast()?;
            for rule_obj in rules_list.iter() {
                let rd = as_dict(&rule_obj)?;
                let action_str: String = extract_required(&rd, "action")?;
                let action = match action_str.as_str() {
                    "allow" => microsandbox_network::policy::Action::Allow,
                    "deny" => microsandbox_network::policy::Action::Deny,
                    _ => {
                        return Err(pyo3::exceptions::PyValueError::new_err(format!(
                            "unknown rule action: {action_str}"
                        )));
                    }
                };
                let direction_str: String =
                    extract_opt(&rd, "direction")?.unwrap_or_else(|| "egress".to_string());
                let direction = match direction_str.as_str() {
                    "egress" => microsandbox_network::policy::Direction::Egress,
                    "ingress" => microsandbox_network::policy::Direction::Ingress,
                    "any" => microsandbox_network::policy::Direction::Any,
                    _ => {
                        return Err(pyo3::exceptions::PyValueError::new_err(format!(
                            "unknown direction: {direction_str}"
                        )));
                    }
                };
                let destination = if let Some(dest_str) = extract_opt::<String>(&rd, "destination")?
                {
                    match dest_str.as_str() {
                        "*" => microsandbox_network::policy::Destination::Any,
                        "public" => microsandbox_network::policy::Destination::Group(
                            microsandbox_network::policy::DestinationGroup::Public,
                        ),
                        "loopback" => microsandbox_network::policy::Destination::Group(
                            microsandbox_network::policy::DestinationGroup::Loopback,
                        ),
                        "private" => microsandbox_network::policy::Destination::Group(
                            microsandbox_network::policy::DestinationGroup::Private,
                        ),
                        "link-local" => microsandbox_network::policy::Destination::Group(
                            microsandbox_network::policy::DestinationGroup::LinkLocal,
                        ),
                        "metadata" => microsandbox_network::policy::Destination::Group(
                            microsandbox_network::policy::DestinationGroup::Metadata,
                        ),
                        "multicast" => microsandbox_network::policy::Destination::Group(
                            microsandbox_network::policy::DestinationGroup::Multicast,
                        ),
                        "host" => microsandbox_network::policy::Destination::Group(
                            microsandbox_network::policy::DestinationGroup::Host,
                        ),
                        s if s.starts_with('.') => {
                            let name = s.parse().map_err(|e| {
                                pyo3::exceptions::PyValueError::new_err(format!(
                                    "invalid domain suffix: {e}"
                                ))
                            })?;
                            microsandbox_network::policy::Destination::DomainSuffix(name)
                        }
                        s if s.contains('/') => {
                            let cidr: ipnetwork::IpNetwork = s.parse().map_err(|e| {
                                pyo3::exceptions::PyValueError::new_err(format!(
                                    "invalid CIDR: {e}"
                                ))
                            })?;
                            microsandbox_network::policy::Destination::Cidr(cidr)
                        }
                        s => {
                            let name = s.parse().map_err(|e| {
                                pyo3::exceptions::PyValueError::new_err(format!(
                                    "invalid domain: {e}"
                                ))
                            })?;
                            microsandbox_network::policy::Destination::Domain(name)
                        }
                    }
                } else {
                    microsandbox_network::policy::Destination::Any
                };
                let protocols = if let Some(proto_str) = extract_opt::<String>(&rd, "protocol")? {
                    let proto = match proto_str.as_str() {
                        "tcp" => microsandbox_network::policy::Protocol::Tcp,
                        "udp" => microsandbox_network::policy::Protocol::Udp,
                        "icmpv4" => microsandbox_network::policy::Protocol::Icmpv4,
                        "icmpv6" => microsandbox_network::policy::Protocol::Icmpv6,
                        _ => {
                            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                                "unknown protocol: {proto_str}"
                            )));
                        }
                    };
                    vec![proto]
                } else {
                    Vec::new()
                };
                let ports = if let Some(port_val) = extract_opt::<String>(&rd, "port")? {
                    if let Ok(p) = port_val.parse::<u16>() {
                        vec![microsandbox_network::policy::PortRange { start: p, end: p }]
                    } else {
                        Vec::new()
                    }
                } else {
                    Vec::new()
                };
                rules.push(microsandbox_network::policy::Rule {
                    direction,
                    destination,
                    protocols,
                    ports,
                    action,
                });
            }
        }

        let mut combined = bulk_deny_rules.clone();
        combined.extend(rules);
        let policy = NetworkPolicy {
            default_egress,
            default_ingress,
            rules: combined,
        };
        builder = builder.network(|n| n.policy(policy));
        policy_set = true;
    }

    // No preset / custom policy was specified, but legacy DNS block
    // entries were. Use permissive defaults so the rest of the network
    // keeps working — preserves the legacy "full network minus blocked
    // domains" semantics.
    if !policy_set && !bulk_deny_rules.is_empty() {
        let policy = NetworkPolicy {
            default_egress: microsandbox_network::policy::Action::Allow,
            default_ingress: microsandbox_network::policy::Action::Allow,
            rules: bulk_deny_rules,
        };
        builder = builder.network(|n| n.policy(policy));
    }

    if let Some(dns) = net.get_item("dns")?
        && !dns.is_none()
    {
        let dns = as_dict(&dns)?;

        let rebind = extract_opt::<bool>(&dns, "rebind_protection")?;
        let nameservers_raw = extract_opt::<Vec<String>>(&dns, "nameservers")?;
        let query_timeout_ms = extract_opt::<u64>(&dns, "query_timeout_ms")?;

        let nameservers: Vec<Nameserver> = nameservers_raw
            .unwrap_or_default()
            .iter()
            .map(|s| s.parse::<Nameserver>())
            .collect::<Result<_, _>>()
            .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))?;

        builder = builder.network(move |n| {
            n.dns(move |mut d| {
                if let Some(r) = rebind {
                    d = d.rebind_protection(r);
                }
                if !nameservers.is_empty() {
                    d = d.nameservers(nameservers);
                }
                if let Some(ms) = query_timeout_ms {
                    d = d.query_timeout_ms(ms);
                }
                d
            })
        });
    }

    // Max connections.
    if let Some(max) = extract_opt::<usize>(net, "max_connections")? {
        builder = builder.network(|n| n.max_connections(max));
    }

    // Host-CA trust (ship host's extra CAs into the guest at boot).
    if let Some(trust) = extract_opt::<bool>(net, "trust_host_cas")? {
        builder = builder.network(move |n| n.trust_host_cas(trust));
    }

    // Secret violation action (sandbox-level, not per-secret).
    if let Some(violation) = extract_opt::<String>(net, "on_secret_violation")? {
        let action = parse_violation_action(&violation)?;
        builder = builder.network(|n| n.on_secret_violation(action));
    }

    // TLS config.
    if let Some(tls) = net.get_item("tls")?
        && !tls.is_none()
    {
        let tls_dict = as_dict(&tls)?;
        let bypass: Vec<String> = extract_opt(&tls_dict, "bypass")?.unwrap_or_default();
        let verify_upstream: Option<bool> = extract_opt(&tls_dict, "verify_upstream")?;
        let intercepted_ports: Option<Vec<u16>> = extract_opt(&tls_dict, "intercepted_ports")?;
        let block_quic: Option<bool> = extract_opt(&tls_dict, "block_quic")?;
        let ca_cert: Option<String> = extract_opt(&tls_dict, "ca_cert")?;
        let ca_key: Option<String> = extract_opt(&tls_dict, "ca_key")?;

        builder = builder.network(|n| {
            n.tls(|mut t| {
                for domain in &bypass {
                    t = t.bypass(domain);
                }
                if let Some(v) = verify_upstream {
                    t = t.verify_upstream(v);
                }
                if let Some(ports) = intercepted_ports {
                    t = t.intercepted_ports(ports);
                }
                if let Some(b) = block_quic {
                    t = t.block_quic(b);
                }
                if let Some(ref cert) = ca_cert {
                    t = t.intercept_ca_cert(cert);
                }
                if let Some(ref key) = ca_key {
                    t = t.intercept_ca_key(key);
                }
                t
            })
        });
    }

    // Ports inside Network object.
    if let Some(ports) = net.get_item("ports")?
        && !ports.is_none()
    {
        let ports_dict: &Bound<'_, PyDict> = ports.downcast()?;
        for (host_obj, guest_obj) in ports_dict.iter() {
            let host_port: u16 = host_obj.extract()?;
            let guest_port: u16 = guest_obj.extract()?;
            builder = builder.port(host_port, guest_port);
        }
    }

    Ok(builder)
}

//--------------------------------------------------------------------------------------------------
// Functions: Secret
//--------------------------------------------------------------------------------------------------

fn apply_secret(
    builder: microsandbox::sandbox::SandboxBuilder,
    secret: &Bound<'_, PyDict>,
) -> PyResult<microsandbox::sandbox::SandboxBuilder> {
    let env_var: String = extract_required(secret, "env_var")?;
    let value: String = extract_required(secret, "value")?;
    let allow_hosts: Vec<String> = extract_opt(secret, "allow_hosts")?.unwrap_or_default();
    let allow_host_patterns: Vec<String> =
        extract_opt(secret, "allow_host_patterns")?.unwrap_or_default();

    let placeholder: Option<String> = extract_opt(secret, "placeholder")?;
    let require_tls: Option<bool> = extract_opt(secret, "require_tls")?;

    Ok(builder.secret(|s| {
        let mut s = s.env(&env_var).value(value.clone());
        for host in &allow_hosts {
            s = s.allow_host(host);
        }
        for pattern in &allow_host_patterns {
            s = s.allow_host_pattern(pattern);
        }
        if let Some(ref ph) = placeholder {
            s = s.placeholder(ph);
        }
        if let Some(req) = require_tls {
            s = s.require_tls_identity(req);
        }
        s
    }))
}

//--------------------------------------------------------------------------------------------------
// Functions: Extraction Helpers
//--------------------------------------------------------------------------------------------------

/// Convert an object to a PyDict — either it's already a dict, or call _to_dict().
fn as_dict<'py>(obj: &Bound<'py, PyAny>) -> PyResult<Bound<'py, PyDict>> {
    if let Ok(dict) = obj.downcast::<PyDict>() {
        return Ok(dict.clone());
    }
    // Try calling _to_dict() on the object (for our frozen dataclasses).
    if let Ok(method) = obj.getattr("_to_dict") {
        let result = method.call0()?;
        return Ok(result.downcast::<PyDict>()?.clone());
    }
    // Try __dict__ as last resort.
    if let Ok(d) = obj.getattr("__dict__")
        && let Ok(dict) = d.downcast::<PyDict>()
    {
        return Ok(dict.clone());
    }
    Err(pyo3::exceptions::PyTypeError::new_err(format!(
        "expected dict or object with _to_dict(), got {}",
        obj.get_type().name()?
    )))
}

fn parse_violation_action(
    s: &str,
) -> PyResult<microsandbox_network::secrets::config::ViolationAction> {
    use microsandbox_network::secrets::config::ViolationAction;
    match s {
        "block" => Ok(ViolationAction::Block),
        "block-and-log" | "block_and_log" => Ok(ViolationAction::BlockAndLog),
        "block-and-terminate" | "block_and_terminate" => Ok(ViolationAction::BlockAndTerminate),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown violation action: {s}"
        ))),
    }
}

fn extract_opt<'py, T: FromPyObject<'py>>(
    dict: &Bound<'py, PyDict>,
    key: &str,
) -> PyResult<Option<T>> {
    match dict.get_item(key)? {
        Some(val) if !val.is_none() => Ok(Some(val.extract()?)),
        _ => Ok(None),
    }
}

fn extract_required<'py, T: FromPyObject<'py>>(
    dict: &Bound<'py, PyDict>,
    key: &str,
) -> PyResult<T> {
    dict.get_item(key)?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err(format!("{key} is required")))?
        .extract()
}
