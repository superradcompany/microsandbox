use microsandbox::sandbox::{NetworkPolicy, Patch, PullPolicy, SandboxBuilder, SecurityProfile};
use microsandbox::{LogLevel, RegistryAuth};
use microsandbox_network::dns::Nameserver;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyList};

//--------------------------------------------------------------------------------------------------
// Functions: Config Conversion
//--------------------------------------------------------------------------------------------------

/// Build a `SandboxBuilder` from the `(name, **kwargs)` form of
/// `Sandbox.create`.
///
/// Sandbox names are limited to 128 UTF-8 bytes by the core builder.
///
/// Returns the builder so the async caller can drive `build().await` or
/// `create().await` itself — the kwarg-extraction phase has to stay sync
/// (PyO3 dict access needs the GIL), but the config materialization step
/// is async because of snapshot manifest I/O.
pub fn sandbox_builder_from_args(
    name: String,
    kwargs: Option<&Bound<'_, PyDict>>,
) -> PyResult<SandboxBuilder> {
    let Some(kwargs) = kwargs else {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "image= or snapshot= is required",
        ));
    };

    let image_present = kwargs.get_item("image")?.is_some();
    let snapshot_present = kwargs.get_item("snapshot")?.is_some();
    if image_present && snapshot_present {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "pass either image= or snapshot=, not both",
        ));
    }
    if !image_present && !snapshot_present {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "image= or snapshot= is required",
        ));
    }

    let mut builder = microsandbox::Sandbox::builder(name);

    if snapshot_present {
        // Boot from a snapshot. Accept str or PathLike.
        let snap_obj = kwargs.get_item("snapshot")?.unwrap();
        let snap_str: String = if let Ok(s) = snap_obj.extract::<String>() {
            s
        } else if let Ok(fspath) = snap_obj.call_method0("__fspath__") {
            fspath.extract()?
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "snapshot must be str or os.PathLike",
            ));
        };
        // Resolve the snapshot synchronously: read the manifest and
        // pin the image. We can't use the async `from_snapshot` here
        // because `sandbox_builder_from_args` runs in sync context; instead
        // we replicate the resolution against the on-disk artifact
        // directly via `snapshot_resolved`.
        let snap_dir = resolve_snapshot_dir(&snap_str);
        if !snap_dir.exists() {
            return Err(pyo3::exceptions::PyFileNotFoundError::new_err(format!(
                "snapshot artifact not found: {}",
                snap_dir.display()
            )));
        }
        let manifest_bytes = std::fs::read(
            snap_dir.join(microsandbox::snapshot::MANIFEST_FILENAME),
        )
        .map_err(|e| {
            pyo3::exceptions::PyFileNotFoundError::new_err(format!(
                "snapshot manifest not readable at {}: {e}",
                snap_dir.display(),
            ))
        })?;
        let manifest =
            microsandbox::snapshot::Manifest::from_bytes(&manifest_bytes).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("snapshot manifest invalid: {e}"))
            })?;
        let upper_path = snap_dir.join(&manifest.upper.file);
        if !upper_path.exists() {
            return Err(pyo3::exceptions::PyFileNotFoundError::new_err(format!(
                "snapshot upper file missing: {}",
                upper_path.display(),
            )));
        }
        builder = builder.image(manifest.image.reference.as_str());
        builder = builder.snapshot_resolved(manifest.image.manifest_digest.clone(), upper_path);
    } else {
        let image_obj = kwargs.get_item("image")?.unwrap();
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

        let fstype = if let Ok(fstype_attr) = image_obj.getattr("_fstype") {
            if fstype_attr.is_none() {
                None
            } else {
                Some(fstype_attr.extract::<String>()?)
            }
        } else {
            None
        };
        let upper_size_mib = if let Ok(upper_size_attr) = image_obj.getattr("_upper_size_mib") {
            if upper_size_attr.is_none() {
                None
            } else {
                Some(upper_size_attr.extract::<u32>()?)
            }
        } else {
            None
        };

        if upper_size_mib.is_some() {
            let image_type = image_obj
                .getattr("_type")
                .ok()
                .and_then(|attr| attr.extract::<String>().ok());
            if image_type.as_deref() != Some("oci") {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "upper_size_mib is only valid for Image.oci(...)",
                ));
            }
        }

        match (fstype, upper_size_mib) {
            (Some(_), Some(_)) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "fstype and upper_size_mib cannot be set on the same ImageSource",
                ));
            }
            (Some(fstype), None) => {
                builder = builder.image_with(|i| i.disk(&image_str).fstype(&fstype));
            }
            (None, Some(size_mib)) => {
                builder = builder.image_with(|i| i.oci(image_str.as_str()).upper_size(size_mib));
            }
            (None, None) => {
                builder = builder.image(image_str.as_str());
            }
        };
    }

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
    if let Some(security) = extract_opt::<String>(kwargs, "security")? {
        let profile = match security.as_str() {
            "default" => SecurityProfile::Default,
            "restricted" => SecurityProfile::Restricted,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "invalid security profile: {security}. Expected: default, restricted"
                )));
            }
        };
        builder = builder.security(profile);
    }
    if let Some(hostname) = extract_opt::<String>(kwargs, "hostname")? {
        builder = builder.hostname(hostname);
    }
    // `libkrunfw_path` is a process-level concern (one dylib per process
    // address space), not a per-sandbox builder kwarg. Users set it once via
    // `microsandbox.set_libkrunfw_path(...)` or the `MSB_LIBKRUNFW_PATH` env var.
    if let Some(user) = extract_opt::<String>(kwargs, "user")? {
        builder = builder.user(user);
    }
    if let Some(entrypoint) = extract_opt::<Vec<String>>(kwargs, "entrypoint")? {
        builder = builder.entrypoint(entrypoint);
    }
    if let Some(init_obj) = kwargs.get_item("init")?
        && !init_obj.is_none()
    {
        let (cmd, args, env) = parse_init_kwarg(&init_obj)?;
        builder = builder.init_with(cmd, |i| i.args(args).envs(env));
    }
    if let Some(replace) = extract_opt::<bool>(kwargs, "replace")?
        && replace
    {
        builder = builder.replace();
    }
    if let Some(timeout) = extract_opt::<f64>(kwargs, "replace_with_timeout")? {
        if timeout < 0.0 {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "replace_with_timeout must be non-negative",
            ));
        }
        builder = builder.replace_with_timeout(std::time::Duration::from_secs_f64(timeout));
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
    if let Some(ephemeral) = extract_opt::<bool>(kwargs, "ephemeral")? {
        builder = builder.ephemeral(ephemeral);
    }

    // Environment variables.
    if let Some(env) = kwargs.get_item("env")? {
        let env_dict: &Bound<'_, PyDict> = env.downcast()?;
        for (k, v) in env_dict.iter() {
            let key: String = k.extract()?;
            let val: String = v.extract()?;
            builder = builder.env(key, val);
        }
    }

    // Labels.
    if let Some(labels) = kwargs.get_item("labels")? {
        let labels_dict: &Bound<'_, PyDict> = labels.downcast()?;
        for (k, v) in labels_dict.iter() {
            let key: String = k.extract()?;
            let val: String = v.extract()?;
            builder = builder.label(key, val);
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
        builder = apply_ports(builder, &ports)?;
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
    if let Some(violation_obj) = kwargs.get_item("on_secret_violation")?
        && !violation_obj.is_none()
    {
        let action = parse_violation_action_obj(&violation_obj)?;
        builder = builder.network(|n| {
            n.on_secret_violation(|_| {
                microsandbox_network::builder::ViolationActionBuilder::from_action(action)
            })
        });
    }

    Ok(builder)
}

//--------------------------------------------------------------------------------------------------
// Functions: Init
//--------------------------------------------------------------------------------------------------

/// Tuple returned by [`parse_init_kwarg`]: `(cmd, args, env)`.
type ParsedInit = (String, Vec<String>, Vec<(String, String)>);

/// Parse the `init=` kwarg into `(cmd, args, env)`.
///
/// Accepted forms (consistent with how other `Sandbox.create` kwargs
/// take a single value: bare scalar for the simple case, dataclass or
/// dict for the rich case — never a tuple-as-pair):
///
/// - `"/sbin/init"` or `"auto"` — bare string, no args/env
/// - `InitConfig(cmd=..., args=[...], env={...})` — dataclass
/// - `{"cmd": ..., "args": [...], "env": {...}}` — equivalent dict
fn parse_init_kwarg(obj: &Bound<'_, PyAny>) -> PyResult<ParsedInit> {
    // Bare string.
    if let Ok(s) = obj.extract::<String>() {
        return Ok((s, Vec::new(), Vec::new()));
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
        let cmd: String = dict
            .get_item("cmd")?
            .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("init dict requires 'cmd'"))?
            .extract()?;
        let (args, env) = parse_args_env(&dict)?;
        return Ok((cmd, args, env));
    }

    Err(pyo3::exceptions::PyTypeError::new_err(
        "init must be str, dict with 'cmd', or InitConfig",
    ))
}

/// `(args, env)` pair extracted from a Python init-options dict.
type ArgsEnv = (Vec<String>, Vec<(String, String)>);

/// Pull `args: list[str]` and `env: dict[str, str]` from an init dict.
/// Both keys are optional.
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
    let noexec = extract_opt::<bool>(mount, "noexec")?.unwrap_or(false);
    let nosuid = extract_opt::<bool>(mount, "nosuid")?.unwrap_or(false);
    let nodev = extract_opt::<bool>(mount, "nodev")?.unwrap_or(false);
    let stat_virt = extract_opt::<String>(mount, "stat_virtualization")?
        .map(parse_stat_virt)
        .transpose()?;
    let host_perms = extract_opt::<String>(mount, "host_permissions")?
        .map(parse_host_perms)
        .transpose()?;

    if let Some(bind_path) = extract_opt::<String>(mount, "bind")? {
        let quota_mib = extract_opt::<u32>(mount, "quota_mib")?;
        Ok(builder.volume(&guest_path, |v| {
            let mut m = v.bind(&bind_path);
            if readonly {
                m = m.readonly();
            }
            if noexec {
                m = m.noexec();
            }
            if nosuid {
                m = m.nosuid();
            }
            if nodev {
                m = m.nodev();
            }
            if let Some(p) = stat_virt {
                m = m.stat_virtualization(p);
            }
            if let Some(p) = host_perms {
                m = m.host_permissions(p);
            }
            if let Some(quota_mib) = quota_mib {
                m = m.quota(quota_mib);
            }
            m
        }))
    } else if let Some(vol_name) = extract_opt::<String>(mount, "named")? {
        let named_mode =
            extract_opt::<String>(mount, "named_mode")?.unwrap_or_else(|| "existing".to_string());
        let named_kind =
            extract_opt::<String>(mount, "named_kind")?.unwrap_or_else(|| "dir".to_string());
        let size_mib = extract_opt::<u32>(mount, "size_mib")?;
        let quota_mib = extract_opt::<u32>(mount, "quota_mib")?;
        if !matches!(named_mode.as_str(), "existing" | "create" | "ensure-exists") {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "invalid named volume mode: {named_mode}"
            )));
        }
        if !matches!(named_kind.as_str(), "dir" | "directory" | "disk") {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "invalid named volume kind: {named_kind}"
            )));
        }
        Ok(builder.volume(&guest_path, |v| {
            let mut m = v.named_with(&vol_name, |mut named| {
                named = match named_mode.as_str() {
                    "existing" => named.existing(),
                    "create" => named.create(),
                    "ensure-exists" => named.ensure_exists(),
                    _ => unreachable!("validated named volume mode"),
                };
                named = match named_kind.as_str() {
                    "dir" | "directory" => named.directory(),
                    "disk" => named.disk(),
                    _ => unreachable!("validated named volume kind"),
                };
                if let Some(size_mib) = size_mib {
                    named = named.size(size_mib);
                }
                if let Some(quota_mib) = quota_mib {
                    named = named.quota(quota_mib);
                }
                named
            });
            if readonly {
                m = m.readonly();
            }
            if noexec {
                m = m.noexec();
            }
            if nosuid {
                m = m.nosuid();
            }
            if nodev {
                m = m.nodev();
            }
            if let Some(p) = stat_virt {
                m = m.stat_virtualization(p);
            }
            if let Some(p) = host_perms {
                m = m.host_permissions(p);
            }
            m
        }))
    } else if extract_opt::<bool>(mount, "tmpfs")?.unwrap_or(false) {
        let size_mib = extract_opt::<u32>(mount, "size_mib")?;
        Ok(builder.volume(&guest_path, |v| {
            let mut m = v.tmpfs();
            if let Some(size) = size_mib {
                m = m.size(size);
            }
            if readonly {
                m = m.readonly();
            }
            if noexec {
                m = m.noexec();
            }
            if nosuid {
                m = m.nosuid();
            }
            if nodev {
                m = m.nodev();
            }
            m
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
            if readonly {
                m = m.readonly();
            }
            if noexec {
                m = m.noexec();
            }
            if nosuid {
                m = m.nosuid();
            }
            if nodev {
                m = m.nodev();
            }
            m
        }))
    } else {
        Err(pyo3::exceptions::PyValueError::new_err(
            "mount must have one of: bind, named, tmpfs, disk",
        ))
    }
}

fn parse_stat_virt(s: String) -> PyResult<microsandbox::sandbox::StatVirtualization> {
    match s.as_str() {
        "strict" => Ok(microsandbox::sandbox::StatVirtualization::Strict),
        "relaxed" => Ok(microsandbox::sandbox::StatVirtualization::Relaxed),
        "off" => Ok(microsandbox::sandbox::StatVirtualization::Off),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "invalid stat_virtualization {other:?} (expected strict|relaxed|off)"
        ))),
    }
}

fn parse_host_perms(s: String) -> PyResult<microsandbox::sandbox::HostPermissions> {
    match s.as_str() {
        "private" => Ok(microsandbox::sandbox::HostPermissions::Private),
        "mirror" => Ok(microsandbox::sandbox::HostPermissions::Mirror),
        other => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "invalid host_permissions {other:?} (expected private|mirror)"
        ))),
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
                let destination_kind = extract_opt::<String>(&rd, "destination_kind")?;
                let destination_raw = extract_opt::<String>(&rd, "destination")?;
                let destination = parse_network_destination(
                    destination_kind.as_deref(),
                    destination_raw.as_deref(),
                )?;
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

    // Guest IPv4 pool.
    if let Some(raw) = extract_opt::<String>(net, "ipv4_pool")? {
        let pool: ipnetwork::Ipv4Network = raw.parse().map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid ipv4_pool {raw:?}: {e}"))
        })?;
        builder = builder.network(|n| n.ipv4_pool(pool));
    }
    if let Some(raw) = extract_opt::<String>(net, "ipv6_pool")? {
        let pool: ipnetwork::Ipv6Network = raw.parse().map_err(|e| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid ipv6_pool {raw:?}: {e}"))
        })?;
        builder = builder.network(|n| n.ipv6_pool(pool));
    }

    // Host-CA trust (ship host's extra CAs into the guest at boot).
    if let Some(trust) = extract_opt::<bool>(net, "trust_host_cas")? {
        builder = builder.network(move |n| n.trust_host_cas(trust));
    }

    // Secret violation action (sandbox-level, not per-secret).
    if let Some(violation_obj) = net.get_item("on_secret_violation")?
        && !violation_obj.is_none()
    {
        let action = parse_violation_action_obj(&violation_obj)?;
        builder = builder.network(|n| {
            n.on_secret_violation(|_| {
                microsandbox_network::builder::ViolationActionBuilder::from_action(action)
            })
        });
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
        builder = apply_ports(builder, &ports)?;
    }

    Ok(builder)
}

fn apply_ports(
    mut builder: microsandbox::sandbox::SandboxBuilder,
    ports: &Bound<'_, PyAny>,
) -> PyResult<microsandbox::sandbox::SandboxBuilder> {
    if let Ok(ports_dict) = ports.downcast::<PyDict>() {
        for (host_obj, guest_obj) in ports_dict.iter() {
            let host_port: u16 = host_obj.extract()?;
            let guest_port: u16 = guest_obj.extract()?;
            builder = builder.port(host_port, guest_port);
        }
        return Ok(builder);
    }

    let iter = ports.try_iter().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(
            "ports must be a mapping of host_port to guest_port or a sequence of PortBinding values",
        )
    })?;

    for item in iter {
        let item = item?;
        let port = as_dict(&item)?;
        let host_port: u16 = extract_required(&port, "host_port")?;
        let guest_port: u16 = extract_required(&port, "guest_port")?;
        let bind: String = extract_opt(&port, "bind")?.unwrap_or_else(|| "127.0.0.1".to_string());
        let bind = bind.parse::<std::net::IpAddr>().map_err(|_| {
            pyo3::exceptions::PyValueError::new_err(format!("invalid bind address: {bind}"))
        })?;
        let protocol: Option<String> = extract_opt(&port, "protocol")?;
        builder = match protocol.as_deref().unwrap_or("tcp") {
            "tcp" => builder.port_bind(bind, host_port, guest_port),
            "udp" => builder.port_udp_bind(bind, host_port, guest_port),
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "invalid port protocol: {other}"
                )));
            }
        };
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
    if allow_hosts.is_empty() && allow_host_patterns.is_empty() {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "SecretEntry requires at least one allowed host or allowed host pattern",
        ));
    }
    let on_violation = if let Some(violation_obj) = secret.get_item("on_violation")?
        && !violation_obj.is_none()
    {
        Some(parse_violation_action_obj(&violation_obj)?)
    } else {
        None
    };

    let placeholder: Option<String> = extract_opt(secret, "placeholder")?;
    let require_tls: Option<bool> = extract_opt(secret, "require_tls")?;

    let (inject_headers, inject_basic_auth, inject_query_params, inject_body) =
        if let Some(injection_obj) = secret.get_item("injection")? {
            let injection = as_dict(&injection_obj)?;
            (
                extract_opt::<bool>(&injection, "headers")?,
                extract_opt::<bool>(&injection, "basic_auth")?,
                extract_opt::<bool>(&injection, "query_params")?,
                extract_opt::<bool>(&injection, "body")?,
            )
        } else {
            (None, None, None, None)
        };

    Ok(builder.secret(|s| {
        let mut s = s.env(&env_var).value(value.clone());
        for host in &allow_hosts {
            s = s.allow_host(host);
        }
        for pattern in &allow_host_patterns {
            s = s.allow_host_pattern(pattern);
        }
        if let Some(action) = on_violation {
            s = s.on_violation(|_| {
                microsandbox_network::builder::ViolationActionBuilder::from_action(action)
            });
        }
        if let Some(ref ph) = placeholder {
            s = s.placeholder(ph);
        }
        if let Some(req) = require_tls {
            s = s.require_tls_identity(req);
        }
        if let Some(v) = inject_headers {
            s = s.inject_headers(v);
        }
        if let Some(v) = inject_basic_auth {
            s = s.inject_basic_auth(v);
        }
        if let Some(v) = inject_query_params {
            s = s.inject_query(v);
        }
        if let Some(v) = inject_body {
            s = s.inject_body(v);
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

fn parse_network_destination(
    kind: Option<&str>,
    raw: Option<&str>,
) -> PyResult<microsandbox_network::policy::Destination> {
    match kind {
        Some("any") => Ok(microsandbox_network::policy::Destination::Any),
        Some("ip") => parse_ip_destination(required_destination(kind, raw)?),
        Some("cidr") => parse_cidr_destination(required_destination(kind, raw)?),
        Some("domain") => parse_domain_destination(required_destination(kind, raw)?),
        Some("domain_suffix") | Some("domain-suffix") => {
            parse_domain_suffix_destination(required_destination(kind, raw)?)
        }
        Some("group") => parse_group_destination(required_destination(kind, raw)?),
        Some(other) => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown destination kind: {other}"
        ))),
        None => parse_shorthand_destination(raw),
    }
}

fn parse_shorthand_destination(
    raw: Option<&str>,
) -> PyResult<microsandbox_network::policy::Destination> {
    let Some(raw) = raw else {
        return Ok(microsandbox_network::policy::Destination::Any);
    };

    if raw == "*" {
        return Ok(microsandbox_network::policy::Destination::Any);
    }
    if let Some(rest) = raw.strip_prefix("domain=") {
        return parse_domain_destination(rest);
    }
    if let Some(rest) = raw.strip_prefix("suffix=") {
        return parse_domain_suffix_destination(rest);
    }
    if let Some(destination) = maybe_group_destination(raw) {
        return Ok(destination);
    }
    if raw.starts_with('.') {
        return parse_domain_suffix_destination(raw);
    }
    if raw.contains('/') {
        return parse_cidr_destination(raw);
    }
    if raw.parse::<std::net::IpAddr>().is_ok() {
        return parse_ip_destination(raw);
    }
    parse_domain_destination(raw)
}

fn required_destination<'a>(kind: Option<&str>, raw: Option<&'a str>) -> PyResult<&'a str> {
    raw.ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!(
            "destination is required for destination kind `{}`",
            kind.unwrap_or("unknown")
        ))
    })
}

fn parse_ip_destination(raw: &str) -> PyResult<microsandbox_network::policy::Destination> {
    let ip: std::net::IpAddr = raw.parse().map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid IP address {raw:?}: {e}"))
    })?;
    let prefix = if ip.is_ipv4() { 32 } else { 128 };
    let cidr = ipnetwork::IpNetwork::new(ip, prefix).map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid IP address {raw:?}: {e}"))
    })?;
    Ok(microsandbox_network::policy::Destination::Cidr(cidr))
}

fn parse_cidr_destination(raw: &str) -> PyResult<microsandbox_network::policy::Destination> {
    let cidr: ipnetwork::IpNetwork = raw.parse().map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid CIDR {raw:?}: {e}"))
    })?;
    Ok(microsandbox_network::policy::Destination::Cidr(cidr))
}

fn parse_domain_destination(raw: &str) -> PyResult<microsandbox_network::policy::Destination> {
    let name = raw.parse().map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid domain {raw:?}: {e}"))
    })?;
    Ok(microsandbox_network::policy::Destination::Domain(name))
}

fn parse_domain_suffix_destination(
    raw: &str,
) -> PyResult<microsandbox_network::policy::Destination> {
    let name = raw.parse().map_err(|e| {
        pyo3::exceptions::PyValueError::new_err(format!("invalid domain suffix {raw:?}: {e}"))
    })?;
    Ok(microsandbox_network::policy::Destination::DomainSuffix(
        name,
    ))
}

fn parse_group_destination(raw: &str) -> PyResult<microsandbox_network::policy::Destination> {
    maybe_group_destination(raw).ok_or_else(|| {
        pyo3::exceptions::PyValueError::new_err(format!("unknown destination group: {raw}"))
    })
}

fn maybe_group_destination(raw: &str) -> Option<microsandbox_network::policy::Destination> {
    use microsandbox_network::policy::{Destination, DestinationGroup};

    let group = match raw {
        "public" => DestinationGroup::Public,
        "loopback" => DestinationGroup::Loopback,
        "private" => DestinationGroup::Private,
        "link-local" | "link_local" => DestinationGroup::LinkLocal,
        "metadata" => DestinationGroup::Metadata,
        "multicast" => DestinationGroup::Multicast,
        "host" => DestinationGroup::Host,
        _ => return None,
    };
    Some(Destination::Group(group))
}

fn parse_violation_action(
    s: &str,
) -> PyResult<microsandbox_network::secrets::config::ViolationAction> {
    use microsandbox_network::secrets::config::{HostPattern, ViolationAction};
    match s {
        "block" => Ok(ViolationAction::Block),
        "block-and-log" | "block_and_log" => Ok(ViolationAction::BlockAndLog),
        "block-and-terminate" | "block_and_terminate" => Ok(ViolationAction::BlockAndTerminate),
        "passthrough" => Ok(ViolationAction::Passthrough(vec![HostPattern::Any])),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown violation action: {s}"
        ))),
    }
}

fn parse_violation_action_obj(
    obj: &Bound<'_, PyAny>,
) -> PyResult<microsandbox_network::secrets::config::ViolationAction> {
    if let Ok(s) = obj.extract::<String>() {
        return parse_violation_action(&s);
    }

    let dict = as_dict(obj)?;
    if let Some(passthrough_obj) = dict.get_item("passthrough")?
        && !passthrough_obj.is_none()
    {
        return parse_passthrough_policy(&as_dict(&passthrough_obj)?);
    }

    Err(pyo3::exceptions::PyValueError::new_err(
        "expected violation action string or {'passthrough': {...}}",
    ))
}

fn parse_passthrough_policy(
    dict: &Bound<'_, PyDict>,
) -> PyResult<microsandbox_network::secrets::config::ViolationAction> {
    use microsandbox_network::secrets::config::{HostPattern, ViolationAction};

    if let Some(fallback) = extract_opt::<String>(dict, "fallback")?
        && matches!(
            parse_violation_action(&fallback)?,
            ViolationAction::Passthrough(_)
        )
    {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "passthrough fallback must be a blocking action",
        ));
    }

    let hosts: Vec<String> = extract_opt(dict, "hosts")?.unwrap_or_default();
    let host_patterns: Vec<String> = extract_opt(dict, "host_patterns")?.unwrap_or_default();
    let all_hosts = extract_opt::<bool>(dict, "all_hosts")?.unwrap_or(false);

    let mut patterns = Vec::new();
    for host in hosts {
        patterns.push(HostPattern::Exact(host));
    }
    for pattern in host_patterns {
        patterns.push(HostPattern::Wildcard(pattern));
    }
    if all_hosts {
        patterns.push(HostPattern::Any);
    }

    Ok(ViolationAction::Passthrough(patterns))
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

/// Resolve a snapshot reference (bare name or path) to its on-disk
/// directory. Mirrors the convention used by `Snapshot::open`.
fn resolve_snapshot_dir(s: &str) -> std::path::PathBuf {
    if s.contains('/') || s.starts_with('.') || s.starts_with('~') {
        std::path::PathBuf::from(s)
    } else {
        microsandbox::backend::default_backend()
            .as_local()
            .map(|local| local.snapshots_dir().join(s))
            .unwrap_or_else(|| std::path::PathBuf::from(s))
    }
}
