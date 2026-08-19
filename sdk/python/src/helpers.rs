use microsandbox::sandbox::{
    CpuPlacement, DeploymentProfile, NetworkPolicy, Patch, PullPolicy, SandboxBuilder,
    SecurityProfile, TransparentHugePagePolicy,
};
use microsandbox::{LogLevel, RegistryAuth};
use microsandbox_network::dns::Nameserver;
use pyo3::prelude::*;
use pyo3::types::{PyByteArray, PyBytes, PyDict, PyList, PyModule};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Kwargs accepted by `Sandbox.create` / `Sandbox.create_with_progress`.
/// `detached` is consumed by the callers in `sandbox.rs`, not here.
const KNOWN_CREATE_KWARGS: &[&str] = &[
    "image",
    "from_snapshot",
    "memory",
    "cpus",
    "max_memory",
    "max_cpus",
    "cpu_placement",
    "placement_profile",
    "thp",
    "workdir",
    "shell",
    "security",
    "deployment_profile",
    "hostname",
    "user",
    "entrypoint",
    "cmd",
    "init",
    "replace",
    "replace_with_timeout",
    "max_duration",
    "idle_timeout",
    "ephemeral",
    "env",
    "labels",
    "scripts",
    "pull_policy",
    "log_level",
    "registry_auth",
    "registry_insecure",
    "registry_ca_certs",
    "volumes",
    "patches",
    "ports",
    "vsock",
    "network",
    "secrets",
    "on_secret_violation",
    "detached",
];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Tuple returned by [`parse_init_kwarg`]: `(cmd, args, env)`.
type ParsedInit = (String, Vec<String>, Vec<(String, String)>);

/// `(args, env)` pair extracted from a Python init-options mapping.
type ArgsEnv = (Vec<String>, Vec<(String, String)>);

/// Root disk configuration extracted from an ImageSource's `_root_disk`
/// attribute (an integer shorthand or concrete `RootDiskConfig`).
struct RootDiskSpec {
    kind: String,
    size_mib: Option<u32>,
    path: Option<String>,
    format: Option<microsandbox::sandbox::DiskImageFormat>,
    fstype: Option<String>,
    clone: Option<microsandbox::sandbox::FlatClone>,
}

/// Identifies whether port entries came directly from the public kwarg or
/// from the already-validated, serialized contents of a `Network` config.
#[derive(Clone, Copy)]
enum PortBindingSource {
    PublicConfig,
    SerializedNetwork,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl RootDiskSpec {
    /// Apply this spec to an OCI image builder.
    fn apply(
        self,
        image: microsandbox::sandbox::ImageBuilder,
    ) -> microsandbox::sandbox::ImageBuilder {
        image.root_disk_with(|mut d| {
            match self.kind.as_str() {
                "managed" => {}
                "tmpfs" => d = d.tmpfs(),
                // Path presence is validated in `extract_root_disk`.
                "disk-image" => d = d.disk_image(self.path.as_deref().unwrap_or_default()),
                "flat" => d = d.flat(),
                _ => unreachable!("validated root disk kind"),
            }
            if let Some(size_mib) = self.size_mib {
                d = d.size(size_mib);
            }
            if let Some(format) = self.format {
                d = d.format(format);
            }
            if let Some(fstype) = self.fstype {
                d = d.fstype(fstype);
            }
            if let Some(clone) = self.clone {
                d = d.clone_strategy(clone);
            }
            d
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Python Enums
//--------------------------------------------------------------------------------------------------

/// Extract the wire value from one exact public Python `StrEnum` class.
///
/// Checking the class before reading `.value` is intentional: `StrEnum`
/// members are also strings, so ordinary string extraction would silently
/// preserve the legacy raw-string API.
pub(crate) fn extract_str_enum(value: &Bound<'_, PyAny>, enum_name: &str) -> PyResult<String> {
    let enum_class = PyModule::import(value.py(), "microsandbox.types")?.getattr(enum_name)?;
    if !value.is_instance(&enum_class)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(format!(
            "expected {enum_name}, got {}",
            value.get_type().name()?
        )));
    }
    value.getattr("value")?.extract()
}

/// Construct a public Python `StrEnum` member from a trusted wire value.
pub(crate) fn str_enum_member(py: Python<'_>, enum_name: &str, value: &str) -> PyResult<PyObject> {
    let enum_class = PyModule::import(py, "microsandbox.types")?.getattr(enum_name)?;
    Ok(enum_class.call1((value,))?.unbind())
}

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
            "image= or from_snapshot= is required",
        ));
    };

    reject_unknown_kwargs(kwargs)?;

    let image_present = kwargs
        .get_item("image")?
        .is_some_and(|value| !value.is_none());
    let snapshot_present = kwargs
        .get_item("from_snapshot")?
        .is_some_and(|value| !value.is_none());
    if image_present && snapshot_present {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "pass either image= or from_snapshot=, not both",
        ));
    }
    if !image_present && !snapshot_present {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "image= or from_snapshot= is required",
        ));
    }

    let mut builder = microsandbox::Sandbox::builder(name);

    if snapshot_present {
        // Boot from a snapshot. Accept str or PathLike.
        let snap_obj = kwargs.get_item("from_snapshot")?.unwrap();
        let snap_str: String = if let Ok(s) = snap_obj.extract::<String>() {
            s
        } else if let Ok(fspath) = snap_obj.call_method0("__fspath__") {
            fspath.extract()?
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "from_snapshot must be str or os.PathLike",
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
            snap_dir.join(microsandbox::snapshot::DESCRIPTOR_FILENAME),
        )
        .map_err(|e| {
            pyo3::exceptions::PyFileNotFoundError::new_err(format!(
                "snapshot descriptor not readable at {}: {e}",
                snap_dir.display(),
            ))
        })?;
        let manifest =
            microsandbox::snapshot::Manifest::from_bytes(&manifest_bytes).map_err(|e| {
                pyo3::exceptions::PyValueError::new_err(format!("snapshot descriptor invalid: {e}"))
            })?;
        if manifest.scope != microsandbox::snapshot::SnapshotScope::Disk {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "restoring non-disk snapshots is not supported by this runtime",
            ));
        }
        let file_state = match &manifest.state {
            microsandbox::snapshot::SnapshotState::File(state) => state,
            microsandbox::snapshot::SnapshotState::Checkpoint(_) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "restoring checkpoint-state snapshots is not supported by this runtime",
                ));
            }
        };
        if file_state.format != microsandbox::snapshot::SnapshotFormat::Raw
            || file_state.fstype != "ext4"
        {
            return Err(pyo3::exceptions::PyValueError::new_err(
                "snapshot file state is not a supported raw ext4 upper",
            ));
        }
        let upper_path = snap_dir.join(&file_state.upper.file);
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
        // Accept an open image reference/path or the concrete ImageSource
        // configuration type. Arbitrary objects with similarly named
        // methods must not bypass ImageSource's enum validation.
        let is_image_source = is_exact_sdk_type(&image_obj, "ImageSource")?;
        let image_str: String = if let Ok(s) = image_obj.extract::<String>() {
            s
        } else if is_image_source {
            image_obj.call_method0("_to_image_str")?.extract()?
        } else if let Ok(fspath) = image_obj.call_method0("__fspath__") {
            fspath.extract()?
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(
                "image must be str, os.PathLike, or ImageSource",
            ));
        };

        let fstype = if is_image_source && let Ok(fstype_attr) = image_obj.getattr("_fstype") {
            if fstype_attr.is_none() {
                None
            } else {
                Some(fstype_attr.extract::<String>()?)
            }
        } else {
            None
        };
        let root_disk = if is_image_source {
            extract_root_disk(&image_obj)?
        } else {
            None
        };

        if root_disk.is_some() {
            let image_type = image_obj
                .getattr("_type")
                .ok()
                .and_then(|attr| attr.extract::<String>().ok());
            if image_type.as_deref() != Some("oci") {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "root_disk is only valid for Image.oci(...)",
                ));
            }
        }

        match (fstype, root_disk) {
            (Some(_), Some(_)) => {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "fstype and root_disk cannot be set on the same ImageSource",
                ));
            }
            (Some(fstype), None) => {
                builder = builder.image_with(|i| i.disk(&image_str).fstype(&fstype));
            }
            (None, Some(spec)) => {
                builder = builder.image_with(|i| spec.apply(i.oci(image_str.as_str())));
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
    if let Some(max_memory) = extract_opt::<u32>(kwargs, "max_memory")? {
        builder = builder.max_memory(max_memory);
    }
    if let Some(max_cpus) = extract_opt::<u8>(kwargs, "max_cpus")? {
        builder = builder.max_cpus(max_cpus);
    }
    if let Some(cpu_placement) = extract_opt::<String>(kwargs, "cpu_placement")? {
        let policy = cpu_placement
            .parse::<CpuPlacement>()
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        builder = builder.cpu_placement(policy);
    }
    if let Some(placement_profile) = extract_opt::<String>(kwargs, "placement_profile")? {
        builder = builder.placement_profile(placement_profile);
    }
    if let Some(thp) = extract_opt::<String>(kwargs, "thp")? {
        let policy = thp
            .parse::<TransparentHugePagePolicy>()
            .map_err(pyo3::exceptions::PyValueError::new_err)?;
        builder = builder.thp(policy);
    }
    if let Some(workdir) = extract_opt::<String>(kwargs, "workdir")? {
        builder = builder.workdir(workdir);
    }
    if let Some(shell) = extract_opt::<String>(kwargs, "shell")? {
        builder = builder.shell(shell);
    }
    if let Some(security_obj) = kwargs.get_item("security")?.filter(|v| !v.is_none()) {
        let security = extract_str_enum(&security_obj, "SecurityProfile")?;
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
    if let Some(deployment_profile_obj) = kwargs
        .get_item("deployment_profile")?
        .filter(|value| !value.is_none())
    {
        let deployment_profile = extract_str_enum(&deployment_profile_obj, "DeploymentProfile")?;
        let profile = match deployment_profile.as_str() {
            "single-tenant" => DeploymentProfile::SingleTenant,
            "multi-tenant" => DeploymentProfile::MultiTenant,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "invalid deployment profile: {deployment_profile}. Expected: single-tenant, multi-tenant"
                )));
            }
        };
        builder = builder.deployment_profile(profile);
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
    if let Some(cmd) = extract_opt::<Vec<String>>(kwargs, "cmd")? {
        builder = builder.cmd(cmd);
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
    if let Some(env) = kwargs.get_item("env")?.filter(|v| !v.is_none()) {
        let env_dict = require_mapping_dict(&env, "env")?;
        for (k, v) in env_dict.iter() {
            let key: String = k.extract()?;
            let val: String = v.extract()?;
            builder = builder.env(key, val);
        }
    }

    // Labels.
    if let Some(labels) = kwargs.get_item("labels")?.filter(|v| !v.is_none()) {
        let labels_dict = require_mapping_dict(&labels, "labels")?;
        for (k, v) in labels_dict.iter() {
            let key: String = k.extract()?;
            let val: String = v.extract()?;
            builder = builder.label(key, val);
        }
    }

    // Scripts.
    if let Some(scripts) = kwargs.get_item("scripts")?.filter(|v| !v.is_none()) {
        let scripts_dict = require_mapping_dict(&scripts, "scripts")?;
        for (k, v) in scripts_dict.iter() {
            let key: String = k.extract()?;
            let val: String = v.extract()?;
            builder = builder.script(key, val);
        }
    }

    // Pull policy.
    if let Some(pp_obj) = kwargs.get_item("pull_policy")?.filter(|v| !v.is_none()) {
        let pp = extract_str_enum(&pp_obj, "PullPolicy")?;
        let policy = match pp.as_str() {
            "always" => PullPolicy::Always,
            "if-missing" => PullPolicy::IfMissing,
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
    if let Some(ll_obj) = kwargs.get_item("log_level")?.filter(|v| !v.is_none()) {
        let ll = extract_str_enum(&ll_obj, "LogLevel")?;
        let level = match ll.as_str() {
            "trace" => LogLevel::Trace,
            "debug" => LogLevel::Debug,
            "info" => LogLevel::Info,
            "warn" => LogLevel::Warn,
            "error" => LogLevel::Error,
            _ => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "invalid log_level: {ll}"
                )));
            }
        };
        builder = builder.log_level(level);
    }

    // Registry overrides: auth, plain-HTTP transport, extra CA roots.
    // `SandboxBuilder::registry` overwrites `insecure` and `ca_certs` on every
    // call, so all three have to be applied through a single closure.
    {
        let auth = parse_registry_auth(kwargs)?;
        let insecure = match kwargs.get_item("registry_insecure")? {
            Some(val) if !val.is_none() => val.extract::<bool>().map_err(|_| {
                pyo3::exceptions::PyTypeError::new_err("registry_insecure must be a bool")
            })?,
            _ => false,
        };
        let ca_certs = parse_registry_ca_certs(kwargs)?;

        if auth.is_some() || insecure || !ca_certs.is_empty() {
            builder = builder.registry(|mut r| {
                if let Some(auth) = auth {
                    r = r.auth(auth);
                }
                if insecure {
                    r = r.insecure();
                }
                for pem in ca_certs {
                    r = r.ca_certs(pem);
                }
                r
            });
        }
    }

    // Volumes.
    if let Some(volumes) = kwargs.get_item("volumes")?.filter(|v| !v.is_none()) {
        let vol_dict = require_mapping_dict(&volumes, "volumes")?;
        for (guest_path_obj, mount_obj) in vol_dict.iter() {
            let guest_path: String = guest_path_obj.extract()?;
            let mount_dict = config_dict(&mount_obj, "MountConfig")?;
            builder = apply_mount(builder, guest_path, &mount_dict)?;
        }
    }

    // Patches.
    if let Some(patches) = kwargs.get_item("patches")?.filter(|v| !v.is_none()) {
        let patches_iter = patches.try_iter().map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err(
                "patches must be a sequence of PatchConfig values",
            )
        })?;
        for patch_obj in patches_iter {
            let patch_obj = patch_obj?;
            let patch_dict = config_dict(&patch_obj, "PatchConfig")?;
            builder = apply_patch(builder, &patch_dict)?;
        }
    }

    // Ports.
    if let Some(ports) = kwargs.get_item("ports")?.filter(|v| !v.is_none()) {
        builder = apply_ports(builder, &ports, PortBindingSource::PublicConfig)?;
    }

    // Guest-to-host vsock routes are independent of IP networking.
    if let Some(vsock) = kwargs.get_item("vsock")?.filter(|v| !v.is_none()) {
        builder = apply_vsock_routes(builder, &vsock)?;
    }

    // Network.
    if let Some(network) = kwargs.get_item("network")?.filter(|v| !v.is_none()) {
        let net_dict = config_dict(&network, "Network")?;
        builder = apply_network(builder, &net_dict)?;
    }

    // Secrets.
    if let Some(secrets) = kwargs.get_item("secrets")?.filter(|v| !v.is_none()) {
        let secrets_iter = secrets.try_iter().map_err(|_| {
            pyo3::exceptions::PyTypeError::new_err(
                "secrets must be a sequence of SecretEntry values",
            )
        })?;
        for secret_obj in secrets_iter {
            let secret_obj = secret_obj?;
            let secret_dict = config_dict(&secret_obj, "SecretEntry")?;
            builder = apply_secret(builder, &secret_dict)?;
        }
    }

    // Secret violation action (top-level kwarg). This is applied after
    // `network=` so the explicit shorthand takes precedence when both are set.
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

    // Rich form: either the concrete SDK config or the explicitly documented
    // Mapping protocol. Arbitrary objects with a coincidental `_to_dict`
    // method are not configuration values.
    let dict_owned = if is_exact_sdk_type(obj, "InitConfig")? {
        let returned = obj.call_method0("_to_dict")?;
        Some(
            returned
                .downcast::<PyDict>()
                .map_err(|_| {
                    pyo3::exceptions::PyTypeError::new_err(
                        "InitConfig._to_dict() must return a dict",
                    )
                })?
                .clone(),
        )
    } else {
        mapping_to_dict(obj)?
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
        "init must be str, Mapping with 'cmd', or InitConfig",
    ))
}

/// Pull `args: list[str]` and `env: Mapping[str, str]` from an init dict.
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
            let env_dict = require_mapping_dict(&env_obj, "init.env")?;
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
// Functions: Root Disk
//--------------------------------------------------------------------------------------------------

/// Read the `_root_disk` attribute of an ImageSource, falling back to the
/// deprecated `_upper_size_mib` (managed sugar) when absent.
fn extract_root_disk(image_obj: &Bound<'_, PyAny>) -> PyResult<Option<RootDiskSpec>> {
    let root_disk_attr = image_obj
        .getattr("_root_disk")
        .ok()
        .filter(|attr| !attr.is_none());

    let Some(attr) = root_disk_attr else {
        // Legacy dataclass instances constructed with only _upper_size_mib.
        if let Ok(upper_size_attr) = image_obj.getattr("_upper_size_mib")
            && !upper_size_attr.is_none()
        {
            return Ok(Some(RootDiskSpec {
                kind: "managed".to_string(),
                size_mib: Some(upper_size_attr.extract::<u32>()?),
                path: None,
                format: None,
                fstype: None,
                clone: None,
            }));
        }
        return Ok(None);
    };

    // Bare exact int: managed root disk of that size. `bool` and integer
    // subclasses do not satisfy this shorthand even though Python normally
    // treats bool as an integer.
    let int_class = PyModule::import(attr.py(), "builtins")?.getattr("int")?;
    if attr.get_type().as_any().is(&int_class) {
        let size_mib = attr.extract::<u32>()?;
        return Ok(Some(RootDiskSpec {
            kind: "managed".to_string(),
            size_mib: Some(size_mib),
            path: None,
            format: None,
            fstype: None,
            clone: None,
        }));
    }

    let dict = config_dict(&attr, "RootDiskConfig")?;
    let kind = extract_opt::<String>(&dict, "kind")?.unwrap_or_else(|| "managed".to_string());
    let size_mib = extract_opt::<u32>(&dict, "size_mib")?;
    let path = extract_opt::<String>(&dict, "path")?;
    let format = extract_opt::<String>(&dict, "format")?
        .map(|s| {
            s.parse::<microsandbox::sandbox::DiskImageFormat>()
                .map_err(|e| pyo3::exceptions::PyValueError::new_err(e.to_string()))
        })
        .transpose()?;
    let fstype = extract_opt::<String>(&dict, "fstype")?;
    let clone = extract_opt::<String>(&dict, "clone")?
        .map(|value| match value.as_str() {
            "auto" => Ok(microsandbox::sandbox::FlatClone::Auto),
            "copy" => Ok(microsandbox::sandbox::FlatClone::Copy),
            "reflink" => Ok(microsandbox::sandbox::FlatClone::Reflink),
            other => Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown flat clone strategy: {other} (expected auto, copy, reflink)"
            ))),
        })
        .transpose()?;

    match kind.as_str() {
        "managed" | "tmpfs" => {
            if path.is_some() || format.is_some() || fstype.is_some() || clone.is_some() {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "path/format/fstype/clone are not valid for a {kind} root disk"
                )));
            }
        }
        "disk-image" => {
            if path.as_deref().unwrap_or_default().is_empty() {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "disk-image root disk requires path",
                ));
            }
            if clone.is_some() {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "clone is only valid for a flat root disk",
                ));
            }
            if size_mib.is_some() {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "size_mib is not valid for a disk-image root disk; resize the image file itself",
                ));
            }
        }
        "flat" => {
            if path.is_some() || format.is_some() {
                return Err(pyo3::exceptions::PyValueError::new_err(
                    "path/format are not valid for a flat root disk",
                ));
            }
        }
        other => {
            return Err(pyo3::exceptions::PyValueError::new_err(format!(
                "unknown root disk kind: {other} (expected managed, tmpfs, disk-image, flat)"
            )));
        }
    }

    Ok(Some(RootDiskSpec {
        kind,
        size_mib,
        path,
        format,
        fstype,
        clone,
    }))
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
    let override_uid = extract_opt::<u32>(mount, "override_uid")?;
    let override_gid = extract_opt::<u32>(mount, "override_gid")?;

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
            if let (Some(uid), Some(gid)) = (override_uid, override_gid) {
                m = m.owner(uid, gid);
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
            if let (Some(uid), Some(gid)) = (override_uid, override_gid) {
                m = m.owner(uid, gid);
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
        "file" => {
            let path: String = extract_required(patch, "path")?;
            let content: Vec<u8> = extract_required(patch, "content")?;
            Ok(builder.add_patch(Patch::File {
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

    if let Some(legacy) = net.get_item("policy")?
        && !legacy.is_none()
    {
        return Err(pyo3::exceptions::PyValueError::new_err(
            "string network policy presets were removed; use Network.from_profiles(...), Network.none(), or Network.allow_all()",
        ));
    }

    // Check for custom policy object.
    if let Some(custom) = net.get_item("custom_policy")?
        && !custom.is_none()
    {
        let cp_dict: Bound<'_, PyDict> = custom.downcast::<PyDict>()?.clone();
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
        // through to Deny (preserves the default public-profile reachability
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
                let rd: Bound<'_, PyDict> = rule_obj.downcast::<PyDict>()?.clone();
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

    // No custom policy was specified, but legacy DNS block
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
        let dns: Bound<'_, PyDict> = dns.downcast::<PyDict>()?.clone();

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

    // Rate limiters (egress = guest -> runtime, ingress = runtime -> guest).
    if let Some(rate_limiter) = net.get_item("rate_limiter")?
        && !rate_limiter.is_none()
    {
        let rate_limiter: Bound<'_, PyDict> = rate_limiter.downcast::<PyDict>()?.clone();
        let egress = parse_rate_limiter(&rate_limiter, "egress")?;
        let ingress = parse_rate_limiter(&rate_limiter, "ingress")?;
        builder = builder.network(move |n| {
            n.rate_limiter(|mut r| {
                if let Some(limiter) = &egress {
                    r = r.egress(|direction| apply_rate_limiter(direction, limiter));
                }
                if let Some(limiter) = &ingress {
                    r = r.ingress(|direction| apply_rate_limiter(direction, limiter));
                }
                r
            })
        });
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
        let action = parse_serialized_violation_action(&violation_obj)?;
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
        let tls_dict: Bound<'_, PyDict> = tls.downcast::<PyDict>()?.clone();
        let bypass: Vec<String> = extract_opt(&tls_dict, "bypass")?.unwrap_or_default();
        let verify_upstream: Option<bool> = extract_opt(&tls_dict, "verify_upstream")?;
        let intercepted_ports: Option<Vec<u16>> = extract_opt(&tls_dict, "intercepted_ports")?;
        let block_quic: Option<bool> = extract_opt(&tls_dict, "block_quic")?;
        let upstream_ca_certs: Vec<String> =
            extract_opt(&tls_dict, "upstream_ca_certs")?.unwrap_or_default();
        let scoped_upstream_ca_certs =
            parse_scoped_upstream_ca_certs(&tls_dict, "scoped_upstream_ca_certs")?;
        let scoped_verify_upstream =
            parse_scoped_verify_upstream(&tls_dict, "scoped_verify_upstream")?;
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
                for path in &upstream_ca_certs {
                    t = t.upstream_ca_cert(path);
                }
                for (pattern, path) in &scoped_upstream_ca_certs {
                    t = t.upstream_ca_cert_for(pattern, path);
                }
                for (pattern, verify) in &scoped_verify_upstream {
                    t = t.verify_upstream_for(pattern, *verify);
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
        builder = apply_ports(builder, &ports, PortBindingSource::SerializedNetwork)?;
    }

    Ok(builder)
}

fn apply_ports(
    mut builder: microsandbox::sandbox::SandboxBuilder,
    ports: &Bound<'_, PyAny>,
    source: PortBindingSource,
) -> PyResult<microsandbox::sandbox::SandboxBuilder> {
    if let Some(ports_dict) = mapping_to_dict(ports)? {
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
        let port = match source {
            PortBindingSource::PublicConfig => config_dict(&item, "PortBinding")?,
            PortBindingSource::SerializedNetwork => {
                item.downcast::<PyDict>().cloned().map_err(|_| {
                    pyo3::exceptions::PyTypeError::new_err(
                        "Network._to_dict() ports must contain dictionaries",
                    )
                })?
            }
        };
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

/// Token bucket values from a Python `TokenBucket` dict.
struct TokenBucketOpts {
    size: u64,
    refill_time_ms: u64,
    one_time_burst: u64,
}

/// Rate limiter values from a Python `RateLimiter` dict.
struct RateLimiterOpts {
    bandwidth: Option<TokenBucketOpts>,
    ops: Option<TokenBucketOpts>,
}

fn parse_rate_limiter(net: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<RateLimiterOpts>> {
    let Some(obj) = net.get_item(key)? else {
        return Ok(None);
    };
    if obj.is_none() {
        return Ok(None);
    }
    let limiter: Bound<'_, PyDict> = obj.downcast::<PyDict>()?.clone();
    Ok(Some(RateLimiterOpts {
        bandwidth: parse_token_bucket(&limiter, "bandwidth")?,
        ops: parse_token_bucket(&limiter, "ops")?,
    }))
}

fn parse_token_bucket(limiter: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<TokenBucketOpts>> {
    let Some(obj) = limiter.get_item(key)? else {
        return Ok(None);
    };
    if obj.is_none() {
        return Ok(None);
    }
    let bucket: Bound<'_, PyDict> = obj.downcast::<PyDict>()?.clone();
    Ok(Some(TokenBucketOpts {
        size: extract_required(&bucket, "size")?,
        refill_time_ms: extract_required(&bucket, "refill_time_ms")?,
        one_time_burst: extract_opt(&bucket, "one_time_burst")?.unwrap_or(0),
    }))
}

/// Apply parsed rate limiter values to the Rust builder. Validation
/// happens in `NetworkBuilder::build`.
fn apply_rate_limiter(
    mut r: microsandbox_network::builder::RateLimiterBuilder,
    opts: &RateLimiterOpts,
) -> microsandbox_network::builder::RateLimiterBuilder {
    if let Some(bandwidth) = &opts.bandwidth {
        r = r.bandwidth(
            bandwidth.size,
            std::time::Duration::from_millis(bandwidth.refill_time_ms),
        );
        if bandwidth.one_time_burst > 0 {
            r = r.bandwidth_burst(bandwidth.one_time_burst);
        }
    }
    if let Some(ops) = &opts.ops {
        r = r.ops(
            ops.size,
            std::time::Duration::from_millis(ops.refill_time_ms),
        );
        if ops.one_time_burst > 0 {
            r = r.ops_burst(ops.one_time_burst);
        }
    }
    r
}

/// Apply the compact `{host_socket: port}` stream shorthand or a sequence of
/// typed `VsockRoute` values for stream/datagram routes.
fn apply_vsock_routes(
    mut builder: microsandbox::sandbox::SandboxBuilder,
    routes: &Bound<'_, PyAny>,
) -> PyResult<microsandbox::sandbox::SandboxBuilder> {
    if let Some(routes_dict) = mapping_to_dict(routes)? {
        for (host_socket, port) in routes_dict.iter() {
            builder = builder.vsock(host_socket.extract::<String>()?, port.extract::<u32>()?);
        }
        return Ok(builder);
    }

    let iter = routes.try_iter().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(
            "vsock must be a mapping of host_socket to port or a sequence of VsockRoute values",
        )
    })?;
    for route in iter {
        let route = config_dict(&route?, "VsockRoute")?;
        let host_socket: String = extract_required(&route, "host_socket")?;
        let port: u32 = extract_required(&route, "port")?;
        let socket_type: String =
            extract_opt(&route, "socket_type")?.unwrap_or_else(|| "stream".to_string());
        builder = match socket_type.as_str() {
            "stream" => builder.vsock(host_socket, port),
            "dgram" => builder.vsock_dgram(host_socket, port),
            other => {
                return Err(pyo3::exceptions::PyValueError::new_err(format!(
                    "invalid vsock socket type: {other}"
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
        Some(parse_serialized_violation_action(&violation_obj)?)
    } else {
        None
    };

    let placeholder: Option<String> = extract_opt(secret, "placeholder")?;
    let require_tls: Option<bool> = extract_opt(secret, "require_tls")?;

    let (inject_headers, inject_basic_auth, inject_query_params, inject_body) =
        if let Some(injection_obj) = secret.get_item("injection")? {
            let injection: Bound<'_, PyDict> = injection_obj.downcast::<PyDict>()?.clone();
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

/// Reject kwargs that no consumer of `Sandbox.create` recognizes, so a
/// typo (or a removed kwarg like `snapshot=`) fails loudly instead of
/// being silently ignored.
fn reject_unknown_kwargs(kwargs: &Bound<'_, PyDict>) -> PyResult<()> {
    let mut unknown: Vec<String> = Vec::new();
    for key in kwargs.keys() {
        let key: String = key.extract()?;
        if !KNOWN_CREATE_KWARGS.contains(&key.as_str()) {
            unknown.push(key);
        }
    }
    if unknown.is_empty() {
        return Ok(());
    }
    let listed = unknown
        .iter()
        .map(|k| {
            if k == "snapshot" {
                "'snapshot' (did you mean 'from_snapshot'?)".to_string()
            } else {
                format!("'{k}'")
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let plural = if unknown.len() == 1 { "" } else { "s" };
    Err(pyo3::exceptions::PyTypeError::new_err(format!(
        "unexpected keyword argument{plural} {listed}"
    )))
}

/// Return whether `obj` has exactly the named public SDK type.
pub(crate) fn is_exact_sdk_type(obj: &Bound<'_, PyAny>, type_name: &str) -> PyResult<bool> {
    let class = PyModule::import(obj.py(), "microsandbox.types")?.getattr(type_name)?;
    Ok(obj.get_type().as_any().is(&class))
}

/// Copy a documented Python Mapping into a concrete dictionary.
fn mapping_to_dict<'py>(obj: &Bound<'py, PyAny>) -> PyResult<Option<Bound<'py, PyDict>>> {
    let mapping_class = PyModule::import(obj.py(), "collections.abc")?.getattr("Mapping")?;
    if !obj.is_instance(&mapping_class)? {
        return Ok(None);
    }
    let dict_class = PyModule::import(obj.py(), "builtins")?.getattr("dict")?;
    let converted = dict_class.call1((obj,))?;
    Ok(Some(converted.downcast::<PyDict>()?.clone()))
}

/// Copy a required documented Mapping into a concrete dictionary.
fn require_mapping_dict<'py>(
    obj: &Bound<'py, PyAny>,
    argument: &str,
) -> PyResult<Bound<'py, PyDict>> {
    mapping_to_dict(obj)?.ok_or_else(|| {
        pyo3::exceptions::PyTypeError::new_err(format!("{argument} must be a Mapping"))
    })
}

/// Serialize one concrete public SDK configuration object.
///
/// Requiring the declared class before calling `_to_dict` is the boundary
/// that keeps raw dictionaries, duck-typed objects, and unrelated enum
/// classes from bypassing the Python SDK's validation.
fn config_dict<'py>(obj: &Bound<'py, PyAny>, type_name: &str) -> PyResult<Bound<'py, PyDict>> {
    if !is_exact_sdk_type(obj, type_name)? {
        return Err(pyo3::exceptions::PyTypeError::new_err(format!(
            "expected {type_name}, got {}",
            obj.get_type().name()?
        )));
    }
    let result = obj.call_method0("_to_dict")?;
    result.downcast::<PyDict>().cloned().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(format!("{type_name}._to_dict() must return a dict"))
    })
}

/// Parse the `registry_auth` kwarg into a `RegistryAuth`.
fn parse_registry_auth(kwargs: &Bound<'_, PyDict>) -> PyResult<Option<RegistryAuth>> {
    let Some(auth) = kwargs
        .get_item("registry_auth")?
        .filter(|value| !value.is_none())
    else {
        return Ok(None);
    };
    let auth_dict = config_dict(&auth, "RegistryAuth")?;
    let auth_dict = &auth_dict;
    let username: String = auth_dict
        .get_item("username")?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("registry_auth.username required"))?
        .extract()?;
    let password: String = auth_dict
        .get_item("password")?
        .ok_or_else(|| pyo3::exceptions::PyValueError::new_err("registry_auth.password required"))?
        .extract()?;
    Ok(Some(RegistryAuth::Basic { username, password }))
}

/// Parse the `registry_ca_certs` kwarg into PEM blobs. Every entry is either
/// the PEM data itself (`bytes` / `bytearray`) or the path of a PEM file
/// (`str` / `os.PathLike`), which is read eagerly so a bad path fails at
/// `create()` time rather than mid-pull.
fn parse_registry_ca_certs(kwargs: &Bound<'_, PyDict>) -> PyResult<Vec<Vec<u8>>> {
    let Some(obj) = kwargs.get_item("registry_ca_certs")? else {
        return Ok(Vec::new());
    };
    if obj.is_none() {
        return Ok(Vec::new());
    }

    let entries: &Bound<'_, PyList> = obj.downcast()?;
    let mut certs = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        // Check for bytes first: `os.fspath` also accepts bytes paths, so
        // probing for a path up front would read inline PEM data as a filename.
        if let Ok(data) = entry.downcast::<PyBytes>() {
            certs.push(data.as_bytes().to_vec());
        } else if let Ok(data) = entry.downcast::<PyByteArray>() {
            certs.push(data.to_vec());
        } else if let Ok(path) = entry.extract::<std::path::PathBuf>() {
            let data = std::fs::read(&path).map_err(|e| {
                pyo3::exceptions::PyOSError::new_err(format!(
                    "failed to read registry_ca_certs entry `{}`: {e}",
                    path.display()
                ))
            })?;
            certs.push(data);
        } else {
            return Err(pyo3::exceptions::PyTypeError::new_err(format!(
                "registry_ca_certs[{index}] must be PEM bytes or a path to a PEM file"
            )));
        }
    }
    Ok(certs)
}

fn parse_scoped_upstream_ca_certs(
    dict: &Bound<'_, PyDict>,
    key: &str,
) -> PyResult<Vec<(String, String)>> {
    let Some(obj) = dict.get_item(key)? else {
        return Ok(Vec::new());
    };
    if obj.is_none() {
        return Ok(Vec::new());
    }

    let entries: &Bound<'_, PyList> = obj.downcast()?;
    let mut scoped = Vec::with_capacity(entries.len());
    for entry in entries.iter() {
        let entry_dict: Bound<'_, PyDict> = entry.downcast::<PyDict>()?.clone();
        scoped.push((
            extract_required(&entry_dict, "pattern")?,
            extract_required(&entry_dict, "path")?,
        ));
    }
    Ok(scoped)
}

fn parse_scoped_verify_upstream(
    dict: &Bound<'_, PyDict>,
    key: &str,
) -> PyResult<Vec<(String, bool)>> {
    let Some(obj) = dict.get_item(key)? else {
        return Ok(Vec::new());
    };
    if obj.is_none() {
        return Ok(Vec::new());
    }

    let entries: &Bound<'_, PyList> = obj.downcast()?;
    let mut scoped = Vec::with_capacity(entries.len());
    for entry in entries.iter() {
        let entry_dict: Bound<'_, PyDict> = entry.downcast::<PyDict>()?.clone();
        scoped.push((
            extract_required(&entry_dict, "pattern")?,
            extract_required(&entry_dict, "verify")?,
        ));
    }
    Ok(scoped)
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
        "block-and-log" => Ok(ViolationAction::BlockAndLog),
        "block-and-terminate" => Ok(ViolationAction::BlockAndTerminate),
        "passthrough" => Ok(ViolationAction::Passthrough(vec![HostPattern::Any])),
        _ => Err(pyo3::exceptions::PyValueError::new_err(format!(
            "unknown violation action: {s}"
        ))),
    }
}

fn parse_violation_action_obj(
    obj: &Bound<'_, PyAny>,
) -> PyResult<microsandbox_network::secrets::config::ViolationAction> {
    if let Ok(s) = extract_str_enum(obj, "ViolationAction") {
        return parse_violation_action(&s);
    }
    if !is_exact_sdk_type(obj, "ViolationPolicy")? {
        return Err(pyo3::exceptions::PyTypeError::new_err(
            "expected ViolationAction or ViolationPolicy",
        ));
    }

    // Convert the concrete policy exactly once. Fallback policies flatten to
    // a ViolationAction member; passthrough policies become a trusted dict.
    let converted = obj.call_method0("_to_dict")?;
    parse_serialized_violation_action(&converted)
}

/// Parse a violation policy after a concrete SDK config has serialized it.
fn parse_serialized_violation_action(
    obj: &Bound<'_, PyAny>,
) -> PyResult<microsandbox_network::secrets::config::ViolationAction> {
    if let Ok(s) = extract_str_enum(obj, "ViolationAction") {
        return parse_violation_action(&s);
    }

    let dict = obj.downcast::<PyDict>().map_err(|_| {
        pyo3::exceptions::PyTypeError::new_err(
            "serialized violation policy must be ViolationAction or dict",
        )
    })?;
    if let Some(passthrough_obj) = dict.get_item("passthrough")?
        && !passthrough_obj.is_none()
    {
        let passthrough: &Bound<'_, PyDict> = passthrough_obj.downcast()?;
        return parse_passthrough_policy(passthrough);
    }

    Err(pyo3::exceptions::PyValueError::new_err(
        "expected ViolationAction or ViolationPolicy",
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
/// directory. Mirrors the convention used by `Snapshot::open`
/// (`snapshot::store::looks_like_path`) — keep the heuristics in sync.
fn resolve_snapshot_dir(s: &str) -> std::path::PathBuf {
    if snapshot_ref_looks_like_path(s) {
        std::path::PathBuf::from(s)
    } else {
        microsandbox::backend::default_backend()
            .as_local()
            .map(|local| local.snapshots_dir().join(s))
            .unwrap_or_else(|| std::path::PathBuf::from(s))
    }
}

/// Heuristic split between a bare snapshot name and a filesystem path.
fn snapshot_ref_looks_like_path(s: &str) -> bool {
    if s.contains('/') || s.starts_with('.') || s.starts_with('~') {
        return true;
    }
    // On Windows hosts, native separators and drive/UNC prefixes (`C:\snaps\foo`, `C:foo`, `\\server\share`) mark a path even when no forward slash appears.
    #[cfg(windows)]
    {
        use typed_path::{Utf8WindowsComponent, Utf8WindowsPath};
        s.contains('\\')
            || matches!(
                Utf8WindowsPath::new(s).components().next(),
                Some(Utf8WindowsComponent::Prefix(_))
            )
    }
    #[cfg(not(windows))]
    {
        false
    }
}
