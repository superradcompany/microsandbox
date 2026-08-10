//! Strict sparse configuration loading for single-sandbox commands.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use microsandbox::sandbox::{
    DiskImageFormat, HostPermissions, Patch, PullPolicy, RlimitResource, SandboxBuilder,
    SecurityProfile, StatVirtualization,
};
use microsandbox_image::RegistryAuth;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use serde_saphyr::granit_parser::{Event, Parser};
use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy, Options};

use crate::commands::common::{
    SandboxConfigSources, SandboxOpts, parse_duration_secs, validate_shell, wrap_shell_script,
};
use crate::ui;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const MAX_CONFIG_BYTES: usize = 16 * 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types: Public Resolution
//--------------------------------------------------------------------------------------------------

/// A merged sparse single-sandbox configuration ready to lower into the SDK builder.
#[derive(Debug)]
pub struct ResolvedSandboxConfig {
    patch: SandboxPatch,
    loaded: bool,
}

/// The final rootfs source selected after file and positional precedence is resolved.
#[derive(Debug, Clone)]
pub enum ResolvedImage {
    /// A normal image spelling accepted by the SDK.
    Image(String),
    /// An explicit OCI image with an optional writable-upper size.
    Oci {
        /// OCI image reference.
        reference: String,
        /// Optional managed writable-upper size.
        upper_size: Option<String>,
    },
    /// A host disk image rootfs.
    Disk {
        /// Absolute host path to the disk image.
        path: PathBuf,
        /// Optional inner filesystem type.
        fstype: Option<String>,
    },
    /// A host directory rootfs.
    Bind(PathBuf),
    /// A saved sandbox snapshot.
    Snapshot(String),
}

//--------------------------------------------------------------------------------------------------
// Types: Sparse Schema
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SandboxPatch {
    image: Option<ImageInput>,
    pull_policy: Option<PullPolicyInput>,
    registry: Option<RegistryInput>,
    cpus: Option<u8>,
    memory: Option<String>,
    max_duration: Option<String>,
    idle_timeout: Option<String>,
    rlimits: Option<Vec<RlimitInput>>,
    workdir: Option<String>,
    shell: Option<String>,
    user: Option<String>,
    hostname: Option<String>,
    security: Option<SecurityInput>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    env: Option<BTreeMap<String, String>>,
    labels: Option<BTreeMap<String, String>>,
    init: Option<InitInput>,
    mounts: Option<Vec<MountInput>>,
    patch_files: Option<Vec<PathBuf>>,
    patches: Option<Vec<PatchInput>>,
    network: Option<NetworkInput>,
    secrets: Option<BTreeMap<String, SecretInput>>,
    scripts: Option<BTreeMap<String, String>>,
    ports: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ResourcePatch {
    cpus: Option<u8>,
    memory: Option<String>,
    max_duration: Option<String>,
    idle_timeout: Option<String>,
    rlimits: Option<Vec<RlimitInput>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimePatch {
    workdir: Option<String>,
    shell: Option<String>,
    user: Option<String>,
    hostname: Option<String>,
    security: Option<SecurityInput>,
    entrypoint: Option<Vec<String>>,
    cmd: Option<Vec<String>>,
    env: Option<BTreeMap<String, String>>,
    labels: Option<BTreeMap<String, String>>,
    init: Option<InitInput>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct FilesystemPatch {
    mounts: Option<Vec<MountInput>>,
    patch_files: Option<Vec<PathBuf>>,
    patches: Option<Vec<PatchInput>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ImageInput {
    String(String),
    Object(ImageObject),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ImageObject {
    oci: Option<String>,
    snapshot: Option<String>,
    disk: Option<PathBuf>,
    bind: Option<PathBuf>,
    layer: Option<Value>,
    upper_size: Option<String>,
    fstype: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum PullPolicyInput {
    Missing,
    Always,
    Never,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RegistryInput {
    username: Option<String>,
    password_env: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SecurityInput {
    Default,
    Restricted,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RlimitInput {
    resource: String,
    soft: u64,
    hard: Option<u64>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct InitInput {
    cmd: Option<String>,
    args: Option<Vec<String>>,
    env: Option<BTreeMap<String, String>>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum MountInput {
    String(String),
    Object(MountObject),
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct MountObject {
    bind: Option<PathBuf>,
    named: Option<String>,
    tmpfs: Option<TmpfsInput>,
    disk: Option<PathBuf>,
    target: Option<String>,
    create: Option<NamedCreateInput>,
    format: Option<DiskFormatInput>,
    fstype: Option<String>,
    readonly: Option<bool>,
    noexec: Option<bool>,
    nosuid: Option<bool>,
    nodev: Option<bool>,
    stat_virtualization: Option<StatVirtualizationInput>,
    host_permissions: Option<HostPermissionsInput>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TmpfsInput {
    size: Option<String>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum NamedCreateInput {
    Existing,
    Create,
    EnsureExists,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum DiskFormatInput {
    Qcow2,
    Raw,
    Vmdk,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum StatVirtualizationInput {
    Strict,
    Relaxed,
    Off,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum HostPermissionsInput {
    Private,
    Mirror,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "snake_case")]
enum PatchInput {
    Text(TextPatchInput),
    File(FilePatchInput),
    CopyFile(CopyFilePatchInput),
    CopyDir(CopyDirPatchInput),
    Symlink(SymlinkPatchInput),
    Mkdir(MkdirPatchInput),
    Remove(RemovePatchInput),
    Append(AppendPatchInput),
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct TextPatchInput {
    path: String,
    content: String,
    mode: Option<String>,
    #[serde(default)]
    replace: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct FilePatchInput {
    path: String,
    content_base64: String,
    mode: Option<String>,
    #[serde(default)]
    replace: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CopyFilePatchInput {
    src: PathBuf,
    dst: String,
    mode: Option<String>,
    #[serde(default)]
    replace: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct CopyDirPatchInput {
    src: PathBuf,
    dst: String,
    #[serde(default)]
    replace: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct SymlinkPatchInput {
    target: String,
    link: String,
    #[serde(default)]
    replace: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct MkdirPatchInput {
    path: String,
    mode: Option<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RemovePatchInput {
    path: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct AppendPatchInput {
    path: String,
    content: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum NetworkInput {
    Preset(NetworkPreset),
    Object(NetworkPatch),
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum NetworkPreset {
    None,
    Public,
    Open,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct NetworkPatch {
    policy: Option<NetworkPreset>,
    allow: Option<Vec<String>>,
    deny: Option<Vec<String>>,
    ports: Option<Vec<String>>,
    dns: Option<DnsInput>,
    tls: Option<TlsInput>,
    trust_host_cas: Option<bool>,
    max_connections: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct DnsInput {
    rebind_protection: Option<bool>,
    nameservers: Option<Vec<String>>,
    query_timeout: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct TlsInput {
    enabled: Option<bool>,
    bypass: Option<Vec<String>>,
    verify_upstream: Option<bool>,
    block_quic: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct SecretInput {
    value: Option<SecretValueInput>,
    allow: Option<Vec<String>>,
    inject: Option<Vec<SecretInjectionInput>>,
    require_tls_identity: Option<bool>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
#[cfg_attr(not(feature = "net"), allow(dead_code))]
enum SecretValueInput {
    Literal(String),
    Environment {
        #[serde(rename = "$msb_env")]
        env: String,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "snake_case")]
enum SecretInjectionInput {
    Headers,
    BasicAuth,
    QueryParams,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchFileInput {
    patches: Vec<PatchInput>,
}

//--------------------------------------------------------------------------------------------------
// Methods: Sparse Merging
//--------------------------------------------------------------------------------------------------

impl SandboxPatch {
    fn merge(&mut self, higher: Self) {
        replace(&mut self.image, higher.image);
        replace(&mut self.pull_policy, higher.pull_policy);
        replace(&mut self.registry, higher.registry);
        replace(&mut self.cpus, higher.cpus);
        replace(&mut self.memory, higher.memory);
        replace(&mut self.max_duration, higher.max_duration);
        replace(&mut self.idle_timeout, higher.idle_timeout);
        replace(&mut self.rlimits, higher.rlimits);
        replace(&mut self.workdir, higher.workdir);
        replace(&mut self.shell, higher.shell);
        replace(&mut self.user, higher.user);
        replace(&mut self.hostname, higher.hostname);
        replace(&mut self.security, higher.security);
        replace(&mut self.entrypoint, higher.entrypoint);
        replace(&mut self.cmd, higher.cmd);
        merge_map(&mut self.env, higher.env);
        merge_map(&mut self.labels, higher.labels);
        merge_init(&mut self.init, higher.init);
        replace(&mut self.mounts, higher.mounts);
        replace(&mut self.patch_files, higher.patch_files);
        replace(&mut self.patches, higher.patches);
        merge_network(&mut self.network, higher.network);
        merge_secrets(&mut self.secrets, higher.secrets);
        merge_map(&mut self.scripts, higher.scripts);
        replace(&mut self.ports, higher.ports);
    }

    fn normalize(&mut self) {
        if let Some(ports) = self.ports.take() {
            let network = self
                .network
                .get_or_insert_with(|| NetworkInput::Object(NetworkPatch::default()));
            network.object_mut().ports = Some(match network.object_mut().ports.take() {
                Some(mut nested) => {
                    nested.extend(ports);
                    nested
                }
                None => ports,
            });
        }
    }
}

impl NetworkInput {
    fn into_object(self) -> NetworkPatch {
        match self {
            Self::Preset(policy) => NetworkPatch {
                policy: Some(policy),
                ..NetworkPatch::default()
            },
            Self::Object(patch) => patch,
        }
    }

    fn object_mut(&mut self) -> &mut NetworkPatch {
        if let Self::Preset(policy) = self {
            *self = Self::Object(NetworkPatch {
                policy: Some(*policy),
                ..NetworkPatch::default()
            });
        }
        let Self::Object(patch) = self else {
            unreachable!("preset was normalized to an object")
        };
        patch
    }
}

//--------------------------------------------------------------------------------------------------
// Methods: Public Resolution
//--------------------------------------------------------------------------------------------------

impl ResolvedSandboxConfig {
    /// Whether any root or scoped configuration file participated in resolution.
    pub fn loaded(&self) -> bool {
        self.loaded
    }

    /// Resolve explicit registry credentials for install-time pre-pulling.
    pub fn registry_auth(&self) -> anyhow::Result<Option<RegistryAuth>> {
        match self.patch.registry.as_ref() {
            Some(registry) => resolve_registry_auth(registry),
            None => Ok(None),
        }
    }

    /// Resolve the final image after positional arguments override file fields.
    pub fn image(
        &self,
        positional_image: Option<&str>,
        positional_snapshot: Option<&str>,
    ) -> anyhow::Result<ResolvedImage> {
        if let Some(snapshot) = positional_snapshot {
            return Ok(ResolvedImage::Snapshot(snapshot.to_string()));
        }
        if let Some(image) = positional_image {
            return Ok(ResolvedImage::Image(image.to_string()));
        }

        let image = self.patch.image.as_ref().ok_or_else(|| {
            anyhow::anyhow!(
                "missing required sandbox field `image`; provide an image argument or set `image` in --conf"
            )
        })?;
        resolve_image_input(image)
    }

    /// Lower the merged sparse file plus CLI network overrides into an SDK builder.
    pub fn apply(
        &self,
        mut builder: SandboxBuilder,
        opts: &SandboxOpts,
    ) -> anyhow::Result<SandboxBuilder> {
        if !self.loaded {
            return Ok(builder);
        }
        let patch = &self.patch;

        if let Some(cpus) = patch.cpus {
            builder = builder.cpus(cpus);
        }
        if let Some(memory) = &patch.memory {
            builder = builder.memory(parse_size("memory", memory)?);
        }
        if let Some(duration) = &patch.max_duration {
            builder = builder.max_duration(parse_duration_secs(duration)?);
        }
        if let Some(duration) = &patch.idle_timeout {
            builder = builder.idle_timeout(parse_duration_secs(duration)?);
        }
        if let Some(rlimits) = &patch.rlimits {
            for input in rlimits {
                let resource = RlimitResource::try_from(input.resource.as_str())
                    .map_err(anyhow::Error::msg)?;
                builder =
                    builder.rlimit_range(resource, input.soft, input.hard.unwrap_or(input.soft));
            }
        }
        if let Some(workdir) = &patch.workdir {
            builder = builder.workdir(workdir);
        }
        if let Some(shell) = &patch.shell {
            validate_shell(shell)?;
            builder = builder.shell(shell);
        }
        if let Some(user) = &patch.user {
            builder = builder.user(user);
        }
        if let Some(hostname) = &patch.hostname {
            builder = builder.hostname(hostname);
        }
        if let Some(security) = patch.security {
            builder = builder.security(match security {
                SecurityInput::Default => SecurityProfile::Default,
                SecurityInput::Restricted => SecurityProfile::Restricted,
            });
        }
        if let Some(entrypoint) = &patch.entrypoint {
            builder = builder.entrypoint(entrypoint.clone());
        }
        if let Some(command) = &patch.cmd {
            // Store the durable workload default without selecting foreground or background
            // launch. `msb run` chooses that intent, while `msb create` only persists the command.
            builder = builder.cmd(command.clone());
        }
        if let Some(env) = &patch.env {
            builder = builder.envs(env.iter().map(|(key, value)| (key.clone(), value.clone())));
        }
        if let Some(labels) = &patch.labels {
            builder = builder.labels(
                labels
                    .iter()
                    .map(|(key, value)| (key.clone(), value.clone())),
            );
        }
        if let Some(init) = &patch.init {
            builder = apply_init(builder, init)?;
        }
        if let Some(mounts) = &patch.mounts {
            for mount in mounts {
                builder = apply_mount(builder, mount)?;
            }
        }
        builder = apply_patch_files(builder, patch.patch_files.as_deref())?;
        if let Some(patches) = &patch.patches {
            for input in patches {
                builder = builder.add_patch(materialize_patch(input)?);
            }
        }
        if let Some(policy) = patch.pull_policy {
            builder = builder.pull_policy(match policy {
                PullPolicyInput::Missing => PullPolicy::IfMissing,
                PullPolicyInput::Always => PullPolicy::Always,
                PullPolicyInput::Never => PullPolicy::Never,
            });
        }
        if let Some(registry) = &patch.registry {
            builder = apply_registry(builder, registry)?;
        }
        if let Some(scripts) = &patch.scripts {
            let effective_shell = opts.shell.as_deref().or(patch.shell.as_deref());
            if let Some(shell) = effective_shell {
                validate_shell(shell)?;
            }
            let mut materialized = Vec::with_capacity(scripts.len());
            for (name, script) in scripts {
                validate_script_name(name)?;
                materialized.push((name.clone(), wrap_shell_script(effective_shell, script)));
            }
            builder = builder.scripts(materialized);
        }

        apply_network(
            builder,
            patch.network.as_ref(),
            patch.secrets.as_ref(),
            opts,
        )
    }
}

impl ResolvedImage {
    /// Apply this rootfs source to a builder.
    pub fn apply(&self, builder: SandboxBuilder) -> anyhow::Result<SandboxBuilder> {
        Ok(match self {
            Self::Image(image) => builder.image(image.as_str()),
            Self::Oci {
                reference,
                upper_size,
            } => match upper_size {
                Some(value) => {
                    let size = parse_size("image.upper_size", value)?;
                    builder.image_with(|image| image.oci(reference).root_disk(size))
                }
                None => builder.image_with(|image| image.oci(reference)),
            },
            Self::Disk { path, fstype } => builder.image_with(|mut image| {
                image = image.disk(path);
                if let Some(fstype) = fstype {
                    image = image.fstype(fstype);
                }
                image
            }),
            Self::Bind(path) => builder.image_with(|image| image.bind(path)),
            Self::Snapshot(snapshot) => builder.from_snapshot(snapshot),
        })
    }

    /// Human-readable source label used by pull progress and installed aliases.
    pub fn display(&self) -> String {
        match self {
            Self::Image(value) | Self::Snapshot(value) => value.clone(),
            Self::Oci { reference, .. } => reference.clone(),
            Self::Disk { path, .. } | Self::Bind(path) => path.display().to_string(),
        }
    }

    /// OCI reference suitable for install-time pre-pulling, when applicable.
    pub fn oci_reference(&self) -> Option<&str> {
        match self {
            Self::Image(value) if !looks_like_local_path(value) => Some(value),
            Self::Oci { reference, .. } => Some(reference),
            Self::Image(_) | Self::Disk { .. } | Self::Bind(_) | Self::Snapshot(_) => None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl From<DiskFormatInput> for DiskImageFormat {
    fn from(value: DiskFormatInput) -> Self {
        match value {
            DiskFormatInput::Qcow2 => Self::Qcow2,
            DiskFormatInput::Raw => Self::Raw,
            DiskFormatInput::Vmdk => Self::Vmdk,
        }
    }
}

impl From<StatVirtualizationInput> for StatVirtualization {
    fn from(value: StatVirtualizationInput) -> Self {
        match value {
            StatVirtualizationInput::Strict => Self::Strict,
            StatVirtualizationInput::Relaxed => Self::Relaxed,
            StatVirtualizationInput::Off => Self::Off,
        }
    }
}

impl From<HostPermissionsInput> for HostPermissions {
    fn from(value: HostPermissionsInput) -> Self {
        match value {
            HostPermissionsInput::Private => Self::Private,
            HostPermissionsInput::Mirror => Self::Mirror,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Loading and Resolution
//--------------------------------------------------------------------------------------------------

/// Load and merge the root and scoped sparse configuration inputs.
pub fn resolve(sources: &SandboxConfigSources) -> anyhow::Result<ResolvedSandboxConfig> {
    let mut patch = SandboxPatch::default();
    if let Some(path) = sources.conf.as_deref() {
        patch.merge(load_root(path)?);
    }

    if let Some(path) = &sources.net_conf {
        reject_scoped_wrapper(path, "network", "--net-conf")?;
        let network = load_typed::<NetworkPatch>(path, "network config")?;
        patch.merge(SandboxPatch {
            network: Some(NetworkInput::Object(network)),
            ..SandboxPatch::default()
        });
    }
    if let Some(path) = &sources.resource_conf {
        let scoped = load_typed::<ResourcePatch>(path, "resource config")?;
        patch.merge(SandboxPatch {
            cpus: scoped.cpus,
            memory: scoped.memory,
            max_duration: scoped.max_duration,
            idle_timeout: scoped.idle_timeout,
            rlimits: scoped.rlimits,
            ..SandboxPatch::default()
        });
    }
    if let Some(path) = &sources.runtime_conf {
        let scoped = load_typed::<RuntimePatch>(path, "runtime config")?;
        patch.merge(SandboxPatch {
            workdir: scoped.workdir,
            shell: scoped.shell,
            user: scoped.user,
            hostname: scoped.hostname,
            security: scoped.security,
            entrypoint: scoped.entrypoint,
            cmd: scoped.cmd,
            env: scoped.env,
            labels: scoped.labels,
            init: scoped.init,
            ..SandboxPatch::default()
        });
    }
    if let Some(path) = &sources.fs_conf {
        let mut scoped = load_typed::<FilesystemPatch>(path, "filesystem config")?;
        absolutize_filesystem_patch(&mut scoped, config_base(path)?);
        patch.merge(SandboxPatch {
            mounts: scoped.mounts,
            patch_files: scoped.patch_files,
            patches: scoped.patches,
            ..SandboxPatch::default()
        });
    }
    if let Some(path) = &sources.secret_conf {
        reject_scoped_wrapper(path, "secrets", "--secret-conf")?;
        let secrets = load_typed_at::<BTreeMap<String, SecretInput>>(
            path,
            "secret config",
            vec!["secrets".to_string()],
        )?;
        patch.merge(SandboxPatch {
            secrets: Some(secrets),
            ..SandboxPatch::default()
        });
    }
    if let Some(path) = &sources.script_conf {
        reject_scoped_wrapper(path, "scripts", "--script-conf")?;
        let scripts = load_typed::<BTreeMap<String, String>>(path, "script config")?;
        patch.merge(SandboxPatch {
            scripts: Some(scripts),
            ..SandboxPatch::default()
        });
    }

    patch.normalize();
    Ok(ResolvedSandboxConfig {
        patch,
        loaded: sources.any(),
    })
}

fn load_root(path: &Path) -> anyhow::Result<SandboxPatch> {
    let mut value = parse_yaml_value(path, "sandbox configuration")?;
    reject_project_only_fields(&value, path)?;
    interpolate_value(&mut value, &mut Vec::new()).map_err(|err| {
        anyhow::anyhow!("invalid sandbox configuration {}: {err}", path.display())
    })?;
    let mut patch: SandboxPatch = serde_json::from_value(value).map_err(|err| {
        anyhow::anyhow!("invalid sandbox configuration {}: {err}", path.display())
    })?;
    absolutize_patch(&mut patch, config_base(path)?);
    // Top-level `ports` is syntax sugar within this source. Normalize it before higher-precedence
    // scoped sources merge so a later network list can replace the root list as documented.
    patch.normalize();
    Ok(patch)
}

fn load_typed<T: DeserializeOwned>(path: &Path, kind: &str) -> anyhow::Result<T> {
    load_typed_at(path, kind, Vec::new())
}

fn load_typed_at<T: DeserializeOwned>(
    path: &Path,
    kind: &str,
    mut interpolation_path: Vec<String>,
) -> anyhow::Result<T> {
    let mut value = parse_yaml_value(path, kind)?;
    interpolate_value(&mut value, &mut interpolation_path)
        .map_err(|err| anyhow::anyhow!("invalid {kind} {}: {err}", path.display()))?;
    serde_json::from_value(value)
        .map_err(|err| anyhow::anyhow!("invalid {kind} {}: {err}", path.display()))
}

fn parse_yaml_value(path: &Path, kind: &str) -> anyhow::Result<Value> {
    let text = fs::read_to_string(path)
        .map_err(|err| anyhow::anyhow!("failed to read {kind} {}: {err}", path.display()))?;
    if text.len() > MAX_CONFIG_BYTES {
        anyhow::bail!(
            "{kind} {} exceeds the {} MiB input limit",
            path.display(),
            MAX_CONFIG_BYTES / (1024 * 1024)
        );
    }
    reject_yaml_extensions(&text, path)?;

    serde_saphyr::from_str_with_options(&text, yaml_options())
        .map_err(|err| anyhow::anyhow!("invalid {kind} {}: {err}", path.display()))
}

fn yaml_options() -> Options {
    serde_saphyr::options! {
        budget: serde_saphyr::budget! {
            max_reader_input_bytes: Some(MAX_CONFIG_BYTES),
            max_events: 250_000,
            max_aliases: 0,
            max_anchors: 0,
            max_depth: 64,
            max_inclusion_depth: 0,
            max_documents: 1,
            max_nodes: 100_000,
            max_total_scalar_bytes: MAX_CONFIG_BYTES,
            max_total_comment_bytes: MAX_CONFIG_BYTES,
            max_merge_keys: 0,
        },
        duplicate_keys: DuplicateKeyPolicy::Error,
        merge_keys: MergeKeyPolicy::Error,
        strict_booleans: true,
        no_schema: true,
    }
}

fn reject_yaml_extensions(text: &str, path: &Path) -> anyhow::Result<()> {
    let parser = Parser::new_from_str(text).keep_tags(true);
    for result in parser {
        let (event, span) =
            result.map_err(|err| anyhow::anyhow!("invalid YAML in {}: {err}", path.display()))?;
        if matches!(event, Event::Alias(_)) || event.anchor_id().is_some() {
            anyhow::bail!(
                "{}:{}:{}: YAML anchors and aliases are not supported",
                path.display(),
                span.start.line() + 1,
                span.start.col() + 1
            );
        }
        if event.tag().is_some_and(|tag| tag.is_custom()) {
            anyhow::bail!(
                "{}:{}:{}: custom YAML tags are not supported",
                path.display(),
                span.start.line() + 1,
                span.start.col() + 1
            );
        }
    }
    Ok(())
}

fn interpolate_value(value: &mut Value, path: &mut Vec<String>) -> anyhow::Result<()> {
    match value {
        Value::String(text) => {
            if is_secret_value_path(path)
                && let Some(name) = exact_env_reference(text)
            {
                *value = serde_json::json!({ "$msb_env": name });
            } else {
                *text = interpolate_string(text)?;
            }
        }
        Value::Array(values) => {
            for (index, value) in values.iter_mut().enumerate() {
                path.push(index.to_string());
                interpolate_value(value, path)?;
                path.pop();
            }
        }
        Value::Object(map) => {
            for (key, value) in map.iter_mut() {
                path.push(key.clone());
                interpolate_value(value, path)?;
                path.pop();
            }
        }
        Value::Null | Value::Bool(_) | Value::Number(_) => {}
    }
    Ok(())
}

fn is_secret_value_path(path: &[String]) -> bool {
    path.last().is_some_and(|part| part == "value") && path.iter().any(|part| part == "secrets")
}

fn exact_env_reference(value: &str) -> Option<String> {
    let body = value.strip_prefix("${")?.strip_suffix('}')?;
    valid_env_name(body).then(|| body.to_string())
}

fn interpolate_string(input: &str) -> anyhow::Result<String> {
    let mut output = String::with_capacity(input.len());
    let mut remaining = input;
    while let Some(start) = remaining.find("${") {
        output.push_str(&remaining[..start]);
        let after = &remaining[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| anyhow::anyhow!("unclosed environment reference in {input:?}"))?;
        let name = &after[..end];
        if !valid_env_name(name) {
            anyhow::bail!(
                "unsupported environment expression `${{{name}}}`; only `${{NAME}}` is allowed"
            );
        }
        let value = std::env::var(name)
            .map_err(|_| anyhow::anyhow!("environment variable {name:?} is not set"))?;
        output.push_str(&value);
        remaining = &after[end + 1..];
    }
    output.push_str(remaining);
    Ok(output)
}

fn valid_env_name(name: &str) -> bool {
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|ch| ch == '_' || ch.is_ascii_alphabetic())
        && chars.all(|ch| ch == '_' || ch.is_ascii_alphanumeric())
}

fn reject_scoped_wrapper(path: &Path, wrapper: &str, flag: &str) -> anyhow::Result<()> {
    let value = parse_yaml_value(path, "scoped config")?;
    if value
        .as_object()
        .is_some_and(|map| map.contains_key(wrapper))
    {
        anyhow::bail!(
            "{}: {flag} expects the contents without a `{wrapper}:` wrapper; use --conf for a root-shaped file",
            path.display()
        );
    }
    Ok(())
}

fn reject_project_only_fields(value: &Value, path: &Path) -> anyhow::Result<()> {
    let Some(map) = value.as_object() else {
        return Ok(());
    };
    let project_only = [
        "sandboxes",
        "layers",
        "volumes",
        "depends_on",
        "name",
        "description",
    ];
    let Some(field) = project_only
        .into_iter()
        .find(|field| map.contains_key(*field))
    else {
        return Ok(());
    };

    anyhow::bail!(
        "{}: `{field}` is project-only and is not valid in sandbox configuration; use `msb compose --conf {}` for a Composefile",
        path.display(),
        path.display()
    )
}

fn config_base(path: &Path) -> anyhow::Result<PathBuf> {
    let absolute = fs::canonicalize(path).map_err(|err| {
        anyhow::anyhow!("failed to resolve config path {}: {err}", path.display())
    })?;
    Ok(absolute
        .parent()
        .expect("a canonical file path has a parent")
        .to_path_buf())
}

fn replace<T>(base: &mut Option<T>, higher: Option<T>) {
    if higher.is_some() {
        *base = higher;
    }
}

fn merge_map<K: Ord, V>(base: &mut Option<BTreeMap<K, V>>, higher: Option<BTreeMap<K, V>>) {
    let Some(higher) = higher else {
        return;
    };
    base.get_or_insert_with(BTreeMap::new).extend(higher);
}

fn merge_init(base: &mut Option<InitInput>, higher: Option<InitInput>) {
    let Some(higher) = higher else {
        return;
    };
    let base = base.get_or_insert_with(InitInput::default);
    replace(&mut base.cmd, higher.cmd);
    replace(&mut base.args, higher.args);
    merge_map(&mut base.env, higher.env);
}

fn merge_secrets(
    base: &mut Option<BTreeMap<String, SecretInput>>,
    higher: Option<BTreeMap<String, SecretInput>>,
) {
    let Some(higher) = higher else {
        return;
    };
    let base = base.get_or_insert_with(BTreeMap::new);
    for (name, higher) in higher {
        match base.get_mut(&name) {
            Some(current) => {
                replace(&mut current.value, higher.value);
                replace(&mut current.allow, higher.allow);
                replace(&mut current.inject, higher.inject);
                replace(
                    &mut current.require_tls_identity,
                    higher.require_tls_identity,
                );
            }
            None => {
                base.insert(name, higher);
            }
        }
    }
}

fn merge_network(base: &mut Option<NetworkInput>, higher: Option<NetworkInput>) {
    let Some(higher) = higher else {
        return;
    };
    let higher = higher.into_object();
    let base = base
        .get_or_insert_with(|| NetworkInput::Object(NetworkPatch::default()))
        .object_mut();
    replace(&mut base.policy, higher.policy);
    replace(&mut base.allow, higher.allow);
    replace(&mut base.deny, higher.deny);
    replace(&mut base.ports, higher.ports);
    merge_dns(&mut base.dns, higher.dns);
    merge_tls(&mut base.tls, higher.tls);
    replace(&mut base.trust_host_cas, higher.trust_host_cas);
    replace(&mut base.max_connections, higher.max_connections);
}

fn merge_dns(base: &mut Option<DnsInput>, higher: Option<DnsInput>) {
    let Some(higher) = higher else {
        return;
    };
    let base = base.get_or_insert_with(DnsInput::default);
    replace(&mut base.rebind_protection, higher.rebind_protection);
    replace(&mut base.nameservers, higher.nameservers);
    replace(&mut base.query_timeout, higher.query_timeout);
}

fn merge_tls(base: &mut Option<TlsInput>, higher: Option<TlsInput>) {
    let Some(higher) = higher else {
        return;
    };
    let base = base.get_or_insert_with(TlsInput::default);
    replace(&mut base.enabled, higher.enabled);
    replace(&mut base.bypass, higher.bypass);
    replace(&mut base.verify_upstream, higher.verify_upstream);
    replace(&mut base.block_quic, higher.block_quic);
}

//--------------------------------------------------------------------------------------------------
// Functions: Path Resolution
//--------------------------------------------------------------------------------------------------

fn absolutize_patch(patch: &mut SandboxPatch, base: PathBuf) {
    if let Some(image) = &mut patch.image {
        absolutize_image(image, &base);
    }
    if let Some(mounts) = &mut patch.mounts {
        absolutize_mounts(mounts, &base);
    }
    if let Some(paths) = &mut patch.patch_files {
        for path in paths {
            absolutize(path, &base);
        }
    }
    if let Some(patches) = &mut patch.patches {
        absolutize_patch_inputs(patches, &base);
    }
}

fn absolutize_filesystem_patch(patch: &mut FilesystemPatch, base: PathBuf) {
    if let Some(mounts) = &mut patch.mounts {
        absolutize_mounts(mounts, &base);
    }
    if let Some(paths) = &mut patch.patch_files {
        for path in paths {
            absolutize(path, &base);
        }
    }
    if let Some(patches) = &mut patch.patches {
        absolutize_patch_inputs(patches, &base);
    }
}

fn absolutize_image(image: &mut ImageInput, base: &Path) {
    match image {
        ImageInput::String(value) if looks_like_local_path(value) => {
            *value = absolute_path(Path::new(value), base)
                .to_string_lossy()
                .into_owned();
        }
        ImageInput::Object(object) => {
            if let Some(path) = &mut object.disk {
                absolutize(path, base);
            }
            if let Some(path) = &mut object.bind {
                absolutize(path, base);
            }
            if let Some(snapshot) = &mut object.snapshot
                && looks_like_local_path(snapshot)
            {
                *snapshot = absolute_path(Path::new(snapshot), base)
                    .to_string_lossy()
                    .into_owned();
            }
        }
        ImageInput::String(_) => {}
    }
}

fn absolutize_mounts(mounts: &mut [MountInput], base: &Path) {
    for mount in mounts {
        match mount {
            MountInput::String(spec) => {
                if let Some(index) = bind_mount_separator(spec) {
                    let source = absolute_path(Path::new(&spec[..index]), base);
                    *spec = format!("{}{}", source.display(), &spec[index..]);
                }
            }
            MountInput::Object(object) => {
                if let Some(path) = &mut object.bind {
                    absolutize(path, base);
                }
                if let Some(path) = &mut object.disk {
                    absolutize(path, base);
                }
            }
        }
    }
}

fn absolutize_patch_inputs(patches: &mut [PatchInput], base: &Path) {
    for patch in patches {
        match patch {
            PatchInput::CopyFile(input) => absolutize(&mut input.src, base),
            PatchInput::CopyDir(input) => absolutize(&mut input.src, base),
            PatchInput::Text(_)
            | PatchInput::File(_)
            | PatchInput::Symlink(_)
            | PatchInput::Mkdir(_)
            | PatchInput::Remove(_)
            | PatchInput::Append(_) => {}
        }
    }
}

fn absolutize(path: &mut PathBuf, base: &Path) {
    if path.is_relative() {
        *path = base.join(&*path);
    }
}

fn absolute_path(path: &Path, base: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

fn looks_like_local_path(value: &str) -> bool {
    value == "."
        || value == ".."
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with('/')
        || cfg!(windows) && value.as_bytes().get(1) == Some(&b':')
}

fn bind_mount_separator(spec: &str) -> Option<usize> {
    spec.char_indices().find_map(|(index, ch)| {
        (ch == ':' && !(cfg!(windows) && index == 1 && spec.as_bytes()[0].is_ascii_alphabetic()))
            .then_some(index)
    })
}

//--------------------------------------------------------------------------------------------------
// Functions: Image and Runtime
//--------------------------------------------------------------------------------------------------

fn resolve_image_input(input: &ImageInput) -> anyhow::Result<ResolvedImage> {
    match input {
        ImageInput::String(value) => Ok(ResolvedImage::Image(value.clone())),
        ImageInput::Object(object) => {
            let count = usize::from(object.oci.is_some())
                + usize::from(object.snapshot.is_some())
                + usize::from(object.disk.is_some())
                + usize::from(object.bind.is_some())
                + usize::from(object.layer.is_some());
            if count != 1 {
                anyhow::bail!(
                    "image object must contain exactly one of `oci`, `snapshot`, `disk`, or `bind`"
                );
            }
            if object.layer.is_some() {
                anyhow::bail!(
                    "`image.layer` is project-only and cannot be used in sandbox configuration; use a published OCI reference"
                );
            }
            if let Some(reference) = &object.oci {
                if object.fstype.is_some() {
                    anyhow::bail!("image.fstype is only valid with image.disk");
                }
                if let Some(size) = &object.upper_size {
                    parse_size("image.upper_size", size)?;
                }
                return Ok(ResolvedImage::Oci {
                    reference: reference.clone(),
                    upper_size: object.upper_size.clone(),
                });
            }
            if object.upper_size.is_some() {
                anyhow::bail!("image.upper_size is only valid with image.oci");
            }
            if let Some(snapshot) = &object.snapshot {
                if object.fstype.is_some() {
                    anyhow::bail!("image.fstype is only valid with image.disk");
                }
                return Ok(ResolvedImage::Snapshot(snapshot.clone()));
            }
            if let Some(path) = &object.disk {
                return Ok(ResolvedImage::Disk {
                    path: path.clone(),
                    fstype: object.fstype.clone(),
                });
            }
            if object.fstype.is_some() {
                anyhow::bail!("image.fstype is only valid with image.disk");
            }
            Ok(ResolvedImage::Bind(
                object
                    .bind
                    .clone()
                    .expect("exactly one image source was checked"),
            ))
        }
    }
}

fn parse_size(field: &str, value: &str) -> anyhow::Result<u32> {
    ui::parse_size_mib(value).map_err(|err| anyhow::anyhow!("{field}: {err}"))
}

fn apply_init(mut builder: SandboxBuilder, init: &InitInput) -> anyhow::Result<SandboxBuilder> {
    let cmd = init
        .cmd
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("init.cmd is required when `init` is present"))?;
    if cmd != microsandbox_protocol::HANDOFF_INIT_AUTO && !cmd.starts_with('/') {
        anyhow::bail!("init.cmd must be an absolute guest path or `auto`, got {cmd:?}");
    }
    let args = init.args.clone().unwrap_or_default();
    let env = init.env.clone().unwrap_or_default();
    if args.is_empty() && env.is_empty() {
        builder = builder.init(cmd);
    } else {
        builder = builder.init_with(cmd, |value| value.args(args).envs(env));
    }
    Ok(builder)
}

fn apply_registry(
    builder: SandboxBuilder,
    registry: &RegistryInput,
) -> anyhow::Result<SandboxBuilder> {
    let Some(auth) = resolve_registry_auth(registry)? else {
        return Ok(builder);
    };
    Ok(builder.registry(|value| value.auth(auth)))
}

fn resolve_registry_auth(registry: &RegistryInput) -> anyhow::Result<Option<RegistryAuth>> {
    match (&registry.username, &registry.password_env) {
        (None, None) => Ok(None),
        (Some(username), Some(password_env)) => {
            let password = std::env::var(password_env).map_err(|_| {
                anyhow::anyhow!(
                    "registry password environment variable {password_env:?} is not set"
                )
            })?;
            Ok(Some(RegistryAuth::Basic {
                username: username.clone(),
                password,
            }))
        }
        _ => {
            anyhow::bail!("registry.username and registry.password_env must be specified together")
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Mounts and Patches
//--------------------------------------------------------------------------------------------------

fn apply_mount(builder: SandboxBuilder, input: &MountInput) -> anyhow::Result<SandboxBuilder> {
    match input {
        MountInput::String(spec) => apply_bind_mount_string(builder, spec),
        MountInput::Object(object) => apply_mount_object(builder, object),
    }
}

fn apply_bind_mount_string(builder: SandboxBuilder, spec: &str) -> anyhow::Result<SandboxBuilder> {
    let index = bind_mount_separator(spec)
        .ok_or_else(|| anyhow::anyhow!("bind mount {spec:?} must use SOURCE:TARGET[:ro]"))?;
    let source = &spec[..index];
    let rest = &spec[index + 1..];
    if !source.starts_with('.') && !source.starts_with('/') && !Path::new(source).is_absolute() {
        anyhow::bail!("bind mount source must start with `.` or `/`, got {source:?}");
    }
    let (target, readonly) = match rest.strip_suffix(":ro") {
        Some(target) => (target, true),
        None => (rest, false),
    };
    if target.is_empty() || !target.starts_with('/') {
        anyhow::bail!("bind mount target must be an absolute guest path, got {target:?}");
    }
    let source = PathBuf::from(source);
    Ok(builder.volume(target, move |mut mount| {
        mount = mount.bind(source);
        if readonly {
            mount = mount.readonly();
        }
        mount
    }))
}

fn apply_mount_object(
    builder: SandboxBuilder,
    object: &MountObject,
) -> anyhow::Result<SandboxBuilder> {
    let source_count = usize::from(object.bind.is_some())
        + usize::from(object.named.is_some())
        + usize::from(object.tmpfs.is_some())
        + usize::from(object.disk.is_some());
    if source_count != 1 {
        anyhow::bail!(
            "mount object must contain exactly one of `bind`, `named`, `tmpfs`, or `disk`"
        );
    }
    let target = object
        .target
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("mount.target is required"))?;
    if !target.starts_with('/') {
        anyhow::bail!("mount.target must be an absolute guest path, got {target:?}");
    }
    if object.create.is_some() && object.named.is_none() {
        anyhow::bail!("mount.create is only valid for a named mount");
    }
    if (object.format.is_some() || object.fstype.is_some()) && object.disk.is_none() {
        anyhow::bail!("mount.format and mount.fstype are only valid for a disk mount");
    }
    if (object.stat_virtualization.is_some() || object.host_permissions.is_some())
        && object.bind.is_none()
        && object.named.is_none()
    {
        anyhow::bail!(
            "mount.stat_virtualization and mount.host_permissions are only valid for bind or named mounts"
        );
    }

    let tmpfs_size = object
        .tmpfs
        .as_ref()
        .and_then(|tmpfs| tmpfs.size.as_deref())
        .map(|size| parse_size("mount.tmpfs.size", size))
        .transpose()?;
    let object = object.clone();
    Ok(builder.volume(target, move |mut mount| {
        if let Some(path) = object.bind {
            mount = mount.bind(path);
        } else if let Some(name) = object.named {
            mount = match object.create.unwrap_or(NamedCreateInput::Existing) {
                NamedCreateInput::Existing => mount.named(name),
                NamedCreateInput::Create => mount.named_with(name, |value| value.create()),
                NamedCreateInput::EnsureExists => {
                    mount.named_with(name, |value| value.ensure_exists())
                }
            };
        } else if object.tmpfs.is_some() {
            mount = mount.tmpfs();
            if let Some(size) = tmpfs_size {
                mount = mount.size(size);
            }
        } else if let Some(path) = object.disk {
            mount = mount.disk(path);
            if let Some(format) = object.format {
                mount = mount.format(format.into());
            }
            if let Some(fstype) = object.fstype {
                mount = mount.fstype(fstype);
            }
        }

        if object.readonly.unwrap_or(false) {
            mount = mount.readonly();
        }
        if object.noexec.unwrap_or(false) {
            mount = mount.noexec();
        }
        if object.nosuid.unwrap_or(false) {
            mount = mount.nosuid();
        }
        if object.nodev.unwrap_or(false) {
            mount = mount.nodev();
        }
        if let Some(policy) = object.stat_virtualization {
            mount = mount.stat_virtualization(policy.into());
        }
        if let Some(policy) = object.host_permissions {
            mount = mount.host_permissions(policy.into());
        }
        mount
    }))
}

fn apply_patch_files(
    mut builder: SandboxBuilder,
    paths: Option<&[PathBuf]>,
) -> anyhow::Result<SandboxBuilder> {
    for path in paths.unwrap_or_default() {
        let mut patch_file = load_typed::<PatchFileInput>(path, "rootfs patch file")?;
        let base = config_base(path)?;
        absolutize_patch_inputs(&mut patch_file.patches, &base);
        for input in &patch_file.patches {
            builder = builder.add_patch(materialize_patch(input)?);
        }
    }
    Ok(builder)
}

fn materialize_patch(input: &PatchInput) -> anyhow::Result<Patch> {
    match input {
        PatchInput::Text(input) => Ok(Patch::Text {
            path: validate_guest_path("patch.text.path", &input.path)?,
            content: input.content.clone(),
            mode: parse_mode(input.mode.as_deref())?,
            replace: input.replace,
        }),
        PatchInput::File(input) => Ok(Patch::File {
            path: validate_guest_path("patch.file.path", &input.path)?,
            content: base64::engine::general_purpose::STANDARD
                .decode(&input.content_base64)
                .map_err(|err| anyhow::anyhow!("patch.file.content_base64: {err}"))?,
            mode: parse_mode(input.mode.as_deref())?,
            replace: input.replace,
        }),
        PatchInput::CopyFile(input) => {
            validate_host_patch_source("patch.copy_file.src", &input.src, false)?;
            Ok(Patch::CopyFile {
                src: input.src.clone(),
                dst: validate_guest_path("patch.copy_file.dst", &input.dst)?,
                mode: parse_mode(input.mode.as_deref())?,
                replace: input.replace,
            })
        }
        PatchInput::CopyDir(input) => {
            validate_host_patch_source("patch.copy_dir.src", &input.src, true)?;
            Ok(Patch::CopyDir {
                src: input.src.clone(),
                dst: validate_guest_path("patch.copy_dir.dst", &input.dst)?,
                replace: input.replace,
            })
        }
        PatchInput::Symlink(input) => Ok(Patch::Symlink {
            target: input.target.clone(),
            link: validate_guest_path("patch.symlink.link", &input.link)?,
            replace: input.replace,
        }),
        PatchInput::Mkdir(input) => Ok(Patch::Mkdir {
            path: validate_guest_path("patch.mkdir.path", &input.path)?,
            mode: parse_mode(input.mode.as_deref())?,
        }),
        PatchInput::Remove(input) => Ok(Patch::Remove {
            path: validate_guest_path("patch.remove.path", &input.path)?,
        }),
        PatchInput::Append(input) => Ok(Patch::Append {
            path: validate_guest_path("patch.append.path", &input.path)?,
            content: input.content.clone(),
        }),
    }
}

fn parse_mode(value: Option<&str>) -> anyhow::Result<Option<u32>> {
    value
        .map(|value| {
            if value.len() != 4 || !value.bytes().all(|byte| matches!(byte, b'0'..=b'7')) {
                anyhow::bail!("mode must be a quoted four-digit octal string such as \"0644\"");
            }
            let mode = u32::from_str_radix(value, 8)
                .map_err(|_| anyhow::anyhow!("invalid octal mode {value:?}"))?;
            if mode > 0o7777 {
                anyhow::bail!("mode is outside the supported 0000..7777 range");
            }
            Ok(mode)
        })
        .transpose()
}

fn validate_guest_path(field: &str, value: &str) -> anyhow::Result<String> {
    if value.is_empty() || !value.starts_with('/') {
        anyhow::bail!("{field} must be an absolute guest path, got {value:?}");
    }
    if value.as_bytes().contains(&0) {
        anyhow::bail!("{field} must not contain a NUL byte");
    }
    Ok(value.to_string())
}

fn validate_host_patch_source(field: &str, path: &Path, directory: bool) -> anyhow::Result<()> {
    let metadata = fs::metadata(path)
        .map_err(|err| anyhow::anyhow!("{field}: failed to inspect {}: {err}", path.display()))?;
    if directory && !metadata.is_dir() {
        anyhow::bail!("{field}: {} is not a directory", path.display());
    }
    if !directory && !metadata.is_file() {
        anyhow::bail!("{field}: {} is not a regular file", path.display());
    }
    Ok(())
}

fn validate_script_name(name: &str) -> anyhow::Result<()> {
    let path = Path::new(name);
    if name.is_empty()
        || name == "."
        || name == ".."
        || name.as_bytes().contains(&0)
        || name.contains(['/', '\\'])
        || path.file_name().and_then(|part| part.to_str()) != Some(name)
    {
        anyhow::bail!("script name {name:?} must be a single non-empty filename");
    }
    Ok(())
}

//--------------------------------------------------------------------------------------------------
// Functions: Network
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "net")]
fn apply_network(
    mut builder: SandboxBuilder,
    network: Option<&NetworkInput>,
    file_secrets: Option<&BTreeMap<String, SecretInput>>,
    opts: &SandboxOpts,
) -> anyhow::Result<SandboxBuilder> {
    use microsandbox::sandbox::SecretSource;
    use microsandbox_network::builder::ViolationActionBuilder;
    use microsandbox_network::dns::Nameserver;
    use microsandbox_network::policy::{Action, NetworkPolicy, NetworkProfile};

    use crate::commands::common::{
        build_network_policy, parse_port_mapping, parse_scoped_upstream_ca_cert, parse_secret,
        parse_violation_action,
    };
    use crate::net_rule::{parse_rule_list, parse_rule_token};

    let has_cli_network = opts.no_dns_rebind_protection
        || !opts.dns_nameserver.is_empty()
        || opts.dns_query_timeout_ms.is_some()
        || !opts.net_rule.is_empty()
        || !opts.net.is_empty()
        || opts.no_net
        || opts.net_default.is_some()
        || opts.net_default_egress.is_some()
        || opts.net_default_ingress.is_some()
        || opts.net_ipv4_pool.is_some()
        || opts.net_ipv6_pool.is_some()
        || opts.max_connections.is_some()
        || opts.trust_host_cas
        || opts.tls_intercept
        || !opts.tls_intercept_port.is_empty()
        || !opts.tls_bypass.is_empty()
        || opts.no_block_quic
        || opts.tls_intercept_ca_cert.is_some()
        || opts.tls_intercept_ca_key.is_some()
        || !opts.tls_upstream_ca_cert.is_empty()
        || !opts.tls_upstream_ca_cert_for.is_empty()
        || !opts.tls_no_verify_upstream_for.is_empty()
        || !opts.secret.is_empty()
        || opts.on_secret_violation.is_some();
    if network.is_none() && file_secrets.is_none() && !has_cli_network {
        return Ok(builder);
    }

    let network = network
        .cloned()
        .map(NetworkInput::into_object)
        .unwrap_or_default();
    let base_policy = match network.policy.unwrap_or(NetworkPreset::Public) {
        NetworkPreset::None => NetworkPolicy::none(),
        NetworkPreset::Public => NetworkPolicy::from_profiles([NetworkProfile::Public]),
        NetworkPreset::Open => NetworkPolicy::allow_all(),
    };
    let mut file_rules = Vec::new();
    for destination in network.deny.as_deref().unwrap_or_default() {
        file_rules
            .push(parse_rule_token(&format!("deny@{destination}")).map_err(anyhow::Error::from)?);
    }
    for destination in network.allow.as_deref().unwrap_or_default() {
        file_rules
            .push(parse_rule_token(&format!("allow@{destination}")).map_err(anyhow::Error::from)?);
    }

    let allowlist = network
        .allow
        .as_ref()
        .is_some_and(|rules| !rules.is_empty());
    let mut policy = NetworkPolicy {
        default_egress: if allowlist {
            Action::Deny
        } else {
            base_policy.default_egress
        },
        default_ingress: base_policy.default_ingress,
        rules: file_rules,
    };
    let cli_replaces_preset = !opts.net.is_empty()
        || opts.no_net
        || opts.net_default.is_some()
        || opts.net_default_egress.is_some()
        || opts.net_default_ingress.is_some();
    if !allowlist && !cli_replaces_preset {
        policy.rules.extend(base_policy.rules);
    }

    if opts.net.is_empty() {
        let mut cli_rules = Vec::new();
        for value in &opts.net_rule {
            cli_rules.extend(parse_rule_list(value).map_err(anyhow::Error::from)?);
        }
        cli_rules.append(&mut policy.rules);
        policy.rules = cli_rules;
    } else {
        // High-level CLI profiles replace the file's preset while retaining lower-precedence
        // file rules after the profile and explicit CLI rules.
        let mut cli_policy = build_network_policy(
            &opts.net,
            &opts.net_rule,
            opts.no_net,
            opts.net_default.as_deref(),
            opts.net_default_egress.as_deref(),
            opts.net_default_ingress.as_deref(),
        )?
        .expect("non-empty --net values must produce a network policy");
        cli_policy.rules.append(&mut policy.rules);
        policy = cli_policy;
    }

    let parse_action = |flag: &str, raw: &str| -> anyhow::Result<Action> {
        match raw {
            "allow" => Ok(Action::Allow),
            "deny" => Ok(Action::Deny),
            other => anyhow::bail!("{flag}: expected `allow` or `deny`, got {other:?}"),
        }
    };
    if opts.no_net {
        policy.default_egress = Action::Deny;
        policy.default_ingress = Action::Deny;
    } else if let Some(raw) = &opts.net_default {
        let action = parse_action("--net-default", raw)?;
        policy.default_egress = action;
        policy.default_ingress = action;
    }
    if let Some(raw) = &opts.net_default_egress {
        policy.default_egress = parse_action("--net-default-egress", raw)?;
    }
    if let Some(raw) = &opts.net_default_ingress {
        policy.default_ingress = parse_action("--net-default-ingress", raw)?;
    }

    for port in network.ports.as_deref().unwrap_or_default() {
        let (bind, host, guest, udp) = parse_port_mapping(port)?;
        builder = if udp {
            builder.port_udp_bind(bind, host, guest)
        } else {
            builder.port_bind(bind, host, guest)
        };
    }

    let mut secrets = file_secrets.cloned().unwrap_or_default();
    for spec in &opts.secret {
        let (name, hosts) = parse_secret(spec, "run")?;
        let env = name.clone();
        secrets.insert(
            name,
            SecretInput {
                value: Some(SecretValueInput::Environment { env }),
                allow: Some(hosts),
                inject: None,
                require_tls_identity: None,
            },
        );
    }
    validate_secrets(&secrets)?;

    let mut rebind_protection = network
        .dns
        .as_ref()
        .and_then(|dns| dns.rebind_protection)
        .unwrap_or(true);
    if !secrets.is_empty() {
        rebind_protection = true;
    }
    if opts.no_dns_rebind_protection {
        rebind_protection = false;
    }
    let nameserver_values = if opts.dns_nameserver.is_empty() {
        network
            .dns
            .as_ref()
            .and_then(|dns| dns.nameservers.clone())
            .unwrap_or_default()
    } else {
        opts.dns_nameserver.clone()
    };
    let nameservers = nameserver_values
        .iter()
        .map(|value| value.parse::<Nameserver>().map_err(anyhow::Error::from))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let query_timeout_ms = match opts.dns_query_timeout_ms {
        Some(value) => value,
        None => network
            .dns
            .as_ref()
            .and_then(|dns| dns.query_timeout.as_deref())
            .map(parse_duration_millis)
            .transpose()?
            .unwrap_or(5_000),
    };

    let tls = network.tls.unwrap_or_default();
    let tls_enabled = !secrets.is_empty() || opts.tls_intercept || tls.enabled.unwrap_or(false);
    let mut tls_bypass = tls.bypass.unwrap_or_default();
    tls_bypass.extend(opts.tls_bypass.clone());
    let verify_upstream = tls.verify_upstream.unwrap_or(true);
    let block_quic = if opts.no_block_quic {
        false
    } else {
        tls.block_quic.unwrap_or(true)
    };
    let tls_ports = if opts.tls_intercept_port.is_empty() {
        vec![443]
    } else {
        opts.tls_intercept_port.clone()
    };
    let scoped_upstream_ca_cert = opts
        .tls_upstream_ca_cert_for
        .iter()
        .map(|spec| parse_scoped_upstream_ca_cert(spec))
        .collect::<anyhow::Result<Vec<_>>>()?;
    let violation_action = parse_violation_action(&opts.on_secret_violation)?;
    let max_connections = opts.max_connections.or(network.max_connections);
    let trust_host_cas = opts.trust_host_cas || network.trust_host_cas.unwrap_or(false);
    let ipv4_pool = opts
        .net_ipv4_pool
        .as_deref()
        .map(str::parse::<ipnetwork::Ipv4Network>)
        .transpose()?;
    let ipv6_pool = opts
        .net_ipv6_pool
        .as_deref()
        .map(str::parse::<ipnetwork::Ipv6Network>)
        .transpose()?;

    builder = builder.network(move |mut value| {
        value = value.policy(policy).dns(move |dns| {
            let mut dns = dns
                .rebind_protection(rebind_protection)
                .query_timeout_ms(query_timeout_ms);
            if !nameservers.is_empty() {
                dns = dns.nameservers(nameservers);
            }
            dns
        });
        if let Some(max) = max_connections {
            value = value.max_connections(max);
        }
        if let Some(pool) = ipv4_pool {
            value = value.ipv4_pool(pool);
        }
        if let Some(pool) = ipv6_pool {
            value = value.ipv6_pool(pool);
        }
        value = value.trust_host_cas(trust_host_cas);
        if let Some(action) = violation_action {
            value = value.on_secret_violation(|_| ViolationActionBuilder::from_action(action));
        }

        if tls_enabled {
            value = value.tls(move |mut tls| {
                tls = tls
                    .intercepted_ports(tls_ports)
                    .verify_upstream(verify_upstream)
                    .block_quic(block_quic);
                for bypass in tls_bypass {
                    tls = tls.bypass(bypass);
                }
                if let Some(cert) = opts.tls_intercept_ca_cert.clone() {
                    tls = tls.intercept_ca_cert(cert);
                }
                if let Some(key) = opts.tls_intercept_ca_key.clone() {
                    tls = tls.intercept_ca_key(key);
                }
                for cert in opts.tls_upstream_ca_cert.clone() {
                    tls = tls.upstream_ca_cert(cert);
                }
                for (pattern, cert) in scoped_upstream_ca_cert {
                    tls = tls.upstream_ca_cert_for(pattern, cert);
                }
                for pattern in opts.tls_no_verify_upstream_for.clone() {
                    tls = tls.verify_upstream_for(pattern, false);
                }
                tls
            });
        }

        for (name, secret) in secrets {
            value = value.secret(move |mut entry| {
                entry = entry.env(&name);
                entry = match secret.value {
                    None => entry.source(SecretSource::Env { var: name.clone() }),
                    Some(SecretValueInput::Environment { env }) => {
                        entry.source(SecretSource::Env { var: env })
                    }
                    Some(SecretValueInput::Literal(literal)) => entry.value(literal),
                };
                for host in secret.allow.unwrap_or_default() {
                    entry = if host.starts_with("*.") {
                        entry.allow_host_pattern(host)
                    } else {
                        entry.allow_host(host)
                    };
                }
                let injection = secret
                    .inject
                    .unwrap_or_else(|| vec![SecretInjectionInput::Headers]);
                entry
                    .inject_headers(injection.contains(&SecretInjectionInput::Headers))
                    .inject_basic_auth(injection.contains(&SecretInjectionInput::BasicAuth))
                    .inject_query(injection.contains(&SecretInjectionInput::QueryParams))
                    .require_tls_identity(secret.require_tls_identity.unwrap_or(true))
            });
        }
        value
    });

    Ok(builder)
}

#[cfg(not(feature = "net"))]
fn apply_network(
    builder: SandboxBuilder,
    network: Option<&NetworkInput>,
    secrets: Option<&BTreeMap<String, SecretInput>>,
    _opts: &SandboxOpts,
) -> anyhow::Result<SandboxBuilder> {
    if network.is_some() || secrets.is_some() {
        anyhow::bail!("network and secret config require an msb build with networking enabled");
    }
    Ok(builder)
}

#[cfg(feature = "net")]
fn validate_secrets(secrets: &BTreeMap<String, SecretInput>) -> anyhow::Result<()> {
    for (name, secret) in secrets {
        if name.is_empty() {
            anyhow::bail!("secret names must not be empty");
        }
        if secret.allow.as_ref().is_none_or(Vec::is_empty) {
            anyhow::bail!("secret {name:?} must declare a non-empty `allow` list");
        }
        if secret
            .inject
            .as_ref()
            .is_some_and(|injection| injection.is_empty())
        {
            anyhow::bail!("secret {name:?} must enable at least one injection location");
        }
    }
    Ok(())
}

#[cfg(feature = "net")]
fn parse_duration_millis(value: &str) -> anyhow::Result<u64> {
    let duration = crate::commands::common::parse_duration(value)?;
    u64::try_from(duration.as_millis())
        .map_err(|_| anyhow::anyhow!("duration {value:?} is too large"))
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn write_config(dir: &Path, name: &str, contents: &str) -> PathBuf {
        let path = dir.join(name);
        fs::write(&path, contents).unwrap();
        path
    }

    #[test]
    fn scoped_files_merge_maps_and_replace_lists() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_config(
            dir.path(),
            "base.yaml",
            r#"
image: "python:3.12"
memory: "1G"
env:
  KEEP: "root"
  CHANGE: "root"
network:
  allow: ["root.example.com"]
  deny: ["192.0.2.1"]
"#,
        );
        let runtime = write_config(
            dir.path(),
            "runtime.yaml",
            r#"
env:
  CHANGE: "scoped"
  ADD: "scoped"
"#,
        );
        let network = write_config(
            dir.path(),
            "network.yaml",
            r#"
allow: ["scoped.example.com"]
"#,
        );
        let sources = SandboxConfigSources {
            conf: Some(root),
            runtime_conf: Some(runtime),
            net_conf: Some(network),
            ..SandboxConfigSources::default()
        };

        let resolved = resolve(&sources).unwrap();
        let env = resolved.patch.env.unwrap();
        assert_eq!(env.get("KEEP").map(String::as_str), Some("root"));
        assert_eq!(env.get("CHANGE").map(String::as_str), Some("scoped"));
        assert_eq!(env.get("ADD").map(String::as_str), Some("scoped"));

        let network = resolved.patch.network.unwrap().into_object();
        assert_eq!(
            network.allow.as_deref(),
            Some(["scoped.example.com".to_string()].as_slice())
        );
        assert_eq!(
            network.deny.as_deref(),
            Some(["192.0.2.1".to_string()].as_slice())
        );
    }

    #[test]
    fn paths_are_relative_to_the_contributing_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        fs::create_dir(&config_dir).unwrap();
        let root = write_config(
            &config_dir,
            "agent.yaml",
            r#"
image: { bind: "./rootfs" }
mounts:
  - "./src:/app"
patch_files: ["./patch.yaml"]
patches:
  - copy_file: { src: "./app.toml", dst: "/etc/app.toml" }
"#,
        );
        let config_base = config_base(&root).unwrap();
        let sources = SandboxConfigSources {
            conf: Some(root),
            ..SandboxConfigSources::default()
        };

        let resolved = resolve(&sources).unwrap();
        let ImageInput::Object(image) = resolved.patch.image.unwrap() else {
            panic!("expected object image")
        };
        assert_eq!(image.bind.unwrap(), config_base.join("./rootfs"));
        assert_eq!(
            resolved.patch.patch_files.unwrap(),
            vec![config_base.join("./patch.yaml")]
        );
        let MountInput::String(mount) = &resolved.patch.mounts.unwrap()[0] else {
            panic!("expected string mount")
        };
        assert_eq!(
            mount,
            &format!("{}:/app", config_base.join("./src").display())
        );
        let PatchInput::CopyFile(copy) = &resolved.patch.patches.unwrap()[0] else {
            panic!("expected copy-file patch")
        };
        assert_eq!(copy.src, config_base.join("./app.toml"));
    }

    #[test]
    fn strict_yaml_rejects_unsafe_extensions_and_ambiguous_scalars() {
        let dir = tempfile::tempdir().unwrap();
        let cases = [
            (
                "anchor.yaml",
                "image: &base alpine\nother: *base\n",
                "anchors and aliases",
            ),
            ("tag.yaml", "image: !custom alpine\n", "custom YAML tags"),
            (
                "duplicate.yaml",
                "image: alpine\nimage: python\n",
                "duplicate",
            ),
            (
                "documents.yaml",
                "image: alpine\n---\nimage: python\n",
                "document",
            ),
            (
                "boolean.yaml",
                "image: alpine\nnetwork:\n  trust_host_cas: yes\n",
                "boolean",
            ),
            (
                "mode.yaml",
                "image: alpine\npatches:\n  - mkdir: { path: /x, mode: 0755 }\n",
                "string",
            ),
        ];

        for (name, text, expected) in cases {
            let path = write_config(dir.path(), name, text);
            let error = load_root(&path).unwrap_err().to_string();
            assert!(
                error.to_lowercase().contains(&expected.to_lowercase()),
                "{name}: expected {expected:?} in {error:?}"
            );
        }
    }

    #[test]
    fn interpolation_supports_only_braced_environment_names() {
        assert_eq!(interpolate_string("plain").unwrap(), "plain");
        assert_eq!(interpolate_string("$PATH").unwrap(), "$PATH");
        assert!(interpolate_string("${PATH:-fallback}").is_err());
        assert!(interpolate_string("${NOT_CLOSED").is_err());
        assert_eq!(exact_env_reference("${PATH}"), Some("PATH".to_string()));
    }

    #[test]
    fn missing_image_is_reported_after_sparse_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_config(dir.path(), "policy.yaml", "memory: \"1G\"\n");
        let sources = SandboxConfigSources {
            conf: Some(root),
            ..SandboxConfigSources::default()
        };
        let resolved = resolve(&sources).unwrap();

        let error = resolved.image(None, None).unwrap_err().to_string();
        assert!(error.contains("missing required sandbox field `image`"));
        assert!(matches!(
            resolved.image(Some("python"), None).unwrap(),
            ResolvedImage::Image(ref value) if value == "python"
        ));
    }

    #[test]
    fn configuration_requires_an_explicit_source() {
        let resolved = resolve(&SandboxConfigSources::default()).unwrap();

        assert!(!resolved.loaded());
        assert!(
            resolved
                .image(None, None)
                .unwrap_err()
                .to_string()
                .contains("missing required sandbox field `image`")
        );
    }

    #[tokio::test]
    async fn complete_config_lowers_into_a_valid_sandbox_spec() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_config(
            dir.path(),
            "agent.yaml",
            r#"
image: "python:3.12"
cpus: 2
memory: "1G"
max_duration: "2m"
workdir: "/app"
shell: "/bin/bash"
security: restricted
entrypoint: ["/usr/bin/tini", "--"]
cmd: ["python", "app.py"]
env: { MODE: "test" }
labels: { team: "platform" }
rlimits:
  - { resource: nofile, soft: 1024, hard: 2048 }
scripts:
  start: "python app.py"
network:
  policy: public
  allow: ["api.openai.com"]
  max_connections: 64
secrets:
  TOKEN:
    value: "literal-test-value"
    allow: ["api.openai.com"]
"#,
        );
        let sources = SandboxConfigSources {
            conf: Some(root),
            ..SandboxConfigSources::default()
        };
        let resolved = resolve(&sources).unwrap();
        let image = resolved.image(None, None).unwrap();
        let opts = SandboxOpts::default();
        let builder = image.apply(SandboxBuilder::new("config-test")).unwrap();
        let config = resolved
            .apply(builder, &opts)
            .unwrap()
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.resources.cpus, 2);
        assert_eq!(config.spec.resources.memory_mib, 1024);
        assert_eq!(config.spec.lifecycle.max_duration_secs, Some(120));
        assert_eq!(config.spec.runtime.workdir.as_deref(), Some("/app"));
        assert_eq!(config.spec.runtime.cmd.as_deref().unwrap()[0], "python");
        assert_eq!(
            config.spec.runtime.scripts.get("start").unwrap(),
            "#!/bin/bash\npython app.py\n"
        );
        assert_eq!(config.spec.network.max_connections, Some(64));
        assert_eq!(config.spec.network.ports.len(), 0);
        assert!(config.spec.network.tls.as_ref().unwrap().enabled);
        assert!(config.spec.network.dns.as_ref().unwrap().rebind_protection);
    }

    #[test]
    fn scoped_secrets_merge_recursively_by_name() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_config(
            dir.path(),
            "base.yaml",
            r#"
image: "python"
secrets:
  TOKEN:
    allow: ["api.example.com"]
    require_tls_identity: false
"#,
        );
        let scoped = write_config(
            dir.path(),
            "secrets.yaml",
            r#"
TOKEN:
  value: "${HOST_TOKEN}"
  inject: [headers, basic_auth]
"#,
        );
        let sources = SandboxConfigSources {
            conf: Some(root),
            secret_conf: Some(scoped),
            ..SandboxConfigSources::default()
        };

        let resolved = resolve(&sources).unwrap();
        let secret = &resolved.patch.secrets.unwrap()["TOKEN"];
        assert_eq!(
            secret.allow.as_deref(),
            Some(["api.example.com".to_string()].as_slice())
        );
        assert_eq!(secret.require_tls_identity, Some(false));
        assert_eq!(
            secret.inject.as_deref(),
            Some(
                [
                    SecretInjectionInput::Headers,
                    SecretInjectionInput::BasicAuth,
                ]
                .as_slice()
            )
        );
        assert!(matches!(
            secret.value,
            Some(SecretValueInput::Environment { ref env }) if env == "HOST_TOKEN"
        ));
    }

    #[test]
    fn project_only_root_fields_point_to_compose() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "Composefile", "sandboxes: {}\n");

        let error = load_root(&path).unwrap_err().to_string();
        assert!(error.contains("`sandboxes` is project-only"));
        assert!(error.contains("msb compose --conf"));
    }

    #[test]
    fn scoped_network_rejects_the_root_wrapper() {
        let dir = tempfile::tempdir().unwrap();
        let path = write_config(dir.path(), "network.yaml", "network: { policy: public }\n");
        let sources = SandboxConfigSources {
            net_conf: Some(path),
            ..SandboxConfigSources::default()
        };

        let error = resolve(&sources).unwrap_err().to_string();
        assert!(error.contains("without a `network:` wrapper"));
        assert!(error.contains("use --conf"));
    }

    #[tokio::test]
    async fn cli_scalars_override_files_and_select_the_script_shell() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_config(
            dir.path(),
            "agent.yaml",
            r#"
image: "python"
memory: "1G"
shell: "/bin/sh"
scripts: { start: "python app.py" }
"#,
        );
        let sources = SandboxConfigSources {
            conf: Some(root),
            ..SandboxConfigSources::default()
        };
        let resolved = resolve(&sources).unwrap();
        let opts = SandboxOpts {
            memory: Some("2G".to_string()),
            shell: Some("/bin/bash".to_string()),
            ..SandboxOpts::default()
        };
        let builder = resolved
            .image(None, None)
            .unwrap()
            .apply(SandboxBuilder::new("cli-override"))
            .unwrap();
        let builder = resolved.apply(builder, &opts).unwrap();
        let config = crate::commands::common::apply_sandbox_opts_after_config(builder, &opts)
            .unwrap()
            .build()
            .await
            .unwrap();

        assert_eq!(config.spec.resources.memory_mib, 2048);
        assert_eq!(config.spec.runtime.shell.as_deref(), Some("/bin/bash"));
        assert_eq!(
            config.spec.runtime.scripts["start"],
            "#!/bin/bash\npython app.py\n"
        );
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn cli_network_defaults_replace_file_presets() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_config(
            dir.path(),
            "agent.yaml",
            "image: \"python\"\nnetwork: public\n",
        );
        let sources = SandboxConfigSources {
            conf: Some(root),
            ..SandboxConfigSources::default()
        };
        let resolved = resolve(&sources).unwrap();
        let opts = SandboxOpts {
            no_net: true,
            ..SandboxOpts::default()
        };
        let builder = resolved
            .image(None, None)
            .unwrap()
            .apply(SandboxBuilder::new("network-override"))
            .unwrap();
        let config = resolved
            .apply(builder, &opts)
            .unwrap()
            .build()
            .await
            .unwrap();

        let policy = serde_json::to_value(config.spec.network.policy.as_ref().unwrap()).unwrap();
        assert_eq!(policy["default_egress"], "deny");
        assert_eq!(policy["default_ingress"], "deny");
        assert_eq!(policy["rules"], serde_json::json!([]));
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn cli_network_profiles_replace_file_presets() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_config(
            dir.path(),
            "agent.yaml",
            "image: \"python\"\nnetwork: open\n",
        );
        let sources = SandboxConfigSources {
            conf: Some(root),
            ..SandboxConfigSources::default()
        };
        let resolved = resolve(&sources).unwrap();
        let opts = SandboxOpts {
            net: vec!["none".to_string()],
            ..SandboxOpts::default()
        };
        let builder = resolved
            .image(None, None)
            .unwrap()
            .apply(SandboxBuilder::new("network-profile-override"))
            .unwrap();
        let config = resolved
            .apply(builder, &opts)
            .unwrap()
            .build()
            .await
            .unwrap();

        let policy = serde_json::to_value(config.spec.network.policy.as_ref().unwrap()).unwrap();
        assert_eq!(policy["default_egress"], "deny");
        assert_eq!(policy["default_ingress"], "deny");
        assert_eq!(policy["rules"], serde_json::json!([]));
    }

    #[test]
    fn modes_accept_the_full_four_digit_octal_range() {
        assert_eq!(parse_mode(Some("0644")).unwrap(), Some(0o644));
        assert_eq!(parse_mode(Some("4755")).unwrap(), Some(0o4755));
        assert!(parse_mode(Some("0888")).is_err());
    }

    #[test]
    fn patch_copy_sources_are_validated_before_creation() {
        let input = PatchInput::CopyFile(CopyFilePatchInput {
            src: PathBuf::from("/definitely/not/a/real/msb-config-source"),
            dst: "/app/config".to_string(),
            mode: None,
            replace: false,
        });

        let error = materialize_patch(&input).unwrap_err().to_string();
        assert!(error.contains("patch.copy_file.src"));
    }
}
