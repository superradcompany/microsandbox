//! Strict sparse configuration loading for single-sandbox commands.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use base64::Engine;
use microsandbox::sandbox::{
    DiskImageFormat, EnvVar, HandoffInit, HostPermissions, MountBuilder, NetworkSpecPatch, Patch,
    PullPolicy, Rlimit, RlimitResource, SandboxBuilder, SandboxConfigPatch, SandboxPolicyPatch,
    SandboxResourcesPatch, SandboxRuntimeOptionsPatch, SecurityProfile, StatVirtualization,
    VolumeMount,
};
#[cfg(feature = "net")]
use microsandbox::sandbox::{
    DnsConfigPatch, NetworkPolicy, NetworkProfile, SecretsConfigPatch, TlsConfigPatch,
};
use microsandbox_image::RegistryAuth;
use microsandbox_types_macros::ConfigPatch;
use serde::Deserialize;
use serde::de::DeserializeOwned;
use serde_json::Value;
use serde_saphyr::granit_parser::{Event, Parser};
use serde_saphyr::{DuplicateKeyPolicy, MergeKeyPolicy, Options};

#[cfg(test)]
use crate::commands::common::SandboxOpts;
use crate::commands::common::{
    SandboxConfigKind, SandboxConfigSources, materialize_bind_mount, parse_duration_secs,
    validate_shell,
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
pub struct ResolvedSandboxConfig {
    #[cfg(test)]
    input: SandboxConfigInput,
    config_patch: SandboxConfigPatch,
    config_scripts: BTreeMap<String, String>,
    image: Option<ResolvedImage>,
    registry_auth: Option<RegistryAuth>,
    loaded: bool,
}

impl std::fmt::Debug for ResolvedSandboxConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ResolvedSandboxConfig")
            .field("loaded", &self.loaded)
            .field("image", &self.image)
            .field(
                "registry_auth",
                &self.registry_auth.as_ref().map(|_| "<redacted>"),
            )
            .finish_non_exhaustive()
    }
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

#[derive(Debug, Default, Deserialize, ConfigPatch)]
#[serde(default, deny_unknown_fields)]
struct SandboxConfigInput {
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
    #[config_patch(merge)]
    env: Option<BTreeMap<String, String>>,
    #[config_patch(merge)]
    labels: Option<BTreeMap<String, String>>,
    #[config_patch(nested)]
    init: Option<InitInput>,
    mounts: Option<Vec<MountInput>>,
    patch_files: Option<Vec<PathBuf>>,
    patches: Option<Vec<PatchInput>>,
    #[config_patch(merge_with = merge_network)]
    network: Option<NetworkInput>,
    #[config_patch(merge_with = merge_secrets)]
    secrets: Option<BTreeMap<String, SecretInput>>,
    #[config_patch(merge)]
    scripts: Option<BTreeMap<String, String>>,
    ports: Option<Vec<String>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct ResourceConfigInput {
    cpus: Option<u8>,
    memory: Option<String>,
    max_duration: Option<String>,
    idle_timeout: Option<String>,
    rlimits: Option<Vec<RlimitInput>>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct RuntimeConfigInput {
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
struct FilesystemConfigInput {
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

#[derive(Debug, Clone, Default, Deserialize, ConfigPatch)]
#[serde(default, deny_unknown_fields)]
struct InitInput {
    cmd: Option<String>,
    args: Option<Vec<String>>,
    #[config_patch(merge)]
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
    uid: Option<u32>,
    gid: Option<u32>,
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
    Object(NetworkConfigInput),
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "lowercase")]
enum NetworkPreset {
    None,
    Public,
    Open,
}

#[derive(Debug, Clone, Default, Deserialize, ConfigPatch)]
#[serde(default, deny_unknown_fields)]
struct NetworkConfigInput {
    policy: Option<NetworkPreset>,
    allow: Option<Vec<String>>,
    deny: Option<Vec<String>>,
    ports: Option<Vec<String>>,
    #[config_patch(nested)]
    dns: Option<DnsInput>,
    #[config_patch(nested)]
    tls: Option<TlsInput>,
    trust_host_cas: Option<bool>,
    max_connections: Option<usize>,
}

#[derive(Debug, Clone, Default, Deserialize, ConfigPatch)]
#[serde(default, deny_unknown_fields)]
struct DnsInput {
    rebind_protection: Option<bool>,
    nameservers: Option<Vec<String>>,
    query_timeout: Option<String>,
}

#[derive(Debug, Clone, Default, Deserialize, ConfigPatch)]
#[serde(default, deny_unknown_fields)]
struct TlsInput {
    enabled: Option<bool>,
    bypass: Option<Vec<String>>,
    verify_upstream: Option<bool>,
    block_quic: Option<bool>,
}

#[derive(Debug, Clone, Default, Deserialize, ConfigPatch)]
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
// Methods: Normalization
//--------------------------------------------------------------------------------------------------

impl SandboxConfigInput {
    fn normalize(&mut self) {
        if let Some(ports) = self.ports.take() {
            let network = self
                .network
                .get_or_insert_with(|| NetworkInput::Object(NetworkConfigInput::default()));
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
    fn into_object(self) -> NetworkConfigInput {
        match self {
            Self::Preset(policy) => NetworkConfigInput {
                policy: Some(policy),
                ..NetworkConfigInput::default()
            },
            Self::Object(input) => input,
        }
    }

    fn object_mut(&mut self) -> &mut NetworkConfigInput {
        if let Self::Preset(policy) = self {
            *self = Self::Object(NetworkConfigInput {
                policy: Some(*policy),
                ..NetworkConfigInput::default()
            });
        }
        let Self::Object(input) = self else {
            unreachable!("preset was normalized to an object")
        };
        input
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
        Ok(self.registry_auth.clone())
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

        self.image.clone().ok_or_else(|| {
            anyhow::anyhow!(
                "missing required sandbox field `image`; provide an image argument or set `image` in --conf"
            )
        })
    }

    /// Apply the typed sparse patch to an SDK builder.
    pub fn apply(&self, builder: SandboxBuilder) -> anyhow::Result<SandboxBuilder> {
        let builder = match &self.image {
            Some(image) => image.apply(builder)?,
            None => builder,
        };
        let mut builder = builder
            .overlay(self.config_patch.clone())
            .config_scripts(self.config_scripts.clone());
        if let Some(auth) = self.registry_auth.clone() {
            builder = builder.registry(|registry| registry.auth(auth));
        }
        Ok(builder)
    }
}

impl ResolvedImage {
    /// Apply this rootfs source to a builder.
    pub fn apply(&self, builder: SandboxBuilder) -> anyhow::Result<SandboxBuilder> {
        Ok(match self {
            Self::Image(image) => builder.override_image(image.as_str()),
            Self::Oci {
                reference,
                upper_size,
            } => match upper_size {
                Some(value) => {
                    let size = parse_size("image.upper_size", value)?;
                    builder.override_image_with(|image| image.oci(reference).root_disk(size))
                }
                None => builder.override_image_with(|image| image.oci(reference)),
            },
            Self::Disk { path, fstype } => builder.override_image_with(|mut image| {
                image = image.disk(path);
                if let Some(fstype) = fstype {
                    image = image.fstype(fstype);
                }
                image
            }),
            Self::Bind(path) => builder.override_image_with(|image| image.bind(path)),
            Self::Snapshot(snapshot) => builder.override_snapshot(snapshot),
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
    let mut input = SandboxConfigInput::default();
    let mut image = None;
    let mut registry_auth = None;
    for source in sources.iter() {
        let contribution = match source.kind {
            SandboxConfigKind::Root => {
                let contribution = load_root(&source.path)?;
                let contribution_image = contribution
                    .image
                    .as_ref()
                    .map(resolve_image_input)
                    .transpose()?;
                let contribution_registry_auth = contribution
                    .registry
                    .as_ref()
                    .map(resolve_registry_auth)
                    .transpose()?
                    .flatten();

                if contribution_image.is_some() {
                    image = contribution_image.clone();
                }
                if contribution_registry_auth.is_some() {
                    registry_auth = contribution_registry_auth.clone();
                }
                contribution
            }
            SandboxConfigKind::Network => {
                reject_scoped_wrapper(&source.path, "network", "--net-conf")?;
                let network = load_typed::<NetworkConfigInput>(&source.path, "network config")?;
                SandboxConfigInput {
                    network: Some(NetworkInput::Object(network)),
                    ..SandboxConfigInput::default()
                }
            }
            SandboxConfigKind::Resources => {
                let scoped = load_typed::<ResourceConfigInput>(&source.path, "resource config")?;
                SandboxConfigInput {
                    cpus: scoped.cpus,
                    memory: scoped.memory,
                    max_duration: scoped.max_duration,
                    idle_timeout: scoped.idle_timeout,
                    rlimits: scoped.rlimits,
                    ..SandboxConfigInput::default()
                }
            }
            SandboxConfigKind::Runtime => {
                let scoped = load_typed::<RuntimeConfigInput>(&source.path, "runtime config")?;
                SandboxConfigInput {
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
                    ..SandboxConfigInput::default()
                }
            }
            SandboxConfigKind::Filesystem => {
                let mut scoped =
                    load_typed::<FilesystemConfigInput>(&source.path, "filesystem config")?;
                absolutize_filesystem_input(&mut scoped, config_base(&source.path)?);
                SandboxConfigInput {
                    mounts: scoped.mounts,
                    patch_files: scoped.patch_files,
                    patches: scoped.patches,
                    ..SandboxConfigInput::default()
                }
            }
            SandboxConfigKind::Secrets => {
                reject_scoped_wrapper(&source.path, "secrets", "--secret-conf")?;
                let secrets = load_typed_at::<BTreeMap<String, SecretInput>>(
                    &source.path,
                    "secret config",
                    vec!["secrets".to_string()],
                )?;
                SandboxConfigInput {
                    secrets: Some(secrets),
                    ..SandboxConfigInput::default()
                }
            }
            SandboxConfigKind::Scripts => {
                reject_scoped_wrapper(&source.path, "scripts", "--script-conf")?;
                let scripts =
                    load_typed::<BTreeMap<String, String>>(&source.path, "script config")?;
                SandboxConfigInput {
                    scripts: Some(scripts),
                    ..SandboxConfigInput::default()
                }
            }
        };

        SandboxConfigInputPatch::from_present_fields(contribution).apply_to(&mut input);
    }

    input.normalize();

    let config_scripts = input.scripts.clone().unwrap_or_default();
    for name in config_scripts.keys() {
        validate_script_name(name)?;
    }

    let mut config_patch = materialize_config_patch(&input)?;
    #[cfg(feature = "net")]
    {
        let network = materialize_network_patch(input.network.as_ref(), input.secrets.as_ref())?;
        config_patch = config_patch.network(network);
    }
    #[cfg(not(feature = "net"))]
    if input.network.is_some() || input.secrets.is_some() {
        anyhow::bail!("network and secret config require an msb build with networking enabled");
    }

    Ok(ResolvedSandboxConfig {
        #[cfg(test)]
        input,
        config_patch,
        config_scripts,
        image,
        registry_auth,
        loaded: sources.any(),
    })
}

fn load_root(path: &Path) -> anyhow::Result<SandboxConfigInput> {
    let mut value = parse_yaml_value(path, "sandbox configuration")?;
    reject_project_only_fields(&value, path)?;
    interpolate_value(&mut value, &mut Vec::new()).map_err(|err| {
        anyhow::anyhow!("invalid sandbox configuration {}: {err}", path.display())
    })?;
    let mut input: SandboxConfigInput = serde_json::from_value(value).map_err(|err| {
        anyhow::anyhow!("invalid sandbox configuration {}: {err}", path.display())
    })?;
    absolutize_input(&mut input, config_base(path)?);
    // Top-level `ports` is syntax sugar within this source. Normalize it before higher-precedence
    // scoped sources merge so a later network list can replace the root list as documented.
    input.normalize();
    Ok(input)
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

fn merge_secrets(base: &mut BTreeMap<String, SecretInput>, higher: BTreeMap<String, SecretInput>) {
    for (name, higher) in higher {
        match base.get_mut(&name) {
            Some(current) => SecretInputPatch::from_present_fields(higher).apply_to(current),
            None => {
                base.insert(name, higher);
            }
        }
    }
}

fn merge_network(base: &mut NetworkInput, higher: NetworkInput) {
    let higher = higher.into_object();
    let replaces_policy =
        higher.policy.is_some() || higher.allow.is_some() || higher.deny.is_some();
    let base = base.object_mut();
    if replaces_policy {
        // A source that supplies policy input replaces the complete lower-layer policy.
        base.policy = None;
        base.allow = None;
        base.deny = None;
    }
    NetworkConfigInputPatch::from_present_fields(higher).apply_to(base);
}

//--------------------------------------------------------------------------------------------------
// Functions: Path Resolution
//--------------------------------------------------------------------------------------------------

fn absolutize_input(input: &mut SandboxConfigInput, base: PathBuf) {
    if let Some(image) = &mut input.image {
        absolutize_image(image, &base);
    }
    if let Some(mounts) = &mut input.mounts {
        absolutize_mounts(mounts, &base);
    }
    if let Some(paths) = &mut input.patch_files {
        for path in paths {
            absolutize(path, &base);
        }
    }
    if let Some(patches) = &mut input.patches {
        absolutize_patch_inputs(patches, &base);
    }
}

fn absolutize_filesystem_input(input: &mut FilesystemConfigInput, base: PathBuf) {
    if let Some(mounts) = &mut input.mounts {
        absolutize_mounts(mounts, &base);
    }
    if let Some(paths) = &mut input.patch_files {
        for path in paths {
            absolutize(path, &base);
        }
    }
    if let Some(patches) = &mut input.patches {
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
                    // YAML string mounts have always been config-relative bind
                    // paths, including bare sources such as `src`.
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

fn materialize_config_patch(input: &SandboxConfigInput) -> anyhow::Result<SandboxConfigPatch> {
    let mut config_patch = SandboxConfigPatch::new();
    if let Some(policy) = input.pull_policy {
        config_patch = config_patch.pull_policy(match policy {
            PullPolicyInput::Missing => PullPolicy::IfMissing,
            PullPolicyInput::Always => PullPolicy::Always,
            PullPolicyInput::Never => PullPolicy::Never,
        });
    }

    let mut resources = SandboxResourcesPatch::new();
    if let Some(cpus) = input.cpus {
        resources = resources.cpus(cpus).max_cpus(cpus);
    }
    if let Some(memory) = &input.memory {
        let memory = parse_size("memory", memory)?;
        resources = resources.memory_mib(memory).max_memory_mib(memory);
    }
    config_patch = config_patch.resources(resources);

    let mut lifecycle = SandboxPolicyPatch::new();
    if let Some(duration) = &input.max_duration {
        lifecycle = lifecycle.max_duration_secs(parse_duration_secs(duration)?);
    }
    if let Some(duration) = &input.idle_timeout {
        lifecycle = lifecycle.idle_timeout_secs(parse_duration_secs(duration)?);
    }
    config_patch = config_patch.lifecycle(lifecycle);

    if let Some(rlimits) = &input.rlimits {
        let values = rlimits
            .iter()
            .map(|input| {
                let resource = RlimitResource::try_from(input.resource.as_str())
                    .map_err(anyhow::Error::msg)?;
                Ok(Rlimit {
                    resource,
                    soft: input.soft,
                    hard: input.hard.unwrap_or(input.soft),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        config_patch = config_patch.rlimits(values);
    }

    let mut runtime = SandboxRuntimeOptionsPatch::new();
    if let Some(value) = &input.workdir {
        runtime = runtime.workdir(value.clone());
    }
    if let Some(value) = &input.shell {
        validate_shell(value)?;
        runtime = runtime.shell(value.clone());
    }
    if let Some(value) = &input.user {
        runtime = runtime.user(value.clone());
    }
    if let Some(value) = &input.hostname {
        runtime = runtime.hostname(value.clone());
    }
    if let Some(value) = input.security {
        config_patch = config_patch.security_profile(match value {
            SecurityInput::Default => SecurityProfile::Default,
            SecurityInput::Restricted => SecurityProfile::Restricted,
        });
    }
    if let Some(value) = &input.entrypoint {
        runtime = runtime.entrypoint(value.clone());
    }
    if let Some(value) = &input.cmd {
        runtime = runtime.cmd(value.clone());
    }
    if let Some(value) = &input.env {
        config_patch = config_patch.env(
            value
                .iter()
                .map(|(key, value)| EnvVar::new(key, value))
                .collect(),
        );
    }
    if let Some(value) = &input.labels {
        config_patch = config_patch.labels(value.clone());
    }
    if let Some(value) = &input.init {
        config_patch = config_patch.init(materialize_init(value)?);
    }
    config_patch = config_patch.runtime(runtime);

    if let Some(mounts) = &input.mounts {
        config_patch = config_patch.mounts(
            mounts
                .iter()
                .map(materialize_mount)
                .collect::<anyhow::Result<Vec<_>>>()?,
        );
    }
    if input.patch_files.is_some() || input.patches.is_some() {
        let mut patches = match &input.patch_files {
            Some(paths) => materialize_patch_files(paths)?,
            None => Vec::new(),
        };
        if let Some(inline) = &input.patches {
            patches.extend(
                inline
                    .iter()
                    .map(materialize_patch)
                    .collect::<anyhow::Result<Vec<_>>>()?,
            );
        }
        config_patch = config_patch.patches(patches);
    }

    Ok(config_patch)
}

fn materialize_init(init: &InitInput) -> anyhow::Result<HandoffInit> {
    let Some(cmd) = init.cmd.clone() else {
        anyhow::bail!("init.cmd is required when init configuration is present");
    };
    if cmd != microsandbox_protocol::HANDOFF_INIT_AUTO && !cmd.starts_with('/') {
        anyhow::bail!("init.cmd must be an absolute guest path or `auto`, got {cmd:?}");
    }
    Ok(HandoffInit {
        cmd,
        args: init.args.clone().unwrap_or_default(),
        env: init.env.clone().unwrap_or_default().into_iter().collect(),
    })
}

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

fn materialize_mount(input: &MountInput) -> anyhow::Result<VolumeMount> {
    match input {
        MountInput::String(spec) => materialize_bind_mount(spec),
        MountInput::Object(object) => materialize_mount_object(object),
    }
}

fn materialize_mount_object(object: &MountObject) -> anyhow::Result<VolumeMount> {
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
    if object.uid.is_some() != object.gid.is_some() {
        anyhow::bail!("mount.uid and mount.gid must be specified together");
    }
    if object.uid.is_some() && object.bind.is_none() && object.named.is_none() {
        anyhow::bail!("mount.uid and mount.gid are only valid for bind or named mounts");
    }

    let tmpfs_size = object
        .tmpfs
        .as_ref()
        .and_then(|tmpfs| tmpfs.size.as_deref())
        .map(|size| parse_size("mount.tmpfs.size", size))
        .transpose()?;
    let object = object.clone();
    let mut mount = MountBuilder::new(target);
    if let Some(path) = object.bind {
        mount = mount.bind(path);
    } else if let Some(name) = object.named {
        mount = match object.create.unwrap_or(NamedCreateInput::Existing) {
            NamedCreateInput::Existing => mount.named(name),
            NamedCreateInput::Create => mount.named_with(name, |value| value.create()),
            NamedCreateInput::EnsureExists => mount.named_with(name, |value| value.ensure_exists()),
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
    if let (Some(uid), Some(gid)) = (object.uid, object.gid) {
        mount = mount.owner(uid, gid);
    }
    mount.build().map_err(Into::into)
}

fn materialize_patch_files(paths: &[PathBuf]) -> anyhow::Result<Vec<Patch>> {
    let mut patches = Vec::new();
    for path in paths {
        let mut patch_file = load_typed::<PatchFileInput>(path, "rootfs patch file")?;
        let base = config_base(path)?;
        absolutize_patch_inputs(&mut patch_file.patches, &base);
        for input in &patch_file.patches {
            patches.push(materialize_patch(input)?);
        }
    }
    Ok(patches)
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
fn materialize_network_patch(
    input: Option<&NetworkInput>,
    secrets: Option<&BTreeMap<String, SecretInput>>,
) -> anyhow::Result<NetworkSpecPatch> {
    use microsandbox_network::dns::Nameserver;
    use microsandbox_network::policy::Action;
    use microsandbox_types::{PortProtocol, PublishedPortSpec};

    use crate::commands::common::parse_port_mapping;
    use crate::net_rule::parse_rule_token;

    let input = input
        .cloned()
        .map(NetworkInput::into_object)
        .unwrap_or_default();
    let tls_present = input.tls.is_some();
    let mut patch = NetworkSpecPatch::new();
    let base_policy = input.policy.map(|base| match base {
        NetworkPreset::None => NetworkPolicy::none(),
        NetworkPreset::Public => NetworkPolicy::from_profiles([NetworkProfile::Public]),
        NetworkPreset::Open => NetworkPolicy::allow_all(),
    });
    let deny_rules = input
        .deny
        .map(|values| {
            values
                .into_iter()
                .map(|destination| {
                    parse_rule_token(&format!("deny@{destination}")).map_err(anyhow::Error::from)
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .transpose()?;
    let allow_rules = input
        .allow
        .map(|values| {
            values
                .into_iter()
                .map(|destination| {
                    parse_rule_token(&format!("allow@{destination}")).map_err(anyhow::Error::from)
                })
                .collect::<anyhow::Result<Vec<_>>>()
        })
        .transpose()?;

    if base_policy.is_some() || deny_rules.is_some() || allow_rules.is_some() {
        let base = base_policy.unwrap_or_default();
        let allowlist = allow_rules.as_ref().is_some_and(|rules| !rules.is_empty());
        let mut rules = deny_rules.unwrap_or_default();
        rules.extend(allow_rules.unwrap_or_default());
        if !allowlist {
            rules.extend(base.rules);
        }
        let policy = NetworkPolicy {
            default_egress: if allowlist {
                Action::Deny
            } else {
                base.default_egress
            },
            default_ingress: base.default_ingress,
            rules,
        };
        let policy: microsandbox_types::NetworkPolicy =
            serde_json::from_value(serde_json::to_value(policy)?)?;
        patch = patch.policy(policy);
    }

    if let Some(ports) = input.ports {
        let ports = ports
            .iter()
            .map(|value| {
                let (host_bind, host_port, guest_port, udp) = parse_port_mapping(value)?;
                Ok(PublishedPortSpec {
                    host_port,
                    guest_port,
                    protocol: if udp {
                        PortProtocol::Udp
                    } else {
                        PortProtocol::Tcp
                    },
                    host_bind: host_bind.to_string(),
                })
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        patch = patch.ports(ports);
    }
    if let Some(dns) = input.dns {
        let mut value = DnsConfigPatch::new();
        if let Some(enabled) = dns.rebind_protection {
            value = value.rebind_protection(enabled);
        }
        if let Some(nameservers) = dns.nameservers {
            for item in &nameservers {
                item.parse::<Nameserver>().map_err(anyhow::Error::from)?;
            }
            value = value.nameservers(nameservers);
        }
        if let Some(timeout) = dns.query_timeout {
            value = value.query_timeout_ms(parse_duration_millis(&timeout)?);
        }
        patch = patch.dns(value);
    }

    let materialized_secrets = secrets.map(materialize_secrets).transpose()?;
    if tls_present
        || materialized_secrets
            .as_ref()
            .is_some_and(|entries| !entries.is_empty())
    {
        let mut value = TlsConfigPatch::new();
        let tls = input.tls.unwrap_or_default();
        if let Some(enabled) = tls.enabled {
            value = value.enabled(enabled);
        }
        if let Some(bypass) = tls.bypass {
            value = value.bypass(bypass);
        }
        if let Some(verify) = tls.verify_upstream {
            value = value.verify_upstream(verify);
        }
        if let Some(block) = tls.block_quic {
            value = value.block_quic_on_intercept(block);
        }
        if materialized_secrets
            .as_ref()
            .is_some_and(|entries| !entries.is_empty())
        {
            value = value.enabled(true);
        }
        patch = patch.tls(value);
    }
    if let Some(entries) = materialized_secrets {
        patch = patch.secrets(SecretsConfigPatch::new().secrets(entries));
    }
    if let Some(enabled) = input.trust_host_cas {
        patch = patch.trust_host_cas(enabled);
    }
    if let Some(max) = input.max_connections {
        patch = patch.max_connections(max);
    }
    Ok(patch)
}

#[cfg(feature = "net")]
fn materialize_secrets(
    input: &BTreeMap<String, SecretInput>,
) -> anyhow::Result<Vec<microsandbox_types::SecretEntry>> {
    use microsandbox::sandbox::SecretSource;
    use microsandbox_types::{HostPattern, SecretInjection};
    use zeroize::Zeroizing;

    let mut entries = Vec::with_capacity(input.len());
    for (name, input) in input {
        let (value, source) = match &input.value {
            Some(SecretValueInput::Literal(value)) => (Zeroizing::new(value.clone()), None),
            Some(SecretValueInput::Environment { env }) => (
                Zeroizing::new(String::new()),
                Some(SecretSource::Env { var: env.clone() }),
            ),
            None => (
                Zeroizing::new(String::new()),
                Some(SecretSource::Env { var: name.clone() }),
            ),
        };
        let allowed_hosts = input
            .allow
            .clone()
            .unwrap_or_default()
            .into_iter()
            .map(|host| {
                if host.starts_with("*.") {
                    HostPattern::Wildcard(host)
                } else {
                    HostPattern::Exact(host)
                }
            })
            .collect();
        let injection_scopes = input
            .inject
            .clone()
            .unwrap_or_else(|| vec![SecretInjectionInput::Headers]);
        let injection = SecretInjection {
            headers: injection_scopes.contains(&SecretInjectionInput::Headers),
            basic_auth: injection_scopes.contains(&SecretInjectionInput::BasicAuth),
            query_params: injection_scopes.contains(&SecretInjectionInput::QueryParams),
            body: false,
        };
        entries.push(microsandbox_types::SecretEntry {
            env_var: name.clone(),
            value,
            source,
            placeholder: microsandbox_utils::secret::default_placeholder(name),
            allowed_hosts,
            injection,
            on_violation: None,
            require_tls_identity: input.require_tls_identity.unwrap_or(true),
        });
    }
    Ok(entries)
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
    fn layered_cli_sources_cover_every_atomic_input_field() {
        let dir = tempfile::tempdir().unwrap();
        write_config(dir.path(), "lower-patches.yaml", "patches: []\n");
        write_config(dir.path(), "higher-patches.yaml", "patches: []\n");
        let base = write_config(
            dir.path(),
            "base.yaml",
            r#"
image: "alpine"
pull_policy: missing
registry: { username: lower, password_env: PATH }
cpus: 1
memory: "1G"
max_duration: "1m"
idle_timeout: "2m"
rlimits: [{ resource: nofile, soft: 1, hard: 2 }]
workdir: "/lower"
shell: "/bin/sh"
user: "lower"
hostname: "lower"
security: default
entrypoint: ["lower-entrypoint"]
cmd: ["lower-command"]
env: { INHERITED: lower }
labels: { inherited: lower }
init:
  cmd: auto
  args: [lower]
  env: { INHERITED: lower }
mounts: ["./lower:/lower"]
patch_files: ["./lower-patches.yaml"]
patches:
  - text: { path: "/lower", content: lower }
scripts: { inherited: "echo lower" }
"#,
        );
        let resources = write_config(
            dir.path(),
            "resources.yaml",
            r#"
cpus: 2
memory: "2G"
max_duration: "3m"
idle_timeout: "4m"
rlimits: [{ resource: nproc, soft: 3, hard: 4 }]
"#,
        );
        let runtime = write_config(
            dir.path(),
            "runtime.yaml",
            r#"
workdir: "/higher"
shell: "/bin/bash"
user: "higher"
hostname: "higher"
security: restricted
entrypoint: ["higher-entrypoint"]
cmd: ["higher-command"]
"#,
        );
        let filesystem = write_config(
            dir.path(),
            "filesystem.yaml",
            r#"
mounts: ["./higher:/higher"]
patch_files: ["./higher-patches.yaml"]
patches:
  - text: { path: "/higher", content: higher }
"#,
        );
        let identity = write_config(
            dir.path(),
            "identity.yaml",
            r#"
image: "python:3.12"
pull_policy: always
registry: { username: higher, password_env: PATH }
"#,
        );

        let resolved = resolve(
            &SandboxConfigSources::default()
                .source(SandboxConfigKind::Root, base)
                .source(SandboxConfigKind::Resources, resources)
                .source(SandboxConfigKind::Runtime, runtime)
                .source(SandboxConfigKind::Filesystem, filesystem)
                .source(SandboxConfigKind::Root, identity),
        )
        .unwrap();
        assert!(matches!(
            resolved.image(None, None).unwrap(),
            ResolvedImage::Image(ref value) if value == "python:3.12"
        ));
        assert!(matches!(
            resolved.registry_auth().unwrap(),
            Some(RegistryAuth::Basic { ref username, .. }) if username == "higher"
        ));

        // Keep this destructuring exhaustive so adding a CLI input field requires assigning it a
        // precedence test instead of silently accepting the macro's default strategy.
        let SandboxConfigInput {
            image,
            pull_policy,
            registry,
            cpus,
            memory,
            max_duration,
            idle_timeout,
            rlimits,
            workdir,
            shell,
            user,
            hostname,
            security,
            entrypoint,
            cmd,
            env,
            labels,
            init,
            mounts,
            patch_files,
            patches,
            network,
            secrets,
            scripts,
            ports,
        } = resolved.input;

        assert!(matches!(image, Some(ImageInput::String(value)) if value == "python:3.12"));
        assert!(matches!(pull_policy, Some(PullPolicyInput::Always)));
        let registry = registry.unwrap();
        assert_eq!(registry.username.as_deref(), Some("higher"));
        assert_eq!(registry.password_env.as_deref(), Some("PATH"));
        assert_eq!(cpus, Some(2));
        assert_eq!(memory.as_deref(), Some("2G"));
        assert_eq!(max_duration.as_deref(), Some("3m"));
        assert_eq!(idle_timeout.as_deref(), Some("4m"));
        let rlimits = rlimits.unwrap();
        assert_eq!(rlimits.len(), 1);
        assert_eq!(rlimits[0].resource, "nproc");
        assert_eq!(rlimits[0].soft, 3);
        assert_eq!(rlimits[0].hard, Some(4));
        assert_eq!(workdir.as_deref(), Some("/higher"));
        assert_eq!(shell.as_deref(), Some("/bin/bash"));
        assert_eq!(user.as_deref(), Some("higher"));
        assert_eq!(hostname.as_deref(), Some("higher"));
        assert!(matches!(security, Some(SecurityInput::Restricted)));
        assert_eq!(entrypoint.as_deref().unwrap(), ["higher-entrypoint"]);
        assert_eq!(cmd.as_deref().unwrap(), ["higher-command"]);
        assert_eq!(env.unwrap()["INHERITED"], "lower");
        assert_eq!(labels.unwrap()["inherited"], "lower");
        let init = init.unwrap();
        assert_eq!(init.cmd.as_deref(), Some("auto"));
        assert_eq!(init.args.as_deref().unwrap(), ["lower"]);
        assert_eq!(init.env.unwrap()["INHERITED"], "lower");

        let canonical_dir = fs::canonicalize(dir.path()).unwrap();
        let mounts = mounts.unwrap();
        assert_eq!(mounts.len(), 1);
        assert!(matches!(
            &mounts[0],
            MountInput::String(value)
                if value == &format!("{}:/higher", canonical_dir.join("./higher").display())
        ));
        assert_eq!(
            patch_files.unwrap(),
            [canonical_dir.join("./higher-patches.yaml")]
        );
        let patches = patches.unwrap();
        assert_eq!(patches.len(), 1);
        assert!(matches!(
            &patches[0],
            PatchInput::Text(value) if value.path == "/higher" && value.content == "higher"
        ));
        assert!(network.is_none());
        assert!(secrets.is_none());
        assert_eq!(scripts.unwrap()["inherited"], "echo lower");
        assert!(ports.is_none());
    }

    #[test]
    fn layered_cli_sources_merge_every_annotated_input_field() {
        let dir = tempfile::tempdir().unwrap();
        let base = write_config(
            dir.path(),
            "base.yaml",
            r#"
image: alpine
env: { KEEP: lower, CHANGE: lower }
labels: { keep: lower, change: lower }
init:
  cmd: auto
  args: [lower]
  env: { KEEP: lower, CHANGE: lower }
scripts: { keep: "echo lower", change: "echo lower" }
"#,
        );
        let runtime = write_config(
            dir.path(),
            "runtime.yaml",
            r#"
env: { CHANGE: higher, ADD: higher }
labels: { change: higher, add: higher }
init:
  args: [higher]
  env: { CHANGE: higher, ADD: higher }
"#,
        );
        let scripts = write_config(
            dir.path(),
            "scripts.yaml",
            r#"
change: "echo higher"
add: "echo higher"
"#,
        );

        let resolved = resolve(
            &SandboxConfigSources::default()
                .source(SandboxConfigKind::Root, base)
                .source(SandboxConfigKind::Runtime, runtime)
                .source(SandboxConfigKind::Scripts, scripts),
        )
        .unwrap();
        let input = resolved.input;

        let env = input.env.unwrap();
        assert_eq!(env["KEEP"], "lower");
        assert_eq!(env["CHANGE"], "higher");
        assert_eq!(env["ADD"], "higher");
        let labels = input.labels.unwrap();
        assert_eq!(labels["keep"], "lower");
        assert_eq!(labels["change"], "higher");
        assert_eq!(labels["add"], "higher");
        let init = input.init.unwrap();
        assert_eq!(init.cmd.as_deref(), Some("auto"));
        assert_eq!(init.args.as_deref().unwrap(), ["higher"]);
        let init_env = init.env.unwrap();
        assert_eq!(init_env["KEEP"], "lower");
        assert_eq!(init_env["CHANGE"], "higher");
        assert_eq!(init_env["ADD"], "higher");
        let scripts = input.scripts.unwrap();
        assert_eq!(scripts["keep"], "echo lower");
        assert_eq!(scripts["change"], "echo higher");
        assert_eq!(scripts["add"], "echo higher");
    }

    #[cfg(feature = "net")]
    #[test]
    fn layered_cli_sources_cover_custom_network_and_secret_merge_rules() {
        let dir = tempfile::tempdir().unwrap();
        let base = write_config(
            dir.path(),
            "base.yaml",
            r#"
image: alpine
network:
  policy: open
  allow: ["lower.example.com"]
  deny: ["192.0.2.1"]
  ports: ["7000:7000"]
  dns:
    rebind_protection: false
    nameservers: ["8.8.8.8"]
    query_timeout: "5s"
  tls:
    enabled: true
    bypass: ["lower.example.com"]
    verify_upstream: false
    block_quic: true
  trust_host_cas: true
  max_connections: 10
secrets:
  TOKEN:
    value: lower
    allow: ["lower.example.com"]
    inject: [headers]
    require_tls_identity: false
  KEEP:
    value: keep
    allow: ["keep.example.com"]
"#,
        );
        let network = write_config(
            dir.path(),
            "network.yaml",
            r#"
allow: ["higher.example.com"]
ports: ["8000:8000"]
dns:
  nameservers: ["1.1.1.1"]
tls:
  bypass: ["higher.example.com"]
trust_host_cas: false
max_connections: 20
"#,
        );
        let ports = write_config(dir.path(), "ports.yaml", "ports: [\"9000:9000\"]\n");
        let secrets = write_config(
            dir.path(),
            "secrets.yaml",
            r#"
TOKEN:
  value: "${PATH}"
  inject: [query_params]
ADD:
  value: add
  allow: ["add.example.com"]
"#,
        );

        let resolved = resolve(
            &SandboxConfigSources::default()
                .source(SandboxConfigKind::Root, base)
                .source(SandboxConfigKind::Network, network)
                .source(SandboxConfigKind::Root, ports)
                .source(SandboxConfigKind::Secrets, secrets),
        )
        .unwrap();
        let input = resolved.input;

        assert!(input.ports.is_none());
        let network = input.network.unwrap().into_object();
        assert!(network.policy.is_none());
        assert_eq!(network.allow.as_deref().unwrap(), ["higher.example.com"]);
        assert!(network.deny.is_none());
        assert_eq!(network.ports.as_deref().unwrap(), ["9000:9000"]);
        let dns = network.dns.unwrap();
        assert_eq!(dns.rebind_protection, Some(false));
        assert_eq!(dns.nameservers.as_deref().unwrap(), ["1.1.1.1"]);
        assert_eq!(dns.query_timeout.as_deref(), Some("5s"));
        let tls = network.tls.unwrap();
        assert_eq!(tls.enabled, Some(true));
        assert_eq!(tls.bypass.as_deref().unwrap(), ["higher.example.com"]);
        assert_eq!(tls.verify_upstream, Some(false));
        assert_eq!(tls.block_quic, Some(true));
        assert_eq!(network.trust_host_cas, Some(false));
        assert_eq!(network.max_connections, Some(20));

        let secrets = input.secrets.unwrap();
        let token = &secrets["TOKEN"];
        assert!(matches!(
            token.value,
            Some(SecretValueInput::Environment { ref env }) if env == "PATH"
        ));
        assert_eq!(token.allow.as_deref().unwrap(), ["lower.example.com"]);
        assert_eq!(
            token.inject.as_deref().unwrap(),
            [SecretInjectionInput::QueryParams]
        );
        assert_eq!(token.require_tls_identity, Some(false));
        assert!(matches!(
            secrets["KEEP"].value,
            Some(SecretValueInput::Literal(ref value)) if value == "keep"
        ));
        assert!(matches!(
            secrets["ADD"].value,
            Some(SecretValueInput::Literal(ref value)) if value == "add"
        ));
    }

    #[test]
    fn scoped_files_replace_network_policy_and_merge_sibling_fields() {
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
  dns:
    rebind_protection: true
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
        let sources = SandboxConfigSources::default()
            .source(SandboxConfigKind::Root, root)
            .source(SandboxConfigKind::Runtime, runtime)
            .source(SandboxConfigKind::Network, network);

        let resolved = resolve(&sources).unwrap();
        let env = resolved.input.env.unwrap();
        assert_eq!(env.get("KEEP").map(String::as_str), Some("root"));
        assert_eq!(env.get("CHANGE").map(String::as_str), Some("scoped"));
        assert_eq!(env.get("ADD").map(String::as_str), Some("scoped"));

        let network = resolved.input.network.unwrap().into_object();
        assert_eq!(
            network.allow.as_deref(),
            Some(["scoped.example.com".to_string()].as_slice())
        );
        assert!(network.deny.is_none());
        assert_eq!(
            network.dns.as_ref().and_then(|dns| dns.rebind_protection),
            Some(true)
        );
    }

    #[test]
    fn repeated_root_and_scoped_sources_overlay_in_supplied_order() {
        let dir = tempfile::tempdir().unwrap();
        let base = write_config(dir.path(), "base.yaml", "image: alpine\nmemory: 1G\n");
        let standard = write_config(dir.path(), "standard.yaml", "memory: 2G\n");
        let project = write_config(dir.path(), "project.yaml", "memory: 3G\n");
        let large = write_config(dir.path(), "large.yaml", "memory: 4G\n");

        let resolved = resolve(
            &SandboxConfigSources::default()
                .source(SandboxConfigKind::Root, base.clone())
                .source(SandboxConfigKind::Resources, standard.clone())
                .source(SandboxConfigKind::Root, project.clone())
                .source(SandboxConfigKind::Resources, large.clone()),
        )
        .unwrap();
        assert_eq!(resolved.input.memory.as_deref(), Some("4G"));
        assert!(matches!(
            resolved.image(None, None).unwrap(),
            ResolvedImage::Image(ref value) if value == "alpine"
        ));

        let reordered = resolve(
            &SandboxConfigSources::default()
                .source(SandboxConfigKind::Root, base)
                .source(SandboxConfigKind::Resources, standard)
                .source(SandboxConfigKind::Resources, large)
                .source(SandboxConfigKind::Root, project),
        )
        .unwrap();
        assert_eq!(reordered.input.memory.as_deref(), Some("3G"));
    }

    #[tokio::test]
    async fn nested_required_fields_can_be_completed_by_a_scoped_patch() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_config(
            dir.path(),
            "base.yaml",
            "image: alpine\ninit:\n  args: [--unit=test.target]\n",
        );
        let runtime = write_config(dir.path(), "runtime.yaml", "init:\n  cmd: auto\n");
        let resolved = resolve(
            &SandboxConfigSources::default()
                .source(SandboxConfigKind::Root, root)
                .source(SandboxConfigKind::Runtime, runtime),
        )
        .unwrap();

        let config = resolved
            .apply(SandboxBuilder::new("completed-init"))
            .unwrap()
            .build()
            .await
            .unwrap();
        let init = config.spec.init.unwrap();
        assert_eq!(init.cmd, "auto");
        assert_eq!(init.args, ["--unit=test.target"]);
    }

    #[test]
    fn unresolved_nested_required_fields_fail_during_resolution() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_config(
            dir.path(),
            "base.yaml",
            "image: alpine\ninit:\n  args: [--unit=test.target]\n",
        );
        let error = resolve(&SandboxConfigSources::default().source(SandboxConfigKind::Root, root))
            .unwrap_err();
        assert!(error.to_string().contains("init.cmd is required"));
    }

    #[test]
    fn paths_are_relative_to_the_contributing_file() {
        let dir = tempfile::tempdir().unwrap();
        let config_dir = dir.path().join("config");
        fs::create_dir(&config_dir).unwrap();
        fs::write(config_dir.join("patch.yaml"), "patches: []\n").unwrap();
        fs::write(config_dir.join("app.toml"), "[app]\n").unwrap();
        let root = write_config(
            &config_dir,
            "agent.yaml",
            r#"
image: { bind: "./rootfs" }
mounts:
  - "src:/app"
patch_files: ["./patch.yaml"]
patches:
  - copy_file: { src: "./app.toml", dst: "/etc/app.toml" }
"#,
        );
        let config_base = config_base(&root).unwrap();
        let sources = SandboxConfigSources::default().source(SandboxConfigKind::Root, root);

        let resolved = resolve(&sources).unwrap();
        let ImageInput::Object(image) = resolved.input.image.unwrap() else {
            panic!("expected object image")
        };
        assert_eq!(image.bind.unwrap(), config_base.join("./rootfs"));
        assert_eq!(
            resolved.input.patch_files.unwrap(),
            vec![config_base.join("./patch.yaml")]
        );
        let MountInput::String(mount) = &resolved.input.mounts.unwrap()[0] else {
            panic!("expected string mount")
        };
        assert_eq!(
            mount,
            &format!("{}:/app", config_base.join("src").display())
        );
        let PatchInput::CopyFile(copy) = &resolved.input.patches.unwrap()[0] else {
            panic!("expected copy-file patch")
        };
        assert_eq!(copy.src, config_base.join("./app.toml"));
    }

    #[test]
    fn yaml_string_mounts_share_the_full_bind_option_grammar() {
        let bind = materialize_mount(&MountInput::String(
            "/host:/workspace:ro,noexec,nosuid,nodev,stat-virt=relaxed,host-perms=mirror,quota=64M,uid=1000,gid=1001"
                .to_string(),
        ))
        .unwrap();

        match bind {
            VolumeMount::Bind {
                host,
                guest,
                options,
                stat_virtualization,
                host_permissions,
                quota_mib,
                ..
            } => {
                assert_eq!(host, PathBuf::from("/host"));
                assert_eq!(guest, "/workspace");
                assert!(options.readonly);
                assert!(options.noexec);
                assert!(options.nosuid);
                assert!(options.nodev);
                assert_eq!(options.override_uid, Some(1000));
                assert_eq!(options.override_gid, Some(1001));
                assert_eq!(stat_virtualization, StatVirtualization::Relaxed);
                assert_eq!(host_permissions, HostPermissions::Mirror);
                assert_eq!(quota_mib, Some(64));
            }
            other => panic!("expected bind mount, got {other:?}"),
        }
    }

    #[test]
    fn yaml_object_mounts_accept_paired_owner_and_reject_invalid_uses() {
        let dir = tempfile::tempdir().unwrap();
        let valid = write_config(
            dir.path(),
            "valid-owner.yaml",
            r#"
image: alpine
mounts:
  - bind: "./workspace"
    target: "/workspace"
    uid: 1000
    gid: 1001
  - named: cache
    target: "/cache"
    uid: 2000
    gid: 2001
"#,
        );
        let patch = load_root(&valid).unwrap();
        let mounts = patch.mounts.unwrap();
        let mount = materialize_mount(&mounts[0]).unwrap();
        match mount {
            VolumeMount::Bind { options, .. } => {
                assert_eq!(options.override_uid, Some(1000));
                assert_eq!(options.override_gid, Some(1001));
            }
            other => panic!("expected bind mount, got {other:?}"),
        }
        let mount = materialize_mount(&mounts[1]).unwrap();
        match mount {
            VolumeMount::Named { options, .. } => {
                assert_eq!(options.override_uid, Some(2000));
                assert_eq!(options.override_gid, Some(2001));
            }
            other => panic!("expected named mount, got {other:?}"),
        }

        let partial = write_config(
            dir.path(),
            "partial-owner.yaml",
            "image: alpine\nmounts:\n  - bind: ./workspace\n    target: /workspace\n    uid: 1000\n",
        );
        let error =
            resolve(&SandboxConfigSources::default().source(SandboxConfigKind::Root, partial))
                .unwrap_err()
                .to_string();
        assert!(error.contains("mount.uid and mount.gid must be specified together"));

        let tmpfs = write_config(
            dir.path(),
            "tmpfs-owner.yaml",
            "image: alpine\nmounts:\n  - tmpfs: {}\n    target: /tmp\n    uid: 1000\n    gid: 1000\n",
        );
        let error =
            resolve(&SandboxConfigSources::default().source(SandboxConfigKind::Root, tmpfs))
                .unwrap_err()
                .to_string();
        assert!(error.contains("only valid for bind or named mounts"));
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
        let sources = SandboxConfigSources::default().source(SandboxConfigKind::Root, root);
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
        let sources = SandboxConfigSources::default().source(SandboxConfigKind::Root, root);
        let resolved = resolve(&sources).unwrap();
        let image = resolved.image(None, None).unwrap();
        let builder = resolved.apply(SandboxBuilder::new("config-test")).unwrap();
        let config = image.apply(builder).unwrap().build().await.unwrap();

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
        assert!(config.spec.network.dns.is_none());
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
        let sources = SandboxConfigSources::default()
            .source(SandboxConfigKind::Root, root)
            .source(SandboxConfigKind::Secrets, scoped);

        let resolved = resolve(&sources).unwrap();
        let secret = &resolved.input.secrets.unwrap()["TOKEN"];
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
        let sources = SandboxConfigSources::default().source(SandboxConfigKind::Network, path);

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
        let sources = SandboxConfigSources::default().source(SandboxConfigKind::Root, root);
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
        let builder = resolved.apply(builder).unwrap();
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
    async fn cli_network_defaults_replace_the_complete_file_policy() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_config(
            dir.path(),
            "agent.yaml",
            r#"
image: "python"
network:
  policy: open
  deny: ["169.254.169.254"]
  allow: ["api.openai.com"]
secrets:
  TOKEN:
    value: "test-secret"
    allow: ["api.openai.com"]
"#,
        );
        let sources = SandboxConfigSources::default().source(SandboxConfigKind::Root, root);
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
        let builder = resolved.apply(builder).unwrap();
        let config = crate::commands::common::apply_sandbox_opts_after_config(builder, &opts)
            .unwrap()
            .build()
            .await
            .unwrap();

        let policy = serde_json::to_value(config.spec.network.policy.as_ref().unwrap()).unwrap();
        assert_eq!(policy["default_egress"], "deny");
        assert_eq!(policy["default_ingress"], "deny");
        assert_eq!(policy["rules"], serde_json::json!([]));
        assert!(config.spec.network.secrets.is_some());
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn cli_network_profiles_replace_the_complete_file_policy() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_config(
            dir.path(),
            "agent.yaml",
            r#"
image: "python"
network:
  policy: open
  deny: ["169.254.169.254"]
  allow: ["api.openai.com"]
"#,
        );
        let sources = SandboxConfigSources::default().source(SandboxConfigKind::Root, root);
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
        let builder = resolved.apply(builder).unwrap();
        let config = crate::commands::common::apply_sandbox_opts_after_config(builder, &opts)
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
    async fn cli_network_rules_prepend_without_discarding_file_rules() {
        let dir = tempfile::tempdir().unwrap();
        let root = write_config(
            dir.path(),
            "agent.yaml",
            r#"
image: "python"
network:
  policy: open
  deny: ["169.254.169.254"]
  allow: ["api.openai.com"]
"#,
        );
        let sources = SandboxConfigSources::default().source(SandboxConfigKind::Root, root);
        let resolved = resolve(&sources).unwrap();
        let opts = SandboxOpts {
            net_rule: vec!["deny@192.0.2.1".to_string()],
            ..SandboxOpts::default()
        };
        let builder = resolved
            .apply(SandboxBuilder::new("network-rule-order"))
            .unwrap();
        let builder = resolved.image(None, None).unwrap().apply(builder).unwrap();
        let config = crate::commands::common::apply_sandbox_opts_after_config(builder, &opts)
            .unwrap()
            .build()
            .await
            .unwrap();

        let policy = serde_json::to_value(config.spec.network.policy.as_ref().unwrap()).unwrap();
        assert_eq!(policy["rules"].as_array().unwrap().len(), 3);
        assert_eq!(policy["rules"][0]["action"], "deny");
        assert_eq!(policy["rules"][1]["action"], "deny");
        assert_eq!(policy["rules"][2]["action"], "allow");
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
