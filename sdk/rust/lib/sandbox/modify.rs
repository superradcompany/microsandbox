//! Sandbox modification planning.

use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use microsandbox_types::{
    EnvVar, RootDisk, RootfsSource, SecretSubstitution, SecretViolationAction,
};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set, sea_query::Expr};

use crate::backend::{Backend, ControlSession};
use crate::db::entity::{sandbox as sandbox_entity, sandbox_label as sandbox_label_entity};
use crate::error::{Operation, UnsupportedReason};
use crate::size::Mebibytes;
use crate::{MicrosandboxError, MicrosandboxResult};
use microsandbox_control_client::{
    GrowRootDisk, SecretsResult, SetCpuTarget, SetMemoryTarget, UpdateSecrets,
};

use super::{SandboxConfig, SandboxStatus};

#[path = "modify_ports.rs"]
mod ports;

pub use microsandbox_types::modify::{
    ChangeKind, ConfigPlannedChange, ModificationConflict, ModificationDisposition,
    ModificationPolicy, ModificationWarning, PlannedChange, PublishedPortKey,
    ResourceConvergenceState, ResourceKind, ResourceResizeStatus, SandboxModificationPatch,
    SandboxModificationPlan, SecretChangeKind, SecretModificationPatch, SecretPlannedChange,
    SecretSource,
};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LIVE_RESIZE_UNAVAILABLE: &str =
    "live CPU and memory resize are not available in this runtime yet";
const LIVE_SECRET_RECONFIGURE_UNAVAILABLE: &str =
    "live secret reconfiguration is not available in this runtime yet";
const SECRET_POLICY_REQUIRES_RESTART: &str =
    "secret policy changes require restart; use restart or next_start";
const LIVE_EXEC_DEFAULT_UPDATE_UNAVAILABLE: &str =
    "affects future execs only after restart; live exec-default updates are not available yet";
const LIVE_LABEL_UPDATE_NEEDS_ACTIVE_CONFIG: &str =
    "live label updates need an active configuration snapshot; restart the sandbox to apply them";
const UPPER_LIVE_RESIZE_UNAVAILABLE: &str =
    "the mounted upper filesystem cannot be resized while the sandbox is running";
const UPPER_GROWS_ON_NEXT_START: &str =
    "the upper.ext4 file grows during the next start's pre-boot preparation";
const FUTURE_EXECS_ONLY: &str =
    "applies to future execs only; running processes keep their current environment";
#[cfg(not(feature = "net"))]
const SECRETS_UNAVAILABLE_WITHOUT_NET: &str =
    "secret modification requires a build with the net feature";
const SECRET_FIELD: &str = "secret";
const TLS_FIELD: &str = "tls";
const TLS_INTERCEPTION_REQUIRES_RESTART: &str =
    "TLS-identity secrets require interception, which cannot be enabled on a running sandbox";
const ROOT_DISK_FIELD: &str = "root_disk_size";
const ENV_FIELD: &str = "env";
const LABEL_FIELD: &str = "label";
const WORKDIR_FIELD: &str = "workdir";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Fluent builder returned by [`Sandbox::modify`](super::Sandbox::modify).
///
/// The builder is intentionally plan-first. Phase 3 exposes the canonical SDK
/// patch and dry-run contract; later phases can wire the same patch type into
/// persistence, live runtime mutation, and restart-backed apply.
#[derive(Clone)]
pub struct SandboxModificationBuilder {
    backend: Arc<dyn Backend>,
    name: String,
    patch: SandboxModificationPatch,
    policy: ModificationPolicy,
}

/// Fluent builder for one declarative secret spec inside a modification
/// patch, obtained through [`SandboxModificationBuilder::secret`].
///
/// It shares the create-time [`SecretBuilder`](crate::sandbox::SecretBuilder)
/// vocabulary: [`env`](Self::env) names the secret, [`source`](Self::source)
/// or [`value`](Self::value) provides material (mutually exclusive),
/// [`placeholder`](Self::placeholder) and [`allow`](Self::allow)
/// state the guest-visible reference and the host allow-list.
#[derive(Default)]
pub struct SecretPatchBuilder {
    spec: SecretModificationPatch,
}

struct DesiredResources {
    max_cpus: u8,
    max_memory_mib: u32,
}

struct ExistingSecret {
    placeholder: String,
    allowed_hosts: Vec<String>,
    substitution: SecretSubstitution,
    passthrough_hosts: Vec<String>,
    violation_action: Option<SecretViolationAction>,
    require_tls_identity: bool,
}

/// A compare-guarded replacement of the sandbox row's `active_config`.
struct ActiveLabelsUpdate {
    /// The `active_config` value the write expects to find.
    expected_json: String,
    /// The `active_config` value to store.
    active_config_json: String,
}

/// Live-control operations the running sandbox process actually serves,
/// discovered through the control socket's `capabilities` op.
#[derive(Debug, Clone, Copy, Default)]
struct LiveControl {
    /// Host understands root growth; the runtime separately preflights its guest.
    root_disk_grow: bool,
    /// CPU and memory resize targets are served.
    cpu_resize: bool,
    memory_resize: bool,

    /// Secret rotation, removal, and allowed-host updates are served.
    secrets: bool,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl SandboxModificationBuilder {
    pub(crate) fn new(backend: Arc<dyn Backend>, name: impl Into<String>) -> Self {
        Self {
            backend,
            name: name.into(),
            patch: SandboxModificationPatch::default(),
            policy: ModificationPolicy::NoRestart,
        }
    }

    /// Set the desired effective vCPU count.
    pub fn cpus(mut self, cpus: u8) -> Self {
        self.patch.cpus = Some(cpus);
        self
    }

    /// Set the desired boot-time maximum possible vCPU count.
    pub fn max_cpus(mut self, max_cpus: u8) -> Self {
        self.patch.max_cpus = Some(max_cpus);
        self
    }

    /// Set the desired effective guest memory. Accepts a bare `u32` in MiB or a typed size.
    pub fn memory(mut self, size: impl Into<Mebibytes>) -> Self {
        self.patch.memory_mib = Some(size.into().as_u32());
        self
    }

    /// Set the boot-time maximum hotpluggable memory. Accepts a bare `u32` in MiB or a typed size.
    pub fn max_memory(mut self, size: impl Into<Mebibytes>) -> Self {
        self.patch.max_memory_mib = Some(size.into().as_u32());
        self
    }

    /// Set the desired total root disk size, accepting a bare `u32` in MiB or a typed size.
    /// Managed and flat roots are grow-only. Tmpfs changes take effect on the next boot;
    /// user-owned disk images cannot be resized through this API.
    pub fn root_disk_size(mut self, size: impl Into<Mebibytes>) -> Self {
        self.patch.root_disk_size_mib = Some(size.into().as_u32());
        self
    }

    /// Set an environment variable for future execs.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.patch.env.push(EnvVar::new(key, value));
        self
    }

    /// Remove an environment variable.
    pub fn remove_env(mut self, key: impl Into<String>) -> Self {
        self.patch.env_remove.push(key.into());
        self
    }

    /// Set a sandbox label.
    pub fn label(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.patch.labels.push((key.into(), value.into()));
        self
    }

    /// Remove a sandbox label.
    pub fn remove_label(mut self, key: impl Into<String>) -> Self {
        self.patch.labels_remove.push(key.into());
        self
    }

    /// Set the working directory for future execs.
    pub fn workdir(mut self, path: impl Into<String>) -> Self {
        self.patch.workdir = Some(path.into());
        self
    }

    /// Add or update a published mapping without changing other host endpoints.
    /// This requires restart or next-start policy on a running sandbox.
    pub fn port(self, host_port: u16, guest_port: u16) -> Self {
        self.port_mapping(microsandbox_types::PublishedPortSpec {
            host_port,
            guest_port,
            ..Default::default()
        })
    }

    /// Add or update a mapping with an explicit host address and protocol.
    pub fn port_mapping(mut self, port: microsandbox_types::PublishedPortSpec) -> Self {
        self.patch.ports.push(port);
        self
    }

    /// Remove one published host endpoint. Missing endpoints are rejected.
    pub fn remove_port(mut self, port: PublishedPortKey) -> Self {
        self.patch.ports_remove.push(port);
        self
    }

    /// Persist the requested changes for the next start.
    pub fn next_start(mut self) -> Self {
        self.policy = ModificationPolicy::NextStart;
        self
    }

    /// Plan the requested changes under restart-backed apply semantics.
    pub fn restart(mut self) -> Self {
        self.policy = ModificationPolicy::Restart;
        self
    }

    /// Declare the desired state of one secret via a closure.
    ///
    /// The spec mirrors the create-time secret vocabulary: name the secret
    /// with `.env(..)`, provide material with `.source(..)` or `.value(..)`,
    /// and optionally set `.placeholder(..)` and `.allow(..)`. The
    /// planner diffs the spec against the existing config to infer the
    /// change: a secret that does not exist yet is added, material on an
    /// existing secret rotates it, and host or placeholder differences
    /// update those aspects.
    ///
    /// ```ignore
    /// sandbox.modify()
    ///     .secret(|s| s
    ///         .env("API_KEY")
    ///         .source(SecretSource::Env { var: "API_KEY".into() })
    ///         .allow("api.example.com"))
    ///     .apply()
    ///     .await?;
    /// ```
    ///
    /// Declaring the same secret again replaces the earlier spec. Removal is
    /// always explicit through [`remove_secret`](Self::remove_secret).
    pub fn secret(mut self, f: impl FnOnce(SecretPatchBuilder) -> SecretPatchBuilder) -> Self {
        let spec = f(SecretPatchBuilder::new()).build();
        self.patch
            .secrets
            .retain(|existing| existing.name != spec.name);
        self.patch.secrets.push(spec);
        self
    }

    /// Remove a secret. Removal is always explicit; omitting a secret from
    /// the patch never removes it.
    pub fn remove_secret(mut self, name: impl Into<String>) -> Self {
        self.patch.secrets_remove.push(name.into());
        self
    }

    /// Replace the accumulated patch wholesale. Language bindings deserialize the canonical [`SandboxModificationPatch`] and inject it here instead of replaying the fluent setters.
    pub fn with_patch(mut self, patch: SandboxModificationPatch) -> Self {
        self.patch = patch;
        self
    }

    /// Compute a modification plan without applying anything.
    pub async fn dry_run(self) -> MicrosandboxResult<SandboxModificationPlan> {
        let handle = self
            .backend
            .sandboxes()
            .get(self.backend.clone(), &self.name)
            .await?;
        let status = handle.status_snapshot();
        let config = handle.config()?;
        let active = handle.active_config().ok().flatten();
        let (live, _) =
            live_control(&self.backend, &self.name, status, &self.patch, self.policy).await?;
        let mut plan = build_plan(
            self.name,
            status,
            &config,
            active.as_ref(),
            live,
            self.patch.clone(),
            self.policy,
        );
        if ports::requested(&self.patch) && plan.conflicts.is_empty() {
            if handle.local().is_none() {
                return Err(MicrosandboxError::local_only(Operation::SandboxModify));
            }
            if let Err(error) = ports::preflight(&config, active.as_ref(), &self.patch, status) {
                plan.conflicts.push(ModificationConflict {
                    field: "port".into(),
                    message: error.to_string(),
                });
            }
        }
        Ok(plan)
    }

    /// Apply supported changes, preserving any earlier live effects on failure.
    ///
    /// Live-capable changes apply to the running VM first (CPU count through
    /// guest CPU hotplug when the target fits inside the active `max_cpus`);
    /// the desired config is persisted only after the live step succeeds, and
    /// live label changes are saved with it. For
    /// stopped sandboxes or `next_start` requests, changes persist for the next
    /// start. When the policy is `restart`, the existing stop/start lifecycle
    /// path makes restart-required changes active. Live secret rotation,
    /// removal, and allowed-host updates go through the runtime control
    /// socket; the durable config records host-side source references for
    /// source-based specs and persists the value for value-based specs (the
    /// same at-rest property as create's `secret_env`).
    ///
    /// Configuring a secret that requires TLS identity on a sandbox with
    /// interception off also turns interception on. That is planned as a
    /// `tls` change and, like every other restart-backed change, needs
    /// `restart` or `next_start` on a running sandbox. Existing secrets that
    /// opt out of TLS identity continue to support live plain-HTTP updates.
    /// Changes to an existing secret's substitution, violation action, TLS
    /// identity requirement, or placeholder passthrough hosts require restart
    /// or next-start policy, even when combined with otherwise live edits.
    pub async fn apply(self) -> MicrosandboxResult<SandboxModificationPlan> {
        let handle = self
            .backend
            .sandboxes()
            .get(self.backend.clone(), &self.name)
            .await?;
        let status = handle.status_snapshot();
        let mut config = handle.config()?;
        // A failed restore can still own staged immutable lower layers. Do not let
        // offline disk growth or a restart-backed modification bypass its launch gate.
        crate::LocalBackend::validate_completed_restore(&config)?;
        let mut active = handle.active_config().ok().flatten();
        let mut active_json = handle.active_config_json().map(str::to_owned);
        let (live, session) =
            live_control(&self.backend, &self.name, status, &self.patch, self.policy).await?;
        let mut plan = build_plan(
            self.name.clone(),
            status,
            &config,
            active.as_ref(),
            live,
            self.patch.clone(),
            self.policy,
        );

        validate_apply_supported(&plan)?;
        if ports::requested(&self.patch) {
            if handle.local().is_none() {
                return Err(MicrosandboxError::local_only(Operation::SandboxModify));
            }
            ports::preflight(&config, active.as_ref(), &self.patch, status)?;
        }
        let restart_required = plan_requires_restart(&plan) && running_status(status);

        if handle.local().is_some() {
            // Validate configuration serialization before stopping a VM,
            // growing a disk, or issuing any live control mutation.
            let mut prospective = config.clone();
            prospective.apply_modification(&self.patch);
            prospective.update_secrets(&self.patch)?;
            serde_json::to_string(&prospective)?;

            // A restart-backed modification must be launchable on the selected
            // runtime before the VM is stopped. Otherwise a capability gap (for
            // example HTTP CONNECT proxy authentication) is only discovered by
            // the start that follows `stop`, which leaves the workload down and
            // the rejected change already persisted.
            if restart_required && let Some(local) = self.backend.as_local() {
                crate::runtime::launch_contract::validate_runtime_config(
                    &prospective,
                    local.config(),
                )
                .await?;
            }
        }

        if restart_required {
            handle.stop().await?;
        }
        if !restart_required && let Some(target) = live_cpu_target(&plan, &self.patch) {
            let state = control_session(&session)?
                .request(&SetCpuTarget::new(u32::from(target)))
                .await
                .map_err(crate::MicrosandboxError::ControlClient)?;
            plan.resize_status.push(ResourceResizeStatus {
                resource: ResourceKind::Cpus,
                requested: target.to_string(),
                actual: state.actual_online.to_string(),
                enforced: state.enforced.to_string(),
                state: if state.actual_online == u32::from(target) {
                    ResourceConvergenceState::Applied
                } else {
                    ResourceConvergenceState::Converging
                },
            });
            // The running VM changed: refresh the active snapshot with the
            // enforced target so inspect does not report the already-live
            // change as pending. The guest driver converges asynchronously;
            // enforcement applies immediately either way.
            if let Some(active) = active.as_mut() {
                active.spec.resources.cpus = target;
                persist_active_config(
                    &self.backend,
                    control_session(&session)?,
                    &mut active_json,
                    active,
                )
                .await?;
            }
        }
        if !restart_required && let Some(target_mib) = live_memory_target(&plan, &self.patch) {
            let state = control_session(&session)?
                .request(&SetMemoryTarget {
                    total_mib: u64::from(target_mib),
                })
                .await
                .map_err(crate::MicrosandboxError::ControlClient)?;
            plan.resize_status.push(ResourceResizeStatus {
                resource: ResourceKind::Memory,
                requested: format_mib(target_mib),
                actual: format_mib(state.current_mib as u32),
                enforced: format_mib(state.target_mib as u32),
                state: if state.current_mib >= state.target_mib {
                    ResourceConvergenceState::Applied
                } else {
                    ResourceConvergenceState::Converging
                },
            });
            // Refresh the active snapshot with the accepted target so inspect
            // does not report the already-live change as pending. Convergence
            // (plugging blocks) continues asynchronously in the guest.
            if let Some(active) = active.as_mut() {
                active.spec.resources.memory_mib = state.target_mib as u32;
                persist_active_config(
                    &self.backend,
                    control_session(&session)?,
                    &mut active_json,
                    active,
                )
                .await?;
            }
        }
        if !restart_required {
            let updates = live_secret_updates(&plan, &self.patch)?;
            if !updates.is_empty() {
                control_secrets_update(control_session(&session)?, updates).await?;
                // The running network layer changed: mirror the secret patch
                // into the active snapshot so inspect does not report the
                // already-live change as pending.
                if let Some(active) = active.as_mut() {
                    active.update_secrets(&self.patch)?;
                    persist_active_config(
                        &self.backend,
                        control_session(&session)?,
                        &mut active_json,
                        active,
                    )
                    .await?;
                }
            }
        }
        if running_status(status)
            && !restart_required
            && self.policy == ModificationPolicy::NoRestart
            && let Some(target_mib) = root_disk_grow_target(&plan, &self.patch, &config)
        {
            let size_bytes = u64::from(target_mib) * 1024 * 1024;
            let observed = control_session(&session)?
                .request(&GrowRootDisk(
                    microsandbox_protocol::control::RootDiskGrow { size_bytes },
                ))
                .await
                .map_err(crate::MicrosandboxError::ControlClient)?;
            if observed.filesystem_bytes != size_bytes || observed.device_bytes < size_bytes {
                return Err(crate::MicrosandboxError::Runtime(
                    "root growth did not confirm usable capacity".into(),
                ));
            }
            if let Some(active) = active.as_mut() {
                let disk_patch = SandboxModificationPatch {
                    root_disk_size_mib: Some(target_mib),
                    ..Default::default()
                };
                active.apply_modification(&disk_patch);
                persist_active_config(
                    &self.backend,
                    control_session(&session)?,
                    &mut active_json,
                    active,
                )
                .await?;
            }
        }
        // Grow the real upper.ext4 before persisting the new desired size:
        // the persisted value may only ever claim capacity the file actually
        // has. A running sandbox under `--next-start` keeps its mounted upper
        // untouched; the pre-boot preparation step grows it on the next start.
        if let Some(target_mib) = root_disk_grow_target(&plan, &self.patch, &config)
            && (stopped_status(status) || restart_required)
        {
            grow_root_disk_now(&self.backend, &self.name, &config, target_mib).await?;
        }
        if !plan.changes.is_empty() {
            config.apply_modification(&self.patch);
            config.update_secrets(&self.patch)?;
            let active_labels = if !restart_required && has_live_label_change(&plan) {
                let (Some(active), Some(expected_json)) = (active.as_mut(), active_json.clone())
                else {
                    return Err(MicrosandboxError::ControlStateChanged);
                };
                active.update_labels(&self.patch);
                Some(ActiveLabelsUpdate {
                    expected_json,
                    active_config_json: serde_json::to_string(active)?,
                })
            } else {
                None
            };
            persist_config(&self.backend, &handle, &config, active_labels).await?;
        }
        if restart_required {
            start_after_modify(&handle).await?;
        }
        plan.applied = true;
        Ok(plan)
    }
}

impl SecretPatchBuilder {
    fn new() -> Self {
        Self::default()
    }

    /// Name the secret (required). This is the environment variable that
    /// exposes the placeholder inside the guest.
    pub fn env(mut self, name: impl Into<String>) -> Self {
        self.spec.name = name.into();
        self
    }

    /// Provide the secret material as a raw value (mutually exclusive with
    /// [`source`](Self::source)), for embedders that hold only a value.
    ///
    /// The value rides in the in-process patch only: it is zeroized on drop,
    /// redacted from `Debug` output, and never enters the plan. Applying a
    /// value persists it into the durable config — the same at-rest property
    /// as create's `secret_env` — until a later source-based rotate migrates
    /// the entry to a reference.
    pub fn value(mut self, value: impl Into<String>) -> Self {
        self.spec.value = zeroize::Zeroizing::new(value.into());
        self
    }

    /// Provide the secret material as a host-side source reference (mutually
    /// exclusive with [`value`](Self::value)). The durable config records
    /// only the reference; the value is resolved host-side when needed.
    pub fn source(mut self, source: SecretSource) -> Self {
        self.spec.source = Some(source);
        self
    }

    /// Set the guest-visible placeholder. New secrets default to
    /// `$MSB_<env_var>`, matching create-time secret configuration.
    /// Placeholder changes cannot reach already-running processes, so they
    /// classify as restart-required on a running sandbox.
    pub fn placeholder(mut self, placeholder: impl Into<String>) -> Self {
        self.spec.placeholder = Some(placeholder.into());
        self
    }

    /// Add an allowed host pattern (`api.example.com`, `*.example.org`, or
    /// `*`). A non-empty list replaces the secret's current allow-list; an
    /// empty list leaves it unchanged.
    pub fn allow(mut self, host: impl Into<String>) -> Self {
        self.spec.allowed_hosts.push(host.into());
        self
    }

    /// Replace the request locations where substitution is enabled.
    pub fn substitution(mut self, value: SecretSubstitution) -> Self {
        self.spec.substitution = Some(value);
        self
    }

    /// Add a host allowed to receive the unchanged placeholder where substitution does not apply.
    pub fn allow_placeholder_for(mut self, host: impl Into<String>) -> Self {
        self.spec.passthrough_hosts.push(host.into());
        self
    }

    /// Deprecated alias for [`allow_placeholder_for`](Self::allow_placeholder_for).
    #[deprecated(note = "use allow_placeholder_for instead")]
    pub fn allow_passthrough_for(self, host: impl Into<String>) -> Self {
        self.allow_placeholder_for(host)
    }

    /// Set the per-secret blocking action.
    pub fn violation_action(mut self, value: SecretViolationAction) -> Self {
        self.spec.violation_action = Some(value);
        self
    }

    /// Set whether substitution requires verified TLS identity.
    pub fn require_tls_identity(mut self, value: bool) -> Self {
        self.spec.require_tls_identity = Some(value);
        self
    }

    fn build(self) -> SecretModificationPatch {
        self.spec
    }
}

impl SandboxConfig {
    /// Apply planned settings to this config and update the saved caller overrides.
    ///
    /// Only changed fields are recorded, so unrelated inherited defaults remain
    /// free to change on rebuild. Secret changes are applied separately. This
    /// updates configuration in memory; it does not persist it or change the VM.
    fn apply_modification(&mut self, patch: &SandboxModificationPatch) {
        let config_patch = self.config_patch_for_modification(patch);
        config_patch.clone().apply_to(self);

        // Effective resource targets must fit even when their maximum is inherited.
        self.spec.resources.max_cpus = self.spec.resources.max_cpus.max(self.spec.resources.cpus);
        self.spec.resources.max_memory_mib = self
            .spec
            .resources
            .max_memory_mib
            .max(self.spec.resources.memory_mib);

        self.caller_config_overrides
            .get_or_insert_with(Default::default)
            .overlay_mut(config_patch);
    }

    /// Translate modification operations into values that can be applied and saved.
    ///
    /// Resolve removals and dependent settings against the current config. Keep
    /// this destructuring exhaustive so adding a modification field requires handling it
    /// here, or explicitly delegating it to a separate path such as secrets.
    fn config_patch_for_modification(
        &self,
        patch: &SandboxModificationPatch,
    ) -> super::SandboxConfigPatch {
        let SandboxModificationPatch {
            cpus,
            max_cpus,
            memory_mib,
            max_memory_mib,
            root_disk_size_mib,
            env,
            env_remove,
            labels,
            labels_remove,
            ports,
            ports_remove,
            workdir,
            // Secrets are validated and recorded by update_secrets.
            secrets: _,
            secrets_remove: _,
        } = patch;

        let mut result = super::SandboxConfigPatch::new();
        let spec = &mut result.spec;
        spec.resources.cpus = *cpus;
        spec.resources.memory_mib = *memory_mib;
        spec.runtime.workdir = workdir.clone().map(Some);

        // Keep a previously explicit maximum in sync when resizing raises it.
        // Otherwise leave inherited capacity out of the saved caller overrides.
        let saved = self.caller_config_overrides.as_deref();
        spec.resources.max_cpus = max_cpus
            .or_else(|| {
                cpus.and_then(|_| {
                    saved
                        .and_then(|saved| saved.spec.resources.max_cpus)
                        .map(|_| self.spec.resources.max_cpus)
                })
            })
            .map(|maximum| maximum.max(cpus.unwrap_or(self.spec.resources.cpus)));
        spec.resources.max_memory_mib = max_memory_mib
            .or_else(|| {
                memory_mib.and_then(|_| {
                    saved
                        .and_then(|saved| saved.spec.resources.max_memory_mib)
                        .map(|_| self.spec.resources.max_memory_mib)
                })
            })
            .map(|maximum| maximum.max(memory_mib.unwrap_or(self.spec.resources.memory_mib)));

        if let Some(size_mib) = root_disk_size_mib {
            let mut image = self.spec.image.clone();
            if let RootfsSource::Oci(oci) = &mut image {
                match &mut oci.root_disk {
                    Some(RootDisk::Managed { size_mib: size })
                    | Some(RootDisk::Tmpfs { size_mib: size })
                    | Some(RootDisk::Flat { size_mib: size, .. }) => *size = Some(*size_mib),
                    // The planner rejects resizing user-owned disk images.
                    Some(RootDisk::DiskImage { .. }) => {}
                    None => {
                        oci.root_disk = Some(RootDisk::Managed {
                            size_mib: Some(*size_mib),
                        })
                    }
                }
            }
            spec.image = Some(image);
        }

        if !env.is_empty() || !env_remove.is_empty() {
            let mut environment = self.spec.env.clone();
            for var in patched_env(patch) {
                let Some(last) = environment.iter().rposition(|entry| entry.key == var.key) else {
                    environment.push(var.clone());
                    continue;
                };
                // Preserve duplicates for unchanged values; otherwise update the
                // last entry (the one commands see) and remove earlier copies.
                if environment[last].value == var.value {
                    continue;
                }
                let mut rest = environment.split_off(last);
                rest[0].value = var.value.clone();
                environment.retain(|entry| entry.key != var.key);
                environment.append(&mut rest);
            }
            environment.retain(|entry| !env_remove.contains(&entry.key));
            spec.replace_env_mut(environment);
        }

        if !labels.is_empty() || !labels_remove.is_empty() {
            let mut updated = self.spec.labels.clone();
            updated.extend(labels.iter().cloned());
            updated.retain(|key, _| !labels_remove.contains(key));
            spec.replace_labels_mut(updated);
        }

        if !ports.is_empty() || !ports_remove.is_empty() {
            // The planner validated the complete resulting set before mutation.
            spec.network.ports = Some(ports::desired(self, patch));
        }

        result
    }

    /// Update labels in this config without recording overrides or persisting it.
    ///
    /// Also used for the running config when labels are applied live; the full
    /// modification path records caller overrides on the desired config.
    fn update_labels(&mut self, patch: &SandboxModificationPatch) {
        for (key, value) in &patch.labels {
            self.spec.labels.insert(key.clone(), value.clone());
        }
        for key in &patch.labels_remove {
            self.spec.labels.remove(key);
        }
    }

    /// Validate and apply secret changes, then record the resulting secret and TLS overrides.
    /// This updates configuration in memory; persistence and live delivery are separate.
    ///
    /// A source-based spec records the host-side reference and drops any
    /// previously inlined raw value; the value is resolved from the source at
    /// spawn time. A value-based spec persists the value into the entry — the
    /// documented at-rest property shared with create's `secret_env` — until a
    /// later source-based rotate migrates the entry to a reference.
    #[cfg(feature = "net")]
    fn update_secrets(&mut self, patch: &SandboxModificationPatch) -> MicrosandboxResult<()> {
        if patch.secrets.is_empty() && patch.secrets_remove.is_empty() {
            return Ok(());
        }

        let mut network = self.local_network_config()?;
        for spec in &patch.secrets {
            apply_secret_spec(&mut network.secrets, spec)?;
        }
        network
            .secrets
            .secrets
            .retain(|entry| !patch.secrets_remove.contains(&entry.env_var));

        // TLS-identity secrets require interception; deliberate plain-HTTP
        // secrets do not. This is one-way because TLS may have been enabled for
        // independent reasons.
        if !network.tls.enabled && network.secrets.has_tls_identity_secrets() {
            network.tls.enabled = true;
        }

        // Enforce env-var and placeholder shape rules before anything persists;
        // validation errors carry entry indexes and sizes, never values.
        network.secrets.validate().map_err(|err| {
            crate::MicrosandboxError::InvalidConfig(format!("invalid secret configuration: {err}"))
        })?;

        self.set_local_network_config(network)?;

        let caller_overrides = self
            .caller_config_overrides
            .get_or_insert_with(Default::default);
        caller_overrides.spec.network.secrets = self
            .spec
            .network
            .secrets
            .clone()
            .map(microsandbox_types::SecretsConfigPatch::from_present_fields);
        caller_overrides.spec.network.tls = self
            .spec
            .network
            .tls
            .clone()
            .map(microsandbox_types::TlsConfigPatch::from_present_fields);
        Ok(())
    }

    /// Accept an unchanged secret configuration; reject secret edits without networking support.
    #[cfg(not(feature = "net"))]
    fn update_secrets(&mut self, patch: &SandboxModificationPatch) -> MicrosandboxResult<()> {
        if patch.secrets.is_empty() && patch.secrets_remove.is_empty() {
            return Ok(());
        }
        Err(crate::MicrosandboxError::unsupported(
            Operation::SandboxModify,
            UnsupportedReason::RequiresCrateFeature("net"),
        ))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Classify requested changes as live, deferred, or conflicting without applying them.
/// Uses both desired and running settings, plus the runtime's available controls.
#[allow(clippy::too_many_arguments)]
fn build_plan(
    name: String,
    status: SandboxStatus,
    config: &SandboxConfig,
    active: Option<&SandboxConfig>,
    live: LiveControl,
    patch: SandboxModificationPatch,
    policy: ModificationPolicy,
) -> SandboxModificationPlan {
    let mut changes = Vec::new();
    let mut conflicts = Vec::new();
    let mut warnings = Vec::new();

    push_resource_changes(
        status,
        config,
        active,
        live,
        &patch,
        policy,
        &mut changes,
        &mut warnings,
    );
    push_root_disk_size_change(status, config, &patch, policy, &mut changes);
    if live.root_disk_grow
        && running_status(status)
        && policy == ModificationPolicy::NoRestart
        && matches!(
            root_disk_size_state(config),
            Some(RootDiskSizeState::Managed { .. })
        )
    {
        for change in &mut changes {
            if let PlannedChange::Config(change) = change
                && change.field == ROOT_DISK_FIELD
            {
                change.disposition = ModificationDisposition::Live;
                change.reason = None;
            }
        }
    }
    push_spec_changes(
        status,
        config,
        active,
        &patch,
        policy,
        &mut changes,
        &mut warnings,
    );
    ports::plan(
        status,
        config,
        active,
        &patch,
        policy,
        &mut changes,
        &mut conflicts,
    );
    push_secret_changes(
        status,
        config,
        active,
        live.secrets,
        &patch,
        policy,
        &mut changes,
        &mut warnings,
    );
    push_resource_conflicts(config, &patch, &mut conflicts);
    push_root_disk_size_conflicts(config, &patch, &mut conflicts);
    push_spec_conflicts(&patch, &mut conflicts);
    push_secret_conflicts(config, &patch, &mut conflicts);

    SandboxModificationPlan {
        sandbox: name,
        status: status_name(status).to_string(),
        applied: false,
        policy,
        changes,
        conflicts,
        warnings,
        resize_status: Vec::new(),
    }
}

/// The live CPU target, when the plan classified the `cpus` change as live.
fn live_cpu_target(plan: &SandboxModificationPlan, patch: &SandboxModificationPatch) -> Option<u8> {
    let live_cpus = plan.changes.iter().any(|change| {
        matches!(
            change,
            PlannedChange::Config(change)
                if change.field == "cpus"
                    && matches!(change.disposition, ModificationDisposition::Live)
        )
    });
    if live_cpus { patch.cpus } else { None }
}

/// The live memory target in MiB, when the plan classified `memory` as live.
fn live_memory_target(
    plan: &SandboxModificationPlan,
    patch: &SandboxModificationPatch,
) -> Option<u32> {
    let live_memory = plan.changes.iter().any(|change| {
        matches!(
            change,
            PlannedChange::Config(change)
                if change.field == "memory"
                    && matches!(change.disposition, ModificationDisposition::Live)
        )
    });
    if live_memory { patch.memory_mib } else { None }
}

/// The host-side grow target in MiB, when the plan carries a root disk size
/// change for the managed kind. Tmpfs sizes are config-only (the guest
/// assembles the tmpfs at boot) and disk-image sizes never plan a change, so
/// neither ever grows a host file.
fn root_disk_grow_target(
    plan: &SandboxModificationPlan,
    patch: &SandboxModificationPatch,
    config: &SandboxConfig,
) -> Option<u32> {
    let planned = plan.changes.iter().any(|change| {
        matches!(
            change,
            PlannedChange::Config(change) if change.field == ROOT_DISK_FIELD
        )
    });
    if planned
        && matches!(
            root_disk_size_state(config),
            Some(RootDiskSizeState::Managed { .. })
        )
    {
        patch.root_disk_size_mib
    } else {
        None
    }
}

/// Grow the sandbox-owned layered upper or flat root disk while it is stopped.
async fn grow_root_disk_now(
    backend: &Arc<dyn Backend>,
    name: &str,
    config: &SandboxConfig,
    target_mib: u32,
) -> MicrosandboxResult<()> {
    let local_backend = backend.as_local().ok_or_else(|| {
        crate::MicrosandboxError::unsupported(
            Operation::SandboxModify,
            UnsupportedReason::LocalOnly,
        )
    })?;
    let sandbox_dir = local_backend.sandboxes_dir().join(name);
    let runtime_dir = sandbox_dir.join("runtime");
    let handled = tokio::task::spawn_blocking(move || {
        microsandbox_runtime::checkpoint::grow_stopped_root(
            &runtime_dir,
            u64::from(target_mib) * 1024 * 1024,
        )
    })
    .await
    .map_err(|e| crate::MicrosandboxError::Runtime(e.to_string()))?
    .map_err(crate::MicrosandboxError::Runtime)?;
    if handled {
        return Ok(());
    }
    if !config.snapshot_upper_layers.is_empty() {
        return Err(crate::MicrosandboxError::Runtime(
            "start this restored sandbox once to initialize its owned root chain before resizing"
                .into(),
        ));
    }
    if matches!(
        &config.spec.image,
        RootfsSource::Oci(oci) if matches!(&oci.root_disk, Some(RootDisk::Flat { .. }))
    ) {
        return super::flat_rootfs::grow_private_flat_rootfs(
            sandbox_dir.join(super::flat_rootfs::FLAT_ROOTFS_FILENAME),
            target_mib,
        )
        .await;
    }
    super::upper::grow_upper_to_mib(sandbox_dir.join("upper.ext4"), target_mib).await
}

/// Discover which live-control operations the running sandbox serves.
async fn live_control(
    backend: &Arc<dyn Backend>,
    name: &str,
    status: SandboxStatus,
    patch: &SandboxModificationPatch,
    policy: ModificationPolicy,
) -> MicrosandboxResult<(LiveControl, Option<ControlSession>)> {
    let needs_control = patch.root_disk_size_mib.is_some()
        || patch.cpus.is_some()
        || patch.memory_mib.is_some()
        || !patch.secrets.is_empty()
        || !patch.secrets_remove.is_empty();
    if !running_status(status) || !needs_control || policy == ModificationPolicy::NextStart {
        return Ok((LiveControl::default(), None));
    }
    let Some(local) = backend.as_local() else {
        return Ok((LiveControl::default(), None));
    };
    let Some(session) = local.control_session(name).await? else {
        return Ok((LiveControl::default(), None));
    };
    let caps = session.capabilities();
    Ok((
        LiveControl {
            root_disk_grow: caps.root_disk_grow,
            cpu_resize: caps.cpu_resize,
            memory_resize: caps.memory_resize,
            secrets: caps.secrets_update,
        },
        Some(session),
    ))
}

fn control_session(session: &Option<ControlSession>) -> MicrosandboxResult<&ControlSession> {
    session.as_ref().ok_or_else(|| {
        crate::MicrosandboxError::ControlClient(Arc::new(
            microsandbox_control_client::ControlClientError::RuntimeChanged,
        ))
    })
}

/// Send the value-bearing live secret batch to the sandbox process. The
/// request travels only over the private per-sandbox control endpoint and is
/// never logged; failures surface the runtime's error, which carries secret
/// names only.
async fn control_secrets_update(
    session: &ControlSession,
    changes: Vec<microsandbox_runtime::control::SecretLiveChange>,
) -> MicrosandboxResult<()> {
    let changes = changes
        .into_iter()
        .map(|change| match change {
            microsandbox_runtime::control::SecretLiveChange::Rotate { name, value } => {
                microsandbox_protocol::control::SecretChange::Rotate {
                    name,
                    value: microsandbox_protocol::control::SecretValue(value.0.clone()),
                }
            }
            microsandbox_runtime::control::SecretLiveChange::Remove { name } => {
                microsandbox_protocol::control::SecretChange::Remove { name }
            }
            microsandbox_runtime::control::SecretLiveChange::SetAllowedHosts { name, hosts } => {
                microsandbox_protocol::control::SecretChange::SetAllowedHosts { name, hosts }
            }
        })
        .collect();
    match session
        .request(&UpdateSecrets::new(changes))
        .await
        .map_err(crate::MicrosandboxError::ControlClient)?
    {
        SecretsResult::Complete { .. } => Ok(()),
        SecretsResult::Failed {
            applied_count,
            failed_index,
            error,
        } => Err(crate::MicrosandboxError::ControlSecretBatch {
            applied_count,
            failed_index,
            error,
        }),
    }
}

fn validate_apply_supported(plan: &SandboxModificationPlan) -> MicrosandboxResult<()> {
    if let Some(conflict) = plan.conflicts.first() {
        return Err(crate::MicrosandboxError::Custom(format!(
            "cannot apply modification: {}",
            conflict.message
        )));
    }

    for change in &plan.changes {
        match change {
            PlannedChange::Config(change) => {
                if matches!(change.disposition, ModificationDisposition::Unsupported) {
                    return Err(crate::MicrosandboxError::Custom(format!(
                        "cannot apply modification: {} is unsupported",
                        change.field
                    )));
                }
                if matches!(change.disposition, ModificationDisposition::RequiresRestart) {
                    if plan.policy == ModificationPolicy::Restart {
                        continue;
                    }
                    return Err(crate::MicrosandboxError::Custom(format!(
                        "cannot apply modification: {} requires restart",
                        change.field
                    )));
                }
            }
            PlannedChange::Secret(change) => {
                if matches!(change.disposition, ModificationDisposition::Unsupported) {
                    let reason = change
                        .reason
                        .as_deref()
                        .map(|reason| format!(" ({reason})"))
                        .unwrap_or_default();
                    return Err(crate::MicrosandboxError::Custom(format!(
                        "cannot apply modification: secret {} is unsupported{reason}",
                        change.name
                    )));
                }
                if matches!(change.disposition, ModificationDisposition::RequiresRestart) {
                    if plan.policy == ModificationPolicy::Restart {
                        continue;
                    }
                    return Err(crate::MicrosandboxError::Custom(format!(
                        "cannot apply modification: secret {} requires restart",
                        change.name
                    )));
                }
            }
        }
    }

    Ok(())
}

fn plan_requires_restart(plan: &SandboxModificationPlan) -> bool {
    plan.changes.iter().any(|change| match change {
        PlannedChange::Config(change) => {
            matches!(change.disposition, ModificationDisposition::RequiresRestart)
        }
        PlannedChange::Secret(change) => {
            matches!(change.disposition, ModificationDisposition::RequiresRestart)
        }
    })
}

fn has_live_label_change(plan: &SandboxModificationPlan) -> bool {
    plan.changes.iter().any(|change| {
        matches!(
            change,
            PlannedChange::Config(change)
                if change.field == LABEL_FIELD
                    && change.disposition == ModificationDisposition::Live
        )
    })
}

/// Secret material carried by one spec: a raw value or a source reference.
#[cfg(feature = "net")]
enum SecretMaterial {
    Value(zeroize::Zeroizing<String>),
    Source(SecretSource),
}

/// Extract the material from a spec, enforcing the value/source exclusivity
/// and the store-source gap. Errors carry the secret name only.
#[cfg(feature = "net")]
fn secret_material(spec: &SecretModificationPatch) -> MicrosandboxResult<Option<SecretMaterial>> {
    if !spec.value.is_empty() {
        if spec.source.is_some() {
            return Err(crate::MicrosandboxError::Custom(format!(
                "secret {}: value and source are mutually exclusive",
                spec.name
            )));
        }
        return Ok(Some(SecretMaterial::Value(spec.value.clone())));
    }
    match &spec.source {
        Some(source @ SecretSource::Env { .. }) => Ok(Some(SecretMaterial::Source(source.clone()))),
        Some(SecretSource::Store { .. }) => Err(crate::MicrosandboxError::Custom(format!(
            "secret {}: store-backed secret sources are not supported yet",
            spec.name
        ))),
        None => Ok(None),
    }
}

#[cfg(feature = "net")]
fn apply_secret_spec(
    secrets: &mut microsandbox_network::secrets::config::SecretsConfig,
    spec: &SecretModificationPatch,
) -> MicrosandboxResult<()> {
    use microsandbox_network::secrets::config::SecretEntry;

    let material = secret_material(spec)?;
    if let Some(entry) = secrets
        .secrets
        .iter_mut()
        .find(|entry| entry.env_var == spec.name)
    {
        match material {
            Some(SecretMaterial::Value(value)) => {
                entry.value = value;
                entry.source = None;
            }
            Some(SecretMaterial::Source(source)) => {
                entry.value = zeroize::Zeroizing::new(String::new());
                entry.source = Some(source);
            }
            None => {}
        }
        if let Some(placeholder) = &spec.placeholder {
            entry.placeholder = placeholder.clone();
        }
        if !spec.allowed_hosts.is_empty() {
            entry.allowed_hosts = parse_host_patterns(&spec.allowed_hosts);
        }
        if let Some(substitution) = &spec.substitution {
            entry.substitution = substitution.clone();
        }
        if !spec.passthrough_hosts.is_empty() {
            entry.passthrough_hosts = parse_host_patterns(&spec.passthrough_hosts);
        }
        if let Some(action) = &spec.violation_action {
            entry.violation_action = Some(action.clone());
        }
        if let Some(required) = spec.require_tls_identity {
            entry.require_tls_identity = required;
        }
    } else {
        let (value, source) = match material {
            Some(SecretMaterial::Value(value)) => (value, None),
            Some(SecretMaterial::Source(source)) => {
                (zeroize::Zeroizing::new(String::new()), Some(source))
            }
            None => {
                return Err(crate::MicrosandboxError::Custom(format!(
                    "secret {} needs a host-side source or value to add",
                    spec.name
                )));
            }
        };
        secrets.secrets.push(SecretEntry {
            env_var: spec.name.clone(),
            value,
            source,
            placeholder: spec
                .placeholder
                .clone()
                .unwrap_or_else(|| microsandbox_utils::secret::default_placeholder(&spec.name)),
            allowed_hosts: parse_host_patterns(&spec.allowed_hosts),
            substitution: spec.substitution.clone().unwrap_or_default(),
            passthrough_hosts: parse_host_patterns(&spec.passthrough_hosts),
            violation_action: spec.violation_action.clone(),
            require_tls_identity: spec.require_tls_identity.unwrap_or(true),
        });
    }
    Ok(())
}

#[cfg(feature = "net")]
fn parse_host_patterns(
    hosts: &[String],
) -> Vec<microsandbox_network::secrets::config::HostPattern> {
    hosts
        .iter()
        .map(|host| microsandbox_network::secrets::config::HostPattern::parse(host))
        .collect()
}

/// Build the value-bearing live batch for secret changes the plan classified
/// as live. Rotation material resolves here, in the caller's process: a
/// caller-supplied value is passed through as-is, a source reference is
/// resolved host-side. Either way the value goes straight to the control
/// socket and never into the plan or logs.
fn live_secret_updates(
    plan: &SandboxModificationPlan,
    patch: &SandboxModificationPatch,
) -> MicrosandboxResult<Vec<microsandbox_runtime::control::SecretLiveChange>> {
    use microsandbox_runtime::control::{SecretLiveChange, SecretValue};

    let spec_for = |name: &str| {
        patch
            .secrets
            .iter()
            .find(|spec| spec.name == name)
            .ok_or_else(|| {
                crate::MicrosandboxError::Runtime(format!(
                    "planned secret change for {name} has no matching patch spec"
                ))
            })
    };

    let mut updates = Vec::new();
    for change in &plan.changes {
        let PlannedChange::Secret(planned) = change else {
            continue;
        };
        if !matches!(planned.disposition, ModificationDisposition::Live) {
            continue;
        }
        match planned.change {
            SecretChangeKind::Rotated => {
                let spec = spec_for(&planned.name)?;
                let value = resolve_secret_value(spec)?;
                updates.push(SecretLiveChange::Rotate {
                    name: spec.name.clone(),
                    value: SecretValue(value),
                });
                // A rotate request may carry new hosts (for example
                // `--secret NAME@HOST[,HOST...]` on an existing secret);
                // apply them in the same batch.
                if !spec.allowed_hosts.is_empty() {
                    updates.push(SecretLiveChange::SetAllowedHosts {
                        name: spec.name.clone(),
                        hosts: spec.allowed_hosts.clone(),
                    });
                }
            }
            SecretChangeKind::Removed => {
                updates.push(SecretLiveChange::Remove {
                    name: planned.name.clone(),
                });
            }
            SecretChangeKind::HostsUpdated => {
                let spec = spec_for(&planned.name)?;
                updates.push(SecretLiveChange::SetAllowedHosts {
                    name: spec.name.clone(),
                    hosts: spec.allowed_hosts.clone(),
                });
            }
            // Added, renamed, and placeholder changes never classify live.
            SecretChangeKind::Added
            | SecretChangeKind::Renamed
            | SecretChangeKind::PlaceholderUpdated => {}
        }
    }
    Ok(updates)
}

/// Resolve a spec's material into the value sent over the control socket.
/// A caller-supplied value wins; otherwise the source reference resolves
/// host-side. Errors name the secret and the source reference only.
fn resolve_secret_value(spec: &SecretModificationPatch) -> MicrosandboxResult<String> {
    if !spec.value.is_empty() {
        return Ok(spec.value.as_str().to_owned());
    }
    resolve_secret_source_value(&spec.name, spec.source.as_ref())
}

/// Resolve a secret source into its value at apply time. Errors name the
/// secret and the source reference; they never carry values.
fn resolve_secret_source_value(
    name: &str,
    source: Option<&SecretSource>,
) -> MicrosandboxResult<String> {
    match source {
        Some(SecretSource::Env { var }) => {
            let value = std::env::var(var).map_err(|_| {
                crate::MicrosandboxError::InvalidConfig(format!(
                    "secret {name}: host environment variable {var} is not set"
                ))
            })?;
            if value.is_empty() {
                return Err(crate::MicrosandboxError::InvalidConfig(format!(
                    "secret {name}: host environment variable {var} is empty"
                )));
            }
            Ok(value)
        }
        Some(SecretSource::Store { .. }) => Err(crate::MicrosandboxError::Custom(format!(
            "secret {name}: store-backed secret sources are not supported yet"
        ))),
        None => Err(crate::MicrosandboxError::Custom(format!(
            "secret {name} needs a host-side source or value to rotate"
        ))),
    }
}

/// Save the desired config, its caller overrides, and searchable labels in one transaction.
///
/// With `active_labels`, also replace `active_config`, but only while the
/// sandbox is running or draining and `active_config` still equals
/// `expected_json`; otherwise the transaction rolls back and returns
/// [`MicrosandboxError::ControlStateChanged`].
async fn persist_config(
    backend: &Arc<dyn Backend>,
    handle: &super::SandboxHandle,
    config: &SandboxConfig,
    active_labels: Option<ActiveLabelsUpdate>,
) -> MicrosandboxResult<()> {
    let local = handle
        .local()
        .ok_or_else(|| crate::MicrosandboxError::local_only(Operation::SandboxModify))?;
    let local_backend = backend
        .as_local()
        .ok_or_else(|| crate::MicrosandboxError::local_only(Operation::SandboxModify))?;

    let labels = config.spec.labels.clone();
    let write_db = local_backend.db().await?.write();
    let config_json = serde_json::to_string(config)?;
    let caller_config_overrides_json = config.caller_config_overrides_json(&config_json)?;

    write_db
        .transaction(|txn| {
            let config_json = config_json.clone();
            let labels = labels.clone();
            let active_labels = active_labels.as_ref();
            let caller_config_overrides_json = caller_config_overrides_json.clone();

            async move {
                sandbox_entity::Entity::update_many()
                    .col_expr(sandbox_entity::Column::Config, Expr::value(config_json))
                    .col_expr(
                        sandbox_entity::Column::CallerConfigOverrides,
                        Expr::value(caller_config_overrides_json),
                    )
                    .col_expr(
                        sandbox_entity::Column::UpdatedAt,
                        Expr::value(chrono::Utc::now().naive_utc()),
                    )
                    .filter(sandbox_entity::Column::Id.eq(local.db_id))
                    .exec(&txn)
                    .await?;

                sandbox_label_entity::Entity::delete_many()
                    .filter(sandbox_label_entity::Column::SandboxId.eq(local.db_id))
                    .exec(&txn)
                    .await?;
                if !labels.is_empty() {
                    sandbox_label_entity::Entity::insert_many(labels.into_iter().map(
                        |(key, value)| sandbox_label_entity::ActiveModel {
                            sandbox_id: Set(local.db_id),
                            key: Set(key),
                            value: Set(value),
                        },
                    ))
                    .exec(&txn)
                    .await?;
                }

                if let Some(active_labels) = active_labels {
                    let result = sandbox_entity::Entity::update_many()
                        .col_expr(
                            sandbox_entity::Column::ActiveConfig,
                            Expr::value(active_labels.active_config_json.clone()),
                        )
                        .col_expr(
                            sandbox_entity::Column::UpdatedAt,
                            Expr::value(chrono::Utc::now().naive_utc()),
                        )
                        .filter(sandbox_entity::Column::Id.eq(local.db_id))
                        .filter(
                            sandbox_entity::Column::Status
                                .is_in([SandboxStatus::Running, SandboxStatus::Draining]),
                        )
                        .filter(
                            sandbox_entity::Column::ActiveConfig
                                .eq(active_labels.expected_json.clone()),
                        )
                        .exec(&txn)
                        .await?;
                    if result.rows_affected != 1 {
                        return Err(MicrosandboxError::ControlStateChanged);
                    }
                }

                Ok((txn, ()))
            }
        })
        .await
}

/// Save the running config through its control session and advance the expected JSON.
/// The session checks that the run and previously observed config still match.
async fn persist_active_config(
    backend: &Arc<dyn Backend>,
    session: &ControlSession,
    expected: &mut Option<String>,
    active: &SandboxConfig,
) -> MicrosandboxResult<()> {
    let local_backend = backend
        .as_local()
        .ok_or_else(|| crate::MicrosandboxError::local_only(Operation::SandboxModify))?;
    let json = session
        .persist_active_config(
            local_backend.db().await?.write(),
            expected.as_deref(),
            active,
        )
        .await?;
    *expected = Some(json);
    Ok(())
}

async fn start_after_modify(handle: &super::SandboxHandle) -> MicrosandboxResult<()> {
    let sandbox = handle.refresh().await?.start_detached().await?;
    sandbox.detach().await;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_resource_changes(
    status: SandboxStatus,
    config: &SandboxConfig,
    active: Option<&SandboxConfig>,
    live_control: LiveControl,
    patch: &SandboxModificationPatch,
    policy: ModificationPolicy,
    changes: &mut Vec<PlannedChange>,
    warnings: &mut Vec<ModificationWarning>,
) {
    let resources = &config.spec.resources;
    let desired = desired_resources(config, patch);

    if let Some(cpus) = patch.cpus
        && cpus != resources.cpus
    {
        // CPUs change live when the target fits inside the capacity the running
        // VM actually booted with. The active config snapshot is the authority;
        // older runtimes without one classify as restart-required.
        let active_max_cpus = active.map(|active| active.spec.resources.max_cpus);
        let live = live_control.cpu_resize && active_max_cpus.is_some_and(|max| cpus <= max);
        let reason = match (resource_disposition(status, policy, live), active_max_cpus) {
            (ModificationDisposition::RequiresRestart, Some(max)) if cpus > max => Some(format!(
                "cpus {cpus} exceeds the active max capacity {max}; restart with a larger max_cpus"
            )),
            _ => resource_reason(status, policy, live),
        };
        changes.push(PlannedChange::Config(ConfigPlannedChange {
            field: "cpus".to_string(),
            change: ChangeKind::Updated,
            before: Some(resources.cpus.to_string()),
            after: Some(cpus.to_string()),
            disposition: resource_disposition(status, policy, live),
            reason,
        }));
        push_live_resize_warning("cpus", status, policy, live, warnings);
    }

    if desired.max_cpus != resources.max_cpus
        && (patch.max_cpus.is_some() || desired.max_cpus > resources.max_cpus)
    {
        changes.push(PlannedChange::Config(ConfigPlannedChange {
            field: "max_cpus".to_string(),
            change: ChangeKind::Updated,
            before: Some(resources.max_cpus.to_string()),
            after: Some(desired.max_cpus.to_string()),
            disposition: boot_capacity_disposition(status, policy),
            reason: boot_capacity_reason(status, policy, "max_cpus"),
        }));
    }

    if let Some(memory_mib) = patch.memory_mib
        && memory_mib != resources.memory_mib
    {
        // Memory changes live through virtio-mem when the target fits inside
        // the active hotpluggable capacity AND the running sandbox exposes a
        // runtime control capability for memory resize.
        let active_max_memory = active.map(|active| active.spec.resources.max_memory_mib);
        let live =
            live_control.memory_resize && active_max_memory.is_some_and(|max| memory_mib <= max);
        let reason = match (
            resource_disposition(status, policy, live),
            active_max_memory,
        ) {
            (ModificationDisposition::RequiresRestart, Some(max)) if memory_mib > max => {
                Some(format!(
                    "memory {} exceeds the active max capacity {}; restart with a larger max_memory",
                    format_mib(memory_mib),
                    format_mib(max)
                ))
            }
            _ => resource_reason(status, policy, live),
        };
        changes.push(PlannedChange::Config(ConfigPlannedChange {
            field: "memory".to_string(),
            change: ChangeKind::Updated,
            before: Some(format_mib(resources.memory_mib)),
            after: Some(format_mib(memory_mib)),
            disposition: resource_disposition(status, policy, live),
            reason,
        }));
        push_live_resize_warning("memory", status, policy, live, warnings);
    }

    if desired.max_memory_mib != resources.max_memory_mib
        && (patch.max_memory_mib.is_some() || desired.max_memory_mib > resources.max_memory_mib)
    {
        changes.push(PlannedChange::Config(ConfigPlannedChange {
            field: "max_memory".to_string(),
            change: ChangeKind::Updated,
            before: Some(format_mib(resources.max_memory_mib)),
            after: Some(format_mib(desired.max_memory_mib)),
            disposition: boot_capacity_disposition(status, policy),
            reason: boot_capacity_reason(status, policy, "max_memory"),
        }));
    }
}

/// Plan the OCI upper grow. The persisted size is only the desired state; the
/// real state is the `upper.ext4` file, so apply grows the file before
/// persisting (stopped or restart-backed), and a running `--next-start`
/// request defers the grow to the pre-boot preparation step. Never live: the
/// upper is mounted by overlayfs while the sandbox runs.
fn push_root_disk_size_change(
    status: SandboxStatus,
    config: &SandboxConfig,
    patch: &SandboxModificationPatch,
    policy: ModificationPolicy,
    changes: &mut Vec<PlannedChange>,
) {
    let Some(target_mib) = patch.root_disk_size_mib else {
        return;
    };
    let (before, after) = match root_disk_size_state(config) {
        // Non-OCI rootfs and user-owned disk images surface as conflicts,
        // not changes.
        None | Some(RootDiskSizeState::DiskImage) => return,
        Some(RootDiskSizeState::Managed { current_mib }) => {
            // Shrink and same-size requests are conflicts, pushed separately.
            if target_mib <= current_mib {
                return;
            }
            (Some(format_mib(current_mib)), format_mib(target_mib))
        }
        Some(RootDiskSizeState::Tmpfs { current_mib }) => {
            // Ephemeral content: any size change is fine, applied next boot.
            // Same-size and over-memory requests are conflicts, pushed
            // separately.
            if current_mib == Some(target_mib)
                || target_mib > patch.memory_mib.unwrap_or(config.spec.resources.memory_mib)
            {
                return;
            }
            (current_mib.map(format_mib), format_mib(target_mib))
        }
    };
    changes.push(PlannedChange::Config(ConfigPlannedChange {
        field: ROOT_DISK_FIELD.to_string(),
        change: ChangeKind::Updated,
        before,
        after: Some(after),
        disposition: boot_capacity_disposition(status, policy),
        reason: upper_size_reason(status, policy),
    }));
}

fn upper_size_reason(status: SandboxStatus, policy: ModificationPolicy) -> Option<String> {
    match boot_capacity_disposition(status, policy) {
        ModificationDisposition::RequiresRestart => Some(UPPER_LIVE_RESIZE_UNAVAILABLE.to_string()),
        ModificationDisposition::NextStart if running_status(status) => {
            Some(UPPER_GROWS_ON_NEXT_START.to_string())
        }
        ModificationDisposition::Unsupported => Some(format!(
            "cannot modify while sandbox is {}",
            status_name(status)
        )),
        _ => None,
    }
}

/// Reject root disk size requests that can never apply: a non-OCI rootfs has
/// no root disk; a disk-image root disk is user-owned; managed shrink (or
/// same-size) is unsupported in v1 because the upper is a real filesystem
/// image where shrinking risks data loss; and a tmpfs size must fit in guest
/// memory.
fn push_root_disk_size_conflicts(
    config: &SandboxConfig,
    patch: &SandboxModificationPatch,
    conflicts: &mut Vec<ModificationConflict>,
) {
    let Some(target_mib) = patch.root_disk_size_mib else {
        return;
    };
    match root_disk_size_state(config) {
        None => {
            conflicts.push(ModificationConflict {
                field: ROOT_DISK_FIELD.to_string(),
                message: "root disk size requires an OCI rootfs".to_string(),
            });
        }
        Some(RootDiskSizeState::DiskImage) => {
            conflicts.push(ModificationConflict {
                field: ROOT_DISK_FIELD.to_string(),
                message:
                    "the root disk is a user-supplied disk image; its size is determined by the image file"
                        .to_string(),
            });
        }
        Some(RootDiskSizeState::Managed { current_mib }) => {
            if target_mib < current_mib {
                conflicts.push(ModificationConflict {
                    field: ROOT_DISK_FIELD.to_string(),
                    message: format!(
                        "root disk size {} is smaller than the current {}; shrink is not supported (recreate the sandbox instead)",
                        format_mib(target_mib),
                        format_mib(current_mib)
                    ),
                });
            } else if target_mib == current_mib {
                conflicts.push(ModificationConflict {
                    field: ROOT_DISK_FIELD.to_string(),
                    message: format!(
                        "root disk size is already {}; only grow is supported",
                        format_mib(current_mib)
                    ),
                });
            }
        }
        Some(RootDiskSizeState::Tmpfs { current_mib }) => {
            // Compare against the desired end-state memory when the same
            // patch also resizes memory.
            let memory_mib = patch.memory_mib.unwrap_or(config.spec.resources.memory_mib);
            if target_mib > memory_mib {
                conflicts.push(ModificationConflict {
                    field: ROOT_DISK_FIELD.to_string(),
                    message: format!(
                        "tmpfs root disk size {} must not exceed sandbox memory ({})",
                        format_mib(target_mib),
                        format_mib(memory_mib)
                    ),
                });
            } else if current_mib == Some(target_mib) {
                conflicts.push(ModificationConflict {
                    field: ROOT_DISK_FIELD.to_string(),
                    message: format!("root disk size is already {}", format_mib(target_mib)),
                });
            }
        }
    }
}

/// Size-relevant view of the configured root disk for an OCI rootfs.
enum RootDiskSizeState {
    /// Managed upper with its effective size (persisted value, or the
    /// create-time default for configs that predate materialized defaults).
    Managed { current_mib: u32 },
    /// Tmpfs upper with its persisted size, if any.
    Tmpfs { current_mib: Option<u32> },
    /// User-supplied disk image: not sizable through modify.
    DiskImage,
}

fn root_disk_size_state(config: &SandboxConfig) -> Option<RootDiskSizeState> {
    let RootfsSource::Oci(oci) = &config.spec.image else {
        return None;
    };
    Some(match &oci.root_disk {
        None => RootDiskSizeState::Managed {
            current_mib: super::config::DEFAULT_OCI_UPPER_SIZE_MIB,
        },
        Some(RootDisk::Managed { size_mib }) => RootDiskSizeState::Managed {
            current_mib: size_mib.unwrap_or(super::config::DEFAULT_OCI_UPPER_SIZE_MIB),
        },
        Some(RootDisk::Flat { size_mib, .. }) => RootDiskSizeState::Managed {
            current_mib: size_mib.unwrap_or(super::config::DEFAULT_OCI_UPPER_SIZE_MIB),
        },
        Some(RootDisk::Tmpfs { size_mib }) => RootDiskSizeState::Tmpfs {
            current_mib: *size_mib,
        },
        Some(RootDisk::DiskImage { .. }) => RootDiskSizeState::DiskImage,
    })
}

#[allow(clippy::too_many_arguments)]
fn push_secret_changes(
    status: SandboxStatus,
    config: &SandboxConfig,
    active: Option<&SandboxConfig>,
    live_secret_reconfigure_supported: bool,
    patch: &SandboxModificationPatch,
    policy: ModificationPolicy,
    changes: &mut Vec<PlannedChange>,
    warnings: &mut Vec<ModificationWarning>,
) {
    for spec in &patch.secrets {
        let existing = existing_secret(config, &spec.name);
        let policy_changed = secret_policy_changes(spec, existing.as_ref())
            || (running_status(status)
                && active.is_some_and(|active| {
                    secret_policy_changes(spec, existing_secret(active, &spec.name).as_ref())
                }));
        let Some(change) = infer_secret_change(spec, existing.as_ref()) else {
            if policy_changed {
                // Use the existing generic config-change contract: older SDKs
                // need no new SecretChangeKind variant to decode this plan.
                changes.push(spec_change(
                    &format!("secret.{}.policy", spec.name),
                    ChangeKind::Updated,
                    None,
                    None,
                    status,
                    policy,
                    SECRET_POLICY_REQUIRES_RESTART,
                ));
            }
            continue;
        };
        let placeholder_changed = secret_placeholder_changes(spec, existing.as_ref());
        let disposition = if policy_changed {
            spec_disposition(status, policy)
        } else {
            secret_disposition(
                status,
                policy,
                change,
                placeholder_changed,
                live_secret_reconfigure_supported,
            )
        };
        let reason = if policy_changed {
            spec_reason(status, disposition, SECRET_POLICY_REQUIRES_RESTART)
        } else {
            secret_reason(
                status,
                policy,
                change,
                placeholder_changed,
                live_secret_reconfigure_supported,
            )
        };

        if !policy_changed {
            push_live_secret_warning(
                status,
                change,
                placeholder_changed,
                disposition,
                live_secret_reconfigure_supported,
                warnings,
            );
        }

        changes.push(PlannedChange::Secret(SecretPlannedChange {
            field: SECRET_FIELD.to_string(),
            name: spec.name.clone(),
            change,
            before_ref: existing.as_ref().map(|secret| secret.placeholder.clone()),
            after_ref: Some(
                spec.placeholder
                    .clone()
                    .or_else(|| existing.as_ref().map(|secret| secret.placeholder.clone()))
                    .unwrap_or_else(|| microsandbox_utils::secret::default_placeholder(&spec.name)),
            ),
            disposition,
            allow_hosts: if spec.allowed_hosts.is_empty() {
                existing
                    .as_ref()
                    .map(|secret| secret.allowed_hosts.clone())
                    .unwrap_or_default()
            } else {
                spec.allowed_hosts.clone()
            },
            reason,
        }));
    }

    for name in &patch.secrets_remove {
        let existing = existing_secret(config, name);
        if existing.is_none() && cfg!(feature = "net") {
            // Already absent: declarative no-op. Without the net feature the
            // change is still emitted so it surfaces as unsupported.
            continue;
        }
        let change = SecretChangeKind::Removed;
        let disposition = secret_disposition(
            status,
            policy,
            change,
            false,
            live_secret_reconfigure_supported,
        );
        let reason = secret_reason(
            status,
            policy,
            change,
            false,
            live_secret_reconfigure_supported,
        );
        push_live_secret_warning(
            status,
            change,
            false,
            disposition,
            live_secret_reconfigure_supported,
            warnings,
        );
        changes.push(PlannedChange::Secret(SecretPlannedChange {
            field: SECRET_FIELD.to_string(),
            name: name.clone(),
            change,
            before_ref: Some(
                existing
                    .as_ref()
                    .map(|secret| secret.placeholder.clone())
                    .unwrap_or_else(|| microsandbox_utils::secret::default_placeholder(name)),
            ),
            after_ref: None,
            disposition,
            allow_hosts: existing
                .as_ref()
                .map(|secret| secret.allowed_hosts.clone())
                .unwrap_or_default(),
            reason,
        }));
    }

    // Surface the implied TLS enable as its own change rather than flipping
    // a config field invisibly: it keeps the dry-run honest and routes the
    // patch through the restart path, the only way interception can start.
    // Check the post-patch secret set so removals, TLS-identity opt-outs, and
    // mixed secret sets cannot make the plan disagree with persisted state.
    if secret_patch_requires_tls_enable(config, patch) {
        changes.push(spec_change(
            TLS_FIELD,
            ChangeKind::Updated,
            Some("interception disabled".to_string()),
            Some("interception enabled".to_string()),
            status,
            policy,
            TLS_INTERCEPTION_REQUIRES_RESTART,
        ));
    }
}

/// Infer what a declarative secret spec changes by diffing it against the
/// existing config. `None` means the spec already matches the target state.
fn infer_secret_change(
    spec: &SecretModificationPatch,
    existing: Option<&ExistingSecret>,
) -> Option<SecretChangeKind> {
    let has_material = spec.source.is_some() || !spec.value.is_empty();
    let Some(existing) = existing else {
        return Some(SecretChangeKind::Added);
    };
    if has_material {
        return Some(SecretChangeKind::Rotated);
    }
    if secret_placeholder_changes(spec, Some(existing)) {
        return Some(SecretChangeKind::PlaceholderUpdated);
    }
    if !spec.allowed_hosts.is_empty() && spec.allowed_hosts != existing.allowed_hosts {
        return Some(SecretChangeKind::HostsUpdated);
    }
    None
}

/// Whether the spec asks for a guest-visible placeholder different from the
/// current one. Placeholder changes cannot reach running processes, so they
/// disqualify an otherwise live-capable change.
fn secret_placeholder_changes(
    spec: &SecretModificationPatch,
    existing: Option<&ExistingSecret>,
) -> bool {
    match (&spec.placeholder, existing) {
        (Some(placeholder), Some(existing)) => *placeholder != existing.placeholder,
        (Some(_), None) => true,
        (None, _) => false,
    }
}

/// Compare only supplied policy fields; omitted options and empty host lists
/// leave an existing policy unchanged, matching persistence semantics.
fn secret_policy_changes(
    spec: &SecretModificationPatch,
    existing: Option<&ExistingSecret>,
) -> bool {
    let Some(existing) = existing else {
        return false;
    };
    spec.substitution.as_ref().is_some_and(|substitution| {
        substitution.headers != existing.substitution.headers
            || substitution.header_fields != existing.substitution.header_fields
            || substitution.query != existing.substitution.query
            || substitution.body != existing.substitution.body
    }) || (!spec.passthrough_hosts.is_empty()
        && spec.passthrough_hosts != existing.passthrough_hosts)
        || spec
            .violation_action
            .as_ref()
            .is_some_and(|action| Some(action) != existing.violation_action.as_ref())
        || spec
            .require_tls_identity
            .is_some_and(|required| required != existing.require_tls_identity)
}

/// Warn when a live-capable secret change falls back to restart-required
/// only because the running runtime lacks live secret reconfiguration.
fn push_live_secret_warning(
    status: SandboxStatus,
    change: SecretChangeKind,
    placeholder_changed: bool,
    disposition: ModificationDisposition,
    live_secret_reconfigure_supported: bool,
    warnings: &mut Vec<ModificationWarning>,
) {
    if matches!(disposition, ModificationDisposition::RequiresRestart)
        && running_status(status)
        && !placeholder_changed
        && !live_secret_reconfigure_supported
        && matches!(
            change,
            SecretChangeKind::Rotated | SecretChangeKind::Removed | SecretChangeKind::HostsUpdated
        )
    {
        warnings.push(ModificationWarning {
            field: SECRET_FIELD.to_string(),
            message: LIVE_SECRET_RECONFIGURE_UNAVAILABLE.to_string(),
        });
    }
}

/// Plan env, label, and workdir changes.
///
/// Labels on a running or draining sandbox with an active configuration are
/// planned live unless the policy is `next_start`. Env and workdir have no live
/// path: they persist for the next start when the sandbox is stopped (or under
/// the next-start policy) and otherwise require a restart.
fn push_spec_changes(
    status: SandboxStatus,
    config: &SandboxConfig,
    active: Option<&SandboxConfig>,
    patch: &SandboxModificationPatch,
    policy: ModificationPolicy,
    changes: &mut Vec<PlannedChange>,
    warnings: &mut Vec<ModificationWarning>,
) {
    // Entries apply in order, so commands see the last entry for a key.
    for var in patched_env(patch) {
        let existing = config.spec.env.iter().rfind(|entry| entry.key == var.key);
        if existing.is_some_and(|entry| entry.value == var.value) {
            continue;
        }
        changes.push(spec_change(
            ENV_FIELD,
            change_kind_for(existing.is_some()),
            existing.map(format_env_var),
            Some(format_env_var(var)),
            status,
            policy,
            LIVE_EXEC_DEFAULT_UPDATE_UNAVAILABLE,
        ));
        push_future_exec_warning(ENV_FIELD, status, policy, warnings);
    }

    for key in &patch.env_remove {
        let Some(existing) = config.spec.env.iter().rfind(|entry| entry.key == *key) else {
            continue;
        };
        changes.push(spec_change(
            ENV_FIELD,
            ChangeKind::Removed,
            Some(format_env_var(existing)),
            None,
            status,
            policy,
            LIVE_EXEC_DEFAULT_UPDATE_UNAVAILABLE,
        ));
        push_future_exec_warning(ENV_FIELD, status, policy, warnings);
    }

    // The active configuration requested labels are also compared against:
    // present for a running sandbox unless the policy is `next_start`.
    let reconcile =
        active.filter(|_| running_status(status) && policy != ModificationPolicy::NextStart);

    for (key, value) in &patch.labels {
        let saved = config.spec.labels.get(key);
        let running = reconcile.and_then(|active_config| active_config.spec.labels.get(key));
        let running_stale = reconcile.is_some() && running != Some(value);
        if saved == Some(value) && !running_stale {
            continue;
        }
        let existing = if running_stale { running } else { saved };
        changes.push(label_change(
            change_kind_for(existing.is_some()),
            existing.map(|current| format!("{key}={current}")),
            Some(format!("{key}={value}")),
            status,
            policy,
            active,
        ));
    }

    for key in &patch.labels_remove {
        let saved = config.spec.labels.get(key);
        let running = reconcile.and_then(|active_config| active_config.spec.labels.get(key));
        let Some(existing) = running.or(saved) else {
            continue;
        };
        changes.push(label_change(
            ChangeKind::Removed,
            Some(format!("{key}={existing}")),
            None,
            status,
            policy,
            active,
        ));
    }

    if let Some(workdir) = &patch.workdir {
        let before = config.spec.runtime.workdir.clone();
        if before.as_deref() != Some(workdir.as_str()) {
            changes.push(spec_change(
                WORKDIR_FIELD,
                change_kind_for(before.is_some()),
                before,
                Some(workdir.clone()),
                status,
                policy,
                LIVE_EXEC_DEFAULT_UPDATE_UNAVAILABLE,
            ));
            push_future_exec_warning(WORKDIR_FIELD, status, policy, warnings);
        }
    }
}

/// The env entries `patch` sets, one per key: a key set twice takes its last value.
fn patched_env(patch: &SandboxModificationPatch) -> impl Iterator<Item = &EnvVar> {
    patch
        .env
        .iter()
        .enumerate()
        .filter(|(index, var)| {
            !patch.env[index + 1..]
                .iter()
                .any(|later| later.key == var.key)
        })
        .map(|(_, var)| var)
}

fn push_spec_conflicts(
    patch: &SandboxModificationPatch,
    conflicts: &mut Vec<ModificationConflict>,
) {
    for var in &patch.env {
        // Apply create's env rules to the entries being set; removals stay allowed.
        if let Err(crate::MicrosandboxError::InvalidConfig(message)) =
            super::validate_env(std::slice::from_ref(var))
        {
            conflicts.push(ModificationConflict {
                field: ENV_FIELD.to_string(),
                message,
            });
        }
        if patch.env_remove.contains(&var.key) {
            conflicts.push(ModificationConflict {
                field: ENV_FIELD.to_string(),
                message: format!(
                    "env {} is both set and removed in the same modification",
                    var.key
                ),
            });
        }
    }
    for (key, _) in &patch.labels {
        // Same key rules as create. Removal is not checked, so a sandbox that
        // already holds such a key can be repaired.
        if let Err(crate::MicrosandboxError::InvalidConfig(message)) =
            super::validate_labels(&BTreeMap::from([(key.clone(), String::new())]))
        {
            conflicts.push(ModificationConflict {
                field: LABEL_FIELD.to_string(),
                message,
            });
        }
        if patch.labels_remove.contains(key) {
            conflicts.push(ModificationConflict {
                field: LABEL_FIELD.to_string(),
                message: format!("label {key} is both set and removed in the same modification"),
            });
        }
    }
}

/// Reject secret specs that could never persist or apply: material conflicts
/// (both value and source, or neither for a new secret), unsupported store
/// sources, a new secret without hosts, and a name that is both configured
/// and removed. Messages carry names and references, never values. Without
/// the net feature the whole secret surface is already unsupported, so no
/// per-entry checks run.
fn push_secret_conflicts(
    config: &SandboxConfig,
    patch: &SandboxModificationPatch,
    conflicts: &mut Vec<ModificationConflict>,
) {
    if cfg!(not(feature = "net")) {
        return;
    }

    let mut conflict = |message: String| {
        conflicts.push(ModificationConflict {
            field: SECRET_FIELD.to_string(),
            message,
        });
    };

    for spec in &patch.secrets {
        let name = &spec.name;
        if name.is_empty() {
            conflict("secret spec needs a name; call .env(..) in the secret closure".to_string());
            continue;
        }

        let has_value = !spec.value.is_empty();
        if has_value && spec.source.is_some() {
            conflict(format!(
                "secret {name}: value and source are mutually exclusive"
            ));
        }
        if matches!(spec.source, Some(SecretSource::Store { .. })) {
            conflict(format!(
                "secret {name}: store-backed secret sources are not supported yet"
            ));
        }

        if existing_secret(config, name).is_none() {
            if spec.source.is_none() && !has_value {
                conflict(format!(
                    "secret {name} needs a host-side source or value to add"
                ));
            }
            if spec.allowed_hosts.is_empty() {
                conflict(format!("secret {name} needs at least one allowed host"));
            }
        }

        if patch.secrets_remove.contains(name) {
            conflict(format!(
                "secret {name} is both configured and removed in the same modification"
            ));
        }
    }
}

fn push_resource_conflicts(
    config: &SandboxConfig,
    patch: &SandboxModificationPatch,
    conflicts: &mut Vec<ModificationConflict>,
) {
    if matches!(patch.cpus, Some(0)) {
        conflicts.push(ModificationConflict {
            field: "cpus".to_string(),
            message: "cpus must be greater than 0".to_string(),
        });
    }
    if matches!(patch.memory_mib, Some(0)) {
        conflicts.push(ModificationConflict {
            field: "memory".to_string(),
            message: "memory must be greater than 0".to_string(),
        });
    }
    if matches!(patch.max_cpus, Some(0)) {
        conflicts.push(ModificationConflict {
            field: "max_cpus".to_string(),
            message: "max_cpus must be greater than 0".to_string(),
        });
    }
    if matches!(patch.max_memory_mib, Some(0)) {
        conflicts.push(ModificationConflict {
            field: "max_memory".to_string(),
            message: "max_memory must be greater than 0".to_string(),
        });
    }

    let desired_cpus = patch.cpus.unwrap_or(config.spec.resources.cpus);
    if let Some(max_cpus) = patch.max_cpus
        && max_cpus < desired_cpus
    {
        conflicts.push(ModificationConflict {
            field: "max_cpus".to_string(),
            message: format!("max_cpus {max_cpus} is lower than requested cpus {desired_cpus}"),
        });
    }

    let desired_memory_mib = patch.memory_mib.unwrap_or(config.spec.resources.memory_mib);
    if let Some(max_memory_mib) = patch.max_memory_mib
        && max_memory_mib < desired_memory_mib
    {
        conflicts.push(ModificationConflict {
            field: "max_memory".to_string(),
            message: format!(
                "max_memory {} is lower than requested memory {}",
                format_mib(max_memory_mib),
                format_mib(desired_memory_mib)
            ),
        });
    }
}

fn desired_resources(config: &SandboxConfig, patch: &SandboxModificationPatch) -> DesiredResources {
    let resources = &config.spec.resources;
    let cpus = patch.cpus.unwrap_or(resources.cpus);
    let memory_mib = patch.memory_mib.unwrap_or(resources.memory_mib);
    let max_cpus = patch.max_cpus.unwrap_or(resources.max_cpus).max(cpus);
    let max_memory_mib = patch
        .max_memory_mib
        .unwrap_or(resources.max_memory_mib)
        .max(memory_mib);

    DesiredResources {
        max_cpus,
        max_memory_mib,
    }
}

fn resource_disposition(
    status: SandboxStatus,
    policy: ModificationPolicy,
    live_resize_supported: bool,
) -> ModificationDisposition {
    if policy == ModificationPolicy::NextStart || stopped_status(status) {
        return ModificationDisposition::NextStart;
    }
    if transitional_status(status) {
        return ModificationDisposition::Unsupported;
    }
    if running_status(status) && live_resize_supported {
        return ModificationDisposition::Live;
    }
    ModificationDisposition::RequiresRestart
}

fn resource_reason(
    status: SandboxStatus,
    policy: ModificationPolicy,
    live_resize_supported: bool,
) -> Option<String> {
    match resource_disposition(status, policy, live_resize_supported) {
        ModificationDisposition::RequiresRestart if running_status(status) => {
            Some(LIVE_RESIZE_UNAVAILABLE.to_string())
        }
        ModificationDisposition::Unsupported => Some(format!(
            "cannot modify while sandbox is {}",
            status_name(status)
        )),
        _ => None,
    }
}

fn boot_capacity_disposition(
    status: SandboxStatus,
    policy: ModificationPolicy,
) -> ModificationDisposition {
    if policy == ModificationPolicy::NextStart || stopped_status(status) {
        return ModificationDisposition::NextStart;
    }
    if transitional_status(status) {
        return ModificationDisposition::Unsupported;
    }
    ModificationDisposition::RequiresRestart
}

fn boot_capacity_reason(
    status: SandboxStatus,
    policy: ModificationPolicy,
    field: &str,
) -> Option<String> {
    match boot_capacity_disposition(status, policy) {
        ModificationDisposition::RequiresRestart => Some(format!(
            "{field} defines boot-time capacity and cannot be raised live"
        )),
        ModificationDisposition::Unsupported => Some(format!(
            "cannot modify while sandbox is {}",
            status_name(status)
        )),
        _ => None,
    }
}

fn spec_change(
    field: &str,
    change: ChangeKind,
    before: Option<String>,
    after: Option<String>,
    status: SandboxStatus,
    policy: ModificationPolicy,
    running_reason: &str,
) -> PlannedChange {
    let disposition = spec_disposition(status, policy);
    config_change(
        field,
        change,
        before,
        after,
        disposition,
        spec_reason(status, disposition, running_reason),
    )
}

fn label_change(
    change: ChangeKind,
    before: Option<String>,
    after: Option<String>,
    status: SandboxStatus,
    policy: ModificationPolicy,
    active: Option<&SandboxConfig>,
) -> PlannedChange {
    let disposition = label_disposition(status, policy, active);
    let reason = spec_reason(status, disposition, LIVE_LABEL_UPDATE_NEEDS_ACTIVE_CONFIG);
    config_change(LABEL_FIELD, change, before, after, disposition, reason)
}

fn config_change(
    field: &str,
    change: ChangeKind,
    before: Option<String>,
    after: Option<String>,
    disposition: ModificationDisposition,
    reason: Option<String>,
) -> PlannedChange {
    PlannedChange::Config(ConfigPlannedChange {
        field: field.to_string(),
        change,
        before,
        after,
        disposition,
        reason,
    })
}

fn label_disposition(
    status: SandboxStatus,
    policy: ModificationPolicy,
    active: Option<&SandboxConfig>,
) -> ModificationDisposition {
    match spec_disposition(status, policy) {
        ModificationDisposition::RequiresRestart if running_status(status) && active.is_some() => {
            ModificationDisposition::Live
        }
        ModificationDisposition::RequiresRestart => ModificationDisposition::RequiresRestart,
        ModificationDisposition::Unsupported => ModificationDisposition::Unsupported,
        ModificationDisposition::Live => ModificationDisposition::Live,
        ModificationDisposition::NextStart => ModificationDisposition::NextStart,
    }
}

fn spec_disposition(status: SandboxStatus, policy: ModificationPolicy) -> ModificationDisposition {
    if policy == ModificationPolicy::NextStart || stopped_status(status) {
        return ModificationDisposition::NextStart;
    }
    if transitional_status(status) {
        return ModificationDisposition::Unsupported;
    }
    ModificationDisposition::RequiresRestart
}

fn spec_reason(
    status: SandboxStatus,
    disposition: ModificationDisposition,
    running_reason: &str,
) -> Option<String> {
    match disposition {
        ModificationDisposition::RequiresRestart if running_status(status) => {
            Some(running_reason.to_string())
        }
        ModificationDisposition::Unsupported => Some(format!(
            "cannot modify while sandbox is {}",
            status_name(status)
        )),
        ModificationDisposition::RequiresRestart
        | ModificationDisposition::Live
        | ModificationDisposition::NextStart => None,
    }
}

fn change_kind_for(existing: bool) -> ChangeKind {
    if existing {
        ChangeKind::Updated
    } else {
        ChangeKind::Added
    }
}

fn format_env_var(var: &EnvVar) -> String {
    format!("{}={}", var.key, var.value)
}

fn secret_disposition(
    status: SandboxStatus,
    policy: ModificationPolicy,
    change: SecretChangeKind,
    placeholder_changed: bool,
    live_secret_reconfigure_supported: bool,
) -> ModificationDisposition {
    // Without the net feature there is no secrets layer to persist into or
    // reconfigure, so every secret change is unsupported.
    #[cfg(not(feature = "net"))]
    {
        let _ = (
            status,
            policy,
            change,
            placeholder_changed,
            live_secret_reconfigure_supported,
        );
        ModificationDisposition::Unsupported
    }
    #[cfg(feature = "net")]
    secret_disposition_net(
        status,
        policy,
        change,
        placeholder_changed,
        live_secret_reconfigure_supported,
    )
}

#[cfg(feature = "net")]
fn secret_disposition_net(
    status: SandboxStatus,
    policy: ModificationPolicy,
    change: SecretChangeKind,
    placeholder_changed: bool,
    live_secret_reconfigure_supported: bool,
) -> ModificationDisposition {
    if policy == ModificationPolicy::NextStart || stopped_status(status) {
        return ModificationDisposition::NextStart;
    }
    if transitional_status(status) {
        return ModificationDisposition::Unsupported;
    }
    if !running_status(status) {
        return ModificationDisposition::RequiresRestart;
    }

    match change {
        // A rotate that also changes the guest-visible placeholder cannot
        // apply live: the new placeholder never reaches running processes.
        SecretChangeKind::Rotated | SecretChangeKind::Removed | SecretChangeKind::HostsUpdated
            if live_secret_reconfigure_supported && !placeholder_changed =>
        {
            ModificationDisposition::Live
        }
        _ => ModificationDisposition::RequiresRestart,
    }
}

fn secret_reason(
    status: SandboxStatus,
    policy: ModificationPolicy,
    change: SecretChangeKind,
    placeholder_changed: bool,
    live_secret_reconfigure_supported: bool,
) -> Option<String> {
    #[cfg(not(feature = "net"))]
    {
        let _ = (
            status,
            policy,
            change,
            placeholder_changed,
            live_secret_reconfigure_supported,
        );
        Some(SECRETS_UNAVAILABLE_WITHOUT_NET.to_string())
    }
    #[cfg(feature = "net")]
    match secret_disposition(
        status,
        policy,
        change,
        placeholder_changed,
        live_secret_reconfigure_supported,
    ) {
        ModificationDisposition::RequiresRestart if running_status(status) => {
            if placeholder_changed
                || matches!(
                    change,
                    SecretChangeKind::Added
                        | SecretChangeKind::Renamed
                        | SecretChangeKind::PlaceholderUpdated
                )
            {
                Some(
                    "guest-visible secret placeholders cannot be introduced into existing processes"
                        .to_string(),
                )
            } else {
                Some(LIVE_SECRET_RECONFIGURE_UNAVAILABLE.to_string())
            }
        }
        ModificationDisposition::Unsupported => Some(format!(
            "cannot modify while sandbox is {}",
            status_name(status)
        )),
        _ => None,
    }
}

fn existing_secret(config: &SandboxConfig, name: &str) -> Option<ExistingSecret> {
    existing_secret_from_network_config(config, name)
}

#[cfg(feature = "net")]
fn existing_secret_from_network_config(
    config: &SandboxConfig,
    name: &str,
) -> Option<ExistingSecret> {
    let network = config.local_network_config().ok()?;
    network
        .secrets
        .secrets
        .into_iter()
        .find(|secret| secret.env_var == name)
        .map(|secret| ExistingSecret {
            placeholder: secret.placeholder,
            substitution: secret.substitution,
            passthrough_hosts: secret
                .passthrough_hosts
                .into_iter()
                .map(format_host_pattern)
                .collect(),
            violation_action: secret.violation_action,
            require_tls_identity: secret.require_tls_identity,
            allowed_hosts: secret
                .allowed_hosts
                .into_iter()
                .map(format_host_pattern)
                .collect(),
        })
}

#[cfg(not(feature = "net"))]
fn existing_secret_from_network_config(
    _config: &SandboxConfig,
    _name: &str,
) -> Option<ExistingSecret> {
    None
}

/// Whether the post-patch secret set requires enabling TLS interception.
///
/// Existing entries retain their `require_tls_identity` setting unless the
/// patch overrides it; new entries use the TLS-identity default unless they
/// explicitly opt out. Removals are evaluated last, just like persistence,
/// without copying or resolving any secret material.
/// Without `net`, secret changes are already unsupported and this returns
/// `false` rather than adding a second planned change.
fn secret_patch_requires_tls_enable(
    config: &SandboxConfig,
    patch: &SandboxModificationPatch,
) -> bool {
    #[cfg(not(feature = "net"))]
    {
        let _ = (config, patch);
        false
    }

    #[cfg(feature = "net")]
    {
        if patch.secrets.is_empty() && patch.secrets_remove.is_empty() {
            return false;
        }
        let Ok(network) = config.local_network_config() else {
            return false;
        };
        if network.tls.enabled {
            return false;
        }

        let mut tls_identity_by_name: HashMap<&str, bool> = network
            .secrets
            .secrets
            .iter()
            .map(|entry| (entry.env_var.as_str(), entry.require_tls_identity))
            .collect();
        for spec in &patch.secrets {
            let required = spec
                .require_tls_identity
                .or_else(|| tls_identity_by_name.get(spec.name.as_str()).copied())
                .unwrap_or(true);
            tls_identity_by_name.insert(spec.name.as_str(), required);
        }
        for name in &patch.secrets_remove {
            tls_identity_by_name.remove(name.as_str());
        }

        tls_identity_by_name.values().any(|required| *required)
    }
}

#[cfg(feature = "net")]
fn format_host_pattern(host: microsandbox_network::secrets::config::HostPattern) -> String {
    match host {
        microsandbox_network::secrets::config::HostPattern::Exact(host) => host,
        microsandbox_network::secrets::config::HostPattern::Wildcard(host) => host,
        microsandbox_network::secrets::config::HostPattern::Any => "*".to_string(),
    }
}

fn push_live_resize_warning(
    field: &str,
    status: SandboxStatus,
    policy: ModificationPolicy,
    live_resize_supported: bool,
    warnings: &mut Vec<ModificationWarning>,
) {
    if running_status(status) && policy != ModificationPolicy::NextStart && !live_resize_supported {
        warnings.push(ModificationWarning {
            field: field.to_string(),
            message: LIVE_RESIZE_UNAVAILABLE.to_string(),
        });
    }
}

/// Warn that a running-sandbox exec-default change (env, workdir) only reaches
/// future execs: even after a `--restart` apply or a persisted `--next-start`
/// patch, processes already running keep the environment they started with.
fn push_future_exec_warning(
    field: &str,
    status: SandboxStatus,
    policy: ModificationPolicy,
    warnings: &mut Vec<ModificationWarning>,
) {
    if !running_status(status)
        || !matches!(
            policy,
            ModificationPolicy::Restart | ModificationPolicy::NextStart
        )
    {
        return;
    }
    if warnings
        .iter()
        .any(|warning| warning.field == field && warning.message == FUTURE_EXECS_ONLY)
    {
        return;
    }
    warnings.push(ModificationWarning {
        field: field.to_string(),
        message: FUTURE_EXECS_ONLY.to_string(),
    });
}

fn stopped_status(status: SandboxStatus) -> bool {
    matches!(
        status,
        SandboxStatus::Created | SandboxStatus::Stopped | SandboxStatus::Crashed
    )
}

fn running_status(status: SandboxStatus) -> bool {
    matches!(status, SandboxStatus::Running | SandboxStatus::Draining)
}

fn transitional_status(status: SandboxStatus) -> bool {
    matches!(status, SandboxStatus::Starting | SandboxStatus::Paused)
}

fn status_name(status: SandboxStatus) -> &'static str {
    match status {
        SandboxStatus::Created => "created",
        SandboxStatus::Starting => "starting",
        SandboxStatus::Running => "running",
        SandboxStatus::Draining => "draining",
        SandboxStatus::Paused => "paused",
        SandboxStatus::Stopped => "stopped",
        SandboxStatus::Crashed => "crashed",
    }
}

fn format_mib(mib: u32) -> String {
    if mib >= 1024 && mib.is_multiple_of(1024) {
        format!("{} GiB", mib / 1024)
    } else {
        format!("{mib} MiB")
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::time::Duration;

    #[cfg(unix)]
    use microsandbox_runtime::control::control_socket_path_for;
    use sea_orm::ActiveModelTrait;
    use tempfile::tempdir;
    #[cfg(unix)]
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

    use super::*;
    use crate::backend::LocalBackend;
    #[cfg(unix)]
    use crate::db::entity::run;
    #[cfg(unix)]
    use crate::runtime::sandbox_agent_socket_path_candidates_for;
    use crate::size::SizeExt;

    #[test]
    fn guest_flush_capability_never_silently_weakens_capture() {
        use microsandbox_types::GuestFlush::{Auto, Required, Skip};
        let old = microsandbox_protocol::control::RuntimeCapabilities::default();
        let new = microsandbox_protocol::control::RuntimeCapabilities {
            guest_flush_policy: true,
            ..old
        };
        for capabilities in [None, Some(old)] {
            assert_eq!(
                ControlSession::capture_flush_policy(capabilities, Auto, false).unwrap(),
                None
            );
            for policy in [Auto, Required, Skip] {
                assert!(ControlSession::capture_flush_policy(capabilities, policy, true).is_err());
                if policy != Auto {
                    assert!(
                        ControlSession::capture_flush_policy(capabilities, policy, false).is_err()
                    );
                }
            }
        }
        for disk in [true, false] {
            for policy in [Auto, Required, Skip] {
                assert_eq!(
                    ControlSession::capture_flush_policy(Some(new), policy, disk).unwrap(),
                    Some(policy)
                );
            }
        }
    }

    #[tokio::test]
    async fn restored_fixed_cpu_counts_do_not_require_a_hotplug_controller() {
        let home = tempfile::tempdir().unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        // No runtime/control endpoint exists: fixed geometry needs no query.
        for cpus in [1, 2, 4] {
            let mut config = config(cpus, 256);
            config.spec.resources.max_cpus = cpus;
            config.spec.resources.max_memory_mib = 256;
            local
                .restore_requested_resources(&mut config)
                .await
                .unwrap();
            assert_eq!(config.spec.resources.cpus, cpus);
            assert_eq!(config.spec.resources.memory_mib, 256);
        }
    }

    /// A checkpoint restore reads the restored CPU target before the creator publishes the
    /// sandbox as `Running`; ordinary control sessions still refuse a sandbox that is `Starting`.
    #[cfg(unix)]
    #[tokio::test]
    async fn restored_cpu_target_is_read_while_the_sandbox_is_still_starting() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let home = tempfile::tempdir_in("/tmp").unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        seed_control_run_with_status(&local, "api", SandboxStatus::Starting).await;
        let agent =
            crate::runtime::sandbox_agent_socket_path_candidates_for(&local, "api").remove(0);
        let path = microsandbox_runtime::control::control_socket_path_for(&agent);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        // An ordinary session does not own a sandbox that has not been published yet.
        assert!(matches!(
            local.control_session("api").await,
            Err(crate::MicrosandboxError::ControlClient(error))
                if matches!(&*error, microsandbox_control_client::ControlClientError::RuntimeChanged)
        ));
        let server = tokio::spawn(async move {
            for (op, reply) in [
                (
                    "capabilities",
                    "{\"ok\":true,\"capabilities\":{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":false}}",
                ),
                (
                    "cpu_state",
                    "{\"ok\":true,\"cpu\":{\"possible\":4,\"requested_online\":2,\"actual_online\":2,\"enforced\":2}}",
                ),
            ] {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&line).unwrap()["op"],
                    op
                );
                stream
                    .get_mut()
                    .write_all(format!("{reply}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let mut config = config(1, 256);
        config.spec.resources.max_cpus = 4;
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            local.restore_requested_resources(&mut config),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(config.spec.resources.cpus, 2);
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restored_hotplug_cpu_state_still_rejects_invalid_targets() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let home = tempfile::tempdir_in("/tmp").unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        seed_control_run(&local, "api").await;
        let agent =
            crate::runtime::sandbox_agent_socket_path_candidates_for(&local, "api").remove(0);
        let path = microsandbox_runtime::control::control_socket_path_for(&agent);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&line).unwrap()["op"],
                "capabilities"
            );
            stream
                .get_mut()
                .write_all(b"{\"ok\":true,\"capabilities\":{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":false}}\n")
                .await
                .unwrap();
            for (possible, requested) in [(3, 2), (4, 0), (4, 5)] {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&line).unwrap()["op"],
                    "cpu_state"
                );
                let response = serde_json::json!({"ok":true,"cpu":{
                    "possible":possible,"requested_online":requested,"actual_online":1,"enforced":1
                }});
                stream
                    .get_mut()
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        for _ in 0..3 {
            let mut config = config(1, 256);
            config.spec.resources.max_cpus = 4;
            let error = tokio::time::timeout(
                std::time::Duration::from_secs(2),
                local.restore_requested_resources(&mut config),
            )
            .await
            .unwrap()
            .unwrap_err();
            assert!(error.to_string().contains("outside captured capacity"));
            assert_eq!(config.spec.resources.cpus, 1);
        }
        server.await.unwrap();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn restored_targets_use_complete_frames_and_requested_not_actual_sizes() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let home = tempfile::tempdir_in("/tmp").unwrap();
        let local = crate::test_support::local_backend_builder(home.path())
            .build()
            .await
            .unwrap();
        seed_control_run(&local, "api").await;
        let agent =
            crate::runtime::sandbox_agent_socket_path_candidates_for(&local, "api").remove(0);
        let path = microsandbox_runtime::control::control_socket_path_for(&agent);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let server = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let mut stream = BufReader::new(stream);
            let mut line = String::new();
            stream.read_line(&mut line).await.unwrap();
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(&line).unwrap()["op"],
                "capabilities"
            );
            stream
                .get_mut()
                .write_all(b"{\"ok\":true,\"capabilities\":{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":false}}\n")
                .await
                .unwrap();
            for (op, response) in [
                (
                    "cpu_state",
                    serde_json::json!({"ok":true,"cpu":{"possible":4,"requested_online":2,"actual_online":3,"enforced":2}}),
                ),
                (
                    "memory_state",
                    serde_json::json!({"ok":true,"memory":{"boot_mib":256,"max_mib":1024,"target_mib":768,"current_mib":512}}),
                ),
            ] {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                assert!(line.ends_with('\n'));
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&line).unwrap()["op"],
                    op
                );
                stream
                    .get_mut()
                    .write_all(format!("{response}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });
        let mut config = config(1, 256);
        config.spec.resources.max_cpus = 4;
        config.spec.resources.max_memory_mib = 1024;
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            local.restore_requested_resources(&mut config),
        )
        .await
        .unwrap()
        .unwrap();
        server.await.unwrap();
        assert_eq!(config.spec.resources.cpus, 2);
        assert_eq!(config.spec.resources.memory_mib, 768);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn compaction_uses_selected_backend_for_discovery_and_mutation() {
        use microsandbox_types::DiskCompactionTarget;
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let first_home = tempfile::tempdir_in("/tmp").unwrap();
        let second_home = tempfile::tempdir_in("/tmp").unwrap();
        let first = crate::test_support::local_backend_builder(first_home.path())
            .build()
            .await
            .unwrap();
        let second = crate::test_support::local_backend_builder(second_home.path())
            .build()
            .await
            .unwrap();
        seed_control_run(&first, "worker").await;
        seed_control_run(&second, "worker").await;
        let mut servers = Vec::new();
        for (local, marker, target) in [
            (&first, 1, DiskCompactionTarget::All),
            (
                &second,
                2,
                DiskCompactionTarget::Disk {
                    guest_path: "/data".into(),
                },
            ),
        ] {
            let agent =
                crate::runtime::sandbox_agent_socket_path_candidates_for(local, "worker").remove(0);
            let path = microsandbox_runtime::control::control_socket_path_for(&agent);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let listener = tokio::net::UnixListener::bind(path).unwrap();
            servers.push(tokio::spawn(async move {
                for request_index in 0..2 {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut stream = BufReader::new(stream);
                    let mut line = String::new();
                    stream.read_line(&mut line).await.unwrap();
                    let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                    let response = if request_index == 0 {
                        assert_eq!(request["op"], "capabilities");
                        serde_json::json!({"ok": true, "capabilities": {
                            "disk_compact_owned": true, "cpu_resize": false,
                            "memory_resize": false, "secrets_update": false
                        }})
                    } else {
                        assert_eq!(request["op"], "disk_compact");
                        assert_eq!(request["target"], serde_json::to_value(target.clone()).unwrap());
                        assert_eq!(request["layers"], 999);
                        assert_eq!(request["dry_run"], true);
                        serde_json::json!({"ok": true, "compaction": microsandbox_types::DiskCompactionResult {
                            dry_run: true, total_us: marker, ..Default::default()
                        }})
                    };
                    stream.get_mut().write_all(format!("{response}\n").as_bytes()).await.unwrap();
                }
            }));
        }
        for (local, marker, target) in [
            (&first, 1, DiskCompactionTarget::All),
            (
                &second,
                2,
                DiskCompactionTarget::Disk {
                    guest_path: "/data".into(),
                },
            ),
        ] {
            let result = tokio::time::timeout(std::time::Duration::from_secs(2), async {
                local
                    .require_control_session("worker")
                    .await?
                    .compact_disks(target, Some(999), true)
                    .await
            })
            .await
            .unwrap()
            .unwrap();
            assert_eq!(result.total_us, marker);
        }
        for server in servers {
            server.await.unwrap();
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn full_checkpoint_uses_selected_backend_and_retains_post_publish_failure() {
        use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

        let first_home = tempfile::tempdir_in("/tmp").unwrap();
        let second_home = tempfile::tempdir_in("/tmp").unwrap();
        let first = crate::test_support::local_backend_builder(first_home.path())
            .build()
            .await
            .unwrap();
        let second = crate::test_support::local_backend_builder(second_home.path())
            .build()
            .await
            .unwrap();
        seed_control_run(&first, "worker").await;
        seed_control_run(&second, "worker").await;
        let mut servers = Vec::new();
        for (local, label, resume_ok) in [(&first, "first", true), (&second, "second", false)] {
            let agent =
                crate::runtime::sandbox_agent_socket_path_candidates_for(local, "worker").remove(0);
            let path = microsandbox_runtime::control::control_socket_path_for(&agent);
            std::fs::create_dir_all(path.parent().unwrap()).unwrap();
            let listener = tokio::net::UnixListener::bind(path).unwrap();
            servers.push(tokio::spawn(async move {
                for request_index in 0..2 {
                    let (stream, _) = listener.accept().await.unwrap();
                    let mut stream = BufReader::new(stream);
                    let mut line = String::new();
                    stream.read_line(&mut line).await.unwrap();
                    let request: serde_json::Value = serde_json::from_str(&line).unwrap();
                    let response = if request_index == 0 {
                        assert_eq!(request["op"], "capabilities");
                        serde_json::json!({"ok":true,"capabilities":{"optional_disk_integrity":true,"checkpoint_create":true,"cpu_resize":false,"memory_resize":false,"secrets_update":false}})
                    } else {
                        assert_eq!(request["op"], "checkpoint_create");
                        assert_eq!(request["record_integrity"], label == "second");
                        serde_json::json!({"ok":resume_ok,"error":"source resume failed","checkpoint":{
                            "checkpoint_id":request["checkpoint_id"], "checkpoint_root":format!("sha256:{}", "a".repeat(64)),
                            "path":format!("/capture/{label}"), "memory_mode":"full", "memory_logical_bytes":4096, "memory_emitted_bytes":4096
                        }})
                    };
                    stream.get_mut().write_all(format!("{response}\n").as_bytes()).await.unwrap();
                }
            }));
        }
        let first_capture = first
            .require_control_session("worker")
            .await
            .unwrap()
            .create_checkpoint(
                "first-checkpoint".into(),
                false,
                microsandbox_types::GuestFlush::Auto,
            )
            .await
            .unwrap();
        let second_capture = second
            .require_control_session("worker")
            .await
            .unwrap()
            .create_checkpoint(
                "second-checkpoint".into(),
                true,
                microsandbox_types::GuestFlush::Auto,
            )
            .await
            .unwrap();
        assert_eq!(
            first_capture.checkpoint.path,
            std::path::Path::new("/capture/first")
        );
        assert!(first_capture.recovery_error.is_none());
        assert_eq!(
            second_capture.checkpoint.path,
            std::path::Path::new("/capture/second")
        );
        assert_eq!(
            second_capture.recovery_error.as_deref(),
            Some("source resume failed")
        );
        for server in servers {
            server.await.unwrap();
        }
    }

    #[tokio::test]
    async fn size_setters_accept_bare_mib_and_typed_sizes() {
        let temp = tempdir().unwrap();
        let backend: Arc<dyn Backend> = Arc::new(
            crate::test_support::local_backend_builder(temp.path())
                .build()
                .await
                .unwrap(),
        );
        let plain = SandboxModificationBuilder::new(backend.clone(), "size-api")
            .memory(1024)
            .max_memory(8192)
            .root_disk_size(4096);
        let typed = SandboxModificationBuilder::new(backend, "size-api")
            .memory(1.gib())
            .max_memory(8.gib())
            .root_disk_size(4.gib());
        for patch in [&plain.patch, &typed.patch] {
            assert_eq!(patch.memory_mib, Some(1024));
            assert_eq!(patch.max_memory_mib, Some(8192));
            assert_eq!(patch.root_disk_size_mib, Some(4096));
        }
    }

    fn config(cpus: u8, memory_mib: u32) -> SandboxConfig {
        let mut config = SandboxConfig::default();
        config.spec.name = "api".to_string();
        config.spec.resources.cpus = cpus;
        config.spec.resources.memory_mib = memory_mib;
        config.spec.resources.max_cpus = cpus;
        config.spec.resources.max_memory_mib = memory_mib;
        config
    }

    async fn seed_control_run(local: &LocalBackend, name: &str) {
        seed_control_run_with_status(local, name, SandboxStatus::Running).await;
    }

    async fn seed_control_run_with_status(local: &LocalBackend, name: &str, status: SandboxStatus) {
        use crate::db::entity::{run, sandbox};

        let db = local.db().await.unwrap();
        let sandbox_id = sandbox::Entity::insert(sandbox::ActiveModel {
            name: Set(name.into()),
            config: Set("{}".into()),
            status: Set(status),
            ephemeral: Set(false),
            ..Default::default()
        })
        .exec(db.write())
        .await
        .unwrap()
        .last_insert_id;
        run::Entity::insert(run::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(std::process::id() as i32)),
            status: Set(run::RunStatus::Running),
            ..Default::default()
        })
        .exec(db.write())
        .await
        .unwrap();
    }

    async fn label_backend(home: &std::path::Path) -> (Arc<LocalBackend>, Arc<dyn Backend>) {
        let builder = crate::test_support::local_backend_builder(home);
        let local = Arc::new(builder.build().await.unwrap());
        let backend = local.clone();
        (local, backend)
    }

    async fn seed_running_labeled(
        local: &LocalBackend,
        saved: &SandboxConfig,
        active: &SandboxConfig,
    ) -> i32 {
        let pools = local.db().await.unwrap();
        let sandbox_id = sandbox_entity::Entity::insert(sandbox_entity::ActiveModel {
            name: Set(saved.spec.name.clone()),
            config: Set(serde_json::to_string(saved).unwrap()),
            active_config: Set(Some(serde_json::to_string(active).unwrap())),
            status: Set(SandboxStatus::Running),
            ephemeral: Set(false),
            ..Default::default()
        })
        .exec(pools.write())
        .await
        .unwrap()
        .last_insert_id;
        if !saved.spec.labels.is_empty() {
            sandbox_label_entity::Entity::insert_many(saved.spec.labels.iter().map(
                |(key, value)| sandbox_label_entity::ActiveModel {
                    sandbox_id: Set(sandbox_id),
                    key: Set(key.clone()),
                    value: Set(value.clone()),
                },
            ))
            .exec(pools.write())
            .await
            .unwrap();
        }
        sandbox_id
    }

    async fn label_copies(
        local: &LocalBackend,
        sandbox_id: i32,
    ) -> (
        BTreeMap<String, String>,
        Option<BTreeMap<String, String>>,
        Vec<(String, String)>,
    ) {
        let pools = local.db().await.unwrap();
        let row = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        let labels = |json: &str| {
            serde_json::from_str::<SandboxConfig>(json)
                .unwrap()
                .spec
                .labels
        };
        let desired = labels(&row.config);
        let active = row.active_config.as_deref().map(labels);
        let mut projection = sandbox_label_entity::Entity::find()
            .filter(sandbox_label_entity::Column::SandboxId.eq(sandbox_id))
            .all(pools.read())
            .await
            .unwrap()
            .into_iter()
            .map(|label| (label.key, label.value))
            .collect::<Vec<_>>();
        projection.sort();
        (desired, active, projection)
    }

    #[tokio::test]
    async fn persist_config_replaces_labels_and_preserves_caller_config_overrides() {
        let temp = tempdir().unwrap();
        let backend: Arc<dyn Backend> = Arc::new(
            LocalBackend::builder()
                .config_path(temp.path().join("config.json"))
                .managed_config_path(temp.path().join("managed.json"))
                .home(temp.path())
                .build()
                .await
                .unwrap(),
        );
        let pools = backend.as_local().unwrap().db().await.unwrap();
        let mut current = config(2, 1024);
        current.spec.image = RootfsSource::oci("alpine");
        let mut options = crate::SandboxConfigPatch::new();
        options.spec.runtime.workdir = Some(None);
        options.spec.runtime.cmd = Some(Vec::new());
        current.caller_config_overrides = Some(Box::new(options));
        current.spec.labels.insert("team".into(), "stale".into());
        current.spec.labels.insert("removed".into(), "ghost".into());
        let model = sandbox_entity::ActiveModel {
            name: Set(current.spec.name.clone()),
            config: Set(serde_json::to_string(&current).unwrap()),
            active_config: Set(None),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            created_at: Set(None),
            updated_at: Set(None),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let sandbox_id = model.id;
        for (key, value) in [("team", "stale"), ("removed", "ghost")] {
            sandbox_label_entity::ActiveModel {
                sandbox_id: Set(sandbox_id),
                key: Set(key.into()),
                value: Set(value.into()),
            }
            .insert(pools.write())
            .await
            .unwrap();
        }

        let mut updated = current;
        updated.apply_modification(&SandboxModificationPatch {
            labels: [
                ("team".into(), "metrics".into()),
                ("tier".into(), "gold".into()),
            ]
            .into(),
            labels_remove: vec!["removed".into()],
            ..Default::default()
        });
        let handle = backend
            .sandboxes()
            .get(backend.clone(), &updated.spec.name)
            .await
            .unwrap();

        persist_config(&backend, &handle, &updated, None)
            .await
            .unwrap();

        let mut rows = sandbox_label_entity::Entity::find()
            .filter(sandbox_label_entity::Column::SandboxId.eq(sandbox_id))
            .all(pools.read())
            .await
            .unwrap();
        rows.sort_by(|left, right| left.key.cmp(&right.key));
        assert_eq!(
            rows.into_iter()
                .map(|row| (row.key, row.value))
                .collect::<Vec<_>>(),
            vec![
                ("team".into(), "metrics".into()),
                ("tier".into(), "gold".into()),
            ]
        );
        let stored = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        let stored =
            SandboxConfig::from_stored(&stored.config, stored.caller_config_overrides.as_deref())
                .unwrap();
        assert_eq!(stored.spec.labels, updated.spec.labels);

        // Reload through the real handle boundary before rebuilding with new defaults.
        let reloaded = backend
            .sandboxes()
            .get(backend.clone(), &updated.spec.name)
            .await
            .unwrap();
        let reloaded = reloaded.config().unwrap();
        let intent = reloaded.caller_config_overrides.as_ref().unwrap();
        assert_eq!(intent.spec.runtime.workdir, Some(None));
        assert_eq!(intent.spec.runtime.cmd, Some(Vec::new()));
        assert!(intent.spec.resources.cpus.is_none());
        assert!(intent.spec.init.is_none());
        let defaults = crate::config::layers::BackendConfig::new(
            serde_json::from_str(r#"{"sandbox_defaults":{"workdir":"/new-default"}}"#).unwrap(),
            Default::default(),
        );
        let rebuilt = crate::sandbox::SandboxBuilder::from(reloaded)
            .finish(Some(&defaults), None)
            .unwrap();
        assert_eq!(rebuilt.spec.runtime.workdir, None);
        assert_eq!(rebuilt.spec.runtime.cmd, Some(Vec::new()));

        let mut without_labels = updated;
        without_labels.spec.labels.clear();
        persist_config(&backend, &handle, &without_labels, None)
            .await
            .unwrap();

        let rows = sandbox_label_entity::Entity::find()
            .filter(sandbox_label_entity::Column::SandboxId.eq(sandbox_id))
            .all(pools.read())
            .await
            .unwrap();
        assert!(rows.is_empty());
        let stored = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(pools.read())
            .await
            .unwrap()
            .unwrap();
        let stored: SandboxConfig = serde_json::from_str(&stored.config).unwrap();
        assert!(stored.spec.labels.is_empty());
    }

    #[tokio::test]
    async fn modify_rejects_invalid_env_and_saves_nothing() {
        let temp = tempdir().unwrap();
        let backend: Arc<dyn Backend> = Arc::new(
            LocalBackend::builder()
                .config_path(temp.path().join("config.json"))
                .managed_config_path(temp.path().join("managed.json"))
                .home(temp.path())
                .build()
                .await
                .unwrap(),
        );
        let pools = backend.as_local().unwrap().db().await.unwrap();
        let mut current = config(2, 1024);
        current.spec.env = vec![EnvVar::new("MODE", "dev"), EnvVar::new("MSB_LEGACY", "1")];
        let stored_before = serde_json::to_string(&current).unwrap();
        let model = sandbox_entity::ActiveModel {
            name: Set(current.spec.name.clone()),
            config: Set(stored_before.clone()),
            active_config: Set(None),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let stored_config = || async {
            sandbox_entity::Entity::find_by_id(model.id)
                .one(pools.read())
                .await
                .unwrap()
                .unwrap()
                .config
        };

        let plan = SandboxModificationBuilder::new(backend.clone(), "api")
            .env("MSB_X", "1")
            .env("OK", "1")
            .dry_run()
            .await
            .unwrap();
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].field, ENV_FIELD);
        assert!(plan.conflicts[0].message.contains("reserved MSB_ prefix"));

        let error = SandboxModificationBuilder::new(backend.clone(), "api")
            .env("MSB_X", "1")
            .env("OK", "1")
            .apply()
            .await
            .unwrap_err();
        assert!(error.to_string().contains("reserved MSB_ prefix"));
        assert_eq!(stored_config().await, stored_before);

        let plan = SandboxModificationBuilder::new(backend.clone(), "api")
            .env("A=B", "1")
            .dry_run()
            .await
            .unwrap();
        assert_eq!(plan.conflicts.len(), 1);
        assert!(plan.conflicts[0].message.contains("must not contain '='"));

        // Removing a reserved key that older state already holds stays allowed.
        let plan = SandboxModificationBuilder::new(backend.clone(), "api")
            .remove_env("MSB_LEGACY")
            .apply()
            .await
            .unwrap();
        assert!(plan.applied);
        let saved: SandboxConfig = serde_json::from_str(&stored_config().await).unwrap();
        assert_eq!(saved.spec.env, vec![EnvVar::new("MODE", "dev")]);
    }

    #[test]
    fn running_resource_changes_require_restart_until_live_resize_lands() {
        let patch = SandboxModificationPatch {
            cpus: Some(4),
            memory_mib: Some(4096),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config(2, 1024),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.changes.len(), 4);
        for change in plan.changes {
            let PlannedChange::Config(change) = change else {
                panic!("expected config change");
            };
            assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
            match change.field.as_str() {
                "cpus" | "memory" => {
                    assert_eq!(change.reason.as_deref(), Some(LIVE_RESIZE_UNAVAILABLE));
                }
                "max_cpus" | "max_memory" => {
                    assert!(
                        change
                            .reason
                            .as_deref()
                            .is_some_and(|reason| { reason.contains("boot-time capacity") })
                    );
                }
                field => panic!("unexpected field {field}"),
            }
        }
    }

    #[test]
    fn running_cpus_within_active_capacity_classify_live() {
        // The sandbox booted with reserved capacity: desired and active agree
        // on max_cpus 8 while only 2 CPUs are online.
        let mut desired = config(2, 1024);
        desired.spec.resources.max_cpus = 8;
        let active = desired.clone();
        let patch = SandboxModificationPatch {
            cpus: Some(4),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &desired,
            Some(&active),
            LiveControl {
                root_disk_grow: false,
                cpu_resize: true,
                memory_resize: true,
                secrets: false,
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        let PlannedChange::Config(change) = &plan.changes[0] else {
            panic!("expected config change");
        };
        assert_eq!(change.field, "cpus");
        assert_eq!(change.disposition, ModificationDisposition::Live);
        assert!(change.reason.is_none());
        assert!(validate_apply_supported(&plan).is_ok());
        assert_eq!(live_cpu_target(&plan, &patch), Some(4));
    }

    #[tokio::test]
    async fn label_guard_rolls_back_all_copies() {
        for (name, active_changed) in [("active config changed", true), ("sandbox stopped", false)]
        {
            let temp = tempdir().unwrap();
            let (local, backend) = label_backend(temp.path()).await;
            let mut current = config(2, 1024);
            current.spec.labels.insert("team".into(), "old".into());
            let sandbox_id = seed_running_labeled(&local, &current, &current).await;
            let pools = local.db().await.unwrap();
            let current_json = serde_json::to_string(&current).unwrap();
            let (active_json, status) = if active_changed {
                let mut changed = current.clone();
                changed
                    .spec
                    .labels
                    .insert("team".into(), "concurrent".into());
                (
                    serde_json::to_string(&changed).unwrap(),
                    SandboxStatus::Running,
                )
            } else {
                (current_json.clone(), SandboxStatus::Stopped)
            };
            sandbox_entity::Entity::update_many()
                .col_expr(
                    sandbox_entity::Column::ActiveConfig,
                    Expr::value(active_json),
                )
                .col_expr(sandbox_entity::Column::Status, Expr::value(status))
                .filter(sandbox_entity::Column::Id.eq(sandbox_id))
                .exec(pools.write())
                .await
                .unwrap();
            let before = label_copies(&local, sandbox_id).await;
            let handle = backend
                .sandboxes()
                .get(backend.clone(), &current.spec.name)
                .await
                .unwrap();
            let mut updated = current.clone();
            updated.spec.labels.insert("team".into(), "new".into());

            let error = persist_config(
                &backend,
                &handle,
                &updated,
                Some(ActiveLabelsUpdate {
                    expected_json: current_json,
                    active_config_json: serde_json::to_string(&updated).unwrap(),
                }),
            )
            .await
            .expect_err("label guard accepted stale state");

            assert!(
                matches!(&error, MicrosandboxError::ControlStateChanged),
                "{name}: unexpected error: {error}"
            );
            assert_eq!(label_copies(&local, sandbox_id).await, before, "{name}");
        }
    }

    #[tokio::test]
    async fn label_only_apply_is_live_under_default_and_restart_policies() {
        let temp = tempdir().unwrap();
        let (local, backend) = label_backend(temp.path()).await;

        for (name, restart, diverged) in [
            ("default-saved-and-active-diverged", false, true),
            ("restart-in-sync", true, false),
        ] {
            let mut current = config(2, 1024);
            current.spec.name = name.into();
            let saved_team = if diverged { "new" } else { "old" };
            current.spec.labels.insert("team".into(), saved_team.into());
            if !diverged {
                current.spec.labels.insert("stale".into(), "remove".into());
            }
            let mut active = current.clone();
            active.spec.labels.insert("team".into(), "old".into());
            if diverged {
                active.spec.labels.insert("stale".into(), "remove".into());
            }
            let sandbox_id = seed_running_labeled(&local, &current, &active).await;
            let modify = SandboxModificationBuilder::new(backend.clone(), name)
                .label("team", "new")
                .label("tier", "web")
                .remove_label("stale");

            let plan = if restart { modify.restart() } else { modify }
                .apply()
                .await
                .unwrap();
            assert!(plan.applied, "{name}");
            assert!(
                plan.changes.iter().all(|change| matches!(
                    change,
                    PlannedChange::Config(change)
                        if change.disposition == ModificationDisposition::Live
                )),
                "{name}"
            );
            let expected = BTreeMap::from([
                ("team".to_string(), "new".to_string()),
                ("tier".to_string(), "web".to_string()),
            ]);
            let (desired, active, projection) = label_copies(&local, sandbox_id).await;
            assert_eq!(desired, expected, "{name}");
            assert_eq!(active.as_ref(), Some(&expected), "{name}");
            assert_eq!(
                projection,
                expected.into_iter().collect::<Vec<_>>(),
                "{name}"
            );
        }
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn live_cpu_then_label_apply_uses_the_refreshed_active_snapshot() {
        let temp = tempfile::tempdir_in("/tmp").unwrap();
        let (local, backend) = label_backend(temp.path()).await;
        let mut current = config(1, 1024);
        current.spec.name = "cpu-label-live".into();
        current.spec.resources.max_cpus = 4;
        current.spec.labels.insert("team".into(), "old".into());
        let sandbox_id = seed_running_labeled(&local, &current, &current).await;
        run::ActiveModel {
            sandbox_id: Set(sandbox_id),
            pid: Set(Some(std::process::id() as i32)),
            status: Set(run::RunStatus::Running),
            ..Default::default()
        }
        .insert(local.db().await.unwrap().write())
        .await
        .unwrap();
        let agent = sandbox_agent_socket_path_candidates_for(&local, &current.spec.name).remove(0);
        let path = control_socket_path_for(&agent);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let listener = tokio::net::UnixListener::bind(path).unwrap();
        let server = tokio::spawn(async move {
            for (op, reply) in [
                (
                    "capabilities",
                    "{\"ok\":true,\"capabilities\":{\"cpu_resize\":true,\"memory_resize\":true,\"secrets_update\":false}}",
                ),
                (
                    "pause_state",
                    "{\"ok\":true,\"pause\":{\"paused\":false,\"recovery_required\":false}}",
                ),
                (
                    "cpu_target",
                    "{\"ok\":true,\"cpu\":{\"possible\":4,\"requested_online\":2,\"actual_online\":2,\"enforced\":2}}",
                ),
            ] {
                let (stream, _) = tokio::time::timeout(Duration::from_secs(2), listener.accept())
                    .await
                    .unwrap()
                    .unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                assert_eq!(
                    serde_json::from_str::<serde_json::Value>(&line).unwrap()["op"],
                    op
                );
                stream
                    .get_mut()
                    .write_all(format!("{reply}\n").as_bytes())
                    .await
                    .unwrap();
            }
        });

        let (apply_result, server_result) = tokio::time::timeout(Duration::from_secs(3), async {
            tokio::join!(
                SandboxModificationBuilder::new(backend, &current.spec.name)
                    .cpus(2)
                    .label("team", "new")
                    .apply(),
                server
            )
        })
        .await
        .expect("live modify and fake control peer timed out");
        server_result.expect("fake control peer task panicked");
        apply_result.expect("live CPU and label modification failed");
        let row = sandbox_entity::Entity::find_by_id(sandbox_id)
            .one(local.db().await.unwrap().read())
            .await
            .unwrap()
            .unwrap();
        let active: SandboxConfig = serde_json::from_str(&row.active_config.unwrap()).unwrap();
        assert_eq!(active.spec.resources.cpus, 2);
        let expected = BTreeMap::from([("team".to_string(), "new".to_string())]);
        let (desired, active, projection) = label_copies(&local, sandbox_id).await;
        assert_eq!(desired, expected);
        assert_eq!(active.as_ref(), Some(&expected));
        assert_eq!(projection, expected.into_iter().collect::<Vec<_>>());
    }

    #[tokio::test]
    async fn running_next_start_label_apply_leaves_active_config_unchanged() {
        let temp = tempdir().unwrap();
        let (local, backend) = label_backend(temp.path()).await;
        let mut current = config(2, 1024);
        current.spec.labels.insert("team".into(), "old".into());
        let sandbox_id = seed_running_labeled(&local, &current, &current).await;

        let plan = SandboxModificationBuilder::new(backend, &current.spec.name)
            .label("team", "queued")
            .next_start()
            .apply()
            .await
            .unwrap();

        let PlannedChange::Config(change) = &plan.changes[0] else {
            panic!("expected config change");
        };
        assert_eq!(change.disposition, ModificationDisposition::NextStart);
        let expected = BTreeMap::from([("team".to_string(), "queued".to_string())]);
        let (desired, active, projection) = label_copies(&local, sandbox_id).await;
        assert_eq!(desired, expected);
        assert_eq!(active.as_ref(), Some(&current.spec.labels));
        assert_eq!(projection, expected.into_iter().collect::<Vec<_>>());
    }

    #[test]
    fn running_memory_within_capacity_classifies_live_only_with_control_socket() {
        let mut desired = config(2, 512);
        desired.spec.resources.max_memory_mib = 2048;
        let active = desired.clone();
        let patch = SandboxModificationPatch {
            memory_mib: Some(1024),
            ..SandboxModificationPatch::default()
        };

        for (live_memory_supported, expected) in [
            (true, ModificationDisposition::Live),
            (false, ModificationDisposition::RequiresRestart),
        ] {
            let plan = build_plan(
                "api".to_string(),
                SandboxStatus::Running,
                &desired,
                Some(&active),
                LiveControl {
                    root_disk_grow: false,
                    cpu_resize: live_memory_supported,
                    memory_resize: live_memory_supported,
                    secrets: false,
                },
                patch.clone(),
                ModificationPolicy::NoRestart,
            );
            let PlannedChange::Config(change) = &plan.changes[0] else {
                panic!("expected config change");
            };
            assert_eq!(change.field, "memory");
            assert_eq!(change.disposition, expected);
            if live_memory_supported {
                assert_eq!(live_memory_target(&plan, &patch), Some(1024));
            } else {
                assert_eq!(live_memory_target(&plan, &patch), None);
            }
        }
    }

    #[test]
    fn cpu_and_memory_capabilities_are_independent() {
        let mut active = config(1, 256);
        active.spec.resources.max_cpus = 2;
        active.spec.resources.max_memory_mib = 512;
        for (cpu_resize, memory_resize) in [(true, false), (false, true)] {
            let plan = build_plan(
                "api".into(),
                SandboxStatus::Running,
                &active,
                Some(&active),
                LiveControl {
                    root_disk_grow: false,
                    cpu_resize,
                    memory_resize,
                    secrets: false,
                },
                SandboxModificationPatch {
                    cpus: Some(2),
                    memory_mib: Some(512),
                    ..Default::default()
                },
                ModificationPolicy::NoRestart,
            );
            for (field, supported) in [("cpus", cpu_resize), ("memory", memory_resize)] {
                let change = plan
                    .changes
                    .iter()
                    .find_map(|change| match change {
                        PlannedChange::Config(change) if change.field == field => Some(change),
                        _ => None,
                    })
                    .unwrap();
                assert_eq!(
                    change.disposition,
                    if supported {
                        ModificationDisposition::Live
                    } else {
                        ModificationDisposition::RequiresRestart
                    }
                );
            }
        }
    }

    #[test]
    fn running_cpus_above_active_capacity_require_restart() {
        let mut active = config(2, 1024);
        active.spec.resources.max_cpus = 8;
        let patch = SandboxModificationPatch {
            cpus: Some(12),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config(2, 1024),
            Some(&active),
            LiveControl {
                root_disk_grow: false,
                cpu_resize: true,
                memory_resize: true,
                secrets: false,
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        let PlannedChange::Config(change) = &plan.changes[0] else {
            panic!("expected config change");
        };
        assert_eq!(change.field, "cpus");
        assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
        assert!(
            change
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("exceeds the active max capacity 8"))
        );
        assert_eq!(live_cpu_target(&plan, &patch), None);
    }

    #[test]
    fn restart_policy_allows_restart_required_resource_apply() {
        let patch = SandboxModificationPatch {
            cpus: Some(4),
            memory_mib: Some(4096),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config(2, 1024),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::Restart,
        );

        assert!(validate_apply_supported(&plan).is_ok());
    }

    #[test]
    fn no_restart_policy_rejects_restart_required_resource_apply() {
        let patch = SandboxModificationPatch {
            cpus: Some(4),
            memory_mib: Some(4096),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config(2, 1024),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert!(validate_apply_supported(&plan).is_err());
    }

    #[test]
    fn stopped_resource_changes_are_next_start() {
        let patch = SandboxModificationPatch {
            cpus: Some(4),
            memory_mib: Some(4096),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config(2, 1024),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.changes.len(), 4);
        for change in plan.changes {
            let PlannedChange::Config(change) = change else {
                panic!("expected config change");
            };
            assert_eq!(change.disposition, ModificationDisposition::NextStart);
            assert!(change.reason.is_none());
        }
    }

    #[test]
    fn max_capacity_conflicts_with_requested_effective_value() {
        let patch = SandboxModificationPatch {
            cpus: Some(8),
            max_cpus: Some(4),
            memory_mib: Some(8192),
            max_memory_mib: Some(4096),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config(2, 1024),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.conflicts.len(), 2);
        assert_eq!(plan.conflicts[0].field, "max_cpus");
        assert_eq!(plan.conflicts[1].field, "max_memory");
    }

    #[test]
    fn zero_resource_values_are_conflicts() {
        let patch = SandboxModificationPatch {
            cpus: Some(0),
            max_cpus: Some(0),
            memory_mib: Some(0),
            max_memory_mib: Some(0),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config(2, 1024),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert!(
            plan.conflicts
                .iter()
                .any(|conflict| conflict.field == "cpus")
        );
        assert!(
            plan.conflicts
                .iter()
                .any(|conflict| conflict.field == "memory")
        );
        assert!(
            plan.conflicts
                .iter()
                .any(|conflict| conflict.field == "max_cpus")
        );
        assert!(
            plan.conflicts
                .iter()
                .any(|conflict| conflict.field == "max_memory")
        );
    }

    #[test]
    fn applying_effective_resource_change_raises_capacity_when_needed() {
        let mut config = config(2, 1024);
        config.spec.image = RootfsSource::oci("alpine");
        let mut options = crate::SandboxConfigPatch::new();
        options.spec.resources.max_cpus = Some(2);
        options.spec.resources.max_memory_mib = Some(1024);
        config.caller_config_overrides = Some(Box::new(options));
        let patch = SandboxModificationPatch {
            cpus: Some(4),
            memory_mib: Some(4096),
            ..SandboxModificationPatch::default()
        };

        config.apply_modification(&patch);

        assert_eq!(config.spec.resources.cpus, 4);
        assert_eq!(config.spec.resources.max_cpus, 4);
        assert_eq!(config.spec.resources.memory_mib, 4096);
        assert_eq!(config.spec.resources.max_memory_mib, 4096);

        // A previous explicit capacity must not reappear after modify raises it.
        let resolved = serde_json::to_string(&config).unwrap();
        let stored = config
            .caller_config_overrides_json(&resolved)
            .unwrap()
            .unwrap();
        let config = SandboxConfig::from_stored(&resolved, Some(&stored)).unwrap();
        let rebuilt = crate::sandbox::SandboxBuilder::from(config)
            .finish(None, None)
            .unwrap();
        assert_eq!(rebuilt.spec.resources.max_cpus, 4);
        assert_eq!(rebuilt.spec.resources.max_memory_mib, 4096);
    }

    #[test]
    fn resize_preserves_effective_capacity_when_saved_overrides_differ() {
        let mut config = config(2, 1024);
        config.spec.resources.max_cpus = 8;
        config.spec.resources.max_memory_mib = 8192;
        let mut saved = crate::SandboxConfigPatch::new();
        saved.spec.resources.max_cpus = Some(2);
        saved.spec.resources.max_memory_mib = Some(1024);
        config.caller_config_overrides = Some(Box::new(saved));

        config.apply_modification(&SandboxModificationPatch {
            cpus: Some(4),
            memory_mib: Some(4096),
            ..Default::default()
        });

        assert_eq!(config.spec.resources.max_cpus, 8);
        assert_eq!(config.spec.resources.max_memory_mib, 8192);
        let saved = config.caller_config_overrides.unwrap();
        assert_eq!(saved.spec.resources.max_cpus, Some(8));
        assert_eq!(saved.spec.resources.max_memory_mib, Some(8192));
    }

    fn oci_config_with_upper(upper_mib: u32) -> SandboxConfig {
        let mut config = config(2, 1024);
        config.spec.image = RootfsSource::Oci(microsandbox_types::OciRootfsSource {
            reference: "python".to_string(),
            root_disk: Some(RootDisk::managed(upper_mib)),
        });
        config
    }

    fn oci_config_with_root_disk(root_disk: RootDisk) -> SandboxConfig {
        let mut config = config(2, 1024);
        config.spec.image = RootfsSource::Oci(microsandbox_types::OciRootfsSource {
            reference: "python".to_string(),
            root_disk: Some(root_disk),
        });
        config
    }

    #[test]
    fn stopped_upper_grow_classifies_next_start() {
        let patch = SandboxModificationPatch {
            root_disk_size_mib: Some(8192),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &oci_config_with_upper(4096),
            None,
            LiveControl::default(),
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        assert!(plan.conflicts.is_empty());
        assert_eq!(plan.changes.len(), 1);
        let PlannedChange::Config(change) = &plan.changes[0] else {
            panic!("expected config change");
        };
        assert_eq!(change.field, "root_disk_size");
        assert_eq!(change.change, ChangeKind::Updated);
        assert_eq!(change.before.as_deref(), Some("4 GiB"));
        assert_eq!(change.after.as_deref(), Some("8 GiB"));
        assert_eq!(change.disposition, ModificationDisposition::NextStart);
        assert!(change.reason.is_none());
        assert!(validate_apply_supported(&plan).is_ok());
        assert_eq!(
            root_disk_grow_target(&plan, &patch, &oci_config_with_upper(4096)),
            Some(8192)
        );
    }

    #[test]
    fn invalid_checkpoint_backed_root_grow_does_not_mutate_the_sealed_base() {
        let sandbox = tempdir().unwrap();
        let runtime = sandbox.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        let base = sandbox.path().join("rootfs.raw");
        let head = sandbox.path().join("root-active.qcow2");
        std::fs::write(&base, vec![0; 4096]).unwrap();
        // Checkpoint chains can grow here; malformed heads must still fail before any write.
        std::fs::write(&head, b"qcow").unwrap();
        let head_before = std::fs::read(&head).unwrap();
        let state = serde_json::json!({
            "schema": "microsandbox.runtime-root-disk/1",
            "volume_id": "vol_00000000000000000000000000000000",
            "device_id": "vda",
            "layout": "flat-root",
            "published_generation": 1,
            "layers": [
                {
                    "layer_id": "layer_00000000000000000000000000000001",
                    "path": base,
                    "format": "raw",
                    "integrity_root": microsandbox_image::checkpoint::sparse_file_integrity(&base).unwrap().root
                },
                {
                    "layer_id": "layer_00000000000000000000000000000002",
                    "path": head,
                    "format": "qcow2",
                    "integrity_root": null
                }
            ]
        });
        std::fs::write(
            runtime.join("root-disk.json"),
            serde_json::to_vec(&state).unwrap(),
        )
        .unwrap();

        let error =
            microsandbox_runtime::checkpoint::grow_stopped_root(&runtime, 8192).unwrap_err();
        let expected = microsandbox_image::checkpoint::layer_capacities(vec![
            microsandbox_image::checkpoint::CompactLayer {
                path: head.clone(),
                qcow2: true,
            },
        ])
        .unwrap_err();
        assert_eq!(error, expected.to_string());
        assert_eq!(std::fs::read(&base).unwrap(), vec![0; 4096]);
        assert_eq!(std::fs::read(&head).unwrap(), head_before);
        assert_eq!(
            std::fs::read(runtime.join("root-disk.json")).unwrap(),
            serde_json::to_vec(&state).unwrap()
        );
    }

    #[test]
    fn old_runtime_upper_grow_requires_explicit_restart() {
        let patch = SandboxModificationPatch {
            root_disk_size_mib: Some(8192),
            ..SandboxModificationPatch::default()
        };

        // CPU/memory resize capability alone does not advertise root growth.
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &oci_config_with_upper(4096),
            None,
            LiveControl {
                root_disk_grow: false,
                cpu_resize: true,
                memory_resize: true,
                secrets: true,
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        let PlannedChange::Config(change) = &plan.changes[0] else {
            panic!("expected config change");
        };
        assert_eq!(change.field, "root_disk_size");
        assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
        assert_eq!(
            change.reason.as_deref(),
            Some(UPPER_LIVE_RESIZE_UNAVAILABLE)
        );
        assert!(validate_apply_supported(&plan).is_err());

        // The restart policy makes the same change applicable.
        let restart_plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &oci_config_with_upper(4096),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::Restart,
        );
        assert!(validate_apply_supported(&restart_plan).is_ok());
        assert!(plan_requires_restart(&restart_plan));
    }

    #[test]
    fn owned_root_growth_uses_live_capability_but_respects_explicit_policies() {
        for root in [RootDisk::managed(512), RootDisk::flat(512)] {
            let config = oci_config_with_root_disk(root);
            for (policy, expected) in [
                (ModificationPolicy::NoRestart, ModificationDisposition::Live),
                (
                    ModificationPolicy::NextStart,
                    ModificationDisposition::NextStart,
                ),
                (
                    ModificationPolicy::Restart,
                    ModificationDisposition::RequiresRestart,
                ),
            ] {
                let plan = build_plan(
                    "grow".into(),
                    SandboxStatus::Running,
                    &config,
                    None,
                    LiveControl {
                        root_disk_grow: true,
                        cpu_resize: false,
                        memory_resize: false,
                        secrets: false,
                    },
                    SandboxModificationPatch {
                        root_disk_size_mib: Some(1024),
                        ..Default::default()
                    },
                    policy,
                );
                assert!(plan.conflicts.is_empty());
                let PlannedChange::Config(change) = &plan.changes[0] else {
                    panic!("expected disk change")
                };
                assert_eq!(change.disposition, expected);
                assert!(validate_apply_supported(&plan).is_ok());
            }
        }
    }

    #[test]
    fn running_upper_grow_under_next_start_persists_desired_only() {
        let patch = SandboxModificationPatch {
            root_disk_size_mib: Some(8192),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &oci_config_with_upper(4096),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NextStart,
        );

        let PlannedChange::Config(change) = &plan.changes[0] else {
            panic!("expected config change");
        };
        assert_eq!(change.disposition, ModificationDisposition::NextStart);
        assert_eq!(change.reason.as_deref(), Some(UPPER_GROWS_ON_NEXT_START));
        assert!(validate_apply_supported(&plan).is_ok());
    }

    #[test]
    fn upper_shrink_and_same_size_requests_conflict() {
        for (target_mib, expected) in [
            (2048, "shrink is not supported"),
            (4096, "only grow is supported"),
        ] {
            let patch = SandboxModificationPatch {
                root_disk_size_mib: Some(target_mib),
                ..SandboxModificationPatch::default()
            };

            let plan = build_plan(
                "api".to_string(),
                SandboxStatus::Stopped,
                &oci_config_with_upper(4096),
                None,
                LiveControl::default(),
                patch,
                ModificationPolicy::NoRestart,
            );

            assert!(plan.changes.is_empty());
            assert_eq!(plan.conflicts.len(), 1);
            assert_eq!(plan.conflicts[0].field, "root_disk_size");
            assert!(
                plan.conflicts[0].message.contains(expected),
                "unexpected conflict for {target_mib}: {}",
                plan.conflicts[0].message
            );
            assert!(validate_apply_supported(&plan).is_err());
        }
    }

    #[test]
    fn non_oci_rootfs_upper_change_conflicts() {
        let mut current = config(2, 1024);
        current.spec.image = RootfsSource::Bind {
            path: "/srv/rootfs".into(),
            follow_root_symlinks: false,
        };
        let patch = SandboxModificationPatch {
            root_disk_size_mib: Some(8192),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &current,
            None,
            LiveControl::default(),
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        assert!(plan.changes.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert_eq!(plan.conflicts[0].field, "root_disk_size");
        assert!(plan.conflicts[0].message.contains("requires an OCI rootfs"));
        assert_eq!(root_disk_grow_target(&plan, &patch, &current), None);
    }

    #[test]
    fn unmaterialized_upper_default_compares_against_create_default() {
        // Configs that predate materialized defaults store no upper size; the
        // effective current size is the create-time default (4 GiB).
        let patch = SandboxModificationPatch {
            root_disk_size_mib: Some(2048),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config(2, 1024),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.conflicts.len(), 1);
        assert!(
            plan.conflicts[0]
                .message
                .contains("shrink is not supported")
        );
    }

    #[test]
    fn applying_upper_patch_updates_oci_config() {
        let mut config = oci_config_with_upper(4096);
        let patch = SandboxModificationPatch {
            root_disk_size_mib: Some(8192),
            ..SandboxModificationPatch::default()
        };

        config.apply_modification(&patch);

        assert_eq!(
            config.spec.image.oci_root_disk(),
            Some(&RootDisk::managed(8192))
        );
    }

    #[test]
    fn tmpfs_root_disk_resizes_any_direction_without_host_grow() {
        let current = oci_config_with_root_disk(RootDisk::tmpfs(1024));
        // Shrink is fine for tmpfs: the content is ephemeral.
        let patch = SandboxModificationPatch {
            root_disk_size_mib: Some(512),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &current,
            None,
            LiveControl::default(),
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        assert!(plan.conflicts.is_empty());
        assert_eq!(plan.changes.len(), 1);
        let PlannedChange::Config(change) = &plan.changes[0] else {
            panic!("expected config change");
        };
        assert_eq!(change.field, "root_disk_size");
        // No host file to grow for a tmpfs root disk.
        assert_eq!(root_disk_grow_target(&plan, &patch, &current), None);
    }

    #[test]
    fn tmpfs_root_disk_resize_over_memory_conflicts() {
        // config() allocates 1024 MiB of guest memory.
        let current = oci_config_with_root_disk(RootDisk::tmpfs(512));
        let patch = SandboxModificationPatch {
            root_disk_size_mib: Some(2048),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &current,
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert!(plan.changes.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert!(
            plan.conflicts[0]
                .message
                .contains("must not exceed sandbox memory")
        );
    }

    #[test]
    fn disk_image_root_disk_resize_conflicts() {
        let current = oci_config_with_root_disk(RootDisk::DiskImage {
            path: "./scratch.img".into(),
            format: microsandbox_types::DiskImageFormat::Raw,
            fstype: None,
        });
        let patch = SandboxModificationPatch {
            root_disk_size_mib: Some(8192),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &current,
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert!(plan.changes.is_empty());
        assert_eq!(plan.conflicts.len(), 1);
        assert!(
            plan.conflicts[0]
                .message
                .contains("user-supplied disk image")
        );
    }

    #[test]
    fn running_env_and_workdir_require_restart_while_labels_are_live() {
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod")],
            labels: vec![("team".to_string(), "infra".to_string())],
            workdir: Some("/srv".to_string()),
            ..SandboxModificationPatch::default()
        };
        let current = config(2, 1024);

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &current,
            Some(&current),
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.changes.len(), 3);
        for change in plan.changes {
            let PlannedChange::Config(change) = change else {
                panic!("expected config change");
            };
            assert_eq!(change.change, ChangeKind::Added);
            match change.field.as_str() {
                "env" | "workdir" => {
                    assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
                    assert_eq!(
                        change.reason.as_deref(),
                        Some(LIVE_EXEC_DEFAULT_UPDATE_UNAVAILABLE)
                    );
                }
                "label" => {
                    assert_eq!(change.disposition, ModificationDisposition::Live);
                    assert!(change.reason.is_none());
                }
                field => panic!("unexpected field {field}"),
            }
        }
    }

    #[test]
    fn label_dispositions_by_status_policy_and_snapshot() {
        let mut current = config(2, 1024);
        current.spec.labels.insert("team".into(), "old".into());
        let patch = SandboxModificationPatch {
            labels: vec![("team".into(), "new".into())],
            ..Default::default()
        };
        let running = SandboxStatus::Running;
        let draining = SandboxStatus::Draining;
        let default = ModificationPolicy::NoRestart;
        let restart = ModificationPolicy::Restart;
        let live = ModificationDisposition::Live;
        let requires_restart = ModificationDisposition::RequiresRestart;
        let next_start = ModificationDisposition::NextStart;
        let unsupported = ModificationDisposition::Unsupported;
        #[rustfmt::skip]
        let cases = [
            ("running default",     running,                 default,                       true,  live,             None,                                              true),
            ("running restart",     running,                 restart,                       true,  live,             None,                                              true),
            ("draining default",    draining,                default,                       true,  live,             None,                                              true),
            ("draining restart",    draining,                restart,                       true,  live,             None,                                              true),
            ("running no snapshot", running,                 default,                       false, requires_restart, Some(LIVE_LABEL_UPDATE_NEEDS_ACTIVE_CONFIG),      false),
            ("no snapshot restart", running,                 restart,                       false, requires_restart, Some(LIVE_LABEL_UPDATE_NEEDS_ACTIVE_CONFIG),      true),
            ("next start",          running,                 ModificationPolicy::NextStart, true,  next_start,       None,                                              true),
            ("starting",            SandboxStatus::Starting, default,                       true,  unsupported,      Some("cannot modify while sandbox is starting"), false),
            ("paused",              SandboxStatus::Paused,   default,                       true,  unsupported,      Some("cannot modify while sandbox is paused"),   false),
        ];

        for (name, status, policy, has_active, disposition, reason, apply_ok) in cases {
            let plan = build_plan(
                "api".into(),
                status,
                &current,
                has_active.then_some(&current),
                LiveControl::default(),
                patch.clone(),
                policy,
            );

            let PlannedChange::Config(change) = &plan.changes[0] else {
                panic!("{name}: expected config change");
            };
            assert_eq!(change.disposition, disposition, "{name}");
            assert_eq!(change.reason.as_deref(), reason, "{name}");
            assert_eq!(validate_apply_supported(&plan).is_ok(), apply_ok, "{name}");
        }
    }

    #[test]
    fn label_plan_reconciles_saved_and_active() {
        #[rustfmt::skip]
        let cases = [
            ("set saved only",                    false, (Some("saved"), None),           Some(ChangeKind::Added),   None),
            ("set active only",                   false, (None, Some("old")),             Some(ChangeKind::Updated), Some("key=old")),
            ("set both differing",                false, (Some("saved"), Some("old")),    Some(ChangeKind::Updated), Some("key=old")),
            ("set saved matches, active differs", false, (Some("x"), Some("old")),        Some(ChangeKind::Updated), Some("key=old")),
            ("set active matches, saved differs", false, (Some("saved"), Some("x")),      Some(ChangeKind::Updated), Some("key=saved")),
            ("set both equal",                    false, (Some("x"), Some("x")),          None,                      None),
            ("remove saved only",                 true,  (Some("saved"), None),           Some(ChangeKind::Removed), Some("key=saved")),
            ("remove active only",                true,  (None, Some("active")),          Some(ChangeKind::Removed), Some("key=active")),
            ("remove both differing",             true,  (Some("saved"), Some("active")), Some(ChangeKind::Removed), Some("key=active")),
            ("remove both absent",                true,  (None, None),                    None,                      None),
        ];
        for (name, remove, (saved, active), kind, before) in cases {
            let mut desired = config(2, 1024);
            if let Some(value) = saved {
                desired.spec.labels.insert("key".into(), value.into());
            }
            let mut active_config = config(2, 1024);
            if let Some(value) = active {
                active_config.spec.labels.insert("key".into(), value.into());
            }
            let mut patch = SandboxModificationPatch::default();
            if remove {
                patch.labels_remove.push("key".into());
            } else {
                patch.labels.push(("key".into(), "x".into()));
            }

            let plan = build_plan(
                "api".into(),
                SandboxStatus::Running,
                &desired,
                Some(&active_config),
                LiveControl::default(),
                patch,
                ModificationPolicy::NoRestart,
            );

            let Some(kind) = kind else {
                assert!(plan.changes.is_empty(), "{name}");
                continue;
            };
            let [PlannedChange::Config(change)] = plan.changes.as_slice() else {
                panic!("{name}: expected one config change");
            };
            assert_eq!(change.change, kind, "{name}");
            assert_eq!(change.before.as_deref(), before, "{name}");
            let after = (!remove).then_some("key=x");
            assert_eq!(change.after.as_deref(), after, "{name}");
        }
    }

    #[test]
    fn mixed_label_and_env_changes_follow_patch_policy() {
        let current = config(2, 1024);
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod")],
            labels: vec![("team".into(), "new".into())],
            ..Default::default()
        };

        for (policy, env, label, apply_allowed, restart) in [
            (
                ModificationPolicy::NoRestart,
                ModificationDisposition::RequiresRestart,
                ModificationDisposition::Live,
                false,
                true,
            ),
            (
                ModificationPolicy::Restart,
                ModificationDisposition::RequiresRestart,
                ModificationDisposition::Live,
                true,
                true,
            ),
            (
                ModificationPolicy::NextStart,
                ModificationDisposition::NextStart,
                ModificationDisposition::NextStart,
                true,
                false,
            ),
        ] {
            let plan = build_plan(
                "api".into(),
                SandboxStatus::Running,
                &current,
                Some(&current),
                LiveControl::default(),
                patch.clone(),
                policy,
            );
            let dispositions = plan
                .changes
                .iter()
                .map(|change| match change {
                    PlannedChange::Config(change) => (change.field.as_str(), change.disposition),
                    PlannedChange::Secret(_) => panic!("expected config change"),
                })
                .collect::<Vec<_>>();

            assert_eq!(dispositions, vec![(ENV_FIELD, env), (LABEL_FIELD, label)]);
            assert_eq!(validate_apply_supported(&plan).is_ok(), apply_allowed);
            assert_eq!(plan_requires_restart(&plan), restart);
        }
    }

    #[test]
    fn stopped_env_label_workdir_changes_are_next_start() {
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod")],
            env_remove: vec!["EXTRA".to_string()],
            labels: vec![("team".to_string(), "infra".to_string())],
            labels_remove: vec!["old".to_string()],
            workdir: Some("/srv".to_string()),
            ..SandboxModificationPatch::default()
        };

        let mut current = config(2, 1024);
        current.spec.env.push(EnvVar::new("EXTRA", "1"));
        current
            .spec
            .labels
            .insert("old".to_string(), "x".to_string());

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &current,
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.changes.len(), 5);
        assert!(plan.conflicts.is_empty());
        for change in plan.changes {
            let PlannedChange::Config(change) = change else {
                panic!("expected config change");
            };
            assert_eq!(change.disposition, ModificationDisposition::NextStart);
            assert!(change.reason.is_none());
        }
    }

    #[test]
    fn spec_change_kinds_follow_current_config() {
        let mut current = config(2, 1024);
        current.spec.env = vec![EnvVar::new("MODE", "dev"), EnvVar::new("EXTRA", "1")];
        current
            .spec
            .labels
            .insert("team".to_string(), "infra".to_string());
        current.spec.runtime.workdir = Some("/app".to_string());

        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod"), EnvVar::new("NEW", "1")],
            env_remove: vec!["EXTRA".to_string(), "MISSING".to_string()],
            labels: vec![("tier".to_string(), "gold".to_string())],
            labels_remove: vec!["team".to_string()],
            workdir: Some("/srv".to_string()),
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &current,
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        let rows: Vec<(&str, ChangeKind, Option<&str>, Option<&str>)> = plan
            .changes
            .iter()
            .map(|change| {
                let PlannedChange::Config(change) = change else {
                    panic!("expected config change");
                };
                (
                    change.field.as_str(),
                    change.change,
                    change.before.as_deref(),
                    change.after.as_deref(),
                )
            })
            .collect();

        assert_eq!(
            rows,
            vec![
                (
                    "env",
                    ChangeKind::Updated,
                    Some("MODE=dev"),
                    Some("MODE=prod")
                ),
                ("env", ChangeKind::Added, None, Some("NEW=1")),
                ("env", ChangeKind::Removed, Some("EXTRA=1"), None),
                ("label", ChangeKind::Added, None, Some("tier=gold")),
                ("label", ChangeKind::Removed, Some("team=infra"), None),
                ("workdir", ChangeKind::Updated, Some("/app"), Some("/srv")),
            ]
        );
    }

    #[test]
    fn running_spec_changes_warn_future_execs_only_under_restart_and_next_start() {
        let current = config(2, 1024);
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod"), EnvVar::new("NEW", "1")],
            workdir: Some("/srv".to_string()),
            labels: vec![("tier".to_string(), "gold".to_string())],
            ..SandboxModificationPatch::default()
        };

        for policy in [ModificationPolicy::Restart, ModificationPolicy::NextStart] {
            let plan = build_plan(
                "api".to_string(),
                SandboxStatus::Running,
                &current,
                None,
                LiveControl::default(),
                patch.clone(),
                policy,
            );

            let future_exec_fields: Vec<&str> = plan
                .warnings
                .iter()
                .filter(|warning| warning.message == FUTURE_EXECS_ONLY)
                .map(|warning| warning.field.as_str())
                .collect();
            // One warning per field: env is deduplicated, labels are excluded.
            assert_eq!(future_exec_fields, vec![ENV_FIELD, WORKDIR_FIELD]);
        }
    }

    #[test]
    fn future_exec_warning_skips_stopped_sandboxes_and_default_policy() {
        let current = config(2, 1024);
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod")],
            workdir: Some("/srv".to_string()),
            ..SandboxModificationPatch::default()
        };

        let cases = [
            (SandboxStatus::Stopped, ModificationPolicy::NextStart),
            (SandboxStatus::Stopped, ModificationPolicy::Restart),
            (SandboxStatus::Running, ModificationPolicy::NoRestart),
        ];
        for (status, policy) in cases {
            let plan = build_plan(
                "api".to_string(),
                status,
                &current,
                None,
                LiveControl::default(),
                patch.clone(),
                policy,
            );

            assert!(
                plan.warnings
                    .iter()
                    .all(|warning| warning.message != FUTURE_EXECS_ONLY),
                "unexpected future-exec warning for {status:?} under {policy:?}"
            );
        }
    }

    #[test]
    fn applying_env_label_workdir_patch_mutates_config() {
        let mut current = config(2, 1024);
        current.spec.env = vec![EnvVar::new("MODE", "dev"), EnvVar::new("EXTRA", "1")];
        current
            .spec
            .labels
            .insert("team".to_string(), "infra".to_string());
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod"), EnvVar::new("NEW", "1")],
            env_remove: vec!["EXTRA".to_string()],
            labels: vec![("tier".to_string(), "gold".to_string())],
            labels_remove: vec!["team".to_string()],
            workdir: Some("/srv".to_string()),
            ..SandboxModificationPatch::default()
        };

        current.apply_modification(&patch);

        assert_eq!(
            current.spec.env,
            vec![EnvVar::new("MODE", "prod"), EnvVar::new("NEW", "1")]
        );
        assert_eq!(
            current.spec.labels.get("tier").map(String::as_str),
            Some("gold")
        );
        assert!(!current.spec.labels.contains_key("team"));
        assert_eq!(current.spec.runtime.workdir.as_deref(), Some("/srv"));
    }

    #[test]
    fn a_repeated_env_key_plans_once_against_its_last_entry() {
        // Commands see the last entry for a key.
        let mut current = config(2, 1024);
        current.spec.env = vec![
            EnvVar::new("KEY", "a"),
            EnvVar::new("OTHER", "1"),
            EnvVar::new("KEY", "b"),
        ];
        let rows = |patch: SandboxModificationPatch| -> Vec<(Option<String>, Option<String>)> {
            build_plan(
                "api".to_string(),
                SandboxStatus::Stopped,
                &current,
                None,
                LiveControl::default(),
                patch,
                ModificationPolicy::NoRestart,
            )
            .changes
            .into_iter()
            .map(|change| {
                let PlannedChange::Config(change) = change else {
                    panic!("expected config change");
                };
                (change.before, change.after)
            })
            .collect()
        };
        let set = |env: Vec<EnvVar>| SandboxModificationPatch {
            env,
            ..SandboxModificationPatch::default()
        };
        let row = |before: &str, after: Option<&str>| {
            (Some(before.to_string()), after.map(str::to_string))
        };

        assert_eq!(
            rows(set(vec![EnvVar::new("KEY", "v")])),
            vec![row("KEY=b", Some("KEY=v"))]
        );
        assert_eq!(
            rows(set(vec![EnvVar::new("KEY", "a")])),
            vec![row("KEY=b", Some("KEY=a"))]
        );
        assert_eq!(
            rows(set(vec![EnvVar::new("KEY", "x"), EnvVar::new("KEY", "y")])),
            vec![row("KEY=b", Some("KEY=y"))]
        );
        assert!(rows(set(vec![EnvVar::new("KEY", "x"), EnvVar::new("KEY", "b")])).is_empty());
        assert_eq!(
            rows(SandboxModificationPatch {
                env_remove: vec!["KEY".to_string()],
                ..SandboxModificationPatch::default()
            }),
            vec![row("KEY=b", None)]
        );
    }

    #[test]
    fn applying_a_repeated_env_key_keeps_one_entry_with_the_new_value() {
        let mut current = config(2, 1024);
        current.spec.env = vec![
            EnvVar::new("KEY", "a"),
            EnvVar::new("OTHER", "1"),
            EnvVar::new("KEY", "b"),
            EnvVar::new("LAST", "1"),
        ];
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("KEY", "x"), EnvVar::new("KEY", "y")],
            ..SandboxModificationPatch::default()
        };

        let mut changed = current.clone();
        changed.apply_modification(&patch);
        assert_eq!(
            changed.spec.env,
            vec![
                EnvVar::new("OTHER", "1"),
                EnvVar::new("KEY", "y"),
                EnvVar::new("LAST", "1"),
            ]
        );

        // A key already at its value plans no change, so apply leaves its entries.
        for env in [
            vec![EnvVar::new("KEY", "b")],
            vec![EnvVar::new("KEY", "x"), EnvVar::new("KEY", "b")],
        ] {
            let mut unchanged = current.clone();
            let patch = SandboxModificationPatch {
                env,
                labels: vec![("team".to_string(), "infra".to_string())],
                ..SandboxModificationPatch::default()
            };
            unchanged.apply_modification(&patch);
            assert_eq!(unchanged.spec.env, current.spec.env);
        }
    }

    #[test]
    fn setting_and_removing_the_same_key_is_a_conflict() {
        let patch = SandboxModificationPatch {
            env: vec![EnvVar::new("MODE", "prod")],
            env_remove: vec!["MODE".to_string()],
            labels: vec![("team".to_string(), "infra".to_string())],
            labels_remove: vec!["team".to_string()],
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config(2, 1024),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(plan.conflicts.len(), 2);
        assert_eq!(plan.conflicts[0].field, "env");
        assert!(plan.conflicts[0].message.contains("MODE"));
        assert_eq!(plan.conflicts[1].field, "label");
        assert!(plan.conflicts[1].message.contains("team"));
        assert!(validate_apply_supported(&plan).is_err());
    }

    #[tokio::test]
    async fn setting_an_invalid_label_key_is_refused_and_nothing_is_saved() {
        let temp = tempdir().unwrap();
        let backend: Arc<dyn Backend> = Arc::new(
            LocalBackend::builder()
                .config_path(temp.path().join("config.json"))
                .managed_config_path(temp.path().join("managed.json"))
                .home(temp.path())
                .build()
                .await
                .unwrap(),
        );
        let pools = backend.as_local().unwrap().db().await.unwrap();
        // `sandbox.legacy` stands in for a key saved before modify checked keys.
        let mut current = config(2, 1024);
        current.spec.labels.insert("team".into(), "infra".into());
        current
            .spec
            .labels
            .insert("sandbox.legacy".into(), "old".into());
        let stored_json = serde_json::to_string(&current).unwrap();
        let model = sandbox_entity::ActiveModel {
            name: Set(current.spec.name.clone()),
            config: Set(stored_json.clone()),
            active_config: Set(None),
            status: Set(SandboxStatus::Stopped),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(pools.write())
        .await
        .unwrap();
        let stored_config = || async {
            sandbox_entity::Entity::find_by_id(model.id)
                .one(pools.read())
                .await
                .unwrap()
                .unwrap()
                .config
        };

        for key in ["", "sandbox.id"] {
            let plan = SandboxModificationBuilder::new(backend.clone(), "api")
                .label(key, "x")
                .dry_run()
                .await
                .unwrap();
            assert_eq!(plan.conflicts.len(), 1, "key {key:?}");
            assert_eq!(plan.conflicts[0].field, LABEL_FIELD);

            let error = SandboxModificationBuilder::new(backend.clone(), "api")
                .label(key, "x")
                .apply()
                .await
                .expect_err(&format!("key {key:?} was applied"));
            assert!(error.to_string().contains("label key"), "{error}");
            assert_eq!(stored_config().await, stored_json);
        }

        let plan = SandboxModificationBuilder::new(backend.clone(), "api")
            .remove_label("sandbox.legacy")
            .apply()
            .await
            .unwrap();
        assert!(plan.applied);
        let saved: SandboxConfig = serde_json::from_str(&stored_config().await).unwrap();
        assert_eq!(
            saved.spec.labels.into_iter().collect::<Vec<_>>(),
            vec![("team".to_string(), "infra".to_string())]
        );
    }

    #[test]
    fn secret_plan_never_contains_secret_values() {
        const VALUE_SENTINEL: &str = "modify-plan-secret-sentinel";

        // Put real material into the input: an empty value would make the
        // absence assertion pass even if planning accidentally copied it.
        let patch = SandboxModificationPatch {
            secrets: vec![SecretModificationPatch {
                name: "API_KEY".to_string(),
                source: None,
                value: zeroize::Zeroizing::new(VALUE_SENTINEL.to_string()),
                placeholder: None,
                allowed_hosts: vec!["api.example.com".to_string()],
                ..SecretModificationPatch::default()
            }],
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config(2, 1024),
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );
        let json = serde_json::to_string(&plan).unwrap();

        assert!(json.contains("$MSB_API_KEY"));
        assert!(json.contains("api.example.com"));
        assert!(!json.contains(VALUE_SENTINEL));
        assert!(!format!("{plan:?}").contains(VALUE_SENTINEL));
        assert_eq!(plan.sandbox, "api");

        let PlannedChange::Secret(change) = &plan.changes[0] else {
            panic!("expected secret change");
        };
        assert_eq!(change.field, SECRET_FIELD);
        assert_eq!(change.change, SecretChangeKind::Added);
        assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
    }

    //----------------------------------------------------------------------------------------------
    // Tests: Secrets
    //----------------------------------------------------------------------------------------------

    #[cfg(feature = "net")]
    const SECRET_SENTINEL: &str = "sentinel-secret-value";

    #[cfg(feature = "net")]
    fn config_with_secret(name: &str, value: &str) -> SandboxConfig {
        use microsandbox_network::secrets::config::{HostPattern, SecretEntry, SecretSubstitution};

        let mut config = config(2, 1024);
        let mut network = config.local_network_config().unwrap();
        network.secrets.secrets.push(SecretEntry {
            env_var: name.to_string(),
            value: zeroize::Zeroizing::new(value.to_string()),
            source: None,
            placeholder: format!("$MSB_{name}"),
            allowed_hosts: vec![HostPattern::Exact("api.example.com".into())],
            substitution: SecretSubstitution::default(),
            passthrough_hosts: Vec::new(),
            violation_action: None,
            require_tls_identity: true,
        });
        // Mirror the top-level sandbox builder's create-time policy.
        crate::sandbox::config::ensure_tls_for_secrets(&mut network);
        config.set_local_network_config(network).unwrap();
        config
    }

    /// The pre-fix shape this bug used to persist: a secret with TLS off.
    #[cfg(feature = "net")]
    fn config_with_secret_and_tls_disabled(name: &str, value: &str) -> SandboxConfig {
        let mut config = config_with_secret(name, value);
        let mut network = config.local_network_config().unwrap();
        network.tls.enabled = false;
        config.set_local_network_config(network).unwrap();
        config
    }

    /// A deliberate plain-HTTP secret configuration: substitution is allowed
    /// without TLS identity, so interception stays off.
    #[cfg(feature = "net")]
    fn config_with_plain_http_secret_and_tls_disabled(name: &str, value: &str) -> SandboxConfig {
        let mut config = config_with_secret_and_tls_disabled(name, value);
        let mut network = config.local_network_config().unwrap();
        network.secrets.secrets[0].require_tls_identity = false;
        config.set_local_network_config(network).unwrap();
        config
    }

    /// A source-based spec for `name`, resolving from the same-named host
    /// environment variable.
    #[cfg(feature = "net")]
    fn source_spec(name: &str, hosts: &[&str]) -> SecretModificationPatch {
        SecretModificationPatch {
            name: name.to_string(),
            source: Some(SecretSource::Env {
                var: name.to_string(),
            }),
            allowed_hosts: hosts.iter().map(ToString::to_string).collect(),
            ..SecretModificationPatch::default()
        }
    }

    /// A material-free spec for `name` (hosts and/or placeholder only).
    #[cfg(feature = "net")]
    fn bare_spec(name: &str, hosts: &[&str]) -> SecretModificationPatch {
        SecretModificationPatch {
            name: name.to_string(),
            allowed_hosts: hosts.iter().map(ToString::to_string).collect(),
            ..SecretModificationPatch::default()
        }
    }

    #[cfg(feature = "net")]
    fn patch_with_specs(specs: Vec<SecretModificationPatch>) -> SandboxModificationPatch {
        SandboxModificationPatch {
            secrets: specs,
            ..SandboxModificationPatch::default()
        }
    }

    #[cfg(feature = "net")]
    fn secret_policy_specs() -> Vec<SecretModificationPatch> {
        vec![
            SecretModificationPatch {
                substitution: Some(SecretSubstitution {
                    headers: false,
                    header_fields: Vec::new(),
                    query: true,
                    body: true,
                }),
                ..bare_spec("API_KEY", &[])
            },
            SecretModificationPatch {
                violation_action: Some(SecretViolationAction::BlockAndTerminate),
                ..bare_spec("API_KEY", &[])
            },
            SecretModificationPatch {
                require_tls_identity: Some(false),
                ..bare_spec("API_KEY", &[])
            },
            SecretModificationPatch {
                passthrough_hosts: vec!["logs.example.com".into()],
                ..bare_spec("API_KEY", &[])
            },
            SecretModificationPatch {
                substitution: Some(SecretSubstitution {
                    header_fields: vec!["authorization".into(), "x-api-key".into()],
                    ..SecretSubstitution::default()
                }),
                ..bare_spec("API_KEY", &[])
            },
        ]
    }

    #[cfg(feature = "net")]
    #[test]
    fn secret_policy_edits_are_planned_and_never_sent_live() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        for spec in secret_policy_specs() {
            for (status, policy, expected, apply_allowed) in [
                (
                    SandboxStatus::Running,
                    ModificationPolicy::NoRestart,
                    ModificationDisposition::RequiresRestart,
                    false,
                ),
                (
                    SandboxStatus::Running,
                    ModificationPolicy::Restart,
                    ModificationDisposition::RequiresRestart,
                    true,
                ),
                (
                    SandboxStatus::Running,
                    ModificationPolicy::NextStart,
                    ModificationDisposition::NextStart,
                    true,
                ),
                (
                    SandboxStatus::Stopped,
                    ModificationPolicy::NoRestart,
                    ModificationDisposition::NextStart,
                    true,
                ),
                (
                    SandboxStatus::Stopped,
                    ModificationPolicy::Restart,
                    ModificationDisposition::NextStart,
                    true,
                ),
                (
                    SandboxStatus::Stopped,
                    ModificationPolicy::NextStart,
                    ModificationDisposition::NextStart,
                    true,
                ),
                (
                    SandboxStatus::Paused,
                    ModificationPolicy::NoRestart,
                    ModificationDisposition::Unsupported,
                    false,
                ),
                (
                    SandboxStatus::Paused,
                    ModificationPolicy::Restart,
                    ModificationDisposition::Unsupported,
                    false,
                ),
                (
                    SandboxStatus::Paused,
                    ModificationPolicy::NextStart,
                    ModificationDisposition::NextStart,
                    true,
                ),
            ] {
                for supported in [false, true] {
                    for combined_change in 0..3 {
                        let mut spec = spec.clone();
                        match combined_change {
                            1 => spec.allowed_hosts = vec!["other.example.com".into()],
                            2 => spec.value = SECRET_SENTINEL.to_string().into(),
                            _ => {}
                        }
                        let patch = patch_with_specs(vec![spec]);
                        let plan = build_plan(
                            "api".into(),
                            status,
                            &config,
                            Some(&config),
                            LiveControl {
                                secrets: supported,
                                ..Default::default()
                            },
                            patch.clone(),
                            policy,
                        );
                        assert_eq!(plan.changes.len(), 1);
                        match &plan.changes[0] {
                            PlannedChange::Config(change) => {
                                assert_eq!(change.field, "secret.API_KEY.policy");
                                assert_eq!(change.change, ChangeKind::Updated);
                                assert_eq!(change.disposition, expected);
                            }
                            PlannedChange::Secret(change) => {
                                assert_ne!(combined_change, 0);
                                assert_eq!(change.disposition, expected);
                            }
                        }
                        assert!(live_secret_updates(&plan, &patch).unwrap().is_empty());
                        assert_eq!(validate_apply_supported(&plan).is_ok(), apply_allowed,);
                        assert_eq!(
                            plan_requires_restart(&plan),
                            expected == ModificationDisposition::RequiresRestart
                        );
                        assert!(
                            !serde_json::to_string(&plan)
                                .unwrap()
                                .contains(SECRET_SENTINEL)
                        );
                        assert!(plan.warnings.is_empty());
                    }
                }
            }
        }
    }

    #[cfg(feature = "net")]
    #[test]
    fn secret_policy_comparison_preserves_noops_and_checks_active_rules() {
        let original = config_with_secret("API_KEY", SECRET_SENTINEL);
        for spec in secret_policy_specs() {
            let patch = patch_with_specs(vec![spec]);
            let mut desired = original.clone();
            desired.update_secrets(&patch).unwrap();
            let plan = build_plan(
                "api".into(),
                SandboxStatus::Running,
                &desired,
                Some(&desired),
                LiveControl {
                    secrets: true,
                    ..Default::default()
                },
                patch.clone(),
                ModificationPolicy::NoRestart,
            );
            assert!(
                plan.changes.is_empty(),
                "identical explicit policies are no-ops"
            );

            let pending = build_plan(
                "api".into(),
                SandboxStatus::Running,
                &desired,
                Some(&original),
                LiveControl {
                    secrets: true,
                    ..Default::default()
                },
                patch.clone(),
                ModificationPolicy::NoRestart,
            );
            assert!(plan_requires_restart(&pending));
            assert!(validate_apply_supported(&pending).is_err());
            assert!(live_secret_updates(&pending, &patch).unwrap().is_empty());

            let omitted = patch_with_specs(vec![bare_spec("API_KEY", &[])]);
            let unchanged = build_plan(
                "api".into(),
                SandboxStatus::Running,
                &desired,
                Some(&desired),
                LiveControl {
                    secrets: true,
                    ..Default::default()
                },
                omitted,
                ModificationPolicy::NoRestart,
            );
            assert!(
                unchanged.changes.is_empty(),
                "omitted fields preserve existing policies"
            );
        }
    }

    #[cfg(feature = "net")]
    #[tokio::test]
    async fn applying_stopped_secret_policy_edits_persists_each_option() {
        let temp = tempdir().unwrap();
        let backend: Arc<dyn Backend> = Arc::new(
            LocalBackend::builder()
                .config_path(temp.path().join("config.json"))
                .managed_config_path(temp.path().join("managed.json"))
                .home(temp.path())
                .build()
                .await
                .unwrap(),
        );
        let pools = backend.as_local().unwrap().db().await.unwrap();
        for (index, spec) in secret_policy_specs().into_iter().enumerate() {
            let mut current = config_with_secret("API_KEY", SECRET_SENTINEL);
            current.spec.name = format!("policy-{index}");
            let model = sandbox_entity::ActiveModel {
                name: Set(current.spec.name.clone()),
                config: Set(serde_json::to_string(&current).unwrap()),
                active_config: Set(None),
                status: Set(SandboxStatus::Stopped),
                ephemeral: Set(false),
                ..Default::default()
            }
            .insert(pools.write())
            .await
            .unwrap();
            let patch = patch_with_specs(vec![spec]);
            let plan = SandboxModificationBuilder::new(backend.clone(), &current.spec.name)
                .with_patch(patch.clone())
                .apply()
                .await
                .unwrap();
            assert!(plan.applied);
            assert_eq!(plan.changes.len(), 1);
            let row = sandbox_entity::Entity::find_by_id(model.id)
                .one(pools.read())
                .await
                .unwrap()
                .unwrap();
            assert!(row.active_config.is_none());
            let saved: SandboxConfig = serde_json::from_str(&row.config).unwrap();
            let network = saved.local_network_config().unwrap();
            let entry = &network.secrets.secrets[0];
            match index {
                0 => {
                    assert!(!entry.substitution.headers);
                    assert!(entry.substitution.query);
                    assert!(entry.substitution.body);
                }
                1 => assert_eq!(
                    entry.violation_action,
                    Some(SecretViolationAction::BlockAndTerminate)
                ),
                2 => assert!(!entry.require_tls_identity),
                3 => assert_eq!(
                    entry
                        .passthrough_hosts
                        .iter()
                        .cloned()
                        .map(format_host_pattern)
                        .collect::<Vec<_>>(),
                    vec!["logs.example.com"]
                ),
                4 => assert_eq!(
                    entry.substitution.header_fields,
                    vec!["authorization", "x-api-key"]
                ),
                _ => unreachable!(),
            }
            assert!(!secret_policy_changes(
                &patch.secrets[0],
                existing_secret(&saved, "API_KEY").as_ref()
            ));
            assert_eq!(
                &*saved.local_network_config().unwrap().secrets.secrets[0].value,
                SECRET_SENTINEL
            );
            let repeat = SandboxModificationBuilder::new(backend.clone(), &current.spec.name)
                .with_patch(patch)
                .apply()
                .await
                .unwrap();
            assert!(repeat.changes.is_empty());
        }
    }

    /// A restart-backed modification must refuse a prospective configuration the
    /// selected runtime cannot launch before stopping the VM. Regression: the
    /// capability check used to run only in the start that followed `stop`, which
    /// left the workload down with the rejected change persisted.
    #[cfg(all(unix, feature = "net"))]
    #[tokio::test]
    async fn restart_preflight_leaves_a_running_sandbox_untouched() {
        use std::os::unix::fs::PermissionsExt;

        use crate::config::{GlobalConfig, PathsConfig};

        // Keep the home path short: the restart sequence derives Unix socket paths
        // from it, and a long macOS temporary directory can exceed the socket limit.
        let temp = tempfile::Builder::new()
            .prefix("msb-restart-preflight-")
            .tempdir_in("/tmp")
            .unwrap();
        let home = temp.path().join("home");
        std::fs::create_dir_all(&home).unwrap();

        // A `#!` wrapper has no embedded version metadata, so it resolves as a
        // legacy launch contract and the pre-stop validation refuses the proxy at
        // the legacy network gate. The auth-specific capability gate needs a real
        // executable that also answers the capability probe, which a unit test
        // cannot fake; `http_connect_credentials_require_runtime_support_before_launch`
        // covers that gate, and this test covers where the gate runs.
        let msb = temp.path().join("msb");
        std::fs::write(
            &msb,
            "#!/bin/sh\n\
             case \"$1\" in\n\
             --version) printf 'msb 0.6.18\\n' ;;\n\
             __launch-protocol) printf '%s' '{\"protocols\":[2,1],\"http_connect_proxy\":true}' ;;\n\
             *) exit 1 ;;\n\
             esac\n",
        )
        .unwrap();
        std::fs::set_permissions(&msb, std::fs::Permissions::from_mode(0o700)).unwrap();
        let library = temp
            .path()
            .join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS));
        std::fs::write(&library, b"").unwrap();

        let backend: Arc<dyn Backend> =
            Arc::new(crate::test_support::local_backend(GlobalConfig {
                home: Some(home),
                paths: PathsConfig {
                    msb: Some(msb),
                    libkrunfw: Some(library),
                    ..Default::default()
                },
                ..Default::default()
            }));

        let mut config = config(2, 1024);
        config.spec.name = "restart-preflight".to_string();
        let mut network = config.local_network_config().unwrap();
        network.outbound_proxy = Some(
            serde_json::from_value(serde_json::json!({
                "protocol": "http_connect",
                "address": "127.0.0.1:3128",
                "credentials": {
                    "username": "proxy-user",
                    "password": {"kind": "env", "var": "HTTP_CONNECT_PASSWORD"}
                }
            }))
            .unwrap(),
        );
        config.set_local_network_config(network).unwrap();

        // The row has no recorded runtime, so `stop` converges the stale `Running`
        // status instead of failing. That keeps the pre-fix ordering observable: the
        // stop, the persisted change, and the failed start all happen for real.
        let local = backend.as_local().unwrap();
        let db = local.db().await.unwrap();
        let row = sandbox_entity::ActiveModel {
            name: Set(config.spec.name.clone()),
            config: Set(serde_json::to_string(&config).unwrap()),
            active_config: Set(None),
            status: Set(SandboxStatus::Running),
            ephemeral: Set(false),
            ..Default::default()
        }
        .insert(db.write())
        .await
        .unwrap();

        let result = SandboxModificationBuilder::new(backend.clone(), &config.spec.name)
            .workdir("/srv")
            .restart()
            .apply()
            .await;

        // The workload and the durable configuration are the regression signal: a
        // preflight that runs after the stop leaves the sandbox terminal and the
        // rejected change already persisted, whatever the start then reports.
        let saved = sandbox_entity::Entity::find_by_id(row.id)
            .one(db.read())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            saved.status,
            SandboxStatus::Running,
            "the restart preflight must fail before stopping the workload"
        );

        let persisted: SandboxConfig = serde_json::from_str(&saved.config).unwrap();
        assert_eq!(
            persisted.spec.runtime.workdir, config.spec.runtime.workdir,
            "the rejected change must not be persisted"
        );
        assert_eq!(
            persisted.local_network_config().unwrap().outbound_proxy,
            config.local_network_config().unwrap().outbound_proxy,
            "the durable network configuration must be unchanged"
        );

        // The refusal is the launch-contract gate, not a stop or start failure. The
        // legacy gate names the proxy feature itself, so it cannot be satisfied by
        // the `HTTP CONNECT proxy authentication` capability refusal.
        let error = result.expect_err("an unsupported runtime must refuse the restart");
        assert!(
            error.to_string().contains("HTTP CONNECT outbound proxies")
                && error.to_string().contains("upgrade msb"),
            "unexpected error: {error}"
        );
    }

    /// The `tls` change a secret patch emits when it must turn interception on.
    #[cfg(feature = "net")]
    fn tls_plan_change(plan: &SandboxModificationPlan) -> Option<&ConfigPlannedChange> {
        plan.changes.iter().find_map(|change| match change {
            PlannedChange::Config(change) if change.field == TLS_FIELD => Some(change),
            _ => None,
        })
    }

    #[cfg(feature = "net")]
    fn secret_plan_dispositions(plan: &SandboxModificationPlan) -> Vec<ModificationDisposition> {
        plan.changes
            .iter()
            .map(|change| match change {
                PlannedChange::Secret(change) => change.disposition,
                PlannedChange::Config(_) => panic!("expected secret change"),
            })
            .collect()
    }

    #[cfg(feature = "net")]
    fn secret_plan_kinds(plan: &SandboxModificationPlan) -> Vec<SecretChangeKind> {
        plan.changes
            .iter()
            .map(|change| match change {
                PlannedChange::Secret(change) => change.change,
                PlannedChange::Config(_) => panic!("expected secret change"),
            })
            .collect()
    }

    #[cfg(feature = "net")]
    #[test]
    fn running_secret_rotate_remove_hosts_classify_live_with_runtime_support() {
        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let mut network = config.local_network_config().unwrap();
        let mut other = network.secrets.secrets[0].clone();
        other.env_var = "OTHER_KEY".to_string();
        other.placeholder = "$MSB_OTHER_KEY".to_string();
        network.secrets.secrets.push(other);
        config.set_local_network_config(network).unwrap();

        let patch = patch_with_specs(vec![
            source_spec("API_KEY", &[]),
            bare_spec("OTHER_KEY", &["*.example.org"]),
        ]);
        let removal_patch = SandboxModificationPatch {
            secrets_remove: vec!["API_KEY".to_string()],
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                root_disk_grow: false,
                cpu_resize: false,
                memory_resize: false,
                secrets: true,
            },
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(
            secret_plan_kinds(&plan),
            vec![SecretChangeKind::Rotated, SecretChangeKind::HostsUpdated]
        );
        assert_eq!(
            secret_plan_dispositions(&plan),
            vec![ModificationDisposition::Live; 2]
        );
        assert!(plan.conflicts.is_empty());
        assert!(plan.warnings.is_empty());
        assert!(validate_apply_supported(&plan).is_ok());

        let removal_plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                root_disk_grow: false,
                cpu_resize: false,
                memory_resize: false,
                secrets: true,
            },
            removal_patch,
            ModificationPolicy::NoRestart,
        );
        assert_eq!(
            secret_plan_kinds(&removal_plan),
            vec![SecretChangeKind::Removed]
        );
        assert_eq!(
            secret_plan_dispositions(&removal_plan),
            vec![ModificationDisposition::Live]
        );
    }

    #[cfg(feature = "net")]
    #[test]
    fn running_secret_add_and_placeholder_change_require_restart_even_with_live_support() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let mut patch = patch_with_specs(vec![source_spec("NEW_KEY", &["api.new.test"])]);
        let mut placeholder_spec = bare_spec("API_KEY", &[]);
        placeholder_spec.placeholder = Some("$ROTATED_REF".to_string());
        patch.secrets.push(placeholder_spec);

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                root_disk_grow: false,
                cpu_resize: false,
                memory_resize: false,
                secrets: true,
            },
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(
            secret_plan_kinds(&plan),
            vec![
                SecretChangeKind::Added,
                SecretChangeKind::PlaceholderUpdated
            ]
        );
        assert_eq!(
            secret_plan_dispositions(&plan),
            vec![ModificationDisposition::RequiresRestart; 2]
        );
        assert!(validate_apply_supported(&plan).is_err());
    }

    #[cfg(feature = "net")]
    #[test]
    fn running_rotate_with_placeholder_change_requires_restart_even_with_live_support() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let mut spec = source_spec("API_KEY", &[]);
        spec.placeholder = Some("$NEW_REF".to_string());
        let patch = patch_with_specs(vec![spec]);

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                root_disk_grow: false,
                cpu_resize: false,
                memory_resize: false,
                secrets: true,
            },
            patch,
            ModificationPolicy::NoRestart,
        );

        let PlannedChange::Secret(change) = &plan.changes[0] else {
            panic!("expected secret change");
        };
        assert_eq!(change.change, SecretChangeKind::Rotated);
        assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
        assert!(
            change
                .reason
                .as_deref()
                .is_some_and(|reason| reason.contains("placeholder"))
        );
        // No live-support warning: the restart is forced by the placeholder,
        // not by a runtime gap.
        assert!(plan.warnings.is_empty());
    }

    #[cfg(feature = "net")]
    #[test]
    fn running_secret_rotate_requires_restart_without_runtime_support() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        let PlannedChange::Secret(change) = &plan.changes[0] else {
            panic!("expected secret change");
        };
        assert_eq!(change.disposition, ModificationDisposition::RequiresRestart);
        assert_eq!(
            change.reason.as_deref(),
            Some(LIVE_SECRET_RECONFIGURE_UNAVAILABLE)
        );
        assert!(
            plan.warnings
                .iter()
                .any(|warning| warning.field == SECRET_FIELD)
        );
        assert!(validate_apply_supported(&plan).is_err());
        // The restart policy unblocks the same plan shape.
        let restart_plan = SandboxModificationPlan {
            policy: ModificationPolicy::Restart,
            ..plan
        };
        assert!(validate_apply_supported(&restart_plan).is_ok());
    }

    #[cfg(feature = "net")]
    #[test]
    fn stopped_secret_changes_are_next_start_and_apply_supported() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert_eq!(
            secret_plan_dispositions(&plan),
            vec![ModificationDisposition::NextStart]
        );
        assert!(validate_apply_supported(&plan).is_ok());
    }

    #[cfg(feature = "net")]
    #[test]
    fn planner_infers_change_kinds_from_spec_diffs() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);

        // Material on an existing secret: rotated (source or value alike).
        let mut value_spec = bare_spec("API_KEY", &[]);
        value_spec.value = zeroize::Zeroizing::new("new-material".to_string());
        for spec in [source_spec("API_KEY", &[]), value_spec] {
            let plan = build_plan(
                "api".to_string(),
                SandboxStatus::Stopped,
                &config,
                None,
                LiveControl::default(),
                patch_with_specs(vec![spec]),
                ModificationPolicy::NoRestart,
            );
            assert_eq!(secret_plan_kinds(&plan), vec![SecretChangeKind::Rotated]);
            assert!(plan.conflicts.is_empty());
        }

        // Material for an unknown name: added.
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch_with_specs(vec![source_spec("NEW_KEY", &["api.new.test"])]),
            ModificationPolicy::NoRestart,
        );
        assert_eq!(secret_plan_kinds(&plan), vec![SecretChangeKind::Added]);
        assert!(plan.conflicts.is_empty());

        // Hosts-only diff: hosts updated.
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch_with_specs(vec![bare_spec("API_KEY", &["*.example.org"])]),
            ModificationPolicy::NoRestart,
        );
        assert_eq!(
            secret_plan_kinds(&plan),
            vec![SecretChangeKind::HostsUpdated]
        );

        // Placeholder-only diff: placeholder updated.
        let mut spec = bare_spec("API_KEY", &[]);
        spec.placeholder = Some("$NEW_REF".to_string());
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch_with_specs(vec![spec]),
            ModificationPolicy::NoRestart,
        );
        assert_eq!(
            secret_plan_kinds(&plan),
            vec![SecretChangeKind::PlaceholderUpdated]
        );
    }

    #[cfg(feature = "net")]
    #[test]
    fn spec_matching_current_state_is_a_declarative_noop() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);

        // Same hosts, same placeholder, no material: nothing to change.
        let mut spec = bare_spec("API_KEY", &["api.example.com"]);
        spec.placeholder = Some("$MSB_API_KEY".to_string());
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch_with_specs(vec![spec]),
            ModificationPolicy::NoRestart,
        );
        assert!(plan.changes.is_empty());
        assert!(plan.conflicts.is_empty());

        // Removing a secret that does not exist is also a no-op.
        let patch = SandboxModificationPatch {
            secrets_remove: vec!["MISSING".to_string()],
            ..SandboxModificationPatch::default()
        };
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );
        assert!(plan.changes.is_empty());
    }

    #[cfg(feature = "net")]
    #[test]
    fn secret_conflicts_reject_impossible_patches() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);

        // Adding a new secret without any allowed host.
        let patch = patch_with_specs(vec![source_spec("NEW_KEY", &[])]);
        let mut conflicts = Vec::new();
        push_secret_conflicts(&config, &patch, &mut conflicts);
        assert!(conflicts[0].message.contains("allowed host"));

        // A new secret needs material (source or value).
        let patch = patch_with_specs(vec![bare_spec("MISSING", &["api.example.com"])]);
        let mut conflicts = Vec::new();
        push_secret_conflicts(&config, &patch, &mut conflicts);
        assert!(conflicts[0].message.contains("source or value"));

        // Value and source together are ambiguous.
        let mut spec = source_spec("API_KEY", &[]);
        spec.value = zeroize::Zeroizing::new("inline-material".to_string());
        let patch = patch_with_specs(vec![spec]);
        let mut conflicts = Vec::new();
        push_secret_conflicts(&config, &patch, &mut conflicts);
        assert!(conflicts[0].message.contains("mutually exclusive"));

        // Store-backed sources are not implemented yet.
        let mut spec = source_spec("API_KEY", &[]);
        spec.source = Some(SecretSource::Store {
            reference: "vault://team/api-key".to_string(),
        });
        let patch = patch_with_specs(vec![spec]);
        let mut conflicts = Vec::new();
        push_secret_conflicts(&config, &patch, &mut conflicts);
        assert!(conflicts[0].message.contains("store-backed"));

        // Configuring and removing the same secret in one patch.
        let mut patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);
        patch.secrets_remove.push("API_KEY".to_string());
        let mut conflicts = Vec::new();
        push_secret_conflicts(&config, &patch, &mut conflicts);
        assert!(conflicts[0].message.contains("both configured and removed"));

        // A spec without a name cannot target anything.
        let patch = patch_with_specs(vec![SecretModificationPatch::default()]);
        let mut conflicts = Vec::new();
        push_secret_conflicts(&config, &patch, &mut conflicts);
        assert!(conflicts[0].message.contains("needs a name"));
    }

    /// Regression for #1422: the first secret left `tls.enabled` false, so the
    /// placeholder reached the upstream unsubstituted.
    #[cfg(feature = "net")]
    #[test]
    fn adding_first_secret_enables_tls_in_durable_config() {
        let mut config = config(2, 1024);
        assert!(!config.local_network_config().unwrap().tls.enabled);

        let patch = patch_with_specs(vec![source_spec("API_KEY", &["api.example.com"])]);
        config.update_secrets(&patch).unwrap();

        let network = config.local_network_config().unwrap();
        assert_eq!(network.secrets.secrets.len(), 1);
        assert!(network.tls.enabled);
    }

    /// Interception is restart-backed, so the first secret must show up in the
    /// plan and drive the restart rather than flip silently under a running VM.
    #[cfg(feature = "net")]
    #[test]
    fn first_secret_plans_tls_change_and_forces_restart() {
        let config = config(2, 1024);
        let patch = patch_with_specs(vec![source_spec("API_KEY", &["api.example.com"])]);

        // Stopped: lands on the next start.
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        let tls = tls_plan_change(&plan).expect("expected a tls change");
        assert_eq!(tls.change, ChangeKind::Updated);
        assert_eq!(tls.disposition, ModificationDisposition::NextStart);
        assert!(validate_apply_supported(&plan).is_ok());

        // Running under the default policy: an explicit error.
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                secrets: true,
                ..LiveControl::default()
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        assert_eq!(
            tls_plan_change(&plan).unwrap().disposition,
            ModificationDisposition::RequiresRestart
        );
        assert!(validate_apply_supported(&plan).is_err());

        // Restart opted in: the restart rebuilds active from the durable config.
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                secrets: true,
                ..LiveControl::default()
            },
            patch,
            ModificationPolicy::Restart,
        );
        assert!(validate_apply_supported(&plan).is_ok());
        assert!(plan_requires_restart(&plan));
    }

    /// Rotating a secret on a legacy TLS-off config classifies as live, and
    /// mirroring it would claim TLS the running proxy does not have.
    #[cfg(feature = "net")]
    #[test]
    fn live_secret_change_on_tls_disabled_config_requires_restart() {
        let config = config_with_secret_and_tls_disabled("API_KEY", SECRET_SENTINEL);
        let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                secrets: true,
                ..LiveControl::default()
            },
            patch,
            ModificationPolicy::NoRestart,
        );

        // The rotate itself is live-applicable, so tls is the only blocker.
        let secret_dispositions: Vec<_> = plan
            .changes
            .iter()
            .filter_map(|change| match change {
                PlannedChange::Secret(change) => Some(change.disposition),
                PlannedChange::Config(_) => None,
            })
            .collect();
        assert_eq!(secret_dispositions, vec![ModificationDisposition::Live]);
        assert_eq!(
            tls_plan_change(&plan).unwrap().disposition,
            ModificationDisposition::RequiresRestart
        );
        let err = validate_apply_supported(&plan).unwrap_err().to_string();
        assert_eq!(err, "cannot apply modification: tls requires restart");
    }

    /// Plain-HTTP substitution is an intentional TLS-off configuration, so a
    /// live rotation must not enable interception or force a restart.
    #[cfg(feature = "net")]
    #[test]
    fn live_plain_http_secret_rotation_does_not_enable_tls() {
        let mut config = config_with_plain_http_secret_and_tls_disabled("API_KEY", SECRET_SENTINEL);
        let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                secrets: true,
                ..LiveControl::default()
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        assert!(tls_plan_change(&plan).is_none());
        assert_eq!(
            secret_plan_dispositions(&plan),
            vec![ModificationDisposition::Live]
        );
        assert!(validate_apply_supported(&plan).is_ok());

        config.update_secrets(&patch).unwrap();
        let network = config.local_network_config().unwrap();
        assert!(!network.tls.enabled);
        assert!(!network.secrets.secrets[0].require_tls_identity);
    }

    /// Enabling TLS identity on an existing plain-HTTP secret must plan the
    /// interception restart that persistence will require.
    #[cfg(feature = "net")]
    #[test]
    fn enabling_tls_identity_on_existing_secret_plans_tls_restart() {
        let mut config = config_with_plain_http_secret_and_tls_disabled("API_KEY", SECRET_SENTINEL);
        let mut spec = source_spec("API_KEY", &[]);
        spec.require_tls_identity = Some(true);
        let patch = patch_with_specs(vec![spec]);

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                secrets: true,
                ..LiveControl::default()
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        assert_eq!(
            tls_plan_change(&plan).unwrap().disposition,
            ModificationDisposition::RequiresRestart
        );
        assert!(validate_apply_supported(&plan).is_err());

        config.update_secrets(&patch).unwrap();
        let network = config.local_network_config().unwrap();
        assert!(network.tls.enabled);
        assert!(network.secrets.secrets[0].require_tls_identity);
    }

    /// A new secret can explicitly opt out of TLS identity, so persistence
    /// and planning must both leave interception disabled.
    #[cfg(feature = "net")]
    #[test]
    fn adding_plain_http_secret_does_not_plan_tls_enable() {
        let mut config = config(2, 1024);
        let mut spec = source_spec("API_KEY", &["api.example.com"]);
        spec.require_tls_identity = Some(false);
        let patch = patch_with_specs(vec![spec]);

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                secrets: true,
                ..LiveControl::default()
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        assert!(tls_plan_change(&plan).is_none());

        config.update_secrets(&patch).unwrap();
        let network = config.local_network_config().unwrap();
        assert!(!network.tls.enabled);
        assert!(!network.secrets.secrets[0].require_tls_identity);
    }

    /// A removal-only patch can leave another TLS-dependent secret behind.
    /// Planning and persistence must both surface the implied TLS enable.
    #[cfg(feature = "net")]
    #[test]
    fn removing_one_legacy_secret_plans_tls_for_the_remaining_secret() {
        let mut config = config_with_secret_and_tls_disabled("KEEP", SECRET_SENTINEL);
        let mut network = config.local_network_config().unwrap();
        let mut removed = network.secrets.secrets[0].clone();
        removed.env_var = "REMOVE".to_string();
        removed.placeholder = "$MSB_REMOVE".to_string();
        network.secrets.secrets.push(removed);
        config.set_local_network_config(network).unwrap();
        let patch = SandboxModificationPatch {
            secrets_remove: vec!["REMOVE".to_string()],
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                secrets: true,
                ..LiveControl::default()
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        assert_eq!(
            tls_plan_change(&plan).unwrap().disposition,
            ModificationDisposition::RequiresRestart
        );
        assert!(validate_apply_supported(&plan).is_err());

        config.update_secrets(&patch).unwrap();
        let network = config.local_network_config().unwrap();
        assert_eq!(network.secrets.secrets.len(), 1);
        assert_eq!(network.secrets.secrets[0].env_var, "KEEP");
        assert!(network.tls.enabled);
    }

    /// Removal-only patches that leave only plain-HTTP secrets remain live and
    /// keep interception disabled.
    #[cfg(feature = "net")]
    #[test]
    fn removing_one_plain_http_secret_keeps_tls_disabled() {
        let mut config = config_with_plain_http_secret_and_tls_disabled("KEEP", SECRET_SENTINEL);
        let mut network = config.local_network_config().unwrap();
        let mut removed = network.secrets.secrets[0].clone();
        removed.env_var = "REMOVE".to_string();
        removed.placeholder = "$MSB_REMOVE".to_string();
        network.secrets.secrets.push(removed);
        config.set_local_network_config(network).unwrap();
        let patch = SandboxModificationPatch {
            secrets_remove: vec!["REMOVE".to_string()],
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                secrets: true,
                ..LiveControl::default()
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );

        assert!(tls_plan_change(&plan).is_none());
        assert!(validate_apply_supported(&plan).is_ok());

        config.update_secrets(&patch).unwrap();
        let network = config.local_network_config().unwrap();
        assert_eq!(network.secrets.secrets.len(), 1);
        assert_eq!(network.secrets.secrets[0].env_var, "KEEP");
        assert!(!network.tls.enabled);
    }

    /// One-way: emptying the secret set must not turn interception off.
    #[cfg(feature = "net")]
    #[test]
    fn removing_last_secret_keeps_tls_enabled() {
        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = SandboxModificationPatch {
            secrets_remove: vec!["API_KEY".to_string()],
            ..SandboxModificationPatch::default()
        };

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        assert!(tls_plan_change(&plan).is_none());

        config.update_secrets(&patch).unwrap();

        let network = config.local_network_config().unwrap();
        assert!(network.secrets.secrets.is_empty());
        assert!(network.tls.enabled);
    }

    /// Interception already on: nothing to enable, so no extra plan noise.
    #[cfg(feature = "net")]
    #[test]
    fn secret_change_with_tls_already_enabled_plans_no_tls_change() {
        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch,
            ModificationPolicy::NoRestart,
        );

        assert!(tls_plan_change(&plan).is_none());
    }
    #[cfg(feature = "net")]
    #[test]
    fn applying_new_source_spec_uses_create_placeholder_default() {
        use microsandbox_network::secrets::config::HostPattern;

        let mut config = config(2, 1024);
        let patch = patch_with_specs(vec![source_spec("API_KEY", &["api.example.com"])]);

        config.update_secrets(&patch).unwrap();

        let network = config.local_network_config().unwrap();
        let entry = &network.secrets.secrets[0];
        assert_eq!(entry.env_var, "API_KEY");
        assert!(entry.value.is_empty());
        assert_eq!(
            entry.source,
            Some(SecretSource::Env {
                var: "API_KEY".into()
            })
        );
        assert_eq!(entry.placeholder, "$MSB_API_KEY");
        assert_eq!(
            entry.allowed_hosts,
            vec![HostPattern::Exact("api.example.com".into())]
        );
        assert!(entry.require_tls_identity);
    }

    #[cfg(feature = "net")]
    #[test]
    fn applying_source_rotate_drops_inlined_value_and_keeps_placeholder() {
        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

        config.update_secrets(&patch).unwrap();

        let network = config.local_network_config().unwrap();
        let entry = &network.secrets.secrets[0];
        assert!(entry.value.is_empty());
        assert_eq!(
            entry.source,
            Some(SecretSource::Env {
                var: "API_KEY".into()
            })
        );
        // Rotation keeps the guest-visible placeholder and host allow-list.
        assert_eq!(entry.placeholder, "$MSB_API_KEY");
        assert_eq!(entry.allowed_hosts.len(), 1);
    }

    #[cfg(feature = "net")]
    #[test]
    fn applying_value_spec_persists_value_and_clears_reference() {
        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        // Give the entry a stale source reference to prove the value clears it.
        let mut network = config.local_network_config().unwrap();
        network.secrets.secrets[0].source = Some(SecretSource::Env {
            var: "API_KEY".into(),
        });
        config.set_local_network_config(network).unwrap();

        let mut spec = bare_spec("API_KEY", &[]);
        spec.value = zeroize::Zeroizing::new("caller-held-value".to_string());
        let patch = patch_with_specs(vec![spec]);

        config.update_secrets(&patch).unwrap();

        // The value persists at rest (documented secret_env-style property)
        // and the entry is no longer reference-backed.
        let network = config.local_network_config().unwrap();
        let entry = &network.secrets.secrets[0];
        assert_eq!(entry.value.as_str(), "caller-held-value");
        assert_eq!(entry.source, None);
        assert_eq!(entry.placeholder, "$MSB_API_KEY");
    }

    #[cfg(feature = "net")]
    #[test]
    fn applying_secret_remove_deletes_entry() {
        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = SandboxModificationPatch {
            secrets_remove: vec!["API_KEY".to_string()],
            ..SandboxModificationPatch::default()
        };

        config.update_secrets(&patch).unwrap();

        let network = config.local_network_config().unwrap();
        assert!(network.secrets.secrets.is_empty());
    }

    #[cfg(feature = "net")]
    #[test]
    fn applying_hosts_only_spec_replaces_allow_list() {
        use microsandbox_network::secrets::config::HostPattern;

        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = patch_with_specs(vec![bare_spec("API_KEY", &["*.example.org", "*"])]);

        config.update_secrets(&patch).unwrap();

        let network = config.local_network_config().unwrap();
        assert_eq!(
            network.secrets.secrets[0].allowed_hosts,
            vec![
                HostPattern::Wildcard("*.example.org".into()),
                HostPattern::Any,
            ]
        );
    }

    #[cfg(feature = "net")]
    #[test]
    fn applying_placeholder_only_spec_renames_guest_reference() {
        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let mut spec = bare_spec("API_KEY", &[]);
        spec.placeholder = Some("$NEW_REF".to_string());
        let patch = patch_with_specs(vec![spec]);

        config.update_secrets(&patch).unwrap();

        let network = config.local_network_config().unwrap();
        assert_eq!(network.secrets.secrets[0].placeholder, "$NEW_REF");
    }

    #[cfg(feature = "net")]
    #[test]
    fn rotate_flow_never_leaks_the_value_into_plans_configs_or_errors() {
        let mut config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = patch_with_specs(vec![source_spec("API_KEY", &[])]);

        // The plan for a live rotate is value-free even though the current
        // config carries an inlined value.
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                root_disk_grow: false,
                cpu_resize: false,
                memory_resize: false,
                secrets: true,
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        let plan_json = serde_json::to_string(&plan).unwrap();
        assert!(!plan_json.contains(SECRET_SENTINEL));

        // The persisted config drops the inlined value in favor of the
        // source reference.
        config.update_secrets(&patch).unwrap();
        let config_json = serde_json::to_string(&config).unwrap();
        assert!(!config_json.contains(SECRET_SENTINEL));
        assert!(config_json.contains("\"var\":\"API_KEY\""));

        // The live control batch carries the value only for socket transport;
        // any Debug-logged form of the request shows [redacted] instead.
        let rotated_value = format!("{SECRET_SENTINEL}-rotated");
        let _env_guard = crate::test_support::lock_env();
        // SAFETY: every environment-mutating SDK unit test holds the shared lock.
        unsafe { std::env::set_var("API_KEY_MODIFY_LEAK_TEST", &rotated_value) };
        let mut live_patch = patch.clone();
        live_patch.secrets[0].source = Some(SecretSource::Env {
            var: "API_KEY_MODIFY_LEAK_TEST".to_string(),
        });
        let updates = live_secret_updates(&plan, &live_patch).unwrap();
        assert!(!updates.is_empty());
        let request =
            microsandbox_runtime::control::ControlRequest::SecretsUpdate { changes: updates };
        assert!(!format!("{request:?}").contains(SECRET_SENTINEL));
        unsafe { std::env::remove_var("API_KEY_MODIFY_LEAK_TEST") };

        // Resolution failures name the variable, never a value.
        let error = resolve_secret_source_value(
            "API_KEY",
            Some(&SecretSource::Env {
                var: "API_KEY_MODIFY_LEAK_TEST_MISSING".to_string(),
            }),
        )
        .unwrap_err();
        let message = error.to_string();
        assert!(message.contains("API_KEY_MODIFY_LEAK_TEST_MISSING"));
        assert!(!message.contains(SECRET_SENTINEL));
    }

    #[cfg(feature = "net")]
    #[test]
    fn value_bearing_patch_never_leaks_into_plans_debug_or_live_request_debug() {
        const VALUE_SENTINEL: &str = "value-sentinel-material";

        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let mut spec = bare_spec("API_KEY", &[]);
        spec.value = zeroize::Zeroizing::new(VALUE_SENTINEL.to_string());
        let patch = patch_with_specs(vec![spec]);

        // Debug output of the patch redacts the value.
        let debug = format!("{patch:?}");
        assert!(!debug.contains(VALUE_SENTINEL));
        assert!(debug.contains("[REDACTED]"));

        // The plan is value-free.
        let plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                root_disk_grow: false,
                cpu_resize: false,
                memory_resize: false,
                secrets: true,
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        assert_eq!(secret_plan_kinds(&plan), vec![SecretChangeKind::Rotated]);
        assert_eq!(
            secret_plan_dispositions(&plan),
            vec![ModificationDisposition::Live]
        );
        let plan_json = serde_json::to_string(&plan).unwrap();
        assert!(!plan_json.contains(VALUE_SENTINEL));

        // The live rotate uses the caller value without touching the host
        // environment, and the request's Debug form stays redacted.
        let updates = live_secret_updates(&plan, &patch).unwrap();
        assert_eq!(updates.len(), 1);
        let request =
            microsandbox_runtime::control::ControlRequest::SecretsUpdate { changes: updates };
        assert!(!format!("{request:?}").contains(VALUE_SENTINEL));

        // Material-free rotate errors name the secret only.
        let error = resolve_secret_value(&bare_spec("API_KEY", &[])).unwrap_err();
        let message = error.to_string();
        assert!(message.contains("API_KEY"));
        assert!(!message.contains(VALUE_SENTINEL));
    }

    #[cfg(feature = "net")]
    #[test]
    fn live_secret_updates_cover_only_live_dispositions() {
        use microsandbox_runtime::control::SecretLiveChange;

        let config = config_with_secret("API_KEY", SECRET_SENTINEL);
        let patch = SandboxModificationPatch {
            secrets: vec![bare_spec("API_KEY", &["api.example.com", "*.example.org"])],
            ..SandboxModificationPatch::default()
        };
        let removal_patch = SandboxModificationPatch {
            secrets_remove: vec!["API_KEY".to_string()],
            ..SandboxModificationPatch::default()
        };

        let live_plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                root_disk_grow: false,
                cpu_resize: false,
                memory_resize: false,
                secrets: true,
            },
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        let updates = live_secret_updates(&live_plan, &patch).unwrap();
        assert_eq!(updates.len(), 1);
        assert!(matches!(
            &updates[0],
            SecretLiveChange::SetAllowedHosts { name, hosts }
                if name == "API_KEY" && hosts.len() == 2
        ));

        let removal_plan = build_plan(
            "api".to_string(),
            SandboxStatus::Running,
            &config,
            None,
            LiveControl {
                root_disk_grow: false,
                cpu_resize: false,
                memory_resize: false,
                secrets: true,
            },
            removal_patch.clone(),
            ModificationPolicy::NoRestart,
        );
        let updates = live_secret_updates(&removal_plan, &removal_patch).unwrap();
        assert_eq!(updates.len(), 1);
        assert!(matches!(&updates[0], SecretLiveChange::Remove { name } if name == "API_KEY"));

        // Next-start plans produce no live updates.
        let stopped_plan = build_plan(
            "api".to_string(),
            SandboxStatus::Stopped,
            &config,
            None,
            LiveControl::default(),
            patch.clone(),
            ModificationPolicy::NoRestart,
        );
        assert!(
            live_secret_updates(&stopped_plan, &patch)
                .unwrap()
                .is_empty()
        );
    }

    #[cfg(feature = "net")]
    #[test]
    #[allow(deprecated)] // Both spellings must produce the existing modification contract.
    fn secret_patch_builder_builds_declarative_specs() {
        let spec = SecretPatchBuilder::new()
            .env("API_KEY")
            .source(SecretSource::Env {
                var: "HOST_API_KEY".to_string(),
            })
            .placeholder("$REF")
            .allow("api.example.com")
            .allow("*.example.org")
            .allow_placeholder_for("api.anthropic.com")
            .allow_passthrough_for("*.anthropic.com")
            .build();

        assert_eq!(spec.name, "API_KEY");
        assert_eq!(
            spec.source,
            Some(SecretSource::Env {
                var: "HOST_API_KEY".to_string()
            })
        );
        assert!(spec.value.is_empty());
        assert_eq!(spec.placeholder.as_deref(), Some("$REF"));
        assert_eq!(spec.allowed_hosts, vec!["api.example.com", "*.example.org"]);
        assert_eq!(
            spec.passthrough_hosts,
            vec!["api.anthropic.com", "*.anthropic.com"]
        );
        let wire = serde_json::to_value(&spec).unwrap();
        assert_eq!(
            wire["passthrough_hosts"],
            serde_json::json!(["api.anthropic.com", "*.anthropic.com"])
        );
        assert!(wire.get("allow_placeholder_for").is_none());

        let spec = SecretPatchBuilder::new()
            .env("API_KEY")
            .value("caller-held")
            .build();
        assert_eq!(spec.value.as_str(), "caller-held");
        assert_eq!(spec.source, None);
    }
}
