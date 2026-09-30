//! Local sandbox modification planning and application.

use std::{collections::HashMap, sync::Arc};

use microsandbox_control_client::{
    GrowRootDisk, SecretsResult, SetCpuTarget, SetMemoryTarget, UpdateSecrets,
};
use microsandbox_types::modify::{
    ChangeKind, ConfigPlannedChange, ModificationConflict, ModificationDisposition,
    ModificationPolicy, ModificationWarning, PlannedChange, ResourceConvergenceState, ResourceKind,
    ResourceResizeStatus, SandboxModificationPatch, SandboxModificationPlan, SecretChangeKind,
    SecretModificationPatch, SecretPlannedChange, SecretSource,
};
use microsandbox_types::{EnvVar, RootDisk, RootfsSource};
use sea_orm::{ColumnTrait, EntityTrait, QueryFilter, Set, sea_query::Expr};

use crate::MicrosandboxResult;
use crate::backend::LocalBackend;
use crate::backend::local::control_session_for_run;
use crate::backend::{Backend, ControlSession};
use crate::db::entity::{sandbox as sandbox_entity, sandbox_label as sandbox_label_entity};
use crate::error::{Operation, UnsupportedReason};
use crate::sandbox::identity::SandboxRunIdentity;
use crate::sandbox::{SandboxConfig, SandboxHandle, SandboxStatus};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const LIVE_RESIZE_UNAVAILABLE: &str =
    "live CPU and memory resize are not available in this runtime yet";
const LIVE_SECRET_RECONFIGURE_UNAVAILABLE: &str =
    "live secret reconfiguration is not available in this runtime yet";
const LIVE_EXEC_DEFAULT_UPDATE_UNAVAILABLE: &str =
    "affects future execs only after restart; live exec-default updates are not available yet";
const LIVE_LABEL_UPDATE_UNAVAILABLE: &str =
    "live label updates are not available in this runtime yet";
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

struct DesiredResources {
    max_cpus: u8,
    max_memory_mib: u32,
}

struct ExistingSecret {
    placeholder: String,
    allowed_hosts: Vec<String>,
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
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) async fn dry_run(
    backend: Arc<dyn Backend>,
    name: String,
    expected_id: i32,
    patch: SandboxModificationPatch,
    policy: ModificationPolicy,
) -> MicrosandboxResult<SandboxModificationPlan> {
    let handle = identified_handle(&backend, &name, expected_id).await?;
    let status = handle.status_snapshot();
    let config = handle.config()?;
    let active = handle.active_config().ok().flatten();
    let (live, _) = live_control(&backend, &name, expected_id, status, &patch, policy).await?;
    Ok(build_plan(
        name,
        status,
        &config,
        active.as_ref(),
        live,
        patch,
        policy,
    ))
}

pub(crate) async fn apply(
    backend: Arc<dyn Backend>,
    name: String,
    expected_id: i32,
    patch: SandboxModificationPatch,
    policy: ModificationPolicy,
) -> MicrosandboxResult<SandboxModificationPlan> {
    let handle = identified_handle(&backend, &name, expected_id).await?;
    let status = handle.status_snapshot();
    let mut config = handle.config()?;
    // A failed restore can still own staged immutable lower layers. Do not let
    // offline disk growth or a restart-backed modification bypass its launch gate.
    crate::LocalBackend::validate_completed_restore(&config)?;
    let mut active = handle.active_config().ok().flatten();
    let mut active_json = handle.active_config_json().map(str::to_owned);
    let (live, session) =
        live_control(&backend, &name, expected_id, status, &patch, policy).await?;
    let mut plan = build_plan(
        name.clone(),
        status,
        &config,
        active.as_ref(),
        live,
        patch.clone(),
        policy,
    );

    validate_apply_supported(&plan)?;
    if handle.local().is_some() {
        // Validate configuration serialization before stopping a VM,
        // growing a disk, or issuing any live control mutation.
        let mut prospective = config.clone();
        apply_patch_to_config(&mut prospective, &patch);
        apply_secret_patch_to_config(&mut prospective, &patch)?;
        serde_json::to_string(&prospective)?;
    }
    let restart_required = plan_requires_restart(&plan) && running_status(status);
    if restart_required {
        handle.stop().await?;
    }
    if !restart_required && let Some(target) = live_cpu_target(&plan, &patch) {
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
                &backend,
                &name,
                control_session(&session)?,
                &mut active_json,
                active,
            )
            .await?;
        }
    }
    if !restart_required && let Some(target_mib) = live_memory_target(&plan, &patch) {
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
                &backend,
                &name,
                control_session(&session)?,
                &mut active_json,
                active,
            )
            .await?;
        }
    }
    if !restart_required {
        let updates = live_secret_updates(&plan, &patch)?;
        if !updates.is_empty() {
            control_secrets_update(control_session(&session)?, updates).await?;
            // The running network layer changed: mirror the secret patch
            // into the active snapshot so inspect does not report the
            // already-live change as pending.
            if let Some(active) = active.as_mut() {
                apply_secret_patch_to_config(active, &patch)?;
                persist_active_config(
                    &backend,
                    &name,
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
        && policy == ModificationPolicy::NoRestart
        && let Some(target_mib) = root_disk_grow_target(&plan, &patch, &config)
    {
        let local_backend = backend
            .as_local()
            .ok_or_else(|| crate::MicrosandboxError::local_only(Operation::SandboxModify))?;
        let run = control_session(&session)?.run_identity();
        grow_root_disk_live(local_backend, &name, run, target_mib).await?;
        if let Some(active) = active.as_mut() {
            let disk_patch = SandboxModificationPatch {
                root_disk_size_mib: Some(target_mib),
                ..Default::default()
            };
            apply_patch_to_config(active, &disk_patch);
            persist_active_config(
                &backend,
                &name,
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
    if let Some(target_mib) = root_disk_grow_target(&plan, &patch, &config)
        && (stopped_status(status) || restart_required)
    {
        grow_root_disk_now(&backend, &name, expected_id, &config, target_mib).await?;
    }
    if !plan.changes.is_empty() {
        apply_patch_to_config(&mut config, &patch);
        apply_secret_patch_to_config(&mut config, &patch)?;
        persist_config(&backend, &handle, &config).await?;
    }
    if restart_required {
        start_after_modify(&handle).await?;
    }
    plan.applied = true;
    Ok(plan)
}

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
    push_spec_changes(status, config, &patch, policy, &mut changes, &mut warnings);
    push_secret_changes(
        status,
        config,
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

/// Grow the running root disk through the runtime generation whose
/// capabilities planned it, never whichever runtime now owns the name.
async fn grow_root_disk_live(
    local_backend: &LocalBackend,
    name: &str,
    run: SandboxRunIdentity,
    target_mib: u32,
) -> MicrosandboxResult<()> {
    let size_bytes = u64::from(target_mib) * 1024 * 1024;
    let _transition =
        LocalBackend::acquire_sandbox_transition_guard(&local_backend.config().run_dir(), name)
            .await?;
    local_backend.validate_control_run(name, run).await?;
    let observed = control_session_for_run(local_backend, name, run)
        .await?
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
    Ok(())
}

/// Grow the sandbox-owned layered upper or flat root disk while it is stopped.
async fn grow_root_disk_now(
    backend: &Arc<dyn Backend>,
    name: &str,
    expected_id: i32,
    config: &SandboxConfig,
    target_mib: u32,
) -> MicrosandboxResult<()> {
    let local_backend = backend.as_local().ok_or_else(|| {
        crate::MicrosandboxError::unsupported(
            Operation::SandboxModify,
            UnsupportedReason::LocalOnly,
        )
    })?;
    // Create and remove hold this guard across their row and storage changes,
    // so the row checked here owns the directory until growth finishes.
    let _transition =
        LocalBackend::acquire_sandbox_transition_guard(&local_backend.config().run_dir(), name)
            .await?;
    match current_sandbox_id(backend, name).await? {
        Some(actual) => super::ensure_local_identity(name, Some(expected_id), actual)?,
        None => return Err(crate::MicrosandboxError::SandboxNotFound(name.to_string())),
    }
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
        return crate::sandbox::flat_rootfs::grow_private_flat_rootfs(
            sandbox_dir.join(crate::sandbox::flat_rootfs::FLAT_ROOTFS_FILENAME),
            target_mib,
        )
        .await;
    }
    crate::sandbox::upper::grow_upper_to_mib(sandbox_dir.join("upper.ext4"), target_mib).await
}

/// Discover which live-control operations the running sandbox serves.
async fn live_control(
    backend: &Arc<dyn Backend>,
    name: &str,
    expected_id: i32,
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
    super::ensure_local_identity(name, Some(expected_id), session.run_identity().sandbox_id)?;
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

pub(super) fn control_session(
    session: &Option<ControlSession>,
) -> MicrosandboxResult<&ControlSession> {
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

fn apply_patch_to_config(config: &mut SandboxConfig, patch: &SandboxModificationPatch) {
    if let Some(cpus) = patch.cpus {
        config.spec.resources.cpus = cpus;
    }
    if let Some(max_cpus) = patch.max_cpus {
        config.spec.resources.max_cpus = max_cpus;
    }
    if config.spec.resources.max_cpus < config.spec.resources.cpus {
        config.spec.resources.max_cpus = config.spec.resources.cpus;
    }
    if let Some(memory_mib) = patch.memory_mib {
        config.spec.resources.memory_mib = memory_mib;
    }
    if let Some(max_memory_mib) = patch.max_memory_mib {
        config.spec.resources.max_memory_mib = max_memory_mib;
    }
    if config.spec.resources.max_memory_mib < config.spec.resources.memory_mib {
        config.spec.resources.max_memory_mib = config.spec.resources.memory_mib;
    }
    if let Some(size_mib) = patch.root_disk_size_mib
        && let RootfsSource::Oci(oci) = &mut config.spec.image
    {
        match &mut oci.root_disk {
            Some(RootDisk::Managed { size_mib: s })
            | Some(RootDisk::Tmpfs { size_mib: s })
            | Some(RootDisk::Flat { size_mib: s, .. }) => {
                *s = Some(size_mib);
            }
            // The planner surfaces disk-image sizing as a conflict; never
            // touch a user-owned image here.
            Some(RootDisk::DiskImage { .. }) => {}
            None => {
                oci.root_disk = Some(RootDisk::Managed {
                    size_mib: Some(size_mib),
                });
            }
        }
    }
    for var in &patch.env {
        if let Some(existing) = config
            .spec
            .env
            .iter_mut()
            .find(|entry| entry.key == var.key)
        {
            existing.value = var.value.clone();
        } else {
            config.spec.env.push(var.clone());
        }
    }
    config
        .spec
        .env
        .retain(|entry| !patch.env_remove.contains(&entry.key));
    for (key, value) in &patch.labels {
        config.spec.labels.insert(key.clone(), value.clone());
    }
    for key in &patch.labels_remove {
        config.spec.labels.remove(key);
    }
    if let Some(workdir) = &patch.workdir {
        config.spec.runtime.workdir = Some(workdir.clone());
    }
}

/// Persist secret specs and removals into the sandbox's network secrets
/// config.
///
/// A source-based spec records the host-side reference and drops any
/// previously inlined raw value; the value is resolved from the source at
/// spawn time. A value-based spec persists the value into the entry — the
/// documented at-rest property shared with create's `secret_env` — until a
/// later source-based rotate migrates the entry to a reference.
#[cfg(feature = "net")]
fn apply_secret_patch_to_config(
    config: &mut SandboxConfig,
    patch: &SandboxModificationPatch,
) -> MicrosandboxResult<()> {
    if patch.secrets.is_empty() && patch.secrets_remove.is_empty() {
        return Ok(());
    }
    let mut network = config.local_network_config()?;
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
    config.set_local_network_config(network)
}

#[cfg(not(feature = "net"))]
fn apply_secret_patch_to_config(
    _config: &mut SandboxConfig,
    patch: &SandboxModificationPatch,
) -> MicrosandboxResult<()> {
    if patch.secrets.is_empty() && patch.secrets_remove.is_empty() {
        return Ok(());
    }
    Err(crate::MicrosandboxError::unsupported(
        Operation::SandboxModify,
        UnsupportedReason::RequiresCrateFeature("net"),
    ))
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

async fn persist_config(
    backend: &Arc<dyn Backend>,
    handle: &SandboxHandle,
    config: &SandboxConfig,
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

    let updated = write_db
        .transaction::<_, _, _, crate::MicrosandboxError>(|txn| {
            let config_json = config_json.clone();
            let labels = labels.clone();
            async move {
                let updated = sandbox_entity::Entity::update_many()
                    .col_expr(sandbox_entity::Column::Config, Expr::value(config_json))
                    .col_expr(
                        sandbox_entity::Column::UpdatedAt,
                        Expr::value(chrono::Utc::now().naive_utc()),
                    )
                    .filter(sandbox_entity::Column::Id.eq(local.db_id))
                    .exec(&txn)
                    .await?
                    .rows_affected;
                if updated == 0 {
                    return Ok((txn, false));
                }

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

                Ok((txn, true))
            }
        })
        .await?;
    if !updated {
        return Err(replaced_error(backend, handle.name(), local.db_id).await);
    }
    Ok(())
}

async fn persist_active_config(
    backend: &Arc<dyn Backend>,
    name: &str,
    session: &ControlSession,
    expected: &mut Option<String>,
    active: &SandboxConfig,
) -> MicrosandboxResult<()> {
    let local_backend = backend
        .as_local()
        .ok_or_else(|| crate::MicrosandboxError::local_only(Operation::SandboxModify))?;
    let json = match session
        .persist_active_config(
            local_backend.db().await?.write(),
            expected.as_deref(),
            active,
        )
        .await
    {
        Ok(json) => json,
        Err(error @ crate::MicrosandboxError::ControlStateChanged) => {
            let sandbox_id = session.run_identity().sandbox_id;
            if current_sandbox_id(backend, name).await? == Some(sandbox_id) {
                return Err(error);
            }
            return Err(replaced_error(backend, name, sandbox_id).await);
        }
        Err(error) => return Err(error),
    };
    *expected = Some(json);
    Ok(())
}

/// Load the handle for `name`, refusing a row other than the captured one.
async fn identified_handle(
    backend: &Arc<dyn Backend>,
    name: &str,
    expected_id: i32,
) -> MicrosandboxResult<SandboxHandle> {
    let local_backend = backend
        .as_local()
        .ok_or_else(|| crate::MicrosandboxError::local_only(Operation::SandboxModify))?;
    local_backend
        .sandbox_handle(backend.clone(), name, Some(expected_id))
        .await
}

/// Row id the name currently resolves to, if any.
async fn current_sandbox_id(
    backend: &Arc<dyn Backend>,
    name: &str,
) -> MicrosandboxResult<Option<i32>> {
    let local_backend = backend
        .as_local()
        .ok_or_else(|| crate::MicrosandboxError::local_only(Operation::SandboxModify))?;
    let pools = local_backend.db().await?;
    Ok(microsandbox_db::catalog::sandbox_query(pools.read())
        .await?
        .filter(sandbox_entity::Column::Name.eq(name))
        .one(pools.read())
        .await?
        .map(|model| model.id))
}

/// Explain a write conditioned on `expected_id` that matched no row: the
/// name now belongs to a replacement, or no longer exists.
async fn replaced_error(
    backend: &Arc<dyn Backend>,
    name: &str,
    expected_id: i32,
) -> crate::MicrosandboxError {
    match current_sandbox_id(backend, name).await {
        Ok(Some(actual)) => super::sandbox_replaced(name, expected_id, actual),
        Ok(None) => crate::MicrosandboxError::SandboxNotFound(name.to_string()),
        Err(error) => error,
    }
}

async fn start_after_modify(handle: &SandboxHandle) -> MicrosandboxResult<()> {
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
            current_mib: crate::sandbox::config::DEFAULT_OCI_UPPER_SIZE_MIB,
        },
        Some(RootDisk::Managed { size_mib }) => RootDiskSizeState::Managed {
            current_mib: size_mib.unwrap_or(crate::sandbox::config::DEFAULT_OCI_UPPER_SIZE_MIB),
        },
        Some(RootDisk::Flat { size_mib, .. }) => RootDiskSizeState::Managed {
            current_mib: size_mib.unwrap_or(crate::sandbox::config::DEFAULT_OCI_UPPER_SIZE_MIB),
        },
        Some(RootDisk::Tmpfs { size_mib }) => RootDiskSizeState::Tmpfs {
            current_mib: *size_mib,
        },
        Some(RootDisk::DiskImage { .. }) => RootDiskSizeState::DiskImage,
    })
}

fn push_secret_changes(
    status: SandboxStatus,
    config: &SandboxConfig,
    live_secret_reconfigure_supported: bool,
    patch: &SandboxModificationPatch,
    policy: ModificationPolicy,
    changes: &mut Vec<PlannedChange>,
    warnings: &mut Vec<ModificationWarning>,
) {
    for spec in &patch.secrets {
        let existing = existing_secret(config, &spec.name);
        let Some(change) = infer_secret_change(spec, existing.as_ref()) else {
            // The spec already matches the current config: declarative no-op.
            continue;
        };
        let placeholder_changed = secret_placeholder_changes(spec, existing.as_ref());
        let disposition = secret_disposition(
            status,
            policy,
            change,
            placeholder_changed,
            live_secret_reconfigure_supported,
        );
        let reason = secret_reason(
            status,
            policy,
            change,
            placeholder_changed,
            live_secret_reconfigure_supported,
        );

        push_live_secret_warning(
            status,
            change,
            placeholder_changed,
            &disposition,
            live_secret_reconfigure_supported,
            warnings,
        );

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
            &disposition,
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

/// Warn when a live-capable secret change falls back to restart-required
/// only because the running runtime lacks live secret reconfiguration.
fn push_live_secret_warning(
    status: SandboxStatus,
    change: SecretChangeKind,
    placeholder_changed: bool,
    disposition: &ModificationDisposition,
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
/// These fields have no live path yet: they persist for the next start when
/// the sandbox is stopped (or under the next-start policy) and otherwise
/// require a restart before future execs or metadata queries observe them.
fn push_spec_changes(
    status: SandboxStatus,
    config: &SandboxConfig,
    patch: &SandboxModificationPatch,
    policy: ModificationPolicy,
    changes: &mut Vec<PlannedChange>,
    warnings: &mut Vec<ModificationWarning>,
) {
    for var in &patch.env {
        let existing = config.spec.env.iter().find(|entry| entry.key == var.key);
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
        let Some(existing) = config.spec.env.iter().find(|entry| entry.key == *key) else {
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

    for (key, value) in &patch.labels {
        let existing = config.spec.labels.get(key);
        if existing.is_some_and(|current| current == value) {
            continue;
        }
        changes.push(spec_change(
            LABEL_FIELD,
            change_kind_for(existing.is_some()),
            existing.map(|current| format!("{key}={current}")),
            Some(format!("{key}={value}")),
            status,
            policy,
            LIVE_LABEL_UPDATE_UNAVAILABLE,
        ));
    }

    for key in &patch.labels_remove {
        let Some(current) = config.spec.labels.get(key) else {
            continue;
        };
        changes.push(spec_change(
            LABEL_FIELD,
            ChangeKind::Removed,
            Some(format!("{key}={current}")),
            None,
            status,
            policy,
            LIVE_LABEL_UPDATE_UNAVAILABLE,
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

fn push_spec_conflicts(
    patch: &SandboxModificationPatch,
    conflicts: &mut Vec<ModificationConflict>,
) {
    for var in &patch.env {
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
    PlannedChange::Config(ConfigPlannedChange {
        field: field.to_string(),
        change,
        before,
        after,
        disposition: spec_disposition(status, policy),
        reason: spec_reason(status, policy, running_reason),
    })
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
    policy: ModificationPolicy,
    running_reason: &str,
) -> Option<String> {
    match spec_disposition(status, policy) {
        ModificationDisposition::RequiresRestart if running_status(status) => {
            Some(running_reason.to_string())
        }
        ModificationDisposition::Unsupported => Some(format!(
            "cannot modify while sandbox is {}",
            status_name(status)
        )),
        _ => None,
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
#[path = "modify_tests.rs"]
mod tests;
