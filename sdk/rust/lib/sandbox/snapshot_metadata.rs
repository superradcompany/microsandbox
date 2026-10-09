//! Capture and restore the portable guest settings independently of destination host policy.

use std::path::Path;

use microsandbox_types::snapshot::{GuestRlimitV1, GuestTmpfsV1, Manifest, SnapshotMetadataV1};
use microsandbox_types::{Rlimit, VolumeMount};

use crate::{MicrosandboxError, MicrosandboxResult};

use super::SandboxConfig;
use super::config::RestoreGuestState;

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

pub(crate) fn capture(config: &SandboxConfig) -> SnapshotMetadataV1 {
    let config = config.clone_for_persistence();
    let spec = config.spec;
    SnapshotMetadataV1 {
        env: spec.env,
        workdir: spec.runtime.workdir,
        shell: spec.runtime.shell,
        // Match runtime script materialization, including deterministic last-writer wins
        // when multiple source keys have the same filename.
        scripts: spec
            .runtime
            .scripts
            .into_iter()
            .map(|(name, body)| {
                let filename = Path::new(&name)
                    .file_name()
                    .and_then(|name| name.to_str())
                    .unwrap_or(&name)
                    .to_owned();
                (filename, body)
            })
            .collect(),
        entrypoint: spec.runtime.entrypoint,
        cmd: spec.runtime.cmd,
        hostname: spec.runtime.hostname,
        init: spec.init,
        rlimits: spec
            .rlimits
            .into_iter()
            .map(|limit| GuestRlimitV1 {
                resource: limit.resource,
                soft: limit.soft,
                hard: limit.hard,
            })
            .collect(),
        security: spec.security_profile,
        thp: spec.resources.thp,
        tmpfs: spec
            .mounts
            .into_iter()
            .filter_map(|mount| match mount {
                VolumeMount::Tmpfs {
                    guest,
                    size_mib,
                    options,
                } => Some(GuestTmpfsV1 {
                    guest,
                    size_mib,
                    options,
                }),
                _ => None,
            })
            .collect(),
    }
}

/// Preserve edits to built, unresolved configurations without promoting defaults to overrides.
pub(crate) fn refresh_pending(config: &mut SandboxConfig) {
    if !matches!(config.restore_guest, RestoreGuestState::Pending { .. }) {
        return;
    }
    let current = capture(config);
    let RestoreGuestState::Pending { overrides, built } = &mut config.restore_guest else {
        unreachable!()
    };
    if let Some(previous) = built.as_ref() {
        if current.env != previous.env {
            overrides.replace_env_mut(current.env.clone());
        }
        if current.workdir != previous.workdir {
            overrides.runtime.workdir = Some(current.workdir.clone());
        }
        if current.shell != previous.shell {
            overrides.runtime.shell = Some(current.shell.clone());
        }
        if current.scripts != previous.scripts {
            let scripts = overrides.runtime.get_scripts_mut();
            scripts.retain(|key, _| config.spec.runtime.scripts.contains_key(key));
            scripts.extend(config.spec.runtime.scripts.clone());
        }
        if current.entrypoint != previous.entrypoint {
            overrides.runtime.entrypoint = current.entrypoint.clone();
        }
        if current.cmd != previous.cmd {
            overrides.runtime.cmd = current.cmd.clone();
        }
        if current.hostname != previous.hostname {
            overrides.runtime.hostname = current.hostname.clone();
        }
        if current.init != previous.init {
            overrides.init = current.init.clone();
        }
        if current.rlimits != previous.rlimits {
            overrides.rlimits = Some(config.spec.rlimits.clone());
        }
        if current.security != previous.security {
            overrides.security_profile = Some(current.security);
        }
        if current.thp != previous.thp {
            overrides.resources.thp = Some(current.thp);
        }
    }
    *built = Some(Box::new(current));
}

pub(crate) fn apply(config: &mut SandboxConfig, manifest: &Manifest) -> MicrosandboxResult<()> {
    refresh_pending(config);
    config
        .restore_boot_overrides
        .validate_scope(manifest.scope, config.snapshot_restore_mode)?;
    let defaults = manifest.restore_defaults()?;
    if config.spec.runtime.user.is_none() {
        config.spec.runtime.user = defaults.user;
    }
    let Some(guest) = defaults.config else {
        config.restore_guest = RestoreGuestState::Unresolved;
        return Ok(());
    };
    // Portable descriptors use guest Unix filenames. Refuse names the destination host
    // would reinterpret while materializing scripts, without making the descriptor unreadable.
    for name in guest.scripts.keys() {
        if Path::new(name).file_name().and_then(|part| part.to_str()) != Some(name.as_str()) {
            return Err(MicrosandboxError::InvalidConfig(format!(
                "snapshot script name {name:?} cannot be materialized on this host"
            )));
        }
    }
    let full = manifest.scope == crate::snapshot::SnapshotScope::Full
        && config.snapshot_restore_mode == super::config::SnapshotRestoreMode::Full;
    apply_tmpfs(&mut config.spec.mounts, &guest.tmpfs, full)?;
    config.spec.env = guest.env;
    config.spec.runtime.workdir = guest.workdir;
    config.spec.runtime.shell = guest.shell;
    config.spec.runtime.scripts = guest.scripts;
    config.spec.runtime.entrypoint = guest.entrypoint;
    config.spec.runtime.cmd = guest.cmd;
    config.spec.runtime.hostname = guest.hostname;
    if !config.restore_boot_overrides.init {
        config.spec.init = guest.init;
    }
    config.spec.rlimits = guest
        .rlimits
        .into_iter()
        .map(|limit| Rlimit {
            resource: limit.resource,
            soft: limit.soft,
            hard: limit.hard,
        })
        .collect();
    if !config.restore_boot_overrides.security {
        config.spec.security_profile = guest.security;
    }
    config.spec.resources.thp = guest.thp;
    let captured = full.then(|| capture(config));
    let mut overrides = match &config.restore_guest {
        RestoreGuestState::Pending { overrides, .. } => (**overrides).clone(),
        RestoreGuestState::Unresolved | RestoreGuestState::Retained(_) => Default::default(),
    };
    if let Some(env) = overrides.get_env() {
        // Like OCI inheritance, replacing the caller's env patch does not erase
        // inherited defaults. The builder starts with an empty replacement patch.
        let env = super::config::merge_env_pairs(&config.spec.env, env);
        overrides.replace_env_mut(env);
    }
    // Apply collection merge/replace semantics on a temporary spec, then copy an explicit
    // allowlist. Future host-policy fields can never overwrite restored guest mount inventory.
    let mut requested = config.spec.clone();
    overrides.apply_to(&mut requested);
    config.spec.env = requested.env;
    config.spec.runtime.workdir = requested.runtime.workdir;
    config.spec.runtime.shell = requested.runtime.shell;
    config.spec.runtime.scripts = requested.runtime.scripts;
    config.spec.runtime.entrypoint = requested.runtime.entrypoint;
    config.spec.runtime.cmd = requested.runtime.cmd;
    config.spec.runtime.hostname = requested.runtime.hostname;
    config.spec.init = requested.init;
    config.spec.rlimits = requested.rlimits;
    config.spec.security_profile = requested.security_profile;
    config.spec.resources.thp = requested.resources.thp;
    if let Some(captured) = captured
        && captured != capture(config)
    {
        return Err(MicrosandboxError::InvalidConfig(
            "explicit guest settings conflict with the snapshot; use a disk-only restore to change them".into(),
        ));
    }
    config.restore_guest = RestoreGuestState::Retained(Box::new(capture(config)));
    Ok(())
}

/// Retain guest-only mounts without importing host bindings or changing a resumed guest.
pub(crate) fn apply_tmpfs(
    mounts: &mut Vec<VolumeMount>,
    captured: &[GuestTmpfsV1],
    full: bool,
) -> MicrosandboxResult<()> {
    microsandbox_types::canonicalize_volume_mounts(mounts)?;
    if full {
        for mount in mounts.iter() {
            if matches!(mount, VolumeMount::Tmpfs { .. })
                && !captured.iter().any(|saved| saved.guest == mount.guest())
            {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "full restore cannot add tmpfs at {}; use a disk-only restore to change guest mounts",
                    mount.guest()
                )));
            }
        }
    }
    for saved in captured {
        if let Some(existing) = mounts.iter().find(|mount| mount.guest() == saved.guest) {
            if full
                && !matches!(existing,
                    VolumeMount::Tmpfs { guest, size_mib, options }
                        if guest == &saved.guest && size_mib == &saved.size_mib && options == &saved.options
                )
            {
                return Err(MicrosandboxError::InvalidConfig(format!(
                    "full restore cannot replace captured tmpfs at {}",
                    saved.guest
                )));
            }
        } else {
            mounts.push(VolumeMount::Tmpfs {
                guest: saved.guest.clone(),
                size_mib: saved.size_mib,
                options: saved.options,
            });
        }
    }
    // Establish the same parent-before-child order used by ordinary mount admission.
    microsandbox_types::canonicalize_volume_mounts(mounts)?;
    Ok(())
}
