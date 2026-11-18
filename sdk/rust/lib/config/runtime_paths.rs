//! Package discovery is separate from explicit process-level runtime overrides.

use std::{
    path::{Path, PathBuf},
    sync::OnceLock,
};

use crate::{MicrosandboxError, MicrosandboxResult};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

static SDK_PACKAGED_MSB_PATH: OnceLock<Result<PathBuf, String>> = OnceLock::new();

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Register an automatically discovered package executable as a home-first fallback.
///
/// The matching library is resolved beside the executable or under `../lib`.
/// Registration does not inspect the target file. Relative paths are captured against
/// the current directory. Set-once: subsequent calls are ignored.
///
/// Resolution errors are retained and returned when runtime resolution is requested.
pub fn set_sdk_packaged_msb_path(path: impl Into<PathBuf>) {
    if SDK_PACKAGED_MSB_PATH.get().is_none() {
        let _ = SDK_PACKAGED_MSB_PATH.set(anchor_registered_path(path.into()));
    }
}

pub(crate) fn sdk_packaged_msb_path() -> crate::MicrosandboxResult<Option<PathBuf>> {
    registered_path(&SDK_PACKAGED_MSB_PATH)
}

/// Infallible registration records failure instead of retaining an unanchored path
/// or unwinding across a language SDK's native boundary.
pub(super) fn anchor_registered_path(path: impl AsRef<Path>) -> Result<PathBuf, String> {
    std::path::absolute(path).map_err(|error| format!("cannot resolve SDK runtime path: {error}"))
}

pub(super) fn registered_path(
    value: &OnceLock<Result<PathBuf, String>>,
) -> crate::MicrosandboxResult<Option<PathBuf>> {
    value
        .get()
        .cloned()
        .transpose()
        .map_err(crate::MicrosandboxError::InvalidConfig)
}

pub(crate) fn resolve(config: &mut super::GlobalConfig) -> MicrosandboxResult<()> {
    // Materialize the ambient home even when the user supplied no override. Otherwise a
    // later MSB_HOME change could split one backend's database and its filesystem state.
    config.home = Some(config.home());
    resolve_from(config, None)
}

fn resolve_from(config: &mut super::GlobalConfig, file: Option<&Path>) -> MicrosandboxResult<()> {
    resolve_fields(
        [
            ("home", &mut config.home),
            ("paths.msb", &mut config.paths.msb),
            ("paths.libkrunfw", &mut config.paths.libkrunfw),
            ("paths.agentd", &mut config.paths.agentd),
            ("paths.cache", &mut config.paths.cache),
            ("paths.sandboxes", &mut config.paths.sandboxes),
            ("paths.volumes", &mut config.paths.volumes),
            ("paths.snapshots", &mut config.paths.snapshots),
            ("paths.logs", &mut config.paths.logs),
            ("paths.secrets", &mut config.paths.secrets),
            ("registries.ca_certs", &mut config.registries.ca_certs),
        ]
        .map(|(field, path)| (field, path.as_mut())),
        file,
    )
}

/// Anchor only present path values, preserving omission and explicit nulls in each layer.
pub(super) fn resolve_patch(
    config: &mut super::GlobalConfigPatch,
    file: Option<&Path>,
    higher: &super::GlobalConfigPatch,
) -> MicrosandboxResult<()> {
    if let Some(Some(microsandbox_types::RootDisk::DiskImage { path, .. })) =
        &mut config.sandbox_defaults.oci.root_disk
        && higher.sandbox_defaults.oci.root_disk.is_none()
    {
        resolve_fields([("sandbox_defaults.oci.root_disk", Some(path))], file)?;
    }
    resolve_fields(
        [
            ("home", &mut config.home, &higher.home),
            ("paths.msb", &mut config.paths.msb, &higher.paths.msb),
            (
                "paths.libkrunfw",
                &mut config.paths.libkrunfw,
                &higher.paths.libkrunfw,
            ),
            (
                "paths.agentd",
                &mut config.paths.agentd,
                &higher.paths.agentd,
            ),
            ("paths.cache", &mut config.paths.cache, &higher.paths.cache),
            (
                "paths.sandboxes",
                &mut config.paths.sandboxes,
                &higher.paths.sandboxes,
            ),
            (
                "paths.volumes",
                &mut config.paths.volumes,
                &higher.paths.volumes,
            ),
            (
                "paths.snapshots",
                &mut config.paths.snapshots,
                &higher.paths.snapshots,
            ),
            ("paths.logs", &mut config.paths.logs, &higher.paths.logs),
            (
                "paths.secrets",
                &mut config.paths.secrets,
                &higher.paths.secrets,
            ),
            (
                "registries.ca_certs",
                &mut config.registries.ca_certs,
                &higher.registries.ca_certs,
            ),
        ]
        .into_iter()
        .filter(|(_, _, higher)| higher.is_none())
        .map(|(field, path, _)| (field, path.as_mut().and_then(Option::as_mut))),
        file,
    )
}

fn resolve_fields<'a>(
    fields: impl IntoIterator<Item = (&'a str, Option<&'a mut PathBuf>)>,
    file: Option<&Path>,
) -> MicrosandboxResult<()> {
    let mut base: Option<PathBuf> = None;
    for (field, path) in fields {
        if let Some(path) = path
            && path.is_relative()
        {
            // Read cwd at most once so every field shares one base. Do not canonicalize:
            // missing destinations and OS symlink/.. traversal remain valid inputs.
            if base.is_none() {
                base = Some((match file {
                    Some(file) => std::path::absolute(file).map(|path| {
                        path.parent().unwrap_or(Path::new(".")).to_path_buf()
                    }),
                    None => std::env::current_dir(),
                }).map_err(|error| {
                    MicrosandboxError::InvalidConfig(format!(
                        "cannot resolve relative local backend {field} path `{}`: {error}; use an absolute path or construct the backend from an accessible working directory",
                        path.display()
                    ))
                })?);
            }
            *path = std::path::absolute(base.as_ref().expect("cwd resolved above").join(&*path))?;
        }
    }
    Ok(())
}
