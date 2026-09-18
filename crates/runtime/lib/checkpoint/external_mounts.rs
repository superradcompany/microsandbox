//! Local authorization records for reconnecting external bind mounts.

#[cfg(feature = "runner")]
use std::{collections::BTreeMap, fs::OpenOptions, io::Write};
use std::{io::Read, path::Path};

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Host-local record, deliberately excluded from portable checkpoint closures.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExternalMountAuthorization {
    /// Opaque source-run binding identity carried by the portable logical resource.
    pub token: String,
    /// Effective host-side mount specifications from the trusted source launcher.
    pub mounts: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl ExternalMountAuthorization {
    /// Read a bounded source-local authorization record. Never use an archive-provided path.
    pub fn read(runtime_dir: &Path) -> Result<Self, String> {
        let mut bytes = Vec::new();
        // runtime_dir is exported writable to the guest as /.msb. Authorization
        // must remain in its host-only parent, not inside that filesystem share.
        let sandbox_dir = runtime_dir
            .parent()
            .ok_or("runtime has no host-only parent")?;
        std::fs::File::open(sandbox_dir.join("external-mounts.json"))
            .and_then(|file| file.take(1024 * 1024 + 1).read_to_end(&mut bytes))
            .map_err(|error| error.to_string())?;
        if bytes.len() > 1024 * 1024 {
            return Err("external binding record is too large".into());
        }
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "runner")]
pub(crate) fn bindings(
    runtime_dir: &Path,
    vm: &crate::vm::VmConfig,
    bootstrap: &microsandbox_protocol::bootstrap::GuestBootstrap,
) -> Result<BTreeMap<String, BTreeMap<String, String>>, String> {
    if vm.mounts.is_empty() && vm.file_mounts.is_empty() {
        return Ok(BTreeMap::new());
    }
    let effective_mounts = vm
        .file_mounts
        .iter()
        .map(|mount| mount.mount.clone())
        .chain(vm.mounts.iter().cloned())
        .collect::<Vec<_>>();
    let authorization = match ExternalMountAuthorization::read(runtime_dir) {
        Ok(record) if record.mounts == effective_mounts => record,
        _ => {
            let record = ExternalMountAuthorization {
                token: format!("external_{:032x}", rand::random::<u128>()),
                mounts: effective_mounts.clone(),
            };
            let sandbox_dir = runtime_dir
                .parent()
                .ok_or("runtime has no host-only parent")?;
            let temporary =
                sandbox_dir.join(format!(".external-mounts.{}.tmp", std::process::id()));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&temporary)
                .map_err(|e| e.to_string())?;
            file.write_all(&serde_json::to_vec(&record).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?;
            file.sync_all().map_err(|e| e.to_string())?;
            super::replace_file(&temporary, &sandbox_dir.join("external-mounts.json"))
                .map_err(|e| e.to_string())?;
            record
        }
    };
    let source = runtime_dir
        .parent()
        .and_then(Path::file_name)
        .and_then(|name| name.to_str())
        .ok_or("source runtime has no sandbox identity")?;
    effective_mounts
        .iter()
        .enumerate()
        .map(|(index, spec)| {
            let tag = spec.split_once(':').ok_or("invalid mount spec")?.0;
            let file = bootstrap.file_mounts.iter().find(|mount| mount.tag == tag);
            let mount = if let Some(file) = file {
                microsandbox_protocol::bootstrap::BootstrapDirMount {
                    tag: file.tag.clone(),
                    guest_path: file.guest_path.clone(),
                    flags: file.flags,
                }
            } else {
                bootstrap
                    .dir_mounts
                    .iter()
                    .find(|mount| mount.tag == tag)
                    .cloned()
                    .ok_or_else(|| format!("external mount {tag} has no guest binding"))?
            };
            let id = format!("virtio_fs{}", 2 + index);
            let mut binding = BTreeMap::from([
                ("role".into(), "external_bind".into()),
                ("source_sandbox".into(), source.into()),
                ("source_binding_token".into(), authorization.token.clone()),
                ("guest_tag".into(), tag.into()),
                (
                    "guest_mount".into(),
                    serde_json::to_string(&mount).map_err(|e| e.to_string())?,
                ),
            ]);
            if vm
                .owned_volumes
                .iter()
                .any(|owned| owned.guest() == mount.guest_path)
            {
                // The portable inventory authorizes private reconstruction; source-local
                // external mount grants must never become ownership authority.
                binding.insert("role".into(), "owned_directory".into());
                binding.remove("source_sandbox");
                binding.remove("source_binding_token");
            }
            if let Some(file) = file {
                binding.insert("filename".into(), file.filename.clone());
            }
            Ok((id, binding))
        })
        .collect()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_ignores_guest_writable_runtime_records() {
        let sandbox = tempfile::tempdir().unwrap();
        let runtime = sandbox.path().join("runtime");
        std::fs::create_dir(&runtime).unwrap();
        let forged = ExternalMountAuthorization {
            token: "guest-forged".into(),
            mounts: vec!["tag:/guest-chosen".into()],
        };
        std::fs::write(
            runtime.join("external-mounts.json"),
            serde_json::to_vec(&forged).unwrap(),
        )
        .unwrap();
        assert!(ExternalMountAuthorization::read(&runtime).is_err());
        let trusted = ExternalMountAuthorization {
            token: "host-record".into(),
            mounts: vec!["tag:/host-selected".into()],
        };
        std::fs::write(
            sandbox.path().join("external-mounts.json"),
            serde_json::to_vec(&trusted).unwrap(),
        )
        .unwrap();
        let actual = ExternalMountAuthorization::read(&runtime).unwrap();
        assert_eq!(actual.token, trusted.token);
        assert_eq!(actual.mounts, trusted.mounts);
    }
}
