//! Protected sandbox storage and crash-forward admission of simple legacy state.

#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SCHEMA: &str = "microsandbox.protected-layout/1";
const MARKER: &str = "state-layout.json";
const MAX_METADATA: u64 = 1024 * 1024;
const UPGRADE_GUARD: &[u8] = b"{\"schema\":\"microsandbox.upgrade-required/protected-state\"}\n";

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Root binding obtained from host configuration, never from a guest journal.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct LegacyRootBinding {
    /// Configured disk path, preserving the host configuration's path semantics.
    pub path: PathBuf,
    /// Explicit image format.
    pub format: String,
    /// True for a flat OCI root; false for an OCI writable upper.
    pub flat: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LayoutRecord {
    schema: String,
    phase: Phase,
    /// Retained during preparation so a crash cannot cause a different journal to be admitted.
    binding: Option<LegacyRootBinding>,
    root: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
enum Phase {
    Preparing,
    Ready,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Host-managed sandbox namespace, derived from the historical launch locator.
pub fn host_root(runtime_dir: &Path) -> Result<&Path, String> {
    runtime_dir
        .parent()
        .ok_or_else(|| "runtime directory has no sandbox parent".into())
}

/// The only internal sandbox subtree exported through `/.msb`.
pub fn guest_root(runtime_dir: &Path) -> Result<PathBuf, String> {
    Ok(host_root(runtime_dir)?.join("guest-state"))
}

/// Admit an existing sandbox under its lifecycle and storage locks.
///
/// Callers must record protection in the catalog before this call, so downgrade preflight can
/// see unfinished filesystem migration. No journal-selected file is opened during admission.
pub fn prepare(runtime_dir: &Path, binding: Option<&LegacyRootBinding>) -> Result<(), String> {
    let sandbox = host_root(runtime_dir)?;
    real_directory(sandbox, false)?;
    real_directory(runtime_dir, true)?;
    let marker = sandbox.join(MARKER);
    if let Some(bytes) = read_optional(&marker)? {
        let record: LayoutRecord = serde_json::from_slice(&bytes)
            .map_err(|error| recovery(format!("invalid layout record: {error}")))?;
        if record.schema != SCHEMA {
            return Err(recovery("unsupported layout record"));
        }
        if record.phase == Phase::Ready {
            real_directory(&guest_root(runtime_dir)?, true)?;
            return require_ready(runtime_dir);
        }
        if record.binding.as_ref() != binding {
            return Err(recovery("host disk configuration changed during migration"));
        }
        return finish(runtime_dir, record);
    }

    // These names have never been guest-exported in the protected format. Without a record,
    // their provenance cannot be established; do not silently adopt a half-converted layout.
    for name in [
        "root-disk.json",
        "owned-disks",
        "checkpoints",
        "checkpoint-store",
        "guest-state",
    ] {
        if fs::symlink_metadata(sandbox.join(name)).is_ok() {
            return Err(recovery(format!("unrecorded protected storage at {name}")));
        }
    }
    reject_advanced_legacy_storage(sandbox, runtime_dir, binding)?;
    let root = super::disk::admit_legacy_root(runtime_dir, binding)?;
    let record = LayoutRecord {
        schema: SCHEMA.into(),
        phase: Phase::Preparing,
        binding: binding.cloned(),
        root,
    };
    atomic_write(
        &marker,
        &serde_json::to_vec(&record).map_err(|e| e.to_string())?,
    )?;
    finish(runtime_dir, record)
}

/// Mark newly reserved, still-empty child storage before restore materialization writes chains.
/// This is not a migration entry point; callers must own a new catalog creation reservation.
pub fn initialize_new(runtime_dir: &Path) -> Result<(), String> {
    let sandbox = host_root(runtime_dir)?;
    real_directory(sandbox, true)?;
    real_directory(runtime_dir, true)?;
    if fs::symlink_metadata(sandbox.join(MARKER)).is_ok() {
        return prepare(runtime_dir, None);
    }
    // Restore materialization may already have created trusted host-side chains. Only the
    // SDK's still-owned catalog creation reservation may select this entry point.
    if read_optional(&runtime_dir.join("root-disk.json"))?.is_some() {
        return Err(recovery(
            "new reservation unexpectedly contains legacy guest state",
        ));
    }
    let record = LayoutRecord {
        schema: SCHEMA.into(),
        phase: Phase::Preparing,
        binding: None,
        root: None,
    };
    atomic_write(
        &sandbox.join(MARKER),
        &serde_json::to_vec(&record).map_err(|e| e.to_string())?,
    )?;
    finish(runtime_dir, record)
}

/// Refuse runtime activation unless migration completed and both old-reader guards remain.
pub fn require_ready(runtime_dir: &Path) -> Result<(), String> {
    let sandbox = host_root(runtime_dir)?;
    real_directory(sandbox, false)?;
    real_directory(runtime_dir, false)?;
    let bytes = read_optional(&sandbox.join(MARKER))?
        .ok_or_else(|| recovery("protected layout has not been prepared by a patched SDK"))?;
    let record: LayoutRecord = serde_json::from_slice(&bytes)
        .map_err(|error| recovery(format!("invalid layout record: {error}")))?;
    if record.schema != SCHEMA || record.phase != Phase::Ready {
        return Err(recovery("protected layout preparation is incomplete"));
    }
    real_directory(&guest_root(runtime_dir)?, false)?;
    real_directory(&runtime_dir.join("heartbeat.json"), false)?;
    if read_optional(&runtime_dir.join("root-disk.json"))?.as_deref() != Some(UPGRADE_GUARD) {
        return Err(recovery(
            "legacy runtime rejection guard is missing or changed",
        ));
    }
    Ok(())
}

/// Recreate per-boot guest files while the guest is stopped. Never reuse guest-created links.
pub fn reset_guest_files(runtime_dir: &Path) -> Result<PathBuf, String> {
    require_ready(runtime_dir)?;
    let guest = guest_root(runtime_dir)?;
    // remove_dir_all does not follow directory symlinks. The exported root itself is host-owned.
    fs::remove_dir_all(&guest).map_err(|e| e.to_string())?;
    fs::create_dir(&guest).map_err(|e| e.to_string())?;
    fs::create_dir(guest.join("scripts")).map_err(|e| e.to_string())?;
    sync_directory(host_root(runtime_dir)?)?;
    Ok(guest)
}

fn finish(runtime_dir: &Path, record: LayoutRecord) -> Result<(), String> {
    finish_with_checkpoint(runtime_dir, record, |_| Ok(()))
}

fn finish_with_checkpoint(
    runtime_dir: &Path,
    mut record: LayoutRecord,
    mut checkpoint: impl FnMut(u8) -> Result<(), String>,
) -> Result<(), String> {
    let sandbox = host_root(runtime_dir)?;
    // Older root readers reject the schema; all supported old runtimes also fail their
    // unconditional remove_file(heartbeat.json) before exporting a filesystem or booting.
    atomic_write(&runtime_dir.join("root-disk.json"), UPGRADE_GUARD)?;
    checkpoint(1)?;
    let heartbeat = runtime_dir.join("heartbeat.json");
    if let Ok(metadata) = fs::symlink_metadata(&heartbeat)
        && (!metadata.is_dir() || metadata_is_link(&metadata))
    {
        fs::remove_file(&heartbeat).map_err(|e| e.to_string())?;
    }
    real_directory(&heartbeat, true)?;
    sync_directory(runtime_dir)?;
    checkpoint(2)?;
    if let Some(root) = &record.root {
        atomic_write(
            &sandbox.join("root-disk.json"),
            &serde_json::to_vec(root).map_err(|e| e.to_string())?,
        )?;
    }
    checkpoint(3)?;
    real_directory(&guest_root(runtime_dir)?, true)?;
    checkpoint(4)?;
    record.phase = Phase::Ready;
    record.root = None;
    record.binding = None;
    atomic_write(
        &sandbox.join(MARKER),
        &serde_json::to_vec(&record).map_err(|e| e.to_string())?,
    )?;
    checkpoint(5)?;
    require_ready(runtime_dir)
}

fn reject_advanced_legacy_storage(
    sandbox: &Path,
    runtime_dir: &Path,
    binding: Option<&LegacyRootBinding>,
) -> Result<(), String> {
    let mut directories = vec![sandbox, runtime_dir];
    if let Some(parent) = binding.and_then(|root| root.path.parent())
        && !parent.as_os_str().is_empty()
        && parent != sandbox
        && parent != runtime_dir
    {
        directories.push(parent);
    }
    let mut budget = 4096;
    for directory in directories {
        for entry in bounded_entries(directory, &mut budget)? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            if directory == runtime_dir
                && matches!(
                    name.as_ref(),
                    "owned-disks" | "checkpoints" | "checkpoint-store"
                )
            {
                // Ordinary legacy boots create an empty object-store skeleton even before
                // the first checkpoint. Only those exact empty directories are discardable.
                let allowed = if name == "checkpoint-store" {
                    vec!["objects", "objects/sha256"]
                } else {
                    vec![]
                };
                require_empty_skeleton(&entry.path(), &allowed, &mut budget)?;
                continue;
            }
            if directory == runtime_dir {
                match name.as_ref() {
                    "scripts" | "tls" => {
                        real_directory(&entry.path(), false)?;
                        for child in bounded_entries(&entry.path(), &mut budget)? {
                            if !fs::symlink_metadata(child.path())
                                .map_err(|e| e.to_string())?
                                .is_file()
                            {
                                return Err(recovery(
                                    "unexplained legacy guest-file directory or link",
                                ));
                            }
                        }
                    }
                    "rootfs" => {
                        require_empty_skeleton(&entry.path(), &["lower", "upperfs"], &mut budget)?
                    }
                    "root-disk.json" | "heartbeat.json" | "runtime-boot-id"
                    | "sdk-process.json" => {
                        // These are disposable metadata, not places to hide a renamed disk tree.
                        read_optional(&entry.path())?;
                    }
                    "agent.sock" | "control.sock" => {
                        let metadata =
                            fs::symlink_metadata(entry.path()).map_err(|e| e.to_string())?;
                        if metadata.is_dir() || metadata_is_link(&metadata) {
                            return Err(recovery("legacy socket path hides a directory or link"));
                        }
                    }
                    _ => {
                        return Err(recovery(format!(
                            "unexplained legacy runtime entry {name}; disk history may have been renamed"
                        )));
                    }
                }
            }
            if name.starts_with(".compact-")
                || name.starts_with(".grow-")
                || ((name.starts_with("upper-") || name.starts_with("root-"))
                    && name.ends_with(".qcow2"))
            {
                return Err(recovery(format!(
                    "legacy chain or checkpoint storage {name} cannot be authenticated automatically"
                )));
            }
        }
    }
    // Missing legacy journals do not authorize reverting an owned disk to its original base.
    let owned = sandbox.join("owned-volumes");
    if owned.exists() {
        real_directory(&owned, false)?;
        for entry in bounded_entries(&owned, &mut budget)? {
            real_directory(&entry.path(), false)?;
            for file in bounded_entries(&entry.path(), &mut budget)? {
                if file.file_name().to_string_lossy().ends_with(".qcow2") {
                    return Err(recovery(
                        "legacy owned-disk chain has no protected authority",
                    ));
                }
            }
        }
    }
    Ok(())
}

fn bounded_entries(path: &Path, budget: &mut usize) -> Result<Vec<fs::DirEntry>, String> {
    real_directory(path, false)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(path).map_err(|e| e.to_string())? {
        *budget = budget
            .checked_sub(1)
            .ok_or_else(|| recovery("legacy storage inventory exceeds its admission bound"))?;
        entries.push(entry.map_err(|e| e.to_string())?);
    }
    Ok(entries)
}

fn require_empty_skeleton(root: &Path, allowed: &[&str], budget: &mut usize) -> Result<(), String> {
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        for entry in bounded_entries(&directory, budget)? {
            let path = entry.path();
            let relative = path.strip_prefix(root).map_err(|e| e.to_string())?;
            if !allowed.iter().any(|name| relative == Path::new(name)) {
                return Err(recovery(
                    "legacy checkpoint or disk state cannot be authenticated automatically",
                ));
            }
            real_directory(&path, false)?;
            pending.push(path);
        }
    }
    Ok(())
}

pub(crate) fn read_optional(path: &Path) -> Result<Option<Vec<u8>>, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        options.custom_flags(windows_sys::Win32::Storage::FileSystem::FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(recovery(format!("open {}: {error}", path.display()))),
    };
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata_is_link(&metadata) || metadata.len() > MAX_METADATA {
        return Err(recovery(
            "metadata must be a bounded regular file, without symlinks or reparse points",
        ));
    }
    let mut bytes = Vec::new();
    file.take(MAX_METADATA + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_METADATA {
        return Err(recovery("metadata exceeds its size bound"));
    }
    Ok(Some(bytes))
}

pub(crate) fn atomic_write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    atomic_write_inner(path, bytes, false)
}

/// Public CA certificates must remain readable by non-root guest processes. Journals keep the
/// private tempfile permissions; grant certificate access before publishing its final name.
pub(crate) fn write_guest_certificate(path: &Path, bytes: &[u8]) -> Result<(), String> {
    atomic_write_inner(path, bytes, true)
}

fn atomic_write_inner(path: &Path, bytes: &[u8], public_certificate: bool) -> Result<(), String> {
    let parent = path.parent().ok_or("metadata has no parent")?;
    real_directory(parent, false)?;
    let mut staging = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    if public_certificate {
        use std::os::unix::fs::PermissionsExt;
        staging
            .as_file()
            .set_permissions(fs::Permissions::from_mode(0o644))
            .map_err(|e| e.to_string())?;
    }
    #[cfg(not(unix))]
    let _ = public_certificate;
    staging
        .write_all(bytes)
        .and_then(|()| staging.as_file().sync_all())
        .map_err(|e| e.to_string())?;
    let (file, temporary) = staging.keep().map_err(|e| e.to_string())?;
    drop(file);
    super::replace_file(&temporary, path).map_err(|e| e.to_string())?;
    sync_directory(parent)
}

pub(crate) fn real_directory(path: &Path, create: bool) -> Result<(), String> {
    if create {
        match fs::create_dir(path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.to_string()),
        }
    }
    let metadata = fs::symlink_metadata(path).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata_is_link(&metadata) {
        return Err(recovery(format!(
            "{} is not a real directory",
            path.display()
        )));
    }
    Ok(())
}

fn metadata_is_link(metadata: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        metadata.file_type().is_symlink() || metadata.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    metadata.file_type().is_symlink()
}

fn sync_directory(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|e| e.to_string())?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

fn recovery(detail: impl std::fmt::Display) -> String {
    format!(
        "migration/recovery required: {detail}; preserve this sandbox and use a verified backup or recover its disk chain before retrying"
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy() -> (tempfile::TempDir, PathBuf, LegacyRootBinding) {
        let temporary = tempfile::tempdir().unwrap();
        let runtime = temporary.path().join("runtime");
        fs::create_dir(&runtime).unwrap();
        let binding = LegacyRootBinding {
            path: temporary.path().join("upper.ext4"),
            format: "raw".into(),
            flat: false,
        };
        fs::write(&binding.path, b"original guest disk bytes").unwrap();
        write_legacy(&runtime, &binding);
        (temporary, runtime, binding)
    }

    fn write_legacy(runtime: &Path, binding: &LegacyRootBinding) {
        let value = serde_json::json!({
            "schema":"microsandbox.runtime-root-disk/1",
            "volume_id":format!("vol_{}", "a".repeat(32)),
            "device_id":if binding.flat {"vda"} else {"vdb"},
            "layout":if binding.flat {"flat-root"} else {"managed-upper"},
            "published_generation":0,
            "layers":[{"layer_id":format!("layer_{}", "b".repeat(32)),
                "path":binding.path, "format":binding.format,
                "integrity_root":"untrusted cached integrity"}]
        });
        fs::write(
            runtime.join("root-disk.json"),
            serde_json::to_vec(&value).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn simple_legacy_migration_preserves_data_and_rebuilds_authority() {
        let (temporary, runtime, binding) = legacy();
        fs::write(
            runtime.join("runtime-boot-id"),
            b"boot_disposable-old-identity",
        )
        .unwrap();
        let old = fs::read(runtime.join("root-disk.json")).unwrap();
        fs::write(runtime.join("sdk-process.json"), b"{\"pid\":123}").unwrap();
        fs::create_dir(runtime.join("checkpoints")).unwrap();
        fs::create_dir_all(runtime.join("checkpoint-store/objects/sha256")).unwrap();
        prepare(&runtime, Some(&binding)).unwrap();
        require_ready(&runtime).unwrap();
        prepare(&runtime, Some(&binding)).unwrap();
        let journal = fs::read(temporary.path().join("root-disk.json")).unwrap();
        assert_ne!(journal, old);
        assert!(
            !String::from_utf8(journal)
                .unwrap()
                .contains("untrusted cached integrity")
        );
        assert_eq!(
            fs::read(&binding.path).unwrap(),
            b"original guest disk bytes"
        );
        assert!(
            !guest_root(&runtime)
                .unwrap()
                .join("root-disk.json")
                .exists()
        );
        assert_eq!(
            fs::read(runtime.join("root-disk.json")).unwrap(),
            UPGRADE_GUARD
        );
        assert!(fs::remove_file(runtime.join("heartbeat.json")).is_err());
    }

    #[test]
    fn forged_metadata_targets_are_refused_before_any_mutation() {
        for sibling in [false, true] {
            let (temporary, runtime, binding) = legacy();
            let canary_dir = tempfile::tempdir().unwrap();
            let target = if sibling {
                canary_dir.path()
            } else {
                temporary.path()
            }
            .join("external-mounts.json");
            fs::write(&target, b"host authority").unwrap();
            let forged = LegacyRootBinding {
                path: target.clone(),
                ..binding.clone()
            };
            write_legacy(&runtime, &forged);
            let before = fs::read(runtime.join("root-disk.json")).unwrap();
            assert!(
                prepare(&runtime, Some(&binding))
                    .unwrap_err()
                    .contains("cannot be authenticated")
            );
            assert_eq!(fs::read(runtime.join("root-disk.json")).unwrap(), before);
            assert_eq!(fs::read(target).unwrap(), b"host authority");
            assert!(!temporary.path().join(MARKER).exists());
        }
    }

    #[test]
    fn interruption_at_each_publication_step_recovers_the_same_admitted_chain() {
        for interrupted in 1..=5 {
            let (temporary, runtime, binding) = legacy();
            let record = LayoutRecord {
                schema: SCHEMA.into(),
                phase: Phase::Preparing,
                binding: Some(binding.clone()),
                root: super::super::disk::admit_legacy_root(&runtime, Some(&binding)).unwrap(),
            };
            atomic_write(
                &temporary.path().join(MARKER),
                &serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
            assert!(
                finish_with_checkpoint(&runtime, record, |step| {
                    if step == interrupted {
                        Err("injected interruption".into())
                    } else {
                        Ok(())
                    }
                })
                .is_err()
            );
            prepare(&runtime, Some(&binding)).unwrap();
            require_ready(&runtime).unwrap();
            let chain = super::super::load_runtime_owned_root_chain(&runtime)
                .unwrap()
                .unwrap();
            assert_eq!(chain.layers[0].path, binding.path);
            assert_eq!(
                fs::read(binding.path).unwrap(),
                b"original guest disk bytes"
            );
        }
    }

    #[test]
    fn missing_or_rewound_journal_cannot_hide_advanced_storage() {
        for missing in [false, true] {
            let (temporary, runtime, binding) = legacy();
            if missing {
                fs::remove_file(runtime.join("root-disk.json")).unwrap();
            }
            fs::write(
                temporary.path().join("upper-sealed.qcow2"),
                b"advanced chain",
            )
            .unwrap();
            assert!(
                prepare(&runtime, Some(&binding))
                    .unwrap_err()
                    .contains("cannot be authenticated")
            );
            assert!(!temporary.path().join(MARKER).exists());
        }
    }

    #[test]
    fn renamed_legacy_growth_storage_is_not_silently_abandoned() {
        let (temporary, runtime, binding) = legacy();
        fs::create_dir(runtime.join("renamed-growth")).unwrap();
        fs::write(
            runtime.join("renamed-growth/upper.ext4"),
            b"newest guest bytes",
        )
        .unwrap();
        fs::remove_file(runtime.join("root-disk.json")).unwrap();
        assert!(
            prepare(&runtime, Some(&binding))
                .unwrap_err()
                .contains("unexplained")
        );
        assert!(!temporary.path().join(MARKER).exists());
        assert_eq!(
            fs::read(runtime.join("renamed-growth/upper.ext4")).unwrap(),
            b"newest guest bytes"
        );
    }

    #[test]
    fn external_advanced_layers_are_detected_even_when_legacy_journal_was_deleted() {
        let (_temporary, runtime, mut binding) = legacy();
        let external = tempfile::tempdir().unwrap();
        binding.path = external.path().join("explicit.raw");
        fs::write(&binding.path, b"base").unwrap();
        fs::write(
            external.path().join("upper-after-snapshot.qcow2"),
            b"latest data",
        )
        .unwrap();
        fs::remove_file(runtime.join("root-disk.json")).unwrap();
        assert!(
            prepare(&runtime, Some(&binding))
                .unwrap_err()
                .contains("cannot be authenticated")
        );
    }

    #[test]
    fn explicit_external_upper_is_preserved() {
        let (temporary, runtime, mut binding) = legacy();
        let external = tempfile::tempdir().unwrap();
        binding.path = external.path().join("explicit-upper.raw");
        fs::write(&binding.path, b"external authorized disk").unwrap();
        write_legacy(&runtime, &binding);
        prepare(&runtime, Some(&binding)).unwrap();
        let chain = super::super::load_runtime_owned_root_chain(&runtime)
            .unwrap()
            .unwrap();
        assert_eq!(chain.layers[0].path, binding.path);
        assert!(temporary.path().join("root-disk.json").is_file());
        assert_eq!(fs::read(binding.path).unwrap(), b"external authorized disk");
    }

    #[cfg(unix)]
    #[test]
    fn guest_file_reset_does_not_follow_symlinks_or_preserve_hardlinks() {
        let (temporary, runtime, binding) = legacy();
        let canary = temporary.path().join("host-canary");
        fs::write(&canary, b"host bytes").unwrap();
        fs::create_dir(runtime.join("scripts")).unwrap();
        fs::hard_link(&canary, runtime.join("scripts/legacy")).unwrap();
        prepare(&runtime, Some(&binding)).unwrap();
        let guest = guest_root(&runtime).unwrap();
        std::os::unix::fs::symlink(temporary.path(), guest.join("scripts")).unwrap();
        reset_guest_files(&runtime).unwrap();
        fs::write(guest.join("scripts/host-canary"), b"new guest script").unwrap();
        assert_eq!(fs::read(canary).unwrap(), b"host bytes");
        assert!(!guest.join("scripts/legacy").exists());
    }

    #[cfg(unix)]
    #[test]
    fn preboot_guest_writes_reject_parent_links_and_replace_file_links() {
        let (_temporary, runtime, binding) = legacy();
        prepare(&runtime, Some(&binding)).unwrap();
        let external = tempfile::tempdir().unwrap();
        let canary = external.path().join("ca.pem");
        fs::write(&canary, b"host bytes").unwrap();
        let tls = guest_root(&runtime).unwrap().join("tls");
        std::os::unix::fs::symlink(external.path(), &tls).unwrap();
        assert!(real_directory(&tls, true).is_err());
        fs::remove_file(&tls).unwrap();
        real_directory(&tls, true).unwrap();
        for hardlink in [false, true] {
            let destination = tls.join("ca.pem");
            if hardlink {
                fs::hard_link(&canary, &destination).unwrap();
            } else {
                std::os::unix::fs::symlink(&canary, &destination).unwrap();
            }
            write_guest_certificate(&destination, b"public guest certificate").unwrap();
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&destination).unwrap().permissions().mode() & 0o777,
                0o644
            );
            assert_eq!(fs::read(&canary).unwrap(), b"host bytes");
            assert_eq!(fs::read(&destination).unwrap(), b"public guest certificate");
            fs::remove_file(destination).unwrap();
        }
    }

    #[cfg(unix)]
    #[test]
    fn metadata_rejects_symlinks_fifos_and_oversized_files() {
        use std::os::unix::ffi::OsStrExt;
        let directory = tempfile::tempdir().unwrap();
        let target = directory.path().join("target");
        fs::write(&target, b"{}").unwrap();
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(read_optional(&link).is_err());
        let fifo = directory.path().join("fifo");
        let name = std::ffi::CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(name.as_ptr(), 0o600) }, 0);
        assert!(read_optional(&fifo).is_err());
        File::create(&target)
            .unwrap()
            .set_len(MAX_METADATA + 1)
            .unwrap();
        assert!(read_optional(&target).is_err());
    }
}
