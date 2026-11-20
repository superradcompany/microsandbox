//! Protected sandbox storage and crash-forward admission of simple legacy state.

#[cfg(unix)]
use std::ffi::OsStr;
#[cfg(unix)]
use std::fs::File;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
#[cfg(unix)]
use std::{collections::HashMap, os::unix::fs::MetadataExt};

#[cfg(unix)]
use cap_primitives::fs as cap_fs;
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const SCHEMA: &str = "microsandbox.protected-layout/1";
const MARKER: &str = "state-layout.json";
const MAX_METADATA: u64 = 1024 * 1024;
#[cfg(unix)]
const MAX_REPAIR_ENTRIES: usize = 1_000_000;
#[cfg(unix)]
const MAX_REPAIR_DEPTH: usize = 128;
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

#[cfg(unix)]
#[derive(Default)]
struct RepairLinkInventory {
    links: HashMap<(u64, u64), RepairLinkRecord>,
    objects: HashMap<PathBuf, RepairObject>,
}

#[cfg(unix)]
#[derive(PartialEq, Eq)]
struct RepairObject {
    device: u64,
    inode: u64,
    directory: bool,
}

#[cfg(unix)]
struct RepairLinkRecord {
    link_count: u64,
    observed_names: u64,
    already_private: bool,
    first_path: PathBuf,
}

#[cfg(unix)]
struct ManagedTreeFrame {
    directory: File,
    relative: PathBuf,
    entries: cap_fs::ReadDir,
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
    private_directory(runtime_dir, true)?;
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
    private_directory(sandbox, true)?;
    private_directory(runtime_dir, true)?;
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

/// Tighten known host-managed files for one stopped, already-protected sandbox.
///
/// This is an explicit repair operation, not part of startup. It deliberately excludes guest
/// state, external mounts, shared caches, and unknown sandbox entries. Callers hold the sandbox
/// lifecycle lock and must establish that the sandbox is stopped before invoking it.
#[cfg(unix)]
pub fn repair_managed_permissions(runtime_dir: &Path) -> Result<(), String> {
    require_ready(runtime_dir)?;

    let sandbox = host_root(runtime_dir)?;
    let sandbox_handle = open_sandbox_directory(sandbox)?;
    let runtime_handle = open_managed_entry(&sandbox_handle, OsStr::new("runtime"))
        .map_err(|error| format!("cannot open protected runtime directory: {error}"))?;
    validate_managed_object(&sandbox_handle, true, sandbox)?;
    validate_managed_object(&runtime_handle, true, runtime_dir)?;

    // Inspect everything before the first permission change, so a known link, special file,
    // or foreign owner cannot leave the sandbox half-repaired. Hardlinks are admitted only when
    // every name for that inode belongs to this recognized sandbox state, or when the shared
    // object is already private and can be left unchanged.
    let mut links = RepairLinkInventory::default();
    record_managed_object(&mut links, &sandbox_handle, Path::new(""))?;
    record_managed_object(&mut links, &runtime_handle, Path::new("runtime"))?;
    preflight_direct_files(
        &sandbox_handle,
        &[
            MARKER,
            "root-disk.json",
            "external-mounts.json",
            "snapshot-lineage.json",
            "restore-mount-warnings.json",
        ],
        Some(MARKER),
        Path::new(""),
        &mut links,
    )?;
    preflight_host_trees(&sandbox_handle, &mut links)?;
    preflight_direct_files(
        &runtime_handle,
        &[
            "root-disk.json",
            "runtime-boot-id",
            "sdk-process.json",
            "restore-activation.json",
        ],
        Some("root-disk.json"),
        Path::new("runtime"),
        &mut links,
    )?;
    preflight_heartbeat_directory(&runtime_handle, &mut links)?;
    validate_repair_link_inventory(&links)?;

    // Reopened names are never authority by themselves. Match every object to the inspected
    // inode before changing it, and restrict directories top-down before entering them.
    harden_inspected_object(&links, &sandbox_handle, true, Path::new(""))?;
    harden_inspected_object(&links, &runtime_handle, true, Path::new("runtime"))?;
    repair_direct_files(
        &sandbox_handle,
        &[
            MARKER,
            "root-disk.json",
            "external-mounts.json",
            "snapshot-lineage.json",
            "restore-mount-warnings.json",
        ],
        Some(MARKER),
        Path::new(""),
        &links,
    )?;
    repair_host_trees(&sandbox_handle, &links)?;
    repair_direct_files(
        &runtime_handle,
        &[
            "root-disk.json",
            "runtime-boot-id",
            "sdk-process.json",
            "restore-activation.json",
        ],
        Some("root-disk.json"),
        Path::new("runtime"),
        &links,
    )?;
    repair_heartbeat_directory(&runtime_handle, &links)?;
    sync_directory(sandbox)?;
    Ok(())
}

/// Windows is not affected by the Unix process umask bug; still require the protected marker.
#[cfg(windows)]
pub fn repair_managed_permissions(runtime_dir: &Path) -> Result<(), String> {
    require_ready(runtime_dir)
}

/// Decode only the old single-root preparation record. It was host-created before legacy
/// guards could replace the original journal, so retain that exact admitted simple view.
pub(crate) fn retained_legacy_root(
    runtime_dir: &Path,
    binding: Option<&LegacyRootBinding>,
) -> Result<Option<Option<Vec<u8>>>, String> {
    let Some(bytes) = read_optional(&host_root(runtime_dir)?.join(MARKER))? else {
        return Ok(None);
    };
    let value: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|_| "invalid protected layout record")?;
    if value.get("schema").and_then(|v| v.as_str()) != Some(SCHEMA)
        || value.get("phase").and_then(|v| v.as_str()) != Some("preparing")
    {
        return Ok(None);
    }
    let record: LayoutRecord =
        serde_json::from_slice(&bytes).map_err(|_| "invalid historical preparation record")?;
    if record.binding.as_ref() != binding {
        return Err("host disk configuration changed during historical preparation".into());
    }
    if let Some(root) = record.root {
        let bytes = serde_json::to_vec(&root).map_err(|_| "invalid retained root record")?;
        let journal = super::compat::v0_7_0::RootJournal::decode(&bytes)?;
        let binding = binding.ok_or("historical preparation has no configured root")?;
        if journal.layers.len() != 1
            || journal.published_generation != 0
            || journal.growth_target.is_some()
            || journal.layers[0].path != binding.path
            || journal.layers[0].format != binding.format
            || (journal.layout == "flat-root") != binding.flat
            || journal
                .launch_base
                .as_ref()
                .is_some_and(|path| path != &binding.path)
        {
            return Err("historical preparation is not the admitted simple root format".into());
        }
        if let Some(current) = read_optional(&runtime_dir.join("root-disk.json"))?
            && current.as_slice() != UPGRADE_GUARD
        {
            let current = super::compat::v0_7_0::RootJournal::decode(&current)?;
            if current.layers.len() != 1
                || current.published_generation != 0
                || current.growth_target.is_some()
                || current.layers[0].path != binding.path
                || current.layers[0].format != binding.format
                || (current.layout == "flat-root") != binding.flat
                || current
                    .launch_base
                    .as_ref()
                    .is_some_and(|path| path != &binding.path)
            {
                return Err("legacy selection changed after historical simple admission".into());
            }
        }
        Ok(Some(Some(bytes)))
    } else {
        Ok(Some(None))
    }
}

/// Finish an imported group only after every protected journal is durably published.
pub(crate) fn publish_import_ready(runtime_dir: &Path) -> Result<(), String> {
    finish(
        runtime_dir,
        LayoutRecord {
            schema: SCHEMA.into(),
            phase: Phase::Preparing,
            binding: None,
            root: None,
        },
    )
}

/// Establish both historical reader guards without publishing a ready marker.
pub(crate) fn install_import_guards(runtime_dir: &Path) -> Result<(), String> {
    atomic_write(&runtime_dir.join("root-disk.json"), UPGRADE_GUARD)?;
    let heartbeat = runtime_dir.join("heartbeat.json");
    if let Ok(metadata) = fs::symlink_metadata(&heartbeat)
        && (!metadata.is_dir() || metadata_is_link(&metadata))
    {
        fs::remove_file(&heartbeat).map_err(|e| e.to_string())?;
    }
    private_directory(&heartbeat, true)?;
    sync_directory(runtime_dir)
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
    private_directory(&heartbeat, true)?;
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
#[cfg(any(test, all(feature = "runner", feature = "net")))]
pub(crate) fn write_guest_certificate(path: &Path, bytes: &[u8]) -> Result<(), String> {
    atomic_write_inner(path, bytes, true)
}

fn atomic_write_inner(path: &Path, bytes: &[u8], public_certificate: bool) -> Result<(), String> {
    let parent = path.parent().ok_or("metadata has no parent")?;
    real_directory(parent, false)?;
    let mut staging = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
    #[cfg(unix)]
    if !public_certificate {
        microsandbox_utils::private_file::harden(staging.as_file(), false)
            .map_err(|error| error.to_string())?;
    }
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
    if create && fs::symlink_metadata(path).is_ok() {
        return real_directory(path, false);
    }
    if create {
        #[cfg(unix)]
        let created = fs::create_dir(path);
        #[cfg(windows)]
        let created = (|| -> std::io::Result<()> {
            // FlushFileBuffers is not a general directory fsync on Windows. Publish each
            // new namespace entry with the same write-through move used for metadata files.
            let parent = path
                .parent()
                .ok_or_else(|| std::io::Error::other("directory has no parent"))?;
            let staging = tempfile::Builder::new()
                .prefix(".layout-directory-")
                .tempdir_in(parent)?;
            microsandbox_utils::private_file::harden_existing_directory(staging.path())?;
            super::replace_file(staging.path(), path)
        })();
        match created {
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

#[cfg(unix)]
fn open_sandbox_directory(sandbox: &Path) -> Result<File, String> {
    let absolute = std::path::absolute(sandbox).map_err(|error| error.to_string())?;
    let parent_path = absolute
        .parent()
        .ok_or_else(|| "sandbox directory has no parent".to_owned())?;
    let name = absolute
        .file_name()
        .ok_or_else(|| "sandbox directory has no name".to_owned())?;
    let parent = cap_fs::open_ambient_dir(parent_path, cap_primitives::ambient_authority())
        .map_err(|error| error.to_string())?;
    open_managed_entry(&parent, name).map_err(|error| error.to_string())
}

#[cfg(unix)]
fn open_managed_entry(parent: &File, name: &OsStr) -> std::io::Result<File> {
    use cap_fs::OpenOptionsExt;

    let mut options = cap_fs::OpenOptions::new();
    options
        .read(true)
        ._cap_fs_ext_follow(cap_fs::FollowSymlinks::No)
        .custom_flags(libc::O_NONBLOCK);
    cap_fs::open(parent, Path::new(name), &options)
}

#[cfg(unix)]
fn preflight_direct_files(
    parent: &File,
    names: &[&str],
    required: Option<&str>,
    relative: &Path,
    links: &mut RepairLinkInventory,
) -> Result<(), String> {
    for name in names {
        match open_managed_entry(parent, OsStr::new(name)) {
            Ok(file) => {
                validate_managed_object(&file, false, Path::new(name))?;
                record_managed_file(links, &file, &relative.join(name))?;
            }
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && required != Some(name) =>
            {
                continue;
            }
            Err(error) => return Err(format!("cannot inspect managed file {name}: {error}")),
        }
    }
    Ok(())
}

#[cfg(unix)]
fn repair_direct_files(
    parent: &File,
    names: &[&str],
    required: Option<&str>,
    relative: &Path,
    links: &RepairLinkInventory,
) -> Result<(), String> {
    for name in names {
        let file = match open_managed_entry(parent, OsStr::new(name)) {
            Ok(file) => file,
            Err(error)
                if error.kind() == std::io::ErrorKind::NotFound && required != Some(name) =>
            {
                continue;
            }
            Err(error) => return Err(format!("cannot open managed file {name}: {error}")),
        };
        harden_inspected_object(links, &file, false, &relative.join(name))?;
    }
    Ok(())
}

#[cfg(unix)]
fn preflight_host_trees(sandbox: &File, links: &mut RepairLinkInventory) -> Result<(), String> {
    const TREES: &[&str] = &[
        "owned-disks",
        "owned-volumes",
        "additional-disks",
        "checkpoints",
        "checkpoint-store",
        "jobs-v1",
        "logs",
    ];

    let mut budget = MAX_REPAIR_ENTRIES;
    for name in TREES {
        let directory = match open_managed_entry(sandbox, OsStr::new(name)) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("cannot inspect managed directory {name}: {error}")),
        };
        validate_managed_object(&directory, true, Path::new(name))?;
        record_managed_object(links, &directory, Path::new(name))?;
        inspect_managed_tree(&directory, Path::new(name), &mut budget, links)?;
    }
    Ok(())
}

#[cfg(unix)]
fn repair_host_trees(sandbox: &File, links: &RepairLinkInventory) -> Result<(), String> {
    const TREES: &[&str] = &[
        "owned-disks",
        "owned-volumes",
        "additional-disks",
        "checkpoints",
        "checkpoint-store",
        "jobs-v1",
        "logs",
    ];

    let mut budget = MAX_REPAIR_ENTRIES;
    for name in TREES {
        let directory = match open_managed_entry(sandbox, OsStr::new(name)) {
            Ok(directory) => directory,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(format!("cannot open managed directory {name}: {error}")),
        };
        harden_inspected_object(links, &directory, true, Path::new(name))?;
        secure_managed_tree(&directory, Path::new(name), &mut budget, links)?;
    }
    Ok(())
}

#[cfg(unix)]
fn preflight_heartbeat_directory(
    runtime: &File,
    links: &mut RepairLinkInventory,
) -> Result<(), String> {
    let heartbeat = open_managed_entry(runtime, OsStr::new("heartbeat.json"))
        .map_err(|error| format!("cannot inspect protected heartbeat guard: {error}"))?;
    validate_managed_object(&heartbeat, true, Path::new("runtime/heartbeat.json"))?;
    record_managed_object(links, &heartbeat, Path::new("runtime/heartbeat.json"))?;
    if cap_fs::read_base_dir(&heartbeat)
        .map_err(|error| error.to_string())?
        .next()
        .is_some()
    {
        return Err("protected heartbeat guard directory is not empty".into());
    }
    Ok(())
}

#[cfg(unix)]
fn repair_heartbeat_directory(runtime: &File, links: &RepairLinkInventory) -> Result<(), String> {
    let heartbeat = open_managed_entry(runtime, OsStr::new("heartbeat.json"))
        .map_err(|error| format!("cannot open protected heartbeat guard: {error}"))?;
    harden_inspected_object(links, &heartbeat, true, Path::new("runtime/heartbeat.json"))
}

#[cfg(unix)]
fn inspect_managed_tree(
    directory: &File,
    relative: &Path,
    budget: &mut usize,
    links: &mut RepairLinkInventory,
) -> Result<(), String> {
    let mut pending = vec![ManagedTreeFrame {
        directory: directory.try_clone().map_err(|error| error.to_string())?,
        relative: relative.to_path_buf(),
        entries: cap_fs::read_base_dir(directory).map_err(|error| error.to_string())?,
    }];
    while !pending.is_empty() {
        let entry = pending
            .last_mut()
            .ok_or_else(|| "managed sandbox repair lost its directory stack".to_owned())?
            .entries
            .next();
        let Some(entry) = entry else {
            pending.pop();
            continue;
        };
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        *budget = (*budget)
            .checked_sub(1)
            .ok_or_else(|| "managed sandbox storage exceeds the repair entry limit".to_owned())?;
        let (parent, parent_path) = {
            let frame = pending
                .last()
                .ok_or_else(|| "managed sandbox repair lost its directory stack".to_owned())?;
            (
                frame
                    .directory
                    .try_clone()
                    .map_err(|error| error.to_string())?,
                frame.relative.clone(),
            )
        };
        let path = parent_path.join(&name);
        if is_guest_volume_data(&path) {
            continue;
        }
        let child = open_managed_entry(&parent, &name).map_err(|error| {
            format!(
                "cannot inspect managed entry {}: {error}",
                parent_path.display()
            )
        })?;
        let metadata = child.metadata().map_err(|error| error.to_string())?;
        if metadata.is_dir() {
            validate_managed_object(&child, true, &path)?;
            record_managed_object(links, &child, &path)?;
            if pending.len() >= MAX_REPAIR_DEPTH {
                return Err("managed sandbox storage exceeds the repair depth limit".into());
            }
            let entries = cap_fs::read_base_dir(&child).map_err(|error| error.to_string())?;
            pending.push(ManagedTreeFrame {
                directory: child,
                relative: path,
                entries,
            });
        } else {
            validate_managed_object(&child, false, &path)?;
            record_managed_file(links, &child, &path)?;
        }
    }
    Ok(())
}

#[cfg(unix)]
fn secure_managed_tree(
    directory: &File,
    relative: &Path,
    budget: &mut usize,
    links: &RepairLinkInventory,
) -> Result<(), String> {
    let mut pending = vec![ManagedTreeFrame {
        directory: directory.try_clone().map_err(|error| error.to_string())?,
        relative: relative.to_path_buf(),
        entries: cap_fs::read_base_dir(directory).map_err(|error| error.to_string())?,
    }];
    while !pending.is_empty() {
        let entry = pending
            .last_mut()
            .ok_or_else(|| "managed sandbox repair lost its directory stack".to_owned())?
            .entries
            .next();
        let Some(entry) = entry else {
            pending.pop();
            continue;
        };
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry.file_name();
        *budget = (*budget)
            .checked_sub(1)
            .ok_or_else(|| "managed sandbox storage exceeds the repair entry limit".to_owned())?;
        let (parent, parent_path) = {
            let frame = pending
                .last()
                .ok_or_else(|| "managed sandbox repair lost its directory stack".to_owned())?;
            (
                frame
                    .directory
                    .try_clone()
                    .map_err(|error| error.to_string())?,
                frame.relative.clone(),
            )
        };
        let path = parent_path.join(&name);
        if is_guest_volume_data(&path) {
            continue;
        }
        let child = open_managed_entry(&parent, &name).map_err(|error| {
            format!(
                "cannot open managed entry {}: {error}",
                parent_path.display()
            )
        })?;
        let metadata = child.metadata().map_err(|error| error.to_string())?;
        if metadata.is_dir() {
            harden_inspected_object(links, &child, true, &path)?;
            if pending.len() >= MAX_REPAIR_DEPTH {
                return Err("managed sandbox storage exceeds the repair depth limit".into());
            }
            let entries = cap_fs::read_base_dir(&child).map_err(|error| error.to_string())?;
            pending.push(ManagedTreeFrame {
                directory: child,
                relative: path,
                entries,
            });
        } else {
            harden_inspected_object(links, &child, false, &path)?;
        }
    }
    Ok(())
}

/// Directory-backed owned volumes contain guest files, unlike their sibling disk images.
/// Skip the exported root itself as well as its contents: chmod or ACL removal would change
/// guest-visible permissions when stat virtualization is disabled.
#[cfg(unix)]
fn is_guest_volume_data(relative: &Path) -> bool {
    let mut components = relative.iter();
    components.next() == Some(OsStr::new("owned-volumes"))
        && components.next().is_some()
        && components.next() == Some(OsStr::new("data"))
}

#[cfg(unix)]
fn validate_managed_object(file: &File, directory: bool, path: &Path) -> Result<(), String> {
    use std::os::unix::fs::MetadataExt;

    let metadata = file.metadata().map_err(|error| error.to_string())?;
    if metadata.uid() != unsafe { libc::geteuid() } {
        return Err(format!(
            "managed entry {} is owned by another account",
            path.display()
        ));
    }
    if directory {
        if !metadata.is_dir() {
            return Err(format!(
                "managed entry {} is not a real directory",
                path.display()
            ));
        }
    } else if !metadata.is_file() {
        return Err(format!(
            "managed entry {} is not a regular file",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn record_managed_file(
    inventory: &mut RepairLinkInventory,
    file: &File,
    path: &Path,
) -> Result<(), String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    record_managed_object(inventory, file, path)?;
    let identity = (metadata.dev(), metadata.ino());
    let record = inventory
        .links
        .entry(identity)
        .or_insert_with(|| RepairLinkRecord {
            link_count: metadata.nlink(),
            observed_names: 0,
            already_private: true,
            first_path: path.to_path_buf(),
        });
    if record.link_count != metadata.nlink() {
        return Err(format!(
            "managed file {} changed while its hardlinks were inspected",
            path.display()
        ));
    }
    record.already_private &= microsandbox_utils::private_file::verify(file).is_ok();
    record.observed_names = record
        .observed_names
        .checked_add(1)
        .ok_or_else(|| "managed hardlink count overflow".to_owned())?;
    Ok(())
}

#[cfg(unix)]
fn record_managed_object(
    inventory: &mut RepairLinkInventory,
    file: &File,
    path: &Path,
) -> Result<(), String> {
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    let object = RepairObject {
        device: metadata.dev(),
        inode: metadata.ino(),
        directory: metadata.is_dir(),
    };
    if inventory
        .objects
        .insert(path.to_path_buf(), object)
        .is_some()
    {
        return Err(format!(
            "managed entry {} appeared twice during inspection",
            path.display()
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn harden_inspected_object(
    inventory: &RepairLinkInventory,
    file: &File,
    directory: bool,
    path: &Path,
) -> Result<(), String> {
    validate_managed_object(file, directory, path)?;
    let metadata = file.metadata().map_err(|error| error.to_string())?;
    let object = RepairObject {
        device: metadata.dev(),
        inode: metadata.ino(),
        directory,
    };
    if inventory.objects.get(path) != Some(&object) {
        return Err(format!(
            "managed entry {} changed after inspection; retry repair",
            path.display()
        ));
    }
    if !directory {
        let record = inventory
            .links
            .get(&(object.device, object.inode))
            .ok_or_else(|| "managed file was not inspected".to_owned())?;
        if record.link_count != metadata.nlink() {
            return Err(format!(
                "managed file {} changed hardlinks after inspection; retry repair",
                path.display()
            ));
        }
        if record.link_count > record.observed_names {
            // Published snapshots can share already-private objects with this sandbox.
            // Recheck their effective access, but never chmod or clear ACLs through a link
            // whose other names are outside this repair's authority.
            return microsandbox_utils::private_file::verify(file).map_err(|error| {
                format!(
                    "shared managed file {} is no longer private: {error}",
                    path.display()
                )
            });
        }
    }
    microsandbox_utils::private_file::harden(file, directory)
        .map_err(|error| format!("cannot secure managed entry {}: {error}", path.display()))
}

#[cfg(unix)]
fn validate_repair_link_inventory(inventory: &RepairLinkInventory) -> Result<(), String> {
    for record in inventory.links.values() {
        if record.link_count < record.observed_names
            || (record.link_count > record.observed_names && !record.already_private)
        {
            return Err(format!(
                "managed file {} has hardlinks outside recognized sandbox state",
                record.first_path.display()
            ));
        }
    }
    Ok(())
}

pub(crate) fn private_directory(path: &Path, create: bool) -> Result<(), String> {
    if create {
        match fs::symlink_metadata(path) {
            Ok(_) => return real_directory(path, false),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                microsandbox_utils::private_file::create_private_directory(path)
                    .map_err(|error| error.to_string())?;
                return real_directory(path, false);
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    real_directory(path, false)
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
    #[cfg(windows)]
    {
        // Every caller publishes through atomic_write/real_directory, whose Windows moves
        // request MOVEFILE_WRITE_THROUGH. Do not call FlushFileBuffers on read-only directory
        // handles or ignore its unsupported-handle errors as if they proved durability.
        let _ = path;
    }
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

    #[cfg(windows)]
    #[test]
    fn metadata_publication_keeps_windows_tempfile_access_contract() {
        let temporary = tempfile::tempdir().unwrap();
        let runtime = temporary.path().join("sandbox/runtime");
        initialize_new(&runtime).unwrap();
        let path = host_root(&runtime).unwrap().join("external-mounts.json");

        // NamedTempFile's ordinary Windows handle does not request WRITE_DAC. Unix ACL
        // cleanup must not turn metadata publication into an ACL-write operation on Windows.
        atomic_write(&path, b"first").unwrap();
        atomic_write(&path, b"replacement").unwrap();

        assert_eq!(fs::read(&path).unwrap(), b"replacement");
        require_ready(&runtime).unwrap();
        repair_managed_permissions(&runtime).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn permission_repair_is_limited_to_recognized_host_state() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let sandbox = temporary.path().join("sandbox");
        let runtime = sandbox.join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        initialize_new(&runtime).unwrap();

        let log_directory = sandbox.join("logs");
        fs::create_dir_all(log_directory.join("nested")).unwrap();
        let log = log_directory.join("runtime.log");
        fs::write(&log, b"runtime output").unwrap();
        let object_directory = sandbox.join("checkpoint-store/objects/sha256");
        fs::create_dir_all(&object_directory).unwrap();
        let object = object_directory.join("object");
        fs::write(&object, b"checkpoint data").unwrap();
        let boot_id = runtime.join("runtime-boot-id");
        fs::write(&boot_id, b"boot-id").unwrap();
        let restore_warnings = sandbox.join("restore-mount-warnings.json");
        fs::write(&restore_warnings, b"[]").unwrap();

        let guest = guest_root(&runtime).unwrap();
        let guest_file = guest.join("guest-note");
        fs::write(&guest_file, b"guest data").unwrap();
        let unknown = sandbox.join("unrecognized-state");
        fs::write(&unknown, b"leave alone").unwrap();
        let unknown_directory = sandbox.join("other");
        fs::create_dir(&unknown_directory).unwrap();

        for (path, mode) in [
            (&sandbox, 0o777),
            (&runtime, 0o777),
            (&sandbox.join(MARKER), 0o666),
            (&log_directory, 0o777),
            (&log_directory.join("nested"), 0o777),
            (&log, 0o666),
            (&sandbox.join("checkpoint-store"), 0o777),
            (&object_directory, 0o777),
            (&object, 0o666),
            (&boot_id, 0o666),
            (&restore_warnings, 0o666),
            (&guest_file, 0o666),
            (&unknown, 0o666),
            (&unknown_directory, 0o777),
        ] {
            fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
        }

        repair_managed_permissions(&runtime).unwrap();

        for (path, mode) in [
            (&sandbox, 0o700),
            (&runtime, 0o700),
            (&sandbox.join(MARKER), 0o600),
            (&log_directory, 0o700),
            (&log_directory.join("nested"), 0o700),
            (&log, 0o600),
            (&sandbox.join("checkpoint-store"), 0o700),
            (&object_directory, 0o700),
            (&object, 0o600),
            (&boot_id, 0o600),
            (&restore_warnings, 0o600),
        ] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                mode,
                "unexpected permissions on {}",
                path.display()
            );
        }
        for (path, mode) in [(&guest_file, 0o666), (&unknown, 0o666)] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                mode
            );
        }
        assert_eq!(
            fs::metadata(&unknown_directory)
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o777
        );
        assert_eq!(fs::read(&guest_file).unwrap(), b"guest data");
        assert_eq!(fs::read(&unknown).unwrap(), b"leave alone");
    }

    #[cfg(unix)]
    #[test]
    fn permission_repair_preserves_directory_volume_guest_data() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let temporary = tempfile::tempdir().unwrap();
        let sandbox = temporary.path().join("sandbox");
        let runtime = sandbox.join("runtime");
        initialize_new(&runtime).unwrap();
        let data = sandbox.join("owned-volumes/owned_directory/data");
        fs::create_dir_all(&data).unwrap();
        let script = data.join("run.sh");
        fs::write(&script, b"#!/bin/sh\necho guest\n").unwrap();
        fs::set_permissions(&data, fs::Permissions::from_mode(0o775)).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o751)).unwrap();
        // Guest directory contents can include links and must not even be inventoried as
        // host state. A sibling disk image still needs normal host permission repair.
        symlink(temporary.path().join("missing"), data.join("guest-link")).unwrap();
        let disk = sandbox.join("owned-volumes/owned_disk/disk.raw");
        fs::create_dir_all(disk.parent().unwrap()).unwrap();
        fs::write(&disk, b"disk bytes").unwrap();
        fs::set_permissions(&disk, fs::Permissions::from_mode(0o666)).unwrap();

        #[cfg(target_os = "macos")]
        let acl_before = {
            for path in [&data, &script] {
                let status = std::process::Command::new("/bin/chmod")
                    .args(["+a", "everyone allow read"])
                    .arg(path)
                    .status()
                    .unwrap();
                assert!(status.success());
            }
            std::process::Command::new("/bin/ls")
                .arg("-lde")
                .args([&data, &script])
                .output()
                .unwrap()
                .stdout
        };

        repair_managed_permissions(&runtime).unwrap();

        assert_eq!(
            fs::metadata(&data).unwrap().permissions().mode() & 0o777,
            0o775
        );
        assert_eq!(
            fs::metadata(&script).unwrap().permissions().mode() & 0o777,
            0o751
        );
        assert_eq!(fs::read(&script).unwrap(), b"#!/bin/sh\necho guest\n");
        assert!(
            fs::symlink_metadata(data.join("guest-link"))
                .unwrap()
                .is_symlink()
        );
        assert_eq!(
            fs::metadata(&disk).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&disk).unwrap(), b"disk bytes");
        #[cfg(target_os = "macos")]
        assert_eq!(
            std::process::Command::new("/bin/ls")
                .arg("-lde")
                .args([&data, &script])
                .output()
                .unwrap()
                .stdout,
            acl_before
        );
    }

    #[cfg(unix)]
    #[test]
    fn permission_repair_rejects_replaced_file_after_inspection() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let sandbox = temporary.path().join("sandbox");
        fs::create_dir(&sandbox).unwrap();
        let journal = sandbox.join("root-disk.json");
        fs::write(&journal, b"managed journal").unwrap();
        let parent = File::open(&sandbox).unwrap();
        let mut inventory = RepairLinkInventory::default();
        preflight_direct_files(
            &parent,
            &["root-disk.json"],
            None,
            Path::new(""),
            &mut inventory,
        )
        .unwrap();
        validate_repair_link_inventory(&inventory).unwrap();

        let unrelated = temporary.path().join("unrelated");
        fs::write(&unrelated, b"unrelated data").unwrap();
        fs::set_permissions(&unrelated, fs::Permissions::from_mode(0o644)).unwrap();
        fs::rename(&journal, sandbox.join("original-journal")).unwrap();
        fs::hard_link(&unrelated, &journal).unwrap();

        let error = repair_direct_files(
            &parent,
            &["root-disk.json"],
            None,
            Path::new(""),
            &inventory,
        )
        .unwrap_err();
        assert!(error.contains("changed after inspection"), "{error}");
        assert_eq!(
            fs::metadata(&unrelated).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(fs::read(&unrelated).unwrap(), b"unrelated data");
    }

    #[cfg(unix)]
    #[test]
    fn permission_repair_rejects_new_hardlink_after_inspection() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let journal = temporary.path().join("root-disk.json");
        fs::write(&journal, b"journal").unwrap();
        fs::set_permissions(&journal, fs::Permissions::from_mode(0o644)).unwrap();
        let parent = File::open(temporary.path()).unwrap();
        let mut inventory = RepairLinkInventory::default();
        preflight_direct_files(
            &parent,
            &["root-disk.json"],
            None,
            Path::new(""),
            &mut inventory,
        )
        .unwrap();
        validate_repair_link_inventory(&inventory).unwrap();
        fs::hard_link(&journal, temporary.path().join("outside-selection")).unwrap();

        let error = repair_direct_files(
            &parent,
            &["root-disk.json"],
            None,
            Path::new(""),
            &inventory,
        )
        .unwrap_err();
        assert!(error.contains("changed hardlinks"), "{error}");
        assert_eq!(
            fs::metadata(&journal).unwrap().permissions().mode() & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn permission_repair_rejects_replaced_directory_after_inspection() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let logs = temporary.path().join("logs");
        fs::create_dir(&logs).unwrap();
        let parent = File::open(temporary.path()).unwrap();
        let mut inventory = RepairLinkInventory::default();
        preflight_host_trees(&parent, &mut inventory).unwrap();
        fs::rename(&logs, temporary.path().join("original-logs")).unwrap();
        fs::create_dir(&logs).unwrap();
        fs::set_permissions(&logs, fs::Permissions::from_mode(0o755)).unwrap();

        let error = repair_host_trees(&parent, &inventory).unwrap_err();
        assert!(error.contains("changed after inspection"), "{error}");
        assert_eq!(
            fs::metadata(&logs).unwrap().permissions().mode() & 0o777,
            0o755
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn permission_repair_preserves_guest_volume_posix_acls() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let temporary = tempfile::tempdir().unwrap();
        let runtime = temporary.path().join("sandbox/runtime");
        initialize_new(&runtime).unwrap();
        let data = temporary
            .path()
            .join("sandbox/owned-volumes/directory/data");
        fs::create_dir_all(&data).unwrap();
        let file = data.join("file");
        fs::write(&file, b"guest data").unwrap();
        let mut acl = 2u32.to_le_bytes().to_vec();
        for (tag, permission, id) in [
            (0x01u16, 0x07u16, u32::MAX),
            (0x02, 0x04, 1001),
            (0x04, 0x00, u32::MAX),
            (0x10, 0x04, u32::MAX),
            (0x20, 0x00, u32::MAX),
        ] {
            acl.extend_from_slice(&tag.to_le_bytes());
            acl.extend_from_slice(&permission.to_le_bytes());
            acl.extend_from_slice(&id.to_le_bytes());
        }
        let entries = [
            (&data, c"system.posix_acl_access"),
            (&data, c"system.posix_acl_default"),
            (&file, c"system.posix_acl_access"),
        ];
        for (path, name) in entries {
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            let result = unsafe {
                libc::setxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    acl.as_ptr().cast(),
                    acl.len(),
                    0,
                )
            };
            if result != 0 {
                let error = std::io::Error::last_os_error();
                if error.raw_os_error() == Some(libc::ENOTSUP) {
                    eprintln!("POSIX ACLs unavailable on test filesystem: {error}");
                    return;
                }
                panic!("cannot set guest ACL: {error}");
            }
        }

        repair_managed_permissions(&runtime).unwrap();

        for (path, name) in entries {
            let path = CString::new(path.as_os_str().as_bytes()).unwrap();
            let mut actual = vec![0u8; acl.len()];
            let size = unsafe {
                libc::getxattr(
                    path.as_ptr(),
                    name.as_ptr(),
                    actual.as_mut_ptr().cast(),
                    actual.len(),
                )
            };
            assert_eq!(size, acl.len() as isize);
            assert_eq!(actual, acl);
        }
    }

    #[cfg(unix)]
    #[test]
    fn new_sandbox_host_root_starts_owner_private() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let sandbox = temporary.path().join("sandbox");
        let runtime = sandbox.join("runtime");

        initialize_new(&runtime).unwrap();

        assert_eq!(
            fs::metadata(&sandbox).unwrap().permissions().mode() & 0o777,
            0o700
        );
        assert_eq!(
            fs::metadata(&runtime).unwrap().permissions().mode() & 0o777,
            0o700
        );
    }

    #[cfg(unix)]
    #[test]
    fn permission_repair_rejects_hardlinks_before_changing_anything() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let sandbox = temporary.path().join("sandbox");
        let runtime = sandbox.join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        initialize_new(&runtime).unwrap();
        let logs = sandbox.join("logs");
        fs::create_dir(&logs).unwrap();
        let log = logs.join("runtime.log");
        fs::write(&log, b"runtime output").unwrap();
        fs::hard_link(&log, temporary.path().join("outside-link")).unwrap();
        fs::set_permissions(&sandbox, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(sandbox.join(MARKER), fs::Permissions::from_mode(0o644)).unwrap();

        let error = repair_managed_permissions(&runtime).unwrap_err();

        assert!(
            error.contains("hardlinks outside recognized sandbox state"),
            "{error}"
        );
        assert_eq!(
            fs::metadata(&sandbox).unwrap().permissions().mode() & 0o777,
            0o777
        );
        assert_eq!(
            fs::metadata(sandbox.join(MARKER))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o644
        );
    }

    #[cfg(unix)]
    #[test]
    fn permission_repair_leaves_private_snapshot_links_unchanged() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let runtime = temporary.path().join("sandbox/runtime");
        initialize_new(&runtime).unwrap();
        let objects = temporary.path().join("sandbox/checkpoint-store/objects");
        fs::create_dir_all(&objects).unwrap();
        let object = objects.join("object");
        fs::write(&object, b"captured state").unwrap();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o400)).unwrap();
        let published = temporary.path().join("published-snapshot-object");
        fs::hard_link(&object, &published).unwrap();
        let marker = host_root(&runtime).unwrap().join(MARKER);
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o644)).unwrap();

        repair_managed_permissions(&runtime).unwrap();

        assert_eq!(
            fs::metadata(&marker).unwrap().permissions().mode() & 0o777,
            0o600
        );
        for path in [&object, &published] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o400
            );
            assert_eq!(fs::read(path).unwrap(), b"captured state");
        }
    }

    #[cfg(unix)]
    #[test]
    fn permission_repair_refuses_excessive_depth_before_changing_modes() {
        use std::os::unix::fs::PermissionsExt;

        let temporary = tempfile::tempdir().unwrap();
        let sandbox = temporary.path().join("sandbox");
        let runtime = sandbox.join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        initialize_new(&runtime).unwrap();

        let checkpoints = sandbox.join("checkpoints");
        fs::create_dir(&checkpoints).unwrap();
        let mut nested = checkpoints.clone();
        for _ in 1..=MAX_REPAIR_DEPTH {
            nested.push("d");
            fs::create_dir(&nested).unwrap();
        }
        fs::set_permissions(&sandbox, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(&checkpoints, fs::Permissions::from_mode(0o777)).unwrap();

        let error = repair_managed_permissions(&runtime).unwrap_err();

        assert!(error.contains("repair depth limit"), "{error}");
        for path in [&sandbox, &checkpoints] {
            assert_eq!(
                fs::metadata(path).unwrap().permissions().mode() & 0o777,
                0o777,
                "preflight changed {}",
                path.display()
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn permission_repair_accepts_hardlinks_within_recognized_state() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};

        let temporary = tempfile::tempdir().unwrap();
        let sandbox = temporary.path().join("sandbox");
        let runtime = sandbox.join("runtime");
        fs::create_dir_all(&runtime).unwrap();
        initialize_new(&runtime).unwrap();

        let objects = sandbox.join("checkpoint-store/objects/sha256");
        let checkpoints = sandbox.join("checkpoints");
        fs::create_dir_all(&objects).unwrap();
        fs::create_dir_all(&checkpoints).unwrap();
        let object = objects.join("object");
        let snapshot = checkpoints.join("object");
        fs::write(&object, b"shared checkpoint object").unwrap();
        fs::hard_link(&object, &snapshot).unwrap();
        fs::set_permissions(&sandbox, fs::Permissions::from_mode(0o777)).unwrap();
        fs::set_permissions(&object, fs::Permissions::from_mode(0o666)).unwrap();

        repair_managed_permissions(&runtime).unwrap();

        for path in [&object, &snapshot] {
            let metadata = fs::metadata(path).unwrap();
            assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
            assert_eq!(metadata.nlink(), 2);
            assert_eq!(fs::read(path).unwrap(), b"shared checkpoint object");
        }
        assert_eq!(
            fs::metadata(&object).unwrap().ino(),
            fs::metadata(&snapshot).unwrap().ino()
        );
    }
}
