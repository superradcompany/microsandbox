//! Producer-specific source roles, complete selection, and alias accounting.

use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use cap_primitives::fs as cap_fs;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::super::compat::v0_7_0::{Layer, OwnedJournal, RootJournal};
use super::super::layout;
use super::budget::ParserBudget;
use super::io::{self, Identity};
use super::types::{AliasSource, CandidateSummary, MigrationBindings};
use super::writer::WriterGuard;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    pub path: PathBuf,
    pub format: String,
    pub identity: Identity,
    pub capacity: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Disk {
    pub id: String,
    pub launch_base: PathBuf,
    pub flat: bool,
    pub readonly: bool,
    pub external: bool,
    pub sources: Vec<Source>,
    pub journal: Option<Vec<u8>>,
}

pub(super) struct Acquired {
    pub disks: Vec<Disk>,
    pub files: Vec<Vec<File>>,
    pub _aliases: Vec<File>,
    pub writers: Option<WriterGuard>,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl Disk {
    pub fn candidate_id(&self, identity: &str) -> Result<String, String> {
        let bytes = serde_json::to_vec(&(identity, &self.id, &self.launch_base, &self.sources))
            .map_err(|_| "cannot bind recovery candidate")?;
        Ok(format!("view-{}", hex::encode(Sha256::digest(bytes))))
    }

    pub fn summary(&self, identity: &str) -> Result<CandidateSummary, String> {
        let bytes = if self.external && self.sources.iter().all(|source| source.format == "raw") {
            0
        } else {
            self.sources.iter().try_fold(0u64, |sum, source| {
                sum.checked_add(source.identity.length)
                    .ok_or("capture size overflow")
            })?
        };
        Ok(CandidateSummary {
            id: self.candidate_id(identity)?,
            disk_id: self.id.clone(),
            layers: self.sources.len(),
            virtual_size: self.sources.last().map_or(0, |s| s.capacity),
            estimated_bytes: bytes,
        })
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn select(runtime: &Path, bindings: &MigrationBindings) -> Result<Acquired, String> {
    if bindings.identity.is_empty()
        || bindings.identity.len() > 4096
        || bindings.config_revision.is_empty()
        || bindings.config_revision.len() > 4096
        || bindings.owned_disks.len() > 64
        || bindings.aliases.len() > 4096
    {
        return Err("host migration bindings exceed their bounds".into());
    }
    let sandbox = layout::host_root(runtime)?;
    let anchor = io::directory(sandbox)?;
    let runtime_name = runtime.file_name().ok_or("runtime locator has no name")?;
    if runtime_name != "runtime" {
        return Err("unsupported legacy runtime locator".into());
    }
    io::directory(runtime)?;
    let mut disks = Vec::new();
    let mut files = Vec::new();
    let mut ids = BTreeSet::new();
    let mut source_count = 0usize;
    if let Some(binding) = &bindings.root {
        let ordinary = sandbox.join(if binding.flat {
            "rootfs.raw"
        } else {
            "upper.ext4"
        });
        let external = binding.path != ordinary;
        if !matches!(binding.format.as_str(), "raw" | "qcow2") {
            return Err("unsupported configured root format".into());
        }
        if external && binding.path.starts_with(runtime) {
            return Err("external root binding overlaps guest-exported legacy storage".into());
        }
        let journal_bytes = io::bytes(&anchor, Path::new("runtime/root-disk.json"))?;
        let bytes = if let Some(retained) =
            layout::retained_legacy_root(runtime, bindings.root.as_ref())?
        {
            retained
        } else {
            journal_bytes.clone()
        };
        let layers = if let Some(bytes) = &bytes {
            let journal = RootJournal::decode(bytes)?;
            if journal.growth_target.is_some() {
                return Err("pending root growth needs operation-aware recovery".into());
            }
            let base = journal
                .launch_base
                .as_ref()
                .unwrap_or(&journal.layers[0].path);
            if base != &binding.path || (journal.layout == "flat-root") != binding.flat {
                return Err("legacy root journal disagrees with the configured disk role".into());
            }
            journal.layers
        } else {
            reject_missing_selection(sandbox, runtime, "root", binding.flat)?;
            vec![Layer {
                layer_id: String::new(),
                path: binding.path.clone(),
                format: binding.format.clone(),
                integrity_root: None,
            }]
        };
        if external
            && (layers.len() != 1
                || layers[0].path != binding.path
                || layers[0].format != binding.format)
        {
            return Err("external disk chain needs separately authorized dependencies and write-through recovery".into());
        }
        source_count += layers.len();
        let (sources, pins) = acquire_layers(
            &anchor,
            sandbox,
            &layers,
            "root",
            binding.flat,
            external,
            None,
        )?;
        disks.push(Disk {
            id: "root".into(),
            launch_base: binding.path.clone(),
            flat: binding.flat,
            readonly: false,
            external,
            sources,
            journal: journal_bytes,
        });
        files.push(pins);
        ids.insert("root".to_string());
    } else if layout::retained_legacy_root(runtime, None)?.is_none()
        && io::bytes(&anchor, Path::new("runtime/root-disk.json"))?.is_some()
    {
        return Err("legacy root journal has no configured writable disk role".into());
    }
    for binding in &bindings.owned_disks {
        if !valid_owned_id(&binding.id)
            || !ids.insert(binding.id.clone())
            || binding.capacity == 0
            || !binding.capacity.is_multiple_of(512)
        {
            return Err("invalid or duplicate configured owned disk role".into());
        }
        let nominal = Path::new("owned-volumes")
            .join(&binding.id)
            .join("disk.raw");
        if binding.path != sandbox.join(&nominal) {
            return Err("owned disk binding differs from its host-managed role".into());
        }
        let journal_path = Path::new("runtime/owned-disks")
            .join(&binding.id)
            .join("disk.json");
        let bytes = io::bytes(&anchor, &journal_path)?;
        let layers = if let Some(bytes) = &bytes {
            let journal = OwnedJournal::decode(bytes)?;
            if journal.device_id != binding.id
                || journal.launch_base != nominal
                || journal.read_only != binding.readonly
            {
                return Err("legacy owned journal disagrees with its configured mount".into());
            }
            journal
                .layers
                .into_iter()
                .map(|mut layer| {
                    layer.path = sandbox.join(layer.path);
                    layer
                })
                .collect()
        } else {
            reject_missing_selection(sandbox, runtime, &binding.id, false)?;
            vec![Layer {
                layer_id: String::new(),
                path: binding.path.clone(),
                format: "raw".into(),
                integrity_root: None,
            }]
        };
        source_count += layers.len();
        if source_count > 1024 {
            return Err("migration exceeds its source handle bound".into());
        }
        let (sources, pins) = acquire_layers(
            &anchor,
            sandbox,
            &layers,
            &binding.id,
            false,
            false,
            Some(binding.capacity),
        )?;
        disks.push(Disk {
            id: binding.id.clone(),
            launch_base: binding.path.clone(),
            flat: false,
            readonly: binding.readonly,
            external: false,
            sources,
            journal: bytes,
        });
        files.push(pins);
    }
    group_bounds(&disks)?;
    Ok(Acquired {
        disks,
        files,
        _aliases: Vec::new(),
        writers: None,
    })
}

pub(super) fn acquire_metadata(
    runtime: &Path,
    bindings: &MigrationBindings,
) -> Result<Acquired, String> {
    let mut acquired = select(runtime, bindings)?;
    acquired._aliases = account_aliases(layout::host_root(runtime)?, bindings, &acquired.disks)?;
    validate_headers(&mut acquired.disks, &acquired.files, bindings)?;
    Ok(acquired)
}

pub(super) fn acquire(runtime: &Path, bindings: &MigrationBindings) -> Result<Acquired, String> {
    let mut acquired = select(runtime, bindings)?;
    acquired._aliases = account_aliases(layout::host_root(runtime)?, bindings, &acquired.disks)?;
    acquired.writers = Some(WriterGuard::acquire(&acquired.files)?);
    validate_headers(&mut acquired.disks, &acquired.files, bindings)?;
    acquired.writers.as_ref().unwrap().audit()?;
    Ok(acquired)
}

/// Report metadata-only alias requirements before related-writer discovery. The result is
/// provisional and cannot authorize capture; `plan` reacquires and validates everything.
pub fn alias_sources(
    runtime: &Path,
    bindings: &MigrationBindings,
) -> Result<Vec<AliasSource>, String> {
    let acquired = if let Some(disks) = super::engine::frozen_disks(runtime, bindings)? {
        // The original ordered view lives in the private operation after the old guard replaces
        // its guest-controlled journal. Never use the guard as a new selection source.
        let sandbox = layout::host_root(runtime)?;
        let anchor = io::directory(sandbox)?;
        let mut files = Vec::new();
        for disk in &disks {
            let mut pins = Vec::new();
            for source in &disk.sources {
                let file = if disk.external {
                    io::exact(&source.path)?
                } else {
                    io::open(&anchor, &io::relative(&source.path, sandbox)?)?
                };
                if io::identity(&file)? != source.identity {
                    return Err("recorded migration source changed".into());
                }
                pins.push(file);
            }
            files.push(pins);
        }
        Acquired {
            disks,
            files,
            _aliases: Vec::new(),
            writers: None,
        }
    } else {
        // An unusable selection must still permit metadata-only alias/writer discovery before
        // explicit recovery. This inventories candidates; it does not silently select a base.
        match select(runtime, bindings) {
            Ok(acquired) => acquired,
            Err(_) => metadata_candidates(runtime, bindings)?,
        }
    };
    Ok(acquired
        .disks
        .iter()
        .flat_map(|disk| {
            disk.sources
                .iter()
                .enumerate()
                .map(|(index, source)| AliasSource {
                    disk_id: disk.id.clone(),
                    path: source.path.clone(),
                    identity_object: source.identity.object.clone(),
                    links: source.identity.links,
                    readonly: disk.readonly
                        || (disk.journal.is_some() && index + 1 < disk.sources.len()),
                })
        })
        .collect())
}

/// Metadata-only selected source identities for either a legacy or ready protected peer.
/// Used to find shared writable heads before related-writer exclusion; it grants no new source
/// authority and reads no disk header or content.
pub fn selected_sources(
    runtime: &Path,
    bindings: &MigrationBindings,
) -> Result<Vec<AliasSource>, String> {
    if layout::require_ready(runtime).is_err() {
        return alias_sources(runtime, bindings);
    }
    let sandbox = layout::host_root(runtime)?;
    let anchor = io::directory(sandbox)?;
    let mut result = Vec::new();
    let mut add = |id: &str, layers: Vec<Layer>, readonly: bool| -> Result<(), String> {
        let count = layers.len();
        for (index, layer) in layers.into_iter().enumerate() {
            let path = if id == "root" {
                layer.path
            } else {
                sandbox.join(layer.path)
            };
            let file = if path.starts_with(sandbox) {
                io::open(&anchor, &io::relative(&path, sandbox)?)?
            } else {
                if id != "root" || bindings.root.as_ref().is_none_or(|root| root.path != path) {
                    return Err("protected peer has an unbound external source".into());
                }
                io::exact(&path)?
            };
            let identity = io::identity(&file)?;
            result.push(AliasSource {
                disk_id: id.into(),
                path,
                identity_object: identity.object,
                links: identity.links,
                readonly: readonly || index + 1 < count,
            });
        }
        Ok(())
    };
    if let Some(bytes) = io::bytes(&anchor, Path::new("root-disk.json"))? {
        let journal = RootJournal::decode(&bytes)?;
        add("root", journal.layers, false)?;
    } else if let Some(root) = &bindings.root {
        add(
            "root",
            vec![Layer {
                layer_id: String::new(),
                path: root.path.clone(),
                format: root.format.clone(),
                integrity_root: None,
            }],
            false,
        )?;
    }
    for disk in &bindings.owned_disks {
        let path = Path::new("owned-disks").join(&disk.id).join("disk.json");
        if let Some(bytes) = io::bytes(&anchor, &path)? {
            let journal = OwnedJournal::decode(&bytes)?;
            add(&disk.id, journal.layers, disk.readonly)?;
        } else {
            add(
                &disk.id,
                vec![Layer {
                    layer_id: String::new(),
                    path: io::relative(&disk.path, sandbox)?,
                    format: "raw".into(),
                    integrity_root: None,
                }],
                disk.readonly,
            )?;
        }
    }
    for retained in super::engine::retained_sources(runtime, bindings)? {
        // Current writable attachments take precedence. A historical record must never label
        // an inode read-only while the protected runtime still selects it as a writable head.
        if !result
            .iter()
            .any(|current| current.identity_object == retained.identity_object)
        {
            result.push(retained);
        }
    }
    Ok(result)
}

/// Classify an exact path by a separately supplied sandbox's configured producer roles.
/// This classifies metadata only; the caller must still pin the object and exclude writers.
pub fn producer_role(runtime: &Path, bindings: &MigrationBindings, path: &Path) -> Option<String> {
    let sandbox = layout::host_root(runtime).ok()?;
    if let Some(root) = &bindings.root {
        if path == root.path {
            return Some("root".into());
        }
        let ordinary = sandbox.join(if root.flat {
            "rootfs.raw"
        } else {
            "upper.ext4"
        });
        if root.path == ordinary
            && io::relative(path, sandbox).ok().is_some_and(|relative| {
                source_role(&relative, "root", root.flat, "raw")
                    || source_role(&relative, "root", root.flat, "qcow2")
            })
        {
            return Some("root".into());
        }
    }
    for disk in &bindings.owned_disks {
        if io::relative(path, sandbox).ok().is_some_and(|relative| {
            source_role(&relative, &disk.id, false, "raw")
                || source_role(&relative, &disk.id, false, "qcow2")
        }) {
            return Some(disk.id.clone());
        }
    }
    None
}

/// The same whole-group limits apply to automatic admission, explicit selection and resume.
fn group_bounds(disks: &[Disk]) -> Result<(), String> {
    let handles = disks
        .iter()
        .try_fold(0usize, |sum, disk| sum.checked_add(disk.sources.len()))
        .ok_or("migration source count overflow")?;
    if handles > 1024 {
        return Err("migration exceeds its source handle bound".into());
    }
    let bytes = disks
        .iter()
        .flat_map(|disk| &disk.sources)
        .try_fold(0u64, |sum, source| sum.checked_add(source.identity.length))
        .ok_or("migration capture size overflow")?;
    if bytes > io::MAX_TOTAL_BYTES {
        return Err("migration exceeds its aggregate capture bound".into());
    }
    Ok(())
}

pub(super) fn reacquire(
    runtime: &Path,
    bindings: &MigrationBindings,
    disks: &[Disk],
) -> Result<Acquired, String> {
    group_bounds(disks)?;
    // The retained journal is never reparsed to choose a new head after admission. Revalidate
    // each frozen resource against the current bindings and the complete current alias set.
    let sandbox = layout::host_root(runtime)?;
    let anchor = io::directory(sandbox)?;
    let mut files = Vec::new();
    for disk in disks {
        let mut pins = Vec::new();
        for source in &disk.sources {
            if !disk.external
                && !source_role(
                    &io::relative(&source.path, sandbox)?,
                    &disk.id,
                    disk.flat,
                    &source.format,
                )
            {
                return Err("recorded source no longer has an authorized producer role".into());
            }
            let file = if disk.external {
                io::exact(&source.path)?
            } else {
                io::open(&anchor, &io::relative(&source.path, sandbox)?)?
            };
            if io::identity(&file)? != source.identity {
                return Err(
                    "migration source changed; preserve staging and inspect recovery".into(),
                );
            }
            if pins.len() >= 2048 {
                return Err("migration alias handles exceed their bound".into());
            }
            pins.push(file);
        }
        files.push(pins);
    }
    validate_parser_budget(disks, &files)?;
    Ok(Acquired {
        disks: disks.to_vec(),
        files,
        _aliases: account_aliases(sandbox, bindings, disks)?,
        writers: None,
    })
}

fn acquire_layers(
    anchor: &File,
    sandbox: &Path,
    layers: &[Layer],
    id: &str,
    flat: bool,
    external: bool,
    _expected: Option<u64>,
) -> Result<(Vec<Source>, Vec<File>), String> {
    let mut sources = Vec::new();
    let mut files = Vec::new();
    let mut objects = BTreeSet::new();

    for layer in layers {
        let file = if external {
            io::exact(&layer.path)?
        } else {
            let relative = io::relative(&layer.path, sandbox)?;
            if !source_role(&relative, id, flat, &layer.format) {
                return Err("legacy selection names a file outside its disk producer roles".into());
            }
            io::open(anchor, &relative)?
        };
        let identity = io::identity(&file)?;
        if identity.length == 0
            || identity.length > io::MAX_TOTAL_BYTES
            || !objects.insert(identity.object.clone())
        {
            return Err("disk chain is empty, excessive, or repeats an inode".into());
        }
        sources.push(Source {
            path: layer.path.clone(),
            format: layer.format.clone(),
            identity,
            capacity: 0,
        });
        files.push(file);
    }
    Ok((sources, files))
}

pub(super) fn protect(acquired: &mut Acquired) -> Result<(), String> {
    if acquired.writers.is_some() {
        return Err("source writer protection must not be reacquired within an attempt".into());
    }
    acquired.writers = Some(WriterGuard::acquire(&acquired.files)?);
    validate_parser_budget(&acquired.disks, &acquired.files)?;
    acquired.writers.as_ref().unwrap().audit()
}

fn validate_parser_budget(disks: &[Disk], files: &[Vec<File>]) -> Result<(), String> {
    let mut budget = ParserBudget::default();
    for (disk, pins) in disks.iter().zip(files) {
        for (index, (source, file)) in disk.sources.iter().zip(pins).enumerate() {
            budget.layer(
                file,
                source.format == "qcow2",
                !disk.readonly && index + 1 == disk.sources.len(),
            )?;
        }
    }
    Ok(())
}

fn validate_headers(
    disks: &mut [Disk],
    files: &[Vec<File>],
    bindings: &MigrationBindings,
) -> Result<(), String> {
    let mut budget = ParserBudget::default();
    for (disk, pins) in disks.iter_mut().zip(files) {
        let expected = bindings
            .owned_disks
            .iter()
            .find(|b| b.id == disk.id)
            .map(|b| b.capacity);
        let mut previous_capacity = 0;
        for (index, pin) in pins.iter().enumerate() {
            let (capacity, backing) = io::header(pin, disk.sources[index].format == "qcow2")?;
            if capacity == 0
                || !capacity.is_multiple_of(512)
                || capacity > io::MAX_TOTAL_BYTES
                || capacity < previous_capacity
                || expected.is_some_and(|v| v != capacity)
            {
                return Err("disk chain has incompatible or excessive capacity".into());
            }
            if index == 0 {
                if backing.is_some() {
                    return Err("first disk layer has an unauthorized implicit predecessor".into());
                }
            } else {
                if disk.sources[index].path.parent() != disk.sources[index - 1].path.parent() {
                    return Err(
                        "legacy chain does not have a complete adjacent producer closure".into(),
                    );
                }
                let previous = disk.sources[index - 1]
                    .path
                    .file_name()
                    .and_then(|s| s.to_str())
                    .ok_or("non-portable disk predecessor")?;
                if backing.as_deref() != Some(previous) {
                    return Err(
                        "disk dependency differs from the explicit selected predecessor".into(),
                    );
                }
            }
            disk.sources[index].capacity = capacity;
            previous_capacity = capacity;
            budget.layer(
                pin,
                disk.sources[index].format == "qcow2",
                !disk.readonly && index + 1 == disk.sources.len(),
            )?;
        }
    }
    Ok(())
}

fn reject_missing_selection(
    sandbox: &Path,
    runtime: &Path,
    id: &str,
    _flat: bool,
) -> Result<(), String> {
    let directory = if id == "root" {
        sandbox.to_path_buf()
    } else {
        sandbox.join("owned-volumes").join(id)
    };
    let mut budget = io::MAX_ENTRIES;
    for entry in entries(&directory, &mut budget)? {
        let name = entry.file_name();
        let name = name.to_string_lossy();
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| "cannot inspect legacy storage")?;
        if id != "root"
            && metadata.is_dir()
            && io::reject_link(&metadata).is_ok()
            && contains_disk(&entry.path(), &mut budget, 0)?
        {
            return Err("nested disk storage has no usable active-head record".into());
        }
        if if id == "root" {
            // Unknown disk-looking leftovers can disprove a simple layout without ever
            // authorizing their contents as a source (for example upper-orphan.qcow2).
            name.ends_with(".qcow2") || name.starts_with(".grow-") || name.starts_with(".compact-")
        } else {
            name.ends_with(".qcow2")
                || (name.ends_with(".raw") && name != "disk.raw")
                || name.starts_with(".grow-")
                || name.starts_with(".compact-")
        } {
            return Err("advanced disk storage has no usable active-head record".into());
        }
    }
    if id == "root" {
        for entry in entries(runtime, &mut budget)? {
            let name = entry.file_name();
            let name = name.to_string_lossy();
            let metadata =
                fs::symlink_metadata(entry.path()).map_err(|_| "cannot inspect legacy storage")?;
            if io::reject_link(&metadata).is_err()
                && matches!(name.as_ref(), "checkpoints" | "checkpoint-store")
            {
                return Err("linked checkpoint storage has no usable active-head record".into());
            }
            if metadata.is_dir()
                && io::reject_link(&metadata).is_ok()
                && contains_disk(&entry.path(), &mut budget, 0)?
            {
                return Err("nested legacy disk storage has no usable active-head record".into());
            }
            if name.ends_with(".qcow2")
                || name.starts_with(".grow-")
                || name.starts_with(".compact-")
            {
                return Err("legacy staging exists without an active-head record".into());
            }
        }
    }
    Ok(())
}

fn contains_disk(directory: &Path, budget: &mut usize, depth: usize) -> Result<bool, String> {
    if depth > 8 {
        return Err("legacy storage inventory exceeds its depth bound".into());
    }
    for entry in entries(directory, budget)? {
        let metadata =
            fs::symlink_metadata(entry.path()).map_err(|_| "cannot inspect legacy storage")?;
        if io::reject_link(&metadata).is_err() {
            continue;
        }
        if metadata.is_dir() && contains_disk(&entry.path(), budget, depth + 1)? {
            return Ok(true);
        }
        if metadata.is_file()
            && matches!(
                entry.path().extension().and_then(|s| s.to_str()),
                Some("raw" | "qcow2" | "ext4")
            )
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn account_aliases(
    sandbox: &Path,
    bindings: &MigrationBindings,
    disks: &[Disk],
) -> Result<Vec<File>, String> {
    if disks.is_empty() {
        return Ok(Vec::new());
    }
    let mut selected = BTreeMap::new();
    let mut counts = BTreeMap::<String, BTreeSet<String>>::new();
    let mut pins = Vec::new();
    let mut anchors = BTreeSet::new();
    let mut entry_cache = io::EntryCache::default();
    for disk in disks {
        for source in &disk.sources {
            if selected
                .insert(source.identity.object.clone(), (disk, source))
                .is_some()
            {
                return Err("different configured disks share a selected inode".into());
            }
            if disk.external || !source.path.starts_with(sandbox.join("runtime")) {
                anchors.insert(source.identity.object.clone());
            }
            let file = io::exact(&source.path)?;
            if io::identity(&file)? != source.identity {
                return Err("selected disk entry changed during alias accounting".into());
            }
            counts
                .entry(source.identity.object.clone())
                .or_default()
                .insert(io::entry_identity(&file, &source.path, &mut entry_cache)?);
        }
    }
    // Targeted metadata inventory only: never recurse into ordinary owned directory mounts,
    // guest filesystem data, logs, or unrelated sandboxes. Unseen aliases remain unaccounted.
    let mut budget = io::MAX_ENTRIES;
    let anchor = io::directory(sandbox)?;
    inventory(
        &anchor,
        sandbox,
        Path::new(""),
        0,
        &mut budget,
        &mut |path| {
            let file = io::open(&anchor, &io::relative(path, sandbox)?)?;
            let identity = io::identity(&file)?;
            if let Some((disk, source)) = selected.get(&identity.object) {
                let relative = io::relative(path, sandbox)?;
                let permitted = source_role(&relative, &disk.id, disk.flat, &source.format)
                    || checkpoint_alias(&relative, &source.format);
                if !permitted {
                    return Err(
                        "selected disk aliases host metadata or a different disk role".into(),
                    );
                }
                if source_role(&relative, &disk.id, disk.flat, &source.format)
                    && !relative.starts_with("runtime")
                {
                    anchors.insert(identity.object.clone());
                }
                counts
                    .get_mut(&identity.object)
                    .unwrap()
                    .insert(io::entry_identity(&file, path, &mut entry_cache)?);
                if pins.len() >= 2048 {
                    return Err("migration alias handles exceed their bound".into());
                }
                pins.push(file);
            }
            Ok(())
        },
    )?;
    for alias in &bindings.aliases {
        let file = io::exact(&alias.path)?;
        let identity = io::identity(&file)?;
        if let Some((disk, _)) = selected.get(&identity.object) {
            if disk.id != alias.disk_id {
                return Err("authorized alias belongs to a different disk role".into());
            }
            counts
                .get_mut(&identity.object)
                .unwrap()
                .insert(io::entry_identity(&file, &alias.path, &mut entry_cache)?);
            if pins.len() >= 2048 {
                return Err("migration alias handles exceed their bound".into());
            }
            pins.push(file);
        }
    }
    for (object, (_, source)) in selected {
        if source.identity.links > 1 && !anchors.contains(&object) {
            return Err("guest-exported staging has shared aliases without its own host-managed disk anchor".into());
        }
        if counts[&object].len() as u64 != source.identity.links {
            return Err("selected storage has unaccounted hardlink aliases; inspect related snapshot resources and exclude their writers".into());
        }
    }
    Ok(pins)
}

fn inventory(
    anchor: &File,
    root: &Path,
    relative: &Path,
    depth: usize,
    budget: &mut usize,
    visit: &mut impl FnMut(&Path) -> Result<(), String>,
) -> Result<(), String> {
    if depth > 9 {
        return Err("storage alias inventory exceeds its depth bound".into());
    }
    let directory = io::subdirectory(anchor, relative)?;
    for entry in
        cap_fs::read_base_dir(&directory).map_err(|_| "cannot inventory storage directory")?
    {
        *budget = budget
            .checked_sub(1)
            .ok_or("storage inventory exceeds its entry bound")?;
        let entry = entry.map_err(|_| "cannot inspect storage entry")?;
        let kind = entry
            .file_type()
            .map_err(|_| "cannot inspect storage entry type")?;
        if kind.is_symlink() {
            continue;
        }
        let relative = relative.join(entry.file_name());
        let path = root.join(&relative);
        if kind.is_file() {
            visit(&path)?;
        } else if kind.is_dir() {
            let parts = relative
                .iter()
                .filter_map(|v| v.to_str())
                .collect::<Vec<_>>();
            let recurse = match parts.as_slice() {
                ["runtime"] | ["owned-volumes"] => true,
                ["runtime", "checkpoints" | "checkpoint-store"] => true,
                ["owned-volumes", id] => valid_owned_id(id),
                ["owned-volumes", _, stage] => staging_name(stage),
                ["runtime", stage] => staging_name(stage),
                ["runtime", "checkpoints" | "checkpoint-store", ..] => true,
                [stage] => staging_name(stage),
                _ => false,
            };
            if recurse {
                inventory(anchor, root, &relative, depth + 1, budget, visit)?;
            }
        }
    }
    Ok(())
}

fn entries(directory: &Path, budget: &mut usize) -> Result<Vec<fs::DirEntry>, String> {
    io::directory(directory)?;
    let mut values = Vec::new();
    for entry in fs::read_dir(directory).map_err(|_| "cannot inventory storage directory")? {
        *budget = budget
            .checked_sub(1)
            .ok_or("storage inventory exceeds its entry bound")?;
        values.push(entry.map_err(|_| "cannot inspect storage entry")?);
    }
    Ok(values)
}

fn checkpoint_alias(path: &Path, format: &str) -> bool {
    let parts = path.iter().filter_map(|s| s.to_str()).collect::<Vec<_>>();
    if !matches!(
        parts.as_slice(),
        ["runtime", "checkpoints", ..] | ["runtime", "checkpoint-store", ..]
    ) {
        return false;
    }
    let Some(name) = parts.last() else {
        return false;
    };
    parts.contains(&"layers")
        && (name
            .strip_suffix(&format!(".{format}"))
            .and_then(|s| s.strip_prefix("layer_"))
            .is_some_and(hex32)
            || root_name(name, false, format)
            || root_name(name, true, format)
            || owned_name(name, format))
}

pub(super) fn source_role(path: &Path, id: &str, flat: bool, format: &str) -> bool {
    let Some(name) = path.file_name().and_then(|s| s.to_str()) else {
        return false;
    };
    let parts = path.iter().filter_map(|s| s.to_str()).collect::<Vec<_>>();
    if id == "root" {
        root_name(name, flat, format)
            && (parts.len() == 1
                || matches!(parts.as_slice(),["runtime",stage,_] if staging_name(stage)))
    } else {
        owned_name(name, format)
            && matches!(parts.as_slice(),["owned-volumes",mount,_] if *mount==id)
            || owned_name(name, format)
                && matches!(parts.as_slice(),["owned-volumes",mount,stage,_] if *mount==id && staging_name(stage))
    }
}

fn root_name(name: &str, flat: bool, format: &str) -> bool {
    if format == "raw" {
        return name == if flat { "rootfs.raw" } else { "upper.ext4" };
    }
    let prefix = if flat { "root-" } else { "upper-" };
    let Some(stem) = name
        .strip_prefix(prefix)
        .and_then(|s| s.strip_suffix(".qcow2"))
    else {
        return false;
    };
    hex32(stem)
        || stem.strip_prefix("restore-").is_some_and(|s| {
            s.len() == 16
                && s.bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
        })
        || stem
            .strip_prefix("sealed-")
            .is_some_and(|s| s.len() == 3 && s.bytes().all(|b| b.is_ascii_digit()))
}

fn owned_name(name: &str, format: &str) -> bool {
    if name == "disk.raw" {
        return format == "raw";
    }
    if name == "writable.qcow2" {
        return format == "qcow2";
    }
    let Some(stem) = name.strip_suffix(&format!(".{format}")) else {
        return false;
    };
    (format == "qcow2" && stem.strip_prefix("head_").is_some_and(hex32))
        || stem.strip_prefix("sealed-").is_some_and(|s| {
            s.len() == 3
                && s.bytes().all(|b| b.is_ascii_digit())
                && (format == "qcow2" || s == "000")
        })
}

fn staging_name(name: &str) -> bool {
    name.strip_prefix(".grow-")
        .or_else(|| name.strip_prefix(".compact-"))
        .is_some_and(|s| s.len() == 6 && s.bytes().all(|b| b.is_ascii_alphanumeric()))
}
fn hex32(value: &str) -> bool {
    value.len() == 32
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn valid_owned_id(id: &str) -> bool {
    id.len() <= 128
        && !id.is_empty()
        && !matches!(id, "vda" | "vdb" | "root")
        && id
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
}

fn metadata_candidates(runtime: &Path, bindings: &MigrationBindings) -> Result<Acquired, String> {
    if bindings.identity.is_empty()
        || bindings.identity.len() > 4096
        || bindings.config_revision.is_empty()
        || bindings.config_revision.len() > 4096
        || bindings.owned_disks.len() > 64
    {
        return Err("invalid recovery host bindings".into());
    }
    let sandbox = layout::host_root(runtime)?;
    let anchor = io::directory(sandbox)?;
    let mut paths = Vec::new();
    let mut budget = io::MAX_ENTRIES;
    inventory(
        &anchor,
        sandbox,
        Path::new(""),
        0,
        &mut budget,
        &mut |path| {
            paths.push(path.to_path_buf());
            Ok(())
        },
    )?;
    let mut disks = Vec::new();
    if let Some(root) = &bindings.root {
        let external = root.path
            != sandbox.join(if root.flat {
                "rootfs.raw"
            } else {
                "upper.ext4"
            });
        if external && root.path.starts_with(runtime)
            || !matches!(root.format.as_str(), "raw" | "qcow2")
        {
            return Err("unsupported recovery root binding".into());
        }
        disks.push(Disk {
            id: "root".into(),
            launch_base: root.path.clone(),
            flat: root.flat,
            readonly: false,
            external,
            sources: Vec::new(),
            journal: None,
        });
    }
    let mut ids = BTreeSet::new();
    for disk in &bindings.owned_disks {
        if !valid_owned_id(&disk.id)
            || !ids.insert(&disk.id)
            || disk.path
                != sandbox
                    .join("owned-volumes")
                    .join(&disk.id)
                    .join("disk.raw")
        {
            return Err("invalid recovery owned disk binding".into());
        }
        disks.push(Disk {
            id: disk.id.clone(),
            launch_base: disk.path.clone(),
            flat: false,
            readonly: disk.readonly,
            external: false,
            sources: Vec::new(),
            journal: None,
        });
    }
    let mut files = Vec::new();
    let mut total = 0usize;
    for disk in &mut disks {
        let candidates = if disk.external {
            vec![disk.launch_base.clone()]
        } else {
            paths
                .iter()
                .filter(|path| {
                    io::relative(path, sandbox).ok().is_some_and(|relative| {
                        source_role(&relative, &disk.id, disk.flat, "raw")
                            || source_role(&relative, &disk.id, disk.flat, "qcow2")
                    })
                })
                .cloned()
                .collect()
        };
        let mut pins = Vec::new();
        let mut identities = BTreeSet::new();
        for path in candidates {
            let file = if disk.external {
                io::exact(&path)?
            } else {
                io::open(&anchor, &io::relative(&path, sandbox)?)?
            };
            let identity = io::identity(&file)?;
            if !identities.insert(identity.object.clone()) {
                continue;
            }
            total += 1;
            if total > 1024 {
                return Err("recovery metadata exceeds its source bound".into());
            }
            let format = if disk.external {
                bindings.root.as_ref().unwrap().format.clone()
            } else if path.extension().and_then(|name| name.to_str()) == Some("qcow2") {
                "qcow2".into()
            } else {
                "raw".into()
            };
            disk.sources.push(Source {
                path,
                format,
                identity,
                capacity: 0,
            });
            pins.push(file);
        }
        files.push(pins);
    }
    Ok(Acquired {
        disks,
        files,
        _aliases: Vec::new(),
        writers: None,
    })
}

/// Enumerate bounded complete views only within host-authorized producer resources. Headers
/// describe dependency edges after alias authorization; they can never introduce another path.
pub(super) fn recovery_views(
    runtime: &Path,
    bindings: &MigrationBindings,
) -> Result<Vec<Disk>, String> {
    let sandbox = layout::host_root(runtime)?;
    let anchor = io::directory(sandbox)?;
    let mut disks = Vec::new();
    if let Some(root) = &bindings.root {
        let ordinary = sandbox.join(if root.flat {
            "rootfs.raw"
        } else {
            "upper.ext4"
        });
        let journal = io::bytes(&anchor, Path::new("runtime/root-disk.json"))?;
        if journal
            .as_ref()
            .and_then(|bytes| RootJournal::decode(bytes).ok())
            .is_some_and(|j| j.growth_target.is_some())
        {
            return Err("pending root growth needs operation-aware recovery".into());
        }
        disks.push(Disk {
            id: "root".into(),
            launch_base: root.path.clone(),
            flat: root.flat,
            readonly: false,
            external: root.path != ordinary,
            sources: Vec::new(),
            journal,
        });
    }
    for binding in &bindings.owned_disks {
        if !valid_owned_id(&binding.id)
            || binding.path
                != sandbox
                    .join("owned-volumes")
                    .join(&binding.id)
                    .join("disk.raw")
        {
            return Err("invalid configured owned disk recovery role".into());
        }
        disks.push(Disk {
            id: binding.id.clone(),
            launch_base: binding.path.clone(),
            flat: false,
            readonly: binding.readonly,
            external: false,
            sources: Vec::new(),
            journal: io::bytes(
                &anchor,
                &Path::new("runtime/owned-disks")
                    .join(&binding.id)
                    .join("disk.json"),
            )?,
        });
    }
    let mut paths = Vec::new();
    let mut budget = io::MAX_ENTRIES;
    inventory(
        &anchor,
        sandbox,
        Path::new(""),
        0,
        &mut budget,
        &mut |path| {
            paths.push(path.to_path_buf());
            Ok(())
        },
    )?;
    let mut source_count = 0usize;
    let mut all_files = Vec::<Vec<File>>::new();
    let mut all_paths = Vec::<BTreeMap<PathBuf, Source>>::new();
    for disk in &mut disks {
        let candidates = if disk.external {
            vec![disk.launch_base.clone()]
        } else {
            paths
                .iter()
                .filter(|path| {
                    io::relative(path, sandbox).ok().is_some_and(|relative| {
                        source_role(&relative, &disk.id, disk.flat, "raw")
                            || source_role(&relative, &disk.id, disk.flat, "qcow2")
                    })
                })
                .cloned()
                .collect()
        };
        if candidates.len() > 1024 {
            return Err("recovery discovery exceeds its source bound".into());
        }
        let mut objects = BTreeSet::new();
        let mut files = Vec::new();
        let mut mapping = BTreeMap::new();
        for path in candidates {
            let format = if disk.external {
                bindings.root.as_ref().unwrap().format.clone()
            } else if path.extension().and_then(|s| s.to_str()) == Some("qcow2") {
                "qcow2".into()
            } else {
                "raw".into()
            };
            let file = if disk.external {
                io::exact(&path)?
            } else {
                io::open(&anchor, &io::relative(&path, sandbox)?)?
            };
            let identity = io::identity(&file)?;
            if identity.length == 0 || identity.length > io::MAX_TOTAL_BYTES {
                return Err("recovery source exceeds its size bounds".into());
            }
            let source = Source {
                path: path.clone(),
                format,
                identity: identity.clone(),
                capacity: 0,
            };
            mapping.insert(path, source.clone());
            if objects.insert(identity.object) {
                source_count += 1;
                if source_count > 1024 {
                    return Err("recovery discovery exceeds its handle bound".into());
                }
                disk.sources.push(source);
                files.push(file);
            }
        }
        all_files.push(files);
        all_paths.push(mapping);
    }
    if disks.iter().map(|disk| disk.sources.len()).sum::<usize>() > 1024 {
        return Err("recovery discovery exceeds its handle bound".into());
    }
    let _aliases = account_aliases(sandbox, bindings, &disks)?;
    let mut views = Vec::new();
    for ((disk, files), mapping) in disks.into_iter().zip(all_files).zip(all_paths) {
        let mut headers = BTreeMap::new();
        for (source, file) in disk.sources.iter().zip(&files) {
            // A malformed unselected candidate is not a reason to guess a different dependency.
            // Omit it and any heads depending on it; complete unrelated views remain inspectable.
            if let Ok(header) = io::header(file, source.format == "qcow2") {
                headers.insert(source.identity.object.clone(), header);
            }
        }
        let expected = bindings
            .owned_disks
            .iter()
            .find(|b| b.id == disk.id)
            .map(|b| b.capacity);
        let mut unique = BTreeSet::new();
        for head in mapping.keys() {
            let mut next = head.clone();
            let mut chain = Vec::new();
            let mut seen = BTreeSet::new();
            let complete = loop {
                let Some(source) = mapping.get(&next) else {
                    break false;
                };
                let Some((capacity, backing)) = headers.get(&source.identity.object) else {
                    break false;
                };
                if chain.len() >= 256
                    || !seen.insert(source.identity.object.clone())
                    || *capacity == 0
                    || !capacity.is_multiple_of(512)
                    || *capacity > io::MAX_TOTAL_BYTES
                    || expected.is_some_and(|v| v != *capacity)
                {
                    break false;
                }
                let mut source = source.clone();
                source.capacity = *capacity;
                chain.push(source);
                if let Some(backing) = backing {
                    if disk.external {
                        break false;
                    }
                    next = next
                        .parent()
                        .ok_or("candidate has no parent")?
                        .join(backing);
                } else {
                    break true;
                }
            };
            if !complete {
                continue;
            }
            chain.reverse();
            if chain.iter().skip(1).any(|source| source.format != "qcow2")
                || chain
                    .windows(2)
                    .any(|pair| pair[0].capacity > pair[1].capacity)
            {
                continue;
            }
            let mut view = disk.clone();
            view.sources = chain;
            let id = view.candidate_id(&bindings.identity)?;
            if unique.insert(id) {
                views.push(view);
            }
            if views.len() > 256 {
                return Err("recovery view count exceeds its bound".into());
            }
        }
    }
    Ok(views)
}
