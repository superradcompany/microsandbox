//! Guarded local observations and private staging, never portable capture or activation authority.

use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    fs::{File, Metadata},
    io::{self, Read, Write},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::Path,
};

use cap_std::fs::{Dir, OpenOptions, OpenOptionsExt};
use tempfile::TempDir;
use zeroize::Zeroizing;

use super::PassthroughFs;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Trusted caller-selected capture bounds; never accept an artifact's own limits.
#[derive(Clone, Copy)]
pub struct RuntimeScriptLimits {
    /// Maximum registered filenames to retain and pin.
    pub max_entries: usize,
    /// Maximum UTF-8 bytes in one observed script.
    pub max_script_bytes: usize,
    /// Maximum combined observed script bytes.
    pub max_total_bytes: usize,
}

/// Guest-visible runtime metadata, distinct from host access permissions and ownership.
/// This is local evidence, not a portable serialization or authorization decision.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct RuntimeScriptMetadata {
    /// Guest-visible owner.
    pub uid: u32,
    /// Guest-visible group.
    pub gid: u32,
    /// Ordinary guest permission bits. Privileged bits are not representable here.
    pub mode: u16,
}

/// Exact cold-boot script input, already normalized by the caller.
///
/// This has no source path or captured-handle identity. Staging these bytes cannot
/// establish compatibility with files held open by a resumed guest.
pub struct RuntimeBootScript<'a> {
    /// One registered filename, not a guest or host path.
    pub name: &'a str,
    /// UTF-8 bytes to write without shell wrapping or newline conversion.
    pub content: &'a str,
    /// Guest permission bits; host access remains private.
    pub mode: u16,
}

/// Source-independent registered backing with captured guest metadata.
/// No source path or serialization: captured filesystem-state admission remains separate.
pub struct RuntimeRestoredScript<'a> {
    /// One validated registered filename.
    pub name: &'a str,
    /// Exact UTF-8 bytes, without wrapping or execution.
    pub content: &'a str,
    /// Captured guest ownership and ordinary mode.
    pub metadata: RuntimeScriptMetadata,
}

/// Pinned observations of registered files and their runtime/scripts directories.
///
/// The caller must hold the source's coherent capture/mutation guard through publication.
/// Revalidation detects observed changes but cannot replace that guard. This captures no
/// unregistered files and proves nothing about other handles in a full filesystem state.
/// It is not serializable: capture exclusions and binding substitution must precede export.
pub struct CapturedRuntimeScripts {
    runtime: Dir,
    limits: RuntimeScriptLimits,
    _scripts: Dir,
    runtime_stamp: FileStamp,
    scripts_stamp: FileStamp,
    runtime_metadata: RuntimeScriptMetadata,
    scripts_metadata: RuntimeScriptMetadata,
    files: BTreeMap<String, ScriptObservation>,
}

struct ScriptObservation {
    // Keep the captured inode alive so replacement cannot recycle its identity.
    _file: File,
    stamp: FileStamp,
    metadata: RuntimeScriptMetadata,
    content: Zeroizing<String>,
}

#[derive(PartialEq, Eq)]
struct FileStamp {
    device: u64,
    inode: u64,
    size: u64,
    links: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl PassthroughFs {
    /// Pin the exact mounted root for guarded runtime-script observation.
    /// The caller must still hold capture authority; a pathname reopened later is not equivalent.
    pub fn pin_runtime_script_root(&self) -> io::Result<File> {
        self.root_fd.try_clone()
    }
}

impl CapturedRuntimeScripts {
    /// Observe exact registered backing below an already pinned runtime directory.
    ///
    /// No source configuration text is reread. Symlinks, hard links, special files, invalid UTF-8,
    /// unsupported guest mode bits and oversized observations refuse with redacted errors.
    /// Empty registration is known empty; it is not permission to omit captured open files.
    pub fn capture(
        runtime: &File,
        registered: &BTreeSet<String>,
        limits: RuntimeScriptLimits,
    ) -> io::Result<Self> {
        if limits.max_script_bytes == usize::MAX {
            return Err(error("SCFG_LIMIT", "invalid script byte limit"));
        }
        if registered.len() > limits.max_entries {
            return Err(error("SCFG_LIMIT", "too many registered scripts"));
        }
        for name in registered {
            validate_name(name)?;
        }
        let runtime = Dir::from_std_file(runtime.try_clone().map_err(io_error)?);
        let scripts = scripts_directory(&runtime)?;
        let (runtime_stamp, runtime_metadata) = directory_observation(&runtime)?;
        let (scripts_stamp, scripts_metadata) = directory_observation(&scripts)?;
        let mut files = BTreeMap::new();
        let mut total = 0usize;
        for name in registered {
            let observation = observe_file(&scripts, name, limits.max_script_bytes)?;
            total = total
                .checked_add(observation.content.len())
                .ok_or_else(|| error("SCFG_LIMIT", "combined registered scripts are too large"))?;
            if total > limits.max_total_bytes {
                return Err(error(
                    "SCFG_LIMIT",
                    "combined registered scripts are too large",
                ));
            }
            files.insert(name.clone(), observation);
        }
        let captured = Self {
            runtime,
            limits,
            _scripts: scripts,
            runtime_stamp,
            scripts_stamp,
            runtime_metadata,
            scripts_metadata,
            files,
        };
        captured.revalidate()?;
        Ok(captured)
    }

    /// Read local observations for the capture sanitizer; content is never Debug/serialized here.
    pub fn observations(&self) -> impl Iterator<Item = (&str, &str, RuntimeScriptMetadata)> {
        self.files
            .iter()
            .map(|(name, file)| (name.as_str(), file.content.as_str(), file.metadata))
    }

    /// Guest metadata for the pinned runtime and scripts directories, in that order.
    /// Directory permissions participate in full backing fidelity independently of file bytes.
    pub fn directory_metadata(&self) -> (RuntimeScriptMetadata, RuntimeScriptMetadata) {
        (self.runtime_metadata, self.scripts_metadata)
    }

    /// Recheck namespace, bytes and guest metadata while the source guard remains held.
    pub fn revalidate(&self) -> io::Result<()> {
        let scripts = scripts_directory(&self.runtime)?;
        let (runtime_stamp, runtime_metadata) = directory_observation(&self.runtime)?;
        let (scripts_stamp, scripts_metadata) = directory_observation(&scripts)?;
        // Directory size/timestamps also change for unrelated runtime heartbeat traffic.
        // Directory identity and guest permissions matter here; the coherent source guard
        // and full-state closure are responsible for other runtime files.
        if !same_inode(&runtime_stamp, &self.runtime_stamp)
            || !same_inode(&scripts_stamp, &self.scripts_stamp)
            || runtime_metadata != self.runtime_metadata
            || scripts_metadata != self.scripts_metadata
        {
            return Err(error("SCFG_RACE", "runtime script directory changed"));
        }
        for (name, original) in &self.files {
            let current = observe_file(&scripts, name, self.limits.max_script_bytes)?;
            if current.stamp != original.stamp
                || current.metadata != original.metadata
                || current.content.as_bytes() != original.content.as_bytes()
            {
                return Err(error("SCFG_RACE", "registered script backing changed"));
            }
        }
        Ok(())
    }

    /// Stage an exact local copy beneath a caller-owned private staging parent.
    ///
    /// The returned temporary runtime directory owns its files and cleans them up on drop.
    /// Nothing is installed over an existing runtime, executed, or published. The caller
    /// must complete source-generation, captured-handle and destination admission checks
    /// before adopting it. This local primitive does not implement archive restoration.
    pub fn stage_exact(&self, parent: &Path) -> io::Result<TempDir> {
        self.stage_with_check(parent, || Ok(()))
    }

    // A private completion seam lets tests inject a source race or a late failure after
    // the files exist. The public operation never runs caller-supplied code.
    pub(super) fn stage_with_check(
        &self,
        parent: &Path,
        after_files: impl FnOnce() -> io::Result<()>,
    ) -> io::Result<TempDir> {
        self.revalidate()?;
        // TempDir retains its pathname for deferred cleanup. Pin a relative destination
        // to this call's cwd without canonicalizing symlinks or collapsing `..`.
        let parent = if parent.is_absolute() {
            parent.to_path_buf()
        } else {
            std::env::current_dir().map_err(io_error)?.join(parent)
        };
        let staged = tempfile::Builder::new()
            .prefix(".runtime-scripts-")
            .tempdir_in(&parent)
            .map_err(io_error)?;
        let runtime =
            Dir::open_ambient_dir(staged.path(), cap_std::ambient_authority()).map_err(io_error)?;
        runtime.create_dir("scripts").map_err(io_error)?;
        let scripts = scripts_directory(&runtime)?;
        for (name, source) in &self.files {
            let mut options = OpenOptions::new();
            options.write(true).create_new(true).mode(0o600);
            options._cap_fs_ext_follow(cap_primitives::fs::FollowSymlinks::No);
            let mut file = scripts
                .open_with(name, &options)
                .map_err(io_error)?
                .into_std();
            file.write_all(source.content.as_bytes())
                .map_err(io_error)?;
            set_metadata(&file, source.metadata)?;
            file.sync_all().map_err(io_error)?;
        }
        set_directory_metadata(&scripts, self.scripts_metadata)?;
        set_directory_metadata(&runtime, self.runtime_metadata)?;
        after_files()?;
        // Verify the guest overlay too: matching host bytes alone would miss the 0640→0755
        // regression, and host mode cannot represent a guest's 0000 permission choice.
        for (name, expected) in &self.files {
            let actual = observe_file(&scripts, name, self.limits.max_script_bytes)?;
            if actual.content.as_bytes() != expected.content.as_bytes()
                || actual.metadata != expected.metadata
            {
                return Err(error("SCFG_INTEGRITY", "staged script backing differs"));
            }
        }
        self.revalidate()?;
        Ok(staged)
    }
}

impl FileStamp {
    fn from_metadata(metadata: &Metadata) -> Self {
        Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            size: metadata.len(),
            links: metadata.nlink(),
            modified: (metadata.mtime(), metadata.mtime_nsec()),
            changed: (metadata.ctime(), metadata.ctime_nsec()),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl fmt::Debug for CapturedRuntimeScripts {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CapturedRuntimeScripts")
            .field("count", &self.files.len())
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for RuntimeBootScript<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RuntimeBootScript").finish_non_exhaustive()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Reproduce registered backing from portable inputs after source deletion.
/// This stages guest metadata faithfully but does not admit unregistered runtime files,
/// filesystem handles, destination policy or a full VM resume.
pub fn stage_runtime_restored_scripts(
    parent: &Path,
    inputs: &[RuntimeRestoredScript<'_>],
    runtime_metadata: RuntimeScriptMetadata,
    scripts_metadata: RuntimeScriptMetadata,
    limits: RuntimeScriptLimits,
) -> io::Result<TempDir> {
    stage_restored_scripts_with_check(
        parent,
        inputs,
        runtime_metadata,
        scripts_metadata,
        limits,
        |_| Ok(()),
    )
}

pub(super) fn stage_restored_scripts_with_check(
    parent: &Path,
    inputs: &[RuntimeRestoredScript<'_>],
    runtime_metadata: RuntimeScriptMetadata,
    scripts_metadata: RuntimeScriptMetadata,
    limits: RuntimeScriptLimits,
    after_files: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<TempDir> {
    if inputs.len() > limits.max_entries || limits.max_script_bytes == usize::MAX {
        return Err(error("SCFG_LIMIT", "invalid script count or byte limit"));
    }
    if [runtime_metadata, scripts_metadata]
        .into_iter()
        .chain(inputs.iter().map(|v| v.metadata))
        .any(|v| v.mode > 0o777)
    {
        return Err(error(
            "SCFG_BACKING",
            "unsupported captured permission bits",
        ));
    }
    let boot: Vec<_> = inputs
        .iter()
        .map(|v| RuntimeBootScript {
            name: v.name,
            content: v.content,
            mode: v.metadata.mode,
        })
        .collect();
    // Reuse bounded private file creation without changing the cold-boot ownership contract.
    let staged = stage_runtime_boot_scripts(parent, &boot, limits)?;
    let runtime =
        Dir::open_ambient_dir(staged.path(), cap_std::ambient_authority()).map_err(io_error)?;
    let scripts = scripts_directory(&runtime)?;
    let mut stamps = Vec::with_capacity(inputs.len());
    for input in inputs {
        let observed = observe_file(&scripts, input.name, limits.max_script_bytes)?;
        set_metadata(&observed._file, input.metadata)?;
        observed._file.sync_all().map_err(io_error)?;
        // Keep each inode pinned through verification; deletion must not allow inode reuse.
        stamps.push(observed);
    }
    set_directory_metadata(&scripts, scripts_metadata)?;
    set_directory_metadata(&runtime, runtime_metadata)?;
    let scripts_stamp = directory_observation(&scripts)?.0;
    let runtime_stamp = directory_observation(&runtime)?.0;
    after_files(staged.path()).map_err(io_error)?;
    let scripts = scripts_directory(&runtime)?;
    let (current_scripts, current_metadata) = directory_observation(&scripts)?;
    let (current_runtime, current_runtime_metadata) = directory_observation(&runtime)?;
    if !same_inode(&scripts_stamp, &current_scripts)
        || !same_inode(&runtime_stamp, &current_runtime)
        || current_metadata != scripts_metadata
        || current_runtime_metadata != runtime_metadata
    {
        return Err(error(
            "SCFG_INTEGRITY",
            "staged captured directories differ",
        ));
    }
    for (input, stamp) in inputs.iter().zip(stamps) {
        let actual = observe_file(&scripts, input.name, limits.max_script_bytes)?;
        if !same_inode(&stamp.stamp, &actual.stamp)
            || actual.content.as_bytes() != input.content.as_bytes()
            || actual.metadata != input.metadata
        {
            return Err(error("SCFG_INTEGRITY", "staged captured backing differs"));
        }
    }
    Ok(staged)
}

/// Materialize exact scripts for a new boot beneath a private caller-owned staging parent.
///
/// All input bounds and names are checked before creating files. The returned temporary
/// runtime owns cleanup; it is neither installed nor executed. New guest files/directories
/// belong to root, with supplied file modes and 0755 directory modes. Full resume must use
/// independently validated captured backing instead of this cold-boot operation.
pub fn stage_runtime_boot_scripts(
    parent: &Path,
    inputs: &[RuntimeBootScript<'_>],
    limits: RuntimeScriptLimits,
) -> io::Result<TempDir> {
    stage_boot_scripts_with_check(parent, inputs, limits, |_| Ok(()))
}

pub(super) fn stage_boot_scripts_with_check(
    parent: &Path,
    inputs: &[RuntimeBootScript<'_>],
    limits: RuntimeScriptLimits,
    after_files: impl FnOnce(&Path) -> io::Result<()>,
) -> io::Result<TempDir> {
    if inputs.len() > limits.max_entries || limits.max_script_bytes == usize::MAX {
        return Err(error("SCFG_LIMIT", "invalid script count or byte limit"));
    }
    let mut names = BTreeSet::new();
    let mut total = 0usize;
    for input in inputs {
        validate_name(input.name)?;
        if !names.insert(input.name.to_owned()) || input.mode > 0o777 {
            return Err(error("SCFG_BACKING", "duplicate name or unsupported mode"));
        }
        total = total
            .checked_add(input.content.len())
            .ok_or_else(|| error("SCFG_LIMIT", "combined scripts are too large"))?;
        if input.content.len() > limits.max_script_bytes || total > limits.max_total_bytes {
            return Err(error("SCFG_LIMIT", "script inputs are too large"));
        }
    }

    // Keep symlink/parent semantics while anchoring TempDir's later cleanup to this call.
    let parent = if parent.is_absolute() {
        parent.to_path_buf()
    } else {
        std::env::current_dir().map_err(io_error)?.join(parent)
    };
    let staged = tempfile::Builder::new()
        .prefix(".runtime-scripts-")
        .tempdir_in(parent)
        .map_err(io_error)?;
    let runtime =
        Dir::open_ambient_dir(staged.path(), cap_std::ambient_authority()).map_err(io_error)?;
    runtime.create_dir("scripts").map_err(io_error)?;
    let scripts = scripts_directory(&runtime)?;
    for input in inputs {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        options._cap_fs_ext_follow(cap_primitives::fs::FollowSymlinks::No);
        let mut file = scripts
            .open_with(input.name, &options)
            .map_err(io_error)?
            .into_std();
        file.write_all(input.content.as_bytes()).map_err(io_error)?;
        set_metadata(
            &file,
            RuntimeScriptMetadata {
                uid: 0,
                gid: 0,
                mode: input.mode,
            },
        )?;
        file.sync_all().map_err(io_error)?;
    }
    let directory_metadata = RuntimeScriptMetadata {
        uid: 0,
        gid: 0,
        mode: 0o755,
    };
    set_directory_metadata(&scripts, directory_metadata)?;
    set_directory_metadata(&runtime, directory_metadata)?;
    let (scripts_stamp, _) = directory_observation(&scripts)?;
    after_files(staged.path()).map_err(io_error)?;

    let scripts = scripts_directory(&runtime)?;
    let (current_stamp, current_metadata) = directory_observation(&scripts)?;
    if !same_inode(&scripts_stamp, &current_stamp)
        || current_metadata != directory_metadata
        || directory_observation(&runtime)?.1 != directory_metadata
    {
        return Err(error("SCFG_INTEGRITY", "staged script directory differs"));
    }
    // Reopen by name: verifying only a still-open writer would miss a replaced file.
    for input in inputs {
        let actual = observe_file(&scripts, input.name, limits.max_script_bytes)?;
        let expected = RuntimeScriptMetadata {
            uid: 0,
            gid: 0,
            mode: input.mode,
        };
        if actual.content.as_bytes() != input.content.as_bytes() || actual.metadata != expected {
            return Err(error("SCFG_INTEGRITY", "staged script backing differs"));
        }
    }
    Ok(staged)
}

fn observe_file(directory: &Dir, name: &str, max_bytes: usize) -> io::Result<ScriptObservation> {
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_NONBLOCK);
    options._cap_fs_ext_follow(cap_primitives::fs::FollowSymlinks::No);
    let mut file = directory
        .open_with(name, &options)
        .map_err(io_error)?
        .into_std();
    let before = file.metadata().map_err(io_error)?;
    if !before.is_file() {
        return Err(error(
            "SCFG_BACKING",
            "registered backing is not a regular file",
        ));
    }
    // Portable scripts are recreated as independent files. Even an alias outside
    // this directory changes link counts and write visibility after reconstruction;
    // equal bytes and permissions cannot establish that inode relationship.
    if before.nlink() != 1 {
        return Err(error(
            "SCFG_BACKING",
            "registered backing has unsupported link relationships",
        ));
    }
    let metadata = guest_metadata(&file)?;
    if before.len() > max_bytes as u64 {
        return Err(error("SCFG_LIMIT", "registered script is too large"));
    }
    let mut bytes = Zeroizing::new(Vec::new());
    Read::by_ref(&mut file)
        .take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(io_error)?;
    if bytes.len() > max_bytes {
        return Err(error("SCFG_LIMIT", "registered script is too large"));
    }
    let content = std::str::from_utf8(&bytes)
        .map_err(|_| error("SCFG_BACKING", "registered script is not UTF-8"))?;
    let after = file.metadata().map_err(io_error)?;
    let stamp = FileStamp::from_metadata(&before);
    if stamp != FileStamp::from_metadata(&after) || metadata != guest_metadata(&file)? {
        return Err(error(
            "SCFG_RACE",
            "registered script changed during observation",
        ));
    }
    Ok(ScriptObservation {
        _file: file,
        stamp,
        metadata,
        content: Zeroizing::new(content.to_owned()),
    })
}

fn scripts_directory(runtime: &Dir) -> io::Result<Dir> {
    let root = runtime.try_clone().map_err(io_error)?.into_std_file();
    cap_primitives::fs::open_dir_nofollow(&root, Path::new("scripts"))
        .map(Dir::from_std_file)
        .map_err(io_error)
}

fn directory_observation(directory: &Dir) -> io::Result<(FileStamp, RuntimeScriptMetadata)> {
    let file = directory.try_clone().map_err(io_error)?.into_std_file();
    Ok((
        FileStamp::from_metadata(&file.metadata().map_err(io_error)?),
        guest_metadata(&file)?,
    ))
}

fn guest_metadata(file: &File) -> io::Result<RuntimeScriptMetadata> {
    let stat = PassthroughFs::runtime_backing_stat(file).map_err(io_error)?;
    #[cfg(target_os = "linux")]
    let mode = stat.st_mode & 0o7777;
    #[cfg(target_os = "macos")]
    let mode = u32::from(stat.st_mode) & 0o7777;
    if mode > 0o777 {
        return Err(error(
            "SCFG_BACKING",
            "guest script metadata contains unsupported bits",
        ));
    }
    Ok(RuntimeScriptMetadata {
        uid: stat.st_uid,
        gid: stat.st_gid,
        mode: mode as u16,
    })
}

fn set_metadata(file: &File, metadata: RuntimeScriptMetadata) -> io::Result<()> {
    PassthroughFs::set_runtime_backing_permissions(file, metadata.uid, metadata.gid, metadata.mode)
        .map_err(io_error)
}

fn set_directory_metadata(directory: &Dir, metadata: RuntimeScriptMetadata) -> io::Result<()> {
    // cap-std directory handles use O_PATH on Linux. Cloning that descriptor cannot
    // make fchmod/fsync work; open "." relative to the pinned directory instead.
    // This keeps the same inode without resolving its potentially replaced pathname.
    let mut options = OpenOptions::new();
    options.read(true).custom_flags(libc::O_DIRECTORY);
    options._cap_fs_ext_follow(cap_primitives::fs::FollowSymlinks::No);
    let file = directory
        .open_with(".", &options)
        .map_err(io_error)?
        .into_std();
    // Protect the host namespace while giving the guest its independently recorded mode.
    file.set_permissions(std::fs::Permissions::from_mode(0o700))
        .map_err(io_error)?;
    set_metadata(&file, metadata)?;
    file.sync_all().map_err(io_error)
}

fn validate_name(name: &str) -> io::Result<()> {
    if name.is_empty()
        || name.len() > 256
        || matches!(name, "." | "..")
        || name.contains(['\0', '/', '\\'])
    {
        return Err(error("SCFG_BACKING", "script name must be one filename"));
    }
    Ok(())
}

fn same_inode(a: &FileStamp, b: &FileStamp) -> bool {
    (a.device, a.inode) == (b.device, b.inode)
}

fn io_error(_: std::io::Error) -> io::Error {
    // Source paths and script names may contain sensitive destination/source values.
    error(
        "SCFG_BACKING",
        "cannot access regular runtime script backing",
    )
}

fn error(code: &str, detail: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("{code}: runtime.scripts: {detail}"),
    )
}
