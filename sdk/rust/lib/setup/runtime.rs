//! Paired resolution and installation of the host runtime.

use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use flate2::read::GzDecoder;
use futures::StreamExt;
use serde::Serialize;
use sha2::{Digest as _, Sha256};
use tar::Archive;

use crate::{MicrosandboxError, MicrosandboxResult, config::GlobalConfig};
#[cfg(unix)]
use microsandbox_utils::LIBKRUNFW_ABI;
use microsandbox_utils::{BIN_SUBDIR, LIB_SUBDIR, PREBUILT_VERSION};

use super::verify::verify_installation;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

#[cfg(feature = "embed-binaries")]
const EMBEDDED_RUNTIME_ARCHIVE: Option<&[u8]> = Some(include_bytes!(concat!(
    env!("OUT_DIR"),
    "/runtime-bundle.tar.gz"
)));
#[cfg(not(feature = "embed-binaries"))]
const EMBEDDED_RUNTIME_ARCHIVE: Option<&[u8]> = None;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Snapshot process-wide paths before resolving; tests can supply candidates without
/// mutating environment variables or the set-once SDK bridge.
#[derive(Default)]
struct RuntimeCandidates {
    env_msb: Option<PathBuf>,
    env_library: Option<PathBuf>,
    explicit_msb: Option<PathBuf>,
    explicit_library: Option<PathBuf>,
    packaged_msb: Option<PathBuf>,
}

/// Where a resolved host runtime pair came from.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeOrigin {
    /// Explicit `MSB_PATH` and optional `MSB_LIBKRUNFW_PATH` environment configuration.
    Environment,
    /// Paths supplied by an SDK package or explicit process-level setter.
    SdkPackage,
    /// Paths from [`GlobalConfig`].
    Configuration,
    /// The normal `MSB_HOME` installation.
    Home,
    /// An explicit installer source.
    Installed,
}

/// The matched host runtime pair used for local sandbox execution.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct ResolvedRuntime {
    /// Path to the `msb` executable.
    pub msb_path: PathBuf,
    /// Path to the matching `libkrunfw` library.
    pub libkrunfw_path: PathBuf,
    /// Resolution source.
    pub origin: RuntimeOrigin,
}

/// Source used by [`install_runtime`].
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub enum InstallSource {
    /// Download an official release archive.
    #[default]
    ReleaseDownload,
    /// Install from an existing `.tar.gz` runtime archive.
    Archive(PathBuf),
    /// Install the exact `msb` and `libkrunfw` files from a directory.
    Directory(PathBuf),
    /// Install from bytes compiled into the Rust SDK.
    EmbeddedArchive,
}

/// Options for an explicit runtime installation.
#[derive(Clone, Debug)]
pub struct InstallOptions {
    /// Runtime source.
    pub source: InstallSource,
    /// Release version for [`InstallSource::ReleaseDownload`].
    pub version: String,
    /// Replace an already complete installation.
    pub force: bool,
    /// Verify the published pair after installation.
    pub verify: bool,
    /// Optional expected SHA-256 for archive bytes.
    pub expected_archive_sha256: Option<String>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for InstallOptions {
    fn default() -> Self {
        Self {
            source: InstallSource::ReleaseDownload,
            version: PREBUILT_VERSION.to_string(),
            force: false,
            verify: true,
            expected_archive_sha256: None,
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve a complete `msb` and `libkrunfw` pair without network access.
///
/// Explicit overrides take precedence, followed by the resolved home and then
/// automatically discovered SDK package binaries.
///
/// This operation never creates directories, extracts archives, or accesses
/// the network. A partial installation is never repaired implicitly.
pub fn resolve_runtime(config: &GlobalConfig) -> MicrosandboxResult<ResolvedRuntime> {
    resolve_runtime_candidates(
        config,
        RuntimeCandidates {
            env_msb: std::env::var_os("MSB_PATH").map(PathBuf::from),
            env_library: std::env::var_os("MSB_LIBKRUNFW_PATH").map(PathBuf::from),
            explicit_msb: crate::config::sdk_msb_path(),
            explicit_library: crate::config::sdk_libkrunfw_path(),
            packaged_msb: crate::config::sdk_packaged_msb_path(),
        },
    )
}

/// Install a complete host runtime pair from an explicit source.
pub async fn install_runtime(
    config: &GlobalConfig,
    options: InstallOptions,
) -> MicrosandboxResult<ResolvedRuntime> {
    let archive = match &options.source {
        InstallSource::ReleaseDownload => {
            let url = microsandbox_utils::bundle_download_url(
                &options.version,
                std::env::consts::ARCH,
                std::env::consts::OS,
            );
            tracing::info!(version = %options.version, %url, "downloading microsandbox runtime");
            download_bytes(&url).await?
        }
        InstallSource::Archive(path) => tokio::fs::read(path).await?,
        InstallSource::EmbeddedArchive => EMBEDDED_RUNTIME_ARCHIVE
            .ok_or_else(|| {
                MicrosandboxError::RuntimeNotInstalled(
                    "this SDK was built without embed-binaries".into(),
                )
            })?
            .to_vec(),
        InstallSource::Directory(directory) => {
            install_directory(config, directory, options.force)?;
            if options.verify {
                verify_home(config)?;
            }
            return resolved_installed(config);
        }
    };

    if let Some(expected) = options.expected_archive_sha256.as_deref() {
        verify_archive_digest(&archive, expected)?;
    }
    install_archive_bytes(config, &archive, options.force)?;
    if options.verify {
        verify_home(config)?;
    }
    resolved_installed(config)
}

/// Resolve the host runtime or explicitly install it when wholly absent.
///
/// `install_options` is ignored when a complete runtime already resolves. An
/// incomplete or invalid explicit pair fails closed instead of being repaired.
pub async fn ensure_runtime(
    config: &GlobalConfig,
    install_options: InstallOptions,
) -> MicrosandboxResult<ResolvedRuntime> {
    match resolve_runtime(config) {
        Ok(runtime) => Ok(runtime),
        Err(MicrosandboxError::RuntimeNotInstalled(_)) => {
            install_runtime(config, install_options).await
        }
        Err(error) => Err(error),
    }
}

/// Return whether a complete runtime pair resolves for the supplied config.
pub fn is_runtime_installed(config: &GlobalConfig) -> bool {
    resolve_runtime(config).is_ok()
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PairPresence {
    Complete,
    Partial,
    Absent,
}

fn pair_presence(msb: &Path, library: &Path) -> PairPresence {
    match (msb.is_file(), library.is_file()) {
        (true, true) => PairPresence::Complete,
        (false, false) => PairPresence::Absent,
        _ => PairPresence::Partial,
    }
}

fn require_pair(
    msb: PathBuf,
    library: Option<PathBuf>,
    origin: RuntimeOrigin,
) -> MicrosandboxResult<ResolvedRuntime> {
    let Some(library) = library else {
        return Err(MicrosandboxError::RuntimeIncomplete(format!(
            "{} has no matching libkrunfw",
            msb.display()
        )));
    };
    match pair_presence(&msb, &library) {
        PairPresence::Complete => Ok(ResolvedRuntime {
            msb_path: msb,
            libkrunfw_path: library,
            origin,
        }),
        PairPresence::Partial | PairPresence::Absent => Err(MicrosandboxError::RuntimeIncomplete(
            format!("expected both {} and {}", msb.display(), library.display()),
        )),
    }
}

fn resolve_runtime_candidates(
    config: &GlobalConfig,
    candidates: RuntimeCandidates,
) -> MicrosandboxResult<ResolvedRuntime> {
    if candidates.env_library.is_some() && candidates.env_msb.is_none() {
        return Err(MicrosandboxError::RuntimeIncomplete(
            "MSB_LIBKRUNFW_PATH requires MSB_PATH so the pair is explicit".into(),
        ));
    }

    if let Some(msb) = candidates.env_msb {
        let library = candidates.env_library.or_else(|| adjacent_library(&msb));
        return require_pair(msb, library, RuntimeOrigin::Environment);
    }

    if let Some(msb) = candidates.explicit_msb {
        let library = candidates
            .explicit_library
            .clone()
            .or_else(|| adjacent_library(&msb));
        return require_pair(msb, library, RuntimeOrigin::SdkPackage);
    }

    if let Some(msb) = config.paths.msb.clone() {
        let library = candidates
            .explicit_library
            .clone()
            .or_else(|| config.paths.libkrunfw.clone())
            .or_else(|| adjacent_library(&msb));
        return require_pair(msb, library, RuntimeOrigin::Configuration);
    }
    if config.paths.libkrunfw.is_some() {
        return Err(MicrosandboxError::RuntimeIncomplete(
            "config.paths.libkrunfw requires config.paths.msb".into(),
        ));
    }

    let home_runtime = runtime_in_home(config);
    // A caller-selected library stays an explicit override even when the executable
    // is discovered in home rather than supplied by the language package.
    if home_runtime.msb_path.is_file()
        && let Some(library) = candidates.explicit_library.clone()
    {
        return require_pair(
            home_runtime.msb_path,
            Some(library),
            RuntimeOrigin::Configuration,
        );
    }
    match pair_presence(&home_runtime.msb_path, &home_runtime.libkrunfw_path) {
        PairPresence::Complete => return Ok(home_runtime),
        PairPresence::Partial => {
            return Err(MicrosandboxError::RuntimeIncomplete(format!(
                "expected both {} and {}",
                home_runtime.msb_path.display(),
                home_runtime.libkrunfw_path.display()
            )));
        }
        PairPresence::Absent => {}
    }

    // Do not let a package mask a partial home installation. Only an absent home
    // reaches this fallback, which must also provide a complete runtime pair.
    if let Some(msb) = candidates.packaged_msb {
        let library = candidates
            .explicit_library
            .or_else(|| adjacent_library(&msb));
        return require_pair(msb, library, RuntimeOrigin::SdkPackage);
    }

    if candidates.explicit_library.is_some() {
        return Err(MicrosandboxError::RuntimeIncomplete(
            "explicit library override has no resolvable msb executable".into(),
        ));
    }

    Err(MicrosandboxError::RuntimeNotInstalled(format!(
        "expected {} and {}; run setup::install_runtime or set MSB_PATH and MSB_LIBKRUNFW_PATH",
        home_runtime.msb_path.display(),
        home_runtime.libkrunfw_path.display()
    )))
}

fn runtime_in_home(config: &GlobalConfig) -> ResolvedRuntime {
    ResolvedRuntime {
        msb_path: config
            .home()
            .join(BIN_SUBDIR)
            .join(microsandbox_utils::msb_binary_filename(
                std::env::consts::OS,
            )),
        libkrunfw_path: config
            .home()
            .join(LIB_SUBDIR)
            .join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS)),
        origin: RuntimeOrigin::Home,
    }
}

fn adjacent_library(msb: &Path) -> Option<PathBuf> {
    let filename = microsandbox_utils::libkrunfw_filename(std::env::consts::OS);
    let parent = msb.parent()?;
    [
        parent.join(&filename),
        parent.join("..").join(LIB_SUBDIR).join(filename),
    ]
    .into_iter()
    .find(|path| path.is_file())
}

fn install_directory(config: &GlobalConfig, source: &Path, force: bool) -> MicrosandboxResult<()> {
    let msb = source.join(microsandbox_utils::msb_binary_filename(
        std::env::consts::OS,
    ));
    let library = source.join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS));
    if pair_presence(&msb, &library) != PairPresence::Complete {
        return Err(MicrosandboxError::RuntimeIncomplete(format!(
            "directory must contain both {} and {}",
            msb.display(),
            library.display()
        )));
    }

    with_install_lock(config, || publish_pair(config, &msb, &library, force))
}

fn install_archive_bytes(
    config: &GlobalConfig,
    bytes: &[u8],
    force: bool,
) -> MicrosandboxResult<()> {
    with_install_lock(config, || {
        let home = config.home();
        fs::create_dir_all(&home)?;
        let stage = tempfile::Builder::new()
            .prefix(".runtime-stage-")
            .tempdir_in(&home)?;
        let staged_msb = stage.path().join(microsandbox_utils::msb_binary_filename(
            std::env::consts::OS,
        ));
        let staged_library = stage
            .path()
            .join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS));

        let decoder = GzDecoder::new(std::io::Cursor::new(bytes));
        let mut archive = Archive::new(decoder);
        let mut found_msb = false;
        let mut found_library = false;
        for entry in archive.entries()? {
            let mut entry = entry?;
            let path = entry.path()?;
            let mut components = path.components();
            // A lone `.` or `..` is one component but has no filename. Require a
            // normal basename so malformed archives return an error instead of panicking.
            let filename = match (components.next(), components.next()) {
                (Some(Component::Normal(filename)), None)
                    if entry.header().entry_type().is_file() =>
                {
                    filename
                }
                _ => {
                    return Err(MicrosandboxError::Custom(format!(
                        "runtime archive contains unexpected entry {}",
                        path.display()
                    )));
                }
            };
            let destination = if filename == staged_msb.file_name().expect("msb filename") {
                if found_msb {
                    return Err(MicrosandboxError::Custom(
                        "runtime archive contains duplicate msb entries".into(),
                    ));
                }
                found_msb = true;
                &staged_msb
            } else if filename == staged_library.file_name().expect("library filename") {
                if found_library {
                    return Err(MicrosandboxError::Custom(
                        "runtime archive contains duplicate libkrunfw entries".into(),
                    ));
                }
                found_library = true;
                &staged_library
            } else {
                return Err(MicrosandboxError::Custom(format!(
                    "runtime archive contains unexpected entry {}",
                    path.display()
                )));
            };
            entry.unpack(destination)?;
        }
        publish_pair(config, &staged_msb, &staged_library, force)
    })
}

fn publish_pair(
    config: &GlobalConfig,
    source_msb: &Path,
    source_library: &Path,
    force: bool,
) -> MicrosandboxResult<()> {
    if pair_presence(source_msb, source_library) != PairPresence::Complete {
        return Err(MicrosandboxError::RuntimeIncomplete(
            "source did not provide both runtime files".into(),
        ));
    }
    let runtime = runtime_in_home(config);
    let existing = pair_presence(&runtime.msb_path, &runtime.libkrunfw_path);
    if existing == PairPresence::Partial {
        return Err(MicrosandboxError::RuntimeIncomplete(format!(
            "refusing to repair partial installation at {}",
            config.home().display()
        )));
    }
    if existing == PairPresence::Complete && !force {
        return Ok(());
    }

    let bin_dir = runtime.msb_path.parent().expect("msb has parent");
    let lib_dir = runtime.libkrunfw_path.parent().expect("library has parent");
    fs::create_dir_all(bin_dir)?;
    fs::create_dir_all(lib_dir)?;
    let staged_library = runtime
        .libkrunfw_path
        .with_extension(format!("stage-{}", std::process::id()));
    let staged_msb = runtime
        .msb_path
        .with_extension(format!("stage-{}", std::process::id()));
    fs::copy(source_library, &staged_library)?;
    fs::copy(source_msb, &staged_msb)?;
    set_executable(&staged_library)?;
    set_executable(&staged_msb)?;

    let backup_library = runtime
        .libkrunfw_path
        .with_extension(format!("backup-{}", std::process::id()));
    let backup_msb = runtime
        .msb_path
        .with_extension(format!("backup-{}", std::process::id()));
    let replacing = existing == PairPresence::Complete;
    if replacing {
        // Remove the completion marker before changing the library. Readers
        // now fail closed until the new msb is published last.
        fs::rename(&runtime.msb_path, &backup_msb)?;
        if let Err(error) = fs::rename(&runtime.libkrunfw_path, &backup_library) {
            let _ = fs::rename(&backup_msb, &runtime.msb_path);
            return Err(error.into());
        }
    }

    if let Err(error) = fs::rename(&staged_library, &runtime.libkrunfw_path) {
        restore_pair(&runtime, &backup_msb, &backup_library, replacing);
        return Err(error.into());
    }
    let links_result = create_library_links(
        lib_dir,
        runtime
            .libkrunfw_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default(),
    );
    if let Err(error) = links_result {
        let _ = fs::remove_file(&runtime.libkrunfw_path);
        restore_pair(&runtime, &backup_msb, &backup_library, replacing);
        return Err(error);
    }
    // Publish msb last: its presence is the completion marker for readers.
    if let Err(error) = fs::rename(&staged_msb, &runtime.msb_path) {
        let _ = fs::remove_file(&runtime.libkrunfw_path);
        restore_pair(&runtime, &backup_msb, &backup_library, replacing);
        return Err(error.into());
    }
    if replacing {
        let _ = fs::remove_file(backup_library);
        let _ = fs::remove_file(backup_msb);
    }
    Ok(())
}

fn with_install_lock<T>(
    config: &GlobalConfig,
    operation: impl FnOnce() -> MicrosandboxResult<T>,
) -> MicrosandboxResult<T> {
    fs::create_dir_all(config.home())?;
    let lock = microsandbox_utils::process_lock::open_lock_file(
        &config.home().join(".runtime-install.lock"),
    )?;
    microsandbox_utils::process_lock::lock_exclusive(&lock)?;
    let result = operation();
    let _ = microsandbox_utils::process_lock::unlock(&lock);
    result
}

fn restore_pair(
    runtime: &ResolvedRuntime,
    backup_msb: &Path,
    backup_library: &Path,
    replacing: bool,
) {
    if !replacing {
        return;
    }
    let _ = fs::rename(backup_library, &runtime.libkrunfw_path);
    let _ = fs::rename(backup_msb, &runtime.msb_path);
}

#[cfg(unix)]
fn set_executable(path: &Path) -> MicrosandboxResult<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_executable(_path: &Path) -> MicrosandboxResult<()> {
    Ok(())
}

#[cfg(unix)]
fn create_library_links(lib_dir: &Path, filename: &str) -> MicrosandboxResult<()> {
    let links: Vec<(String, String)> = if cfg!(target_os = "macos") {
        vec![("libkrunfw.dylib".into(), filename.into())]
    } else {
        let soname = format!("libkrunfw.so.{LIBKRUNFW_ABI}");
        vec![
            (soname.clone(), filename.into()),
            ("libkrunfw.so".into(), soname),
        ]
    };
    for (name, target) in links {
        let path = lib_dir.join(name);
        if path.exists() || path.is_symlink() {
            fs::remove_file(&path)?;
        }
        std::os::unix::fs::symlink(target, path)?;
    }
    Ok(())
}

#[cfg(not(unix))]
fn create_library_links(_lib_dir: &Path, _filename: &str) -> MicrosandboxResult<()> {
    Ok(())
}

async fn download_bytes(url: &str) -> MicrosandboxResult<Vec<u8>> {
    let response = reqwest::get(url).await?.error_for_status()?;
    let mut stream = response.bytes_stream();
    let mut data = Vec::new();
    while let Some(chunk) = stream.next().await {
        data.extend_from_slice(&chunk?);
    }
    Ok(data)
}

fn verify_archive_digest(bytes: &[u8], expected: &str) -> MicrosandboxResult<()> {
    let expected = expected.strip_prefix("sha256:").unwrap_or(expected);
    if expected.len() != 64 || !expected.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(MicrosandboxError::Custom(
            "invalid expected SHA-256 digest".into(),
        ));
    }
    let actual = hex::encode(Sha256::digest(bytes));
    if !actual.eq_ignore_ascii_case(expected) {
        return Err(MicrosandboxError::Custom(format!(
            "runtime archive SHA-256 mismatch: expected {expected}, got {actual}"
        )));
    }
    Ok(())
}

fn verify_home(config: &GlobalConfig) -> MicrosandboxResult<()> {
    verify_installation(
        &config.home().join(BIN_SUBDIR),
        &config.home().join(LIB_SUBDIR),
    )
}

fn resolved_installed(config: &GlobalConfig) -> MicrosandboxResult<ResolvedRuntime> {
    let runtime = runtime_in_home(config);
    require_pair(
        runtime.msb_path,
        Some(runtime.libkrunfw_path),
        RuntimeOrigin::Installed,
    )
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn archive_bytes(entries: &[(&str, tar::EntryType, &[u8])]) -> Vec<u8> {
        let encoder = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        let mut archive = tar::Builder::new(encoder);
        for (name, entry_type, bytes) in entries {
            let mut header = tar::Header::new_gnu();
            // Write the raw name so malicious fixtures reach our reader instead
            // of being rejected by tar::Builder's safe path setter first.
            assert!(name.len() < 100, "fixture name fits the tar name field");
            header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
            header.set_entry_type(*entry_type);
            if entry_type.is_symlink() || entry_type.is_hard_link() {
                header.set_link_name("../outside-target").unwrap();
            }
            header.set_mode(0o755);
            header.set_size(bytes.len() as u64);
            header.set_cksum();
            archive.append(&header, *bytes).unwrap();
        }
        archive
            .into_inner()
            .unwrap()
            .finish()
            .expect("finish test runtime archive")
    }

    fn pair_fixture(root: &Path, name: &str) -> (GlobalConfig, PathBuf) {
        let config = GlobalConfig {
            home: Some(root.join(name)),
            ..Default::default()
        };
        let runtime = runtime_in_home(&config);
        fs::create_dir_all(runtime.msb_path.parent().unwrap()).unwrap();
        fs::create_dir_all(runtime.libkrunfw_path.parent().unwrap()).unwrap();
        fs::write(&runtime.msb_path, b"an older installed runtime").unwrap();
        fs::write(&runtime.libkrunfw_path, b"matching firmware").unwrap();
        (config, runtime.msb_path)
    }

    #[test]
    fn home_precedes_package_without_inspecting_versions() {
        let temp = tempfile::tempdir().unwrap();
        let (config, home_msb) = pair_fixture(temp.path(), "home");
        let (_, packaged_msb) = pair_fixture(temp.path(), "package");
        let runtime = resolve_runtime_candidates(
            &config,
            RuntimeCandidates {
                packaged_msb: Some(packaged_msb),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(runtime.msb_path, home_msb);
        assert_eq!(runtime.origin, RuntimeOrigin::Home);
    }

    #[test]
    fn package_is_used_only_when_home_is_absent() {
        let temp = tempfile::tempdir().unwrap();
        let (_, packaged_msb) = pair_fixture(temp.path(), "package");
        let config = GlobalConfig {
            home: Some(temp.path().join("absent")),
            ..Default::default()
        };
        let runtime = resolve_runtime_candidates(
            &config,
            RuntimeCandidates {
                packaged_msb: Some(packaged_msb.clone()),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(runtime.msb_path, packaged_msb);
        assert_eq!(runtime.origin, RuntimeOrigin::SdkPackage);
        assert!(!config.home().exists(), "resolution must remain read-only");
    }

    #[test]
    fn neither_half_of_a_partial_home_is_masked_by_package() {
        let temp = tempfile::tempdir().unwrap();
        let (_, packaged_msb) = pair_fixture(temp.path(), "package");
        for remove_msb in [false, true] {
            let (config, _) =
                pair_fixture(temp.path(), if remove_msb { "no-msb" } else { "no-lib" });
            let home = runtime_in_home(&config);
            fs::remove_file(if remove_msb {
                &home.msb_path
            } else {
                &home.libkrunfw_path
            })
            .unwrap();
            assert!(matches!(
                resolve_runtime_candidates(
                    &config,
                    RuntimeCandidates {
                        packaged_msb: Some(packaged_msb.clone()),
                        ..Default::default()
                    }
                ),
                Err(MicrosandboxError::RuntimeIncomplete(_))
            ));
        }
    }

    #[test]
    fn explicit_paths_precede_home_and_package_and_fail_closed() {
        let temp = tempfile::tempdir().unwrap();
        let (mut config, _) = pair_fixture(temp.path(), "home");
        let (_, packaged_msb) = pair_fixture(temp.path(), "package");
        let (_, configured_msb) = pair_fixture(temp.path(), "configured");
        let (_, explicit_msb) = pair_fixture(temp.path(), "explicit");
        let (_, env_msb) = pair_fixture(temp.path(), "environment");
        config.paths.msb = Some(configured_msb.clone());
        for (environment, explicit, expected) in [
            (Some(env_msb.clone()), Some(explicit_msb.clone()), env_msb),
            (None, Some(explicit_msb.clone()), explicit_msb),
            (None, None, configured_msb),
        ] {
            let runtime = resolve_runtime_candidates(
                &config,
                RuntimeCandidates {
                    env_msb: environment,
                    explicit_msb: explicit,
                    packaged_msb: Some(packaged_msb.clone()),
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(runtime.msb_path, expected);
        }
        assert!(matches!(
            resolve_runtime_candidates(
                &config,
                RuntimeCandidates {
                    env_msb: Some(temp.path().join("missing")),
                    packaged_msb: Some(packaged_msb),
                    ..Default::default()
                }
            ),
            Err(MicrosandboxError::RuntimeIncomplete(_))
        ));
    }

    #[test]
    fn explicit_library_override_applies_to_home_or_package() {
        let temp = tempfile::tempdir().unwrap();
        let (home, _) = pair_fixture(temp.path(), "home");
        let (_, packaged_msb) = pair_fixture(temp.path(), "package");
        let library = temp.path().join("user-library");
        fs::write(&library, b"explicit firmware").unwrap();
        for config in [
            home,
            GlobalConfig {
                home: Some(temp.path().join("absent")),
                ..Default::default()
            },
        ] {
            let runtime = resolve_runtime_candidates(
                &config,
                RuntimeCandidates {
                    explicit_library: Some(library.clone()),
                    packaged_msb: Some(packaged_msb.clone()),
                    ..Default::default()
                },
            )
            .unwrap();
            assert_eq!(runtime.libkrunfw_path, library);
        }
    }

    #[test]
    fn explicit_library_without_any_executable_does_not_trigger_installation() {
        let temp = tempfile::tempdir().unwrap();
        let config = GlobalConfig {
            home: Some(temp.path().join("absent")),
            ..Default::default()
        };
        assert!(matches!(
            resolve_runtime_candidates(
                &config,
                RuntimeCandidates {
                    explicit_library: Some(temp.path().join("library")),
                    ..Default::default()
                }
            ),
            Err(MicrosandboxError::RuntimeIncomplete(_))
        ));
    }

    #[tokio::test]
    async fn ensure_reuses_home_even_when_embedded_install_is_requested() {
        let temp = tempfile::tempdir().unwrap();
        let (config, home_msb) = pair_fixture(temp.path(), "home");
        // This also works without the feature: resolution wins before inspecting
        // the install source, force flag, digest, or requested release version.
        let runtime = ensure_runtime(
            &config,
            InstallOptions {
                source: InstallSource::EmbeddedArchive,
                force: true,
                expected_archive_sha256: Some("invalid".into()),
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(runtime.msb_path, home_msb);
        // Read the fixture-owned path after checking the returned selection. A
        // resolver result must never choose which file this assertion reads.
        assert_eq!(fs::read(&home_msb).unwrap(), b"an older installed runtime");
    }

    #[cfg(feature = "embed-binaries")]
    #[tokio::test]
    async fn embedded_archive_is_installed_only_by_explicit_ensure() {
        let temp = tempfile::tempdir().unwrap();
        let home = temp.path().join("absent");
        let expected_msb = home
            .join(BIN_SUBDIR)
            .join(microsandbox_utils::msb_binary_filename(
                std::env::consts::OS,
            ));
        let expected_library = home
            .join(LIB_SUBDIR)
            .join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS));
        let config = GlobalConfig {
            home: Some(home),
            ..Default::default()
        };
        assert!(matches!(
            resolve_runtime(&config),
            Err(MicrosandboxError::RuntimeNotInstalled(_))
        ));
        assert!(!config.home().exists());
        let runtime = ensure_runtime(
            &config,
            InstallOptions {
                source: InstallSource::EmbeddedArchive,
                ..Default::default()
            },
        )
        .await
        .unwrap();
        assert_eq!(runtime.origin, RuntimeOrigin::Installed);
        // Assert exact destinations before checking fixture-owned paths. Archive
        // contents and resolver results cannot redirect these filesystem probes.
        assert_eq!(runtime.msb_path, expected_msb);
        assert_eq!(runtime.libkrunfw_path, expected_library);
        assert!(expected_msb.is_file());
        assert!(expected_library.is_file());
        assert_eq!(
            resolve_runtime(&config).unwrap().origin,
            RuntimeOrigin::Home
        );
    }

    #[tokio::test]
    async fn directory_install_publishes_the_complete_pair() {
        let source = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let msb_name = microsandbox_utils::msb_binary_filename(std::env::consts::OS);
        let library_name = microsandbox_utils::libkrunfw_filename(std::env::consts::OS);
        fs::write(source.path().join(&msb_name), b"msb").unwrap();
        fs::write(source.path().join(&library_name), b"libkrunfw").unwrap();
        let config = GlobalConfig {
            home: Some(home.path().to_path_buf()),
            ..Default::default()
        };

        let runtime = install_runtime(
            &config,
            InstallOptions {
                source: InstallSource::Directory(source.path().to_path_buf()),
                verify: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(runtime.origin, RuntimeOrigin::Installed);
        let expected_msb = home.path().join(BIN_SUBDIR).join(msb_name);
        let expected_library = home.path().join(LIB_SUBDIR).join(library_name);
        assert_eq!(runtime.msb_path, expected_msb);
        assert_eq!(runtime.libkrunfw_path, expected_library);
        assert!(expected_msb.is_file());
        assert!(expected_library.is_file());
    }

    #[tokio::test]
    async fn forced_directory_install_replaces_both_files() {
        let source = tempfile::tempdir().unwrap();
        let home = tempfile::tempdir().unwrap();
        let msb_name = microsandbox_utils::msb_binary_filename(std::env::consts::OS);
        let library_name = microsandbox_utils::libkrunfw_filename(std::env::consts::OS);
        fs::create_dir_all(home.path().join(BIN_SUBDIR)).unwrap();
        fs::create_dir_all(home.path().join(LIB_SUBDIR)).unwrap();
        fs::write(home.path().join(BIN_SUBDIR).join(&msb_name), b"old-msb").unwrap();
        fs::write(
            home.path().join(LIB_SUBDIR).join(&library_name),
            b"old-library",
        )
        .unwrap();
        fs::write(source.path().join(&msb_name), b"new-msb").unwrap();
        fs::write(source.path().join(&library_name), b"new-library").unwrap();
        let config = GlobalConfig {
            home: Some(home.path().to_path_buf()),
            ..Default::default()
        };

        let runtime = install_runtime(
            &config,
            InstallOptions {
                source: InstallSource::Directory(source.path().to_path_buf()),
                force: true,
                verify: false,
                ..Default::default()
            },
        )
        .await
        .unwrap();

        let expected_msb = home.path().join(BIN_SUBDIR).join(msb_name);
        let expected_library = home.path().join(LIB_SUBDIR).join(library_name);
        assert_eq!(runtime.msb_path, expected_msb);
        assert_eq!(runtime.libkrunfw_path, expected_library);
        assert_eq!(fs::read(expected_msb).unwrap(), b"new-msb");
        assert_eq!(fs::read(expected_library).unwrap(), b"new-library");
    }

    #[test]
    fn explicit_partial_pair_fails_closed() {
        let temp = tempfile::tempdir().unwrap();
        let msb = temp.path().join("msb");
        fs::write(&msb, b"msb").unwrap();
        let config = GlobalConfig {
            paths: crate::config::PathsConfig {
                msb: Some(msb),
                libkrunfw: Some(temp.path().join("missing-libkrunfw")),
                ..Default::default()
            },
            ..Default::default()
        };

        assert!(matches!(
            resolve_runtime(&config),
            Err(MicrosandboxError::RuntimeIncomplete(_))
        ));
        // Public path helpers must not independently accept the existing half of a broken pair.
        assert!(matches!(
            config.resolve_msb_path(),
            Err(MicrosandboxError::RuntimeIncomplete(_))
        ));
        assert!(matches!(
            config.resolve_libkrunfw_path(),
            Err(MicrosandboxError::RuntimeIncomplete(_))
        ));
    }

    #[test]
    fn runtime_resolution_is_read_only_when_the_pair_is_absent() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("missing-home");
        let config = GlobalConfig {
            home: Some(home.clone()),
            ..Default::default()
        };

        assert!(matches!(
            resolve_runtime(&config),
            Err(MicrosandboxError::RuntimeNotInstalled(_))
        ));
        assert!(config.resolve_msb_path().is_err());
        assert!(config.resolve_libkrunfw_path().is_err());
        assert!(!home.exists());
    }

    #[tokio::test]
    async fn archive_digest_mismatch_precedes_installation_mutations() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("uncreated-home");
        let archive = root.path().join("runtime.tar.gz");
        fs::write(&archive, b"untrusted archive bytes").unwrap();
        let config = GlobalConfig {
            home: Some(home.clone()),
            ..Default::default()
        };
        let error = install_runtime(
            &config,
            InstallOptions {
                source: InstallSource::Archive(archive),
                expected_archive_sha256: Some("00".repeat(32)),
                verify: false,
                ..Default::default()
            },
        )
        .await
        .unwrap_err();
        assert!(error.to_string().contains("SHA-256"), "{error}");
        assert!(!home.exists());
    }

    #[test]
    fn runtime_archive_rejects_unexpected_entries() {
        let home = tempfile::tempdir().unwrap();
        let config = GlobalConfig {
            home: Some(home.path().to_path_buf()),
            ..Default::default()
        };
        let msb_name = microsandbox_utils::msb_binary_filename(std::env::consts::OS);
        let library_name = microsandbox_utils::libkrunfw_filename(std::env::consts::OS);
        let archive = archive_bytes(&[
            (&msb_name, tar::EntryType::Regular, b"msb"),
            (&library_name, tar::EntryType::Regular, b"libkrunfw"),
            ("unexpected", tar::EntryType::Regular, b"unexpected"),
        ]);

        let error = install_archive_bytes(&config, &archive, false).unwrap_err();
        assert!(error.to_string().contains("unexpected entry"));
        assert!(!runtime_in_home(&config).msb_path.exists());
        assert!(!runtime_in_home(&config).libkrunfw_path.exists());
    }

    #[tokio::test]
    async fn archive_install_cannot_choose_the_returned_executable_path() {
        let root = tempfile::tempdir().unwrap();
        let home = root.path().join("home");
        let archive_path = root.path().join("caller-selected-archive-name.tar.gz");
        let msb_name = microsandbox_utils::msb_binary_filename(std::env::consts::OS);
        let library_name = microsandbox_utils::libkrunfw_filename(std::env::consts::OS);
        let archive = archive_bytes(&[
            (
                &msb_name,
                tar::EntryType::Regular,
                b"../not-an-executable-path",
            ),
            (&library_name, tar::EntryType::Regular, b"library payload"),
        ]);
        fs::write(&archive_path, archive).unwrap();
        let config = GlobalConfig {
            home: Some(home.clone()),
            ..Default::default()
        };
        let runtime = install_runtime(
            &config,
            InstallOptions {
                source: InstallSource::Archive(archive_path),
                ..Default::default()
            },
        )
        .await
        .unwrap();

        assert_eq!(runtime.origin, RuntimeOrigin::Installed);
        assert_eq!(runtime.msb_path, home.join(BIN_SUBDIR).join(msb_name));
        assert_eq!(
            runtime.libkrunfw_path,
            home.join(LIB_SUBDIR).join(library_name)
        );
        assert_eq!(
            fs::read(runtime.msb_path).unwrap(),
            b"../not-an-executable-path"
        );
        assert_eq!(
            fs::read(runtime.libkrunfw_path).unwrap(),
            b"library payload"
        );
        assert!(!root.path().join("not-an-executable-path").exists());
    }

    #[test]
    fn unsafe_archive_entries_fail_before_publishing_or_replacing_a_pair() {
        let msb_name = microsandbox_utils::msb_binary_filename(std::env::consts::OS);
        let library_name = microsandbox_utils::libkrunfw_filename(std::env::consts::OS);
        for (name, entry_type, expected_error) in [
            (".", tar::EntryType::Regular, "unexpected entry"),
            ("..", tar::EntryType::Regular, "unexpected entry"),
            ("", tar::EntryType::Regular, "unexpected entry"),
            (
                "../escaped-msb",
                tar::EntryType::Regular,
                "unexpected entry",
            ),
            ("/absolute-msb", tar::EntryType::Regular, "unexpected entry"),
            ("nested/msb", tar::EntryType::Regular, "unexpected entry"),
            ("unexpected", tar::EntryType::Regular, "unexpected entry"),
            (
                msb_name.as_str(),
                tar::EntryType::Symlink,
                "unexpected entry",
            ),
            (
                library_name.as_str(),
                tar::EntryType::Link,
                "unexpected entry",
            ),
            (msb_name.as_str(), tar::EntryType::Regular, "duplicate msb"),
        ] {
            for existing in [false, true] {
                let root = tempfile::tempdir().unwrap();
                let config = GlobalConfig {
                    home: Some(root.path().join("home")),
                    ..Default::default()
                };
                let runtime = runtime_in_home(&config);
                if existing {
                    fs::create_dir_all(runtime.msb_path.parent().unwrap()).unwrap();
                    fs::create_dir_all(runtime.libkrunfw_path.parent().unwrap()).unwrap();
                    fs::write(&runtime.msb_path, b"original-msb").unwrap();
                    fs::write(&runtime.libkrunfw_path, b"original-library").unwrap();
                }
                // Place the bad entry after both legitimate files: even a
                // complete staged pair must not publish until parsing finishes.
                let archive = archive_bytes(&[
                    (&msb_name, tar::EntryType::Regular, b"replacement-msb"),
                    (
                        &library_name,
                        tar::EntryType::Regular,
                        b"replacement-library",
                    ),
                    (name, entry_type, b""),
                ]);
                let error = install_archive_bytes(&config, &archive, true).unwrap_err();
                assert!(
                    error.to_string().contains(expected_error),
                    "{name}: {error}"
                );
                if existing {
                    assert_eq!(fs::read(&runtime.msb_path).unwrap(), b"original-msb");
                    assert_eq!(
                        fs::read(&runtime.libkrunfw_path).unwrap(),
                        b"original-library"
                    );
                } else {
                    assert!(!runtime.msb_path.exists());
                    assert!(!runtime.libkrunfw_path.exists());
                }
                assert!(!root.path().join("escaped-msb").exists());
                assert!(!config.home().join("nested").exists());
            }
        }
    }

    #[cfg(feature = "embed-binaries")]
    #[test]
    fn embedded_ensure_materializes_into_normal_home_layout_without_network_io() {
        let home = tempfile::tempdir().unwrap();
        let config = GlobalConfig {
            home: Some(home.path().to_path_buf()),
            ..Default::default()
        };

        // No I/O driver is enabled: a Tokio/reqwest download cannot complete
        // here. This tests the selected embedded branch, not packet filtering
        // or the separate, explicitly requested ReleaseDownload installer.
        let offline = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let embedded = EMBEDDED_RUNTIME_ARCHIVE.expect("compiled embedded runtime");
        let runtime = offline
            .block_on(ensure_runtime(
                &config,
                InstallOptions {
                    source: InstallSource::EmbeddedArchive,
                    expected_archive_sha256: Some(hex::encode(Sha256::digest(embedded))),
                    verify: false,
                    ..Default::default()
                },
            ))
            .unwrap();

        assert_eq!(runtime.origin, RuntimeOrigin::Installed);
        let expected_msb =
            home.path()
                .join(BIN_SUBDIR)
                .join(microsandbox_utils::msb_binary_filename(
                    std::env::consts::OS,
                ));
        let expected_library = home
            .path()
            .join(LIB_SUBDIR)
            .join(microsandbox_utils::libkrunfw_filename(std::env::consts::OS));
        assert_eq!(runtime.msb_path, expected_msb);
        assert_eq!(runtime.libkrunfw_path, expected_library);
        assert!(expected_msb.is_file());
        assert!(expected_library.is_file());
        let mut archive = Archive::new(GzDecoder::new(embedded));
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap();
            let destination = if name == Path::new(expected_msb.file_name().unwrap()) {
                &expected_msb
            } else {
                assert_eq!(name, Path::new(expected_library.file_name().unwrap()));
                &expected_library
            };
            let mut expected = Vec::new();
            std::io::Read::read_to_end(&mut entry, &mut expected).unwrap();
            assert_eq!(fs::read(destination).unwrap(), expected);
        }
    }
}
