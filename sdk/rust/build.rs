//! Build-time acquisition and optional embedding of the host runtime pair.

#[cfg(any(feature = "download-binaries", feature = "embed-binaries"))]
use std::path::{Path, PathBuf};

#[cfg(all(feature = "download-binaries", unix))]
use microsandbox_utils::LIBKRUNFW_ABI;
#[cfg(feature = "download-binaries")]
use microsandbox_utils::{PREBUILT_VERSION, bundle_download_url, http_client, resolve_home};
#[cfg(any(feature = "download-binaries", feature = "embed-binaries"))]
use microsandbox_utils::{libkrunfw_filename, msb_binary_filename};

fn main() {
    println!("cargo:rerun-if-env-changed=MSB_HOME");
    println!("cargo:rerun-if-env-changed=MSB_EMBED_ARTIFACTS_DIR");
    println!("cargo:rerun-if-env-changed=MSB_EMBED_RUNTIME_BUNDLE_PATH");

    #[cfg(feature = "download-binaries")]
    install_runtime_at_build_time();

    #[cfg(feature = "embed-binaries")]
    stage_embedded_runtime();
}

#[cfg(feature = "download-binaries")]
fn install_runtime_at_build_time() {
    let home = resolve_home();
    std::fs::create_dir_all(&home).unwrap_or_else(|error| {
        panic!("failed to create runtime home {}: {error}", home.display())
    });
    let lock =
        microsandbox_utils::process_lock::open_lock_file(&home.join(".runtime-install.lock"))
            .expect("failed to open runtime install lock");
    microsandbox_utils::process_lock::lock_exclusive(&lock)
        .expect("failed to lock runtime installation");
    install_runtime_at_build_time_locked(&home);
    microsandbox_utils::process_lock::unlock(&lock).expect("failed to unlock runtime installation");
}

#[cfg(feature = "download-binaries")]
fn install_runtime_at_build_time_locked(home: &Path) {
    let target_os = target_os();
    let msb_destination = home
        .join(microsandbox_utils::BIN_SUBDIR)
        .join(msb_binary_filename(&target_os));
    let library_destination = home
        .join(microsandbox_utils::LIB_SUBDIR)
        .join(libkrunfw_filename(&target_os));
    println!("cargo:rerun-if-changed={}", msb_destination.display());
    println!("cargo:rerun-if-changed={}", library_destination.display());

    let artifact_directory = artifact_directory();
    let workspace_directory =
        workspace_build_directory().filter(|directory| pair_exists(directory));
    let msb_present = msb_destination.is_file();
    let library_present = library_destination.is_file();
    if msb_present && library_present {
        if target_runs_on_host()
            && installed_msb_version(&msb_destination).as_deref() == Some(PREBUILT_VERSION)
        {
            return;
        }
        // Cross-target binaries cannot be executed by the build script. Compare the complete pair
        // against the selected local source or cached release archive instead of reinstalling it on
        // every Cargo invocation.
        if artifact_directory.as_deref().is_some_and(|directory| {
            pair_matches_directory(directory, &msb_destination, &library_destination)
        }) || workspace_directory.as_deref().is_some_and(|directory| {
            pair_matches_directory(directory, &msb_destination, &library_destination)
        }) || cached_archive_matches_pair(&msb_destination, &library_destination)
        {
            return;
        }
    }
    if msb_present != library_present {
        panic!(
            "refusing to repair a partial runtime installation in {}; remove both files or run explicit setup",
            home.display()
        );
    }

    if let Some(directory) = artifact_directory {
        install_pair(
            &directory.join(msb_binary_filename(&target_os)),
            &directory.join(libkrunfw_filename(&target_os)),
            &msb_destination,
            &library_destination,
        );
        return;
    }

    if let Some(directory) = workspace_directory {
        install_pair(
            &directory.join(msb_binary_filename(&target_os)),
            &directory.join(libkrunfw_filename(&target_os)),
            &msb_destination,
            &library_destination,
        );
        return;
    }

    let archive = download_release_archive();
    install_archive(&archive, &msb_destination, &library_destination);
}

#[cfg(feature = "embed-binaries")]
fn stage_embedded_runtime() {
    let destination = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by Cargo"))
        .join("runtime-bundle.tar.gz");

    if let Some(path) = std::env::var_os("MSB_EMBED_RUNTIME_BUNDLE_PATH").map(PathBuf::from) {
        if !path.is_file() {
            panic!(
                "MSB_EMBED_RUNTIME_BUNDLE_PATH is not a file: {}",
                path.display()
            );
        }
        println!("cargo:rerun-if-changed={}", path.display());
        std::fs::copy(&path, &destination).unwrap_or_else(|error| {
            panic!(
                "failed to copy {} to {}: {error}",
                path.display(),
                destination.display()
            )
        });
        return;
    }

    if let Some(directory) = artifact_directory() {
        create_archive(&directory, &destination);
        return;
    }
    if let Some(directory) = workspace_build_directory()
        && pair_exists(&directory)
    {
        create_archive(&directory, &destination);
        return;
    }

    #[cfg(feature = "download-binaries")]
    {
        let archive = download_release_archive();
        std::fs::write(&destination, archive)
            .unwrap_or_else(|error| panic!("failed to write {}: {error}", destination.display()));
    }

    #[cfg(not(feature = "download-binaries"))]
    panic!(
        "embed-binaries requires MSB_EMBED_RUNTIME_BUNDLE_PATH, \
         MSB_EMBED_ARTIFACTS_DIR, a workspace build/ pair, or download-binaries"
    );
}

#[cfg(any(feature = "download-binaries", feature = "embed-binaries"))]
fn artifact_directory() -> Option<PathBuf> {
    std::env::var_os("MSB_EMBED_ARTIFACTS_DIR").map(|value| {
        let target_os = target_os();
        let directory = PathBuf::from(value);
        if !pair_exists(&directory) {
            panic!(
                "MSB_EMBED_ARTIFACTS_DIR must contain {} and {}",
                msb_binary_filename(&target_os),
                libkrunfw_filename(&target_os)
            );
        }
        println!("cargo:rerun-if-changed={}", directory.display());
        directory
    })
}

#[cfg(any(feature = "download-binaries", feature = "embed-binaries"))]
fn workspace_build_directory() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let root = manifest_dir.parent()?.parent()?;
    Some(root.join("build"))
}

#[cfg(any(feature = "download-binaries", feature = "embed-binaries"))]
fn pair_exists(directory: &Path) -> bool {
    let target_os = target_os();
    directory.join(msb_binary_filename(&target_os)).is_file()
        && directory.join(libkrunfw_filename(&target_os)).is_file()
}

#[cfg(feature = "download-binaries")]
fn download_release_archive() -> Vec<u8> {
    use std::io::Read as _;

    let cache = cached_release_archive_path();
    if let Ok(bytes) = std::fs::read(&cache) {
        return bytes;
    }

    // Build scripts run for the host, so Rust's compile-time architecture constants describe the
    // ARM64 Surface even when Cargo is producing an x64 binary for Prism. Cargo's target variables
    // are the source of truth for selecting the distributable runtime bundle.
    let url = bundle_download_url(PREBUILT_VERSION, &target_arch(), &target_os());
    println!("cargo:warning=downloading microsandbox runtime v{PREBUILT_VERSION} from {url}");
    let response = http_client()
        .get(&url)
        .call()
        .unwrap_or_else(|error| panic!("failed to download {url}: {error}"));
    let mut bytes = Vec::new();
    response
        .into_body()
        .into_reader()
        .read_to_end(&mut bytes)
        .unwrap_or_else(|error| panic!("failed to read {url}: {error}"));
    publish_cached_archive(&cache, &bytes);
    bytes
}

#[cfg(feature = "download-binaries")]
fn cached_release_archive_path() -> PathBuf {
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by Cargo"));
    // Cargo clears OUT_DIR before rerunning a build script. Keep downloaded release inputs in the
    // target profile directory so they survive reruns but are still removed by `cargo clean`.
    let profile_dir = out_dir
        .ancestors()
        .nth(3)
        .expect("OUT_DIR follows Cargo's target/<profile>/build/<package>/out layout");
    profile_dir
        .join(".microsandbox-runtime-cache")
        .join(format!(
            "microsandbox-runtime-{}-{}-{}.tar.gz",
            PREBUILT_VERSION,
            target_os(),
            target_arch()
        ))
}

#[cfg(feature = "download-binaries")]
fn publish_cached_archive(cache: &Path, bytes: &[u8]) {
    let directory = cache.parent().expect("runtime archive cache parent");
    std::fs::create_dir_all(directory)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", directory.display()));
    let staged = cache.with_extension(format!("stage-{}", std::process::id()));
    std::fs::write(&staged, bytes)
        .unwrap_or_else(|error| panic!("failed to stage {}: {error}", staged.display()));
    match std::fs::rename(&staged, cache) {
        Ok(()) => {}
        // Another build script may publish the same immutable version/target archive first.
        Err(_) if cache.is_file() => {
            let _ = std::fs::remove_file(staged);
        }
        Err(error) => panic!("failed to publish {}: {error}", cache.display()),
    }
}

#[cfg(feature = "download-binaries")]
fn cached_archive_matches_pair(msb_destination: &Path, library_destination: &Path) -> bool {
    let Ok(bytes) = std::fs::read(cached_release_archive_path()) else {
        return false;
    };
    let Ok(stage) = tempfile::tempdir() else {
        return false;
    };
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    if archive.unpack(stage.path()).is_err() {
        return false;
    }
    let msb = find_file(
        stage.path(),
        msb_destination.file_name().expect("msb filename"),
    );
    let library = find_file(
        stage.path(),
        library_destination.file_name().expect("library filename"),
    );
    files_equal(&msb, msb_destination) && files_equal(&library, library_destination)
}

#[cfg(feature = "download-binaries")]
fn installed_msb_version(path: &Path) -> Option<String> {
    let output = std::process::Command::new(path)
        .arg("--version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()?
        .trim()
        .strip_prefix("msb ")
        .map(str::to_owned)
}

#[cfg(feature = "download-binaries")]
fn install_archive(bytes: &[u8], msb_destination: &Path, library_destination: &Path) {
    let stage = tempfile::tempdir().expect("failed to create runtime staging directory");
    let decoder = flate2::read::GzDecoder::new(std::io::Cursor::new(bytes));
    let mut archive = tar::Archive::new(decoder);
    archive
        .unpack(stage.path())
        .expect("failed to unpack runtime archive");
    let msb = find_file(
        stage.path(),
        msb_destination.file_name().expect("msb filename"),
    );
    let library = find_file(
        stage.path(),
        library_destination.file_name().expect("library filename"),
    );
    install_pair(&msb, &library, msb_destination, library_destination);
}

#[cfg(feature = "download-binaries")]
fn find_file(root: &Path, filename: &std::ffi::OsStr) -> PathBuf {
    let entries = std::fs::read_dir(root).expect("failed to read extracted runtime archive");
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            let candidate = find_file(&path, filename);
            if candidate.is_file() {
                return candidate;
            }
        } else if path.file_name() == Some(filename) {
            return path;
        }
    }
    PathBuf::new()
}

#[cfg(feature = "download-binaries")]
fn pair_matches_directory(
    directory: &Path,
    msb_destination: &Path,
    library_destination: &Path,
) -> bool {
    let target_os = target_os();
    files_equal(
        &directory.join(msb_binary_filename(&target_os)),
        msb_destination,
    ) && files_equal(
        &directory.join(libkrunfw_filename(&target_os)),
        library_destination,
    )
}

#[cfg(feature = "download-binaries")]
fn files_equal(left: &Path, right: &Path) -> bool {
    use std::io::{BufReader, Read as _};

    let Ok(left_file) = std::fs::File::open(left) else {
        return false;
    };
    let Ok(right_file) = std::fs::File::open(right) else {
        return false;
    };
    if left_file.metadata().ok().map(|metadata| metadata.len())
        != right_file.metadata().ok().map(|metadata| metadata.len())
    {
        return false;
    }

    let mut left_reader = BufReader::new(left_file);
    let mut right_reader = BufReader::new(right_file);
    let mut left_buffer = [0_u8; 64 * 1024];
    let mut right_buffer = [0_u8; 64 * 1024];
    loop {
        let Ok(left_read) = left_reader.read(&mut left_buffer) else {
            return false;
        };
        let Ok(right_read) = right_reader.read(&mut right_buffer) else {
            return false;
        };
        if left_read != right_read || left_buffer[..left_read] != right_buffer[..right_read] {
            return false;
        }
        if left_read == 0 {
            return true;
        }
    }
}

#[cfg(feature = "download-binaries")]
fn install_pair(msb: &Path, library: &Path, msb_destination: &Path, library_destination: &Path) {
    if !msb.is_file() || !library.is_file() {
        panic!("runtime source does not contain both msb and libkrunfw");
    }
    std::fs::create_dir_all(msb_destination.parent().expect("msb parent"))
        .expect("failed to create runtime bin directory");
    std::fs::create_dir_all(library_destination.parent().expect("library parent"))
        .expect("failed to create runtime lib directory");

    let id = std::process::id();
    let staged_library = library_destination.with_extension(format!("stage-{id}"));
    let staged_msb = msb_destination.with_extension(format!("stage-{id}"));
    std::fs::copy(library, &staged_library).expect("failed to stage libkrunfw");
    std::fs::copy(msb, &staged_msb).expect("failed to stage msb");
    set_executable(&staged_library);
    set_executable(&staged_msb);

    let replacing = msb_destination.is_file() && library_destination.is_file();
    let backup_library = library_destination.with_extension(format!("backup-{id}"));
    let backup_msb = msb_destination.with_extension(format!("backup-{id}"));
    let result = (|| -> std::io::Result<()> {
        if replacing {
            // Remove the completion marker before changing the library.
            std::fs::rename(msb_destination, &backup_msb)?;
            if let Err(error) = std::fs::rename(library_destination, &backup_library) {
                let _ = std::fs::rename(&backup_msb, msb_destination);
                return Err(error);
            }
        }
        std::fs::rename(&staged_library, library_destination)?;
        create_library_links(
            library_destination.parent().expect("library parent"),
            library_destination
                .file_name()
                .and_then(|name| name.to_str())
                .expect("UTF-8 library filename"),
        )?;
        // Publish msb last: readers treat it as the pair completion marker.
        std::fs::rename(&staged_msb, msb_destination)?;
        Ok(())
    })();
    if let Err(error) = result {
        let _ = std::fs::remove_file(library_destination);
        if replacing {
            let _ = std::fs::rename(&backup_library, library_destination);
            let _ = std::fs::rename(&backup_msb, msb_destination);
        }
        panic!("failed to publish runtime pair: {error}");
    }
    if replacing {
        let _ = std::fs::remove_file(backup_library);
        let _ = std::fs::remove_file(backup_msb);
    }
}

#[cfg(feature = "embed-binaries")]
fn create_archive(directory: &Path, destination: &Path) {
    use flate2::{Compression, write::GzEncoder};

    let target_os = target_os();
    let file = std::fs::File::create(destination)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", destination.display()));
    let encoder = GzEncoder::new(file, Compression::default());
    let mut archive = tar::Builder::new(encoder);
    for filename in [
        msb_binary_filename(&target_os),
        libkrunfw_filename(&target_os),
    ] {
        let source = directory.join(&filename);
        archive
            .append_path_with_name(&source, &filename)
            .unwrap_or_else(|error| panic!("failed to archive {}: {error}", source.display()));
    }
    archive.finish().expect("failed to finish runtime archive");
}

#[cfg(all(feature = "download-binaries", unix))]
fn set_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o755))
        .expect("failed to mark runtime artifact executable");
}

#[cfg(all(feature = "download-binaries", not(unix)))]
fn set_executable(_path: &Path) {}

#[cfg(all(feature = "download-binaries", unix))]
fn create_library_links(directory: &Path, filename: &str) -> std::io::Result<()> {
    let links: Vec<(String, String)> = if target_os() == "macos" {
        vec![("libkrunfw.dylib".into(), filename.into())]
    } else {
        let soname = format!("libkrunfw.so.{LIBKRUNFW_ABI}");
        vec![
            (soname.clone(), filename.into()),
            ("libkrunfw.so".into(), soname),
        ]
    };
    for (name, target) in links {
        let path = directory.join(name);
        if path.exists() || path.is_symlink() {
            std::fs::remove_file(&path)?;
        }
        std::os::unix::fs::symlink(target, &path)?;
    }
    Ok(())
}

#[cfg(all(feature = "download-binaries", not(unix)))]
fn create_library_links(_directory: &Path, _filename: &str) -> std::io::Result<()> {
    Ok(())
}

#[cfg(any(feature = "download-binaries", feature = "embed-binaries"))]
fn target_os() -> String {
    std::env::var("CARGO_CFG_TARGET_OS").expect("Cargo target operating system")
}

#[cfg(feature = "download-binaries")]
fn target_arch() -> String {
    std::env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo target architecture")
}

#[cfg(feature = "download-binaries")]
fn target_runs_on_host() -> bool {
    target_arch() == std::env::consts::ARCH && target_os() == std::env::consts::OS
}
