#[cfg(feature = "embed-binaries")]
use std::path::{Path, PathBuf};

#[cfg(all(feature = "embed-binaries", not(feature = "download-binaries")))]
use std::time::SystemTime;

#[cfg(feature = "embed-binaries")]
use microsandbox_utils::AGENTD_BINARY;
#[cfg(feature = "download-binaries")]
use microsandbox_utils::{PREBUILT_VERSION, agentd_download_url, http_client};

#[cfg(feature = "embed-binaries")]
#[path = "lib/agentd/format.rs"]
mod agentd_format;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-env-changed=MSB_EMBED_ARTIFACTS_DIR");

    #[cfg(feature = "embed-binaries")]
    {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by Cargo"));
        stage_agentd(&workspace_root, &out_dir);
    }
}

#[cfg(feature = "embed-binaries")]
fn stage_agentd(workspace_root: &Path, out_dir: &Path) {
    let destination = out_dir.join(AGENTD_BINARY);
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo target architecture is set");

    if let Some(artifacts_dir) = std::env::var_os("MSB_EMBED_ARTIFACTS_DIR").map(PathBuf::from) {
        let source = artifacts_dir.join(AGENTD_BINARY);
        if !source.is_file() {
            panic!(
                "MSB_EMBED_ARTIFACTS_DIR does not contain {AGENTD_BINARY}: {}",
                source.display()
            );
        }
        println!("cargo:rerun-if-changed={}", source.display());
        validate_agentd_file(&source, &target_arch);
        copy_agentd(&source, &destination);
        return;
    }

    let local = workspace_root.join("build").join(AGENTD_BINARY);
    if local.is_file() {
        // Source and output watches belong only to the workspace-local path. Watching a missing
        // build/agentd makes Cargo rerun this script forever for ordinary release-download builds.
        println!("cargo:rerun-if-changed=../agentd");
        println!("cargo:rerun-if-changed=../protocol");
        println!("cargo:rerun-if-changed={}", local.display());
        #[cfg(not(feature = "download-binaries"))]
        reject_stale_agentd(workspace_root, &local);
        validate_agentd_file(&local, &target_arch);
        copy_agentd(&local, &destination);
        return;
    }

    #[cfg(feature = "download-binaries")]
    {
        let url = agentd_download_url(PREBUILT_VERSION, &target_arch);
        download_to(&url, &destination);
        validate_agentd_file(&destination, &target_arch);
    }

    #[cfg(not(feature = "download-binaries"))]
    panic!(
        "agentd is required by embed-binaries but was not found. Set \
         MSB_EMBED_ARTIFACTS_DIR or run `just build-agentd`; alternatively enable \
         download-binaries"
    );
}

#[cfg(feature = "embed-binaries")]
fn validate_agentd_file(path: &Path, target_arch: &str) {
    let bytes = std::fs::read(path).unwrap_or_else(|error| {
        panic!("failed to read Agentd payload {}: {error}", path.display())
    });
    agentd_format::validate_agentd(&bytes, target_arch).unwrap_or_else(|error| {
        panic!(
            "invalid Agentd payload {} for target architecture {target_arch}: {error}",
            path.display()
        )
    });
}

#[cfg(feature = "embed-binaries")]
fn copy_agentd(source: &Path, destination: &Path) {
    match std::fs::remove_file(destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("failed to replace {}: {error}", destination.display()),
    }
    std::fs::copy(source, destination).unwrap_or_else(|error| {
        panic!(
            "failed to copy {} to {}: {error}",
            source.display(),
            destination.display()
        )
    });
}

#[cfg(all(feature = "embed-binaries", not(feature = "download-binaries")))]
fn reject_stale_agentd(workspace_root: &Path, binary: &Path) {
    let binary_time = std::fs::metadata(binary).and_then(|metadata| metadata.modified());
    let Ok(binary_time) = binary_time else {
        return;
    };
    let stale = [
        workspace_root.join("crates/agentd"),
        workspace_root.join("crates/protocol"),
    ]
    .iter()
    .filter_map(|root| newest_tree_mtime(root))
    .any(|source_time| source_time > binary_time);
    if stale {
        panic!(
            "build/{AGENTD_BINARY} is older than crates/agentd or crates/protocol source. \
             Run `just build-agentd` to rebuild the guest agent binary."
        );
    }
}

#[cfg(all(feature = "embed-binaries", not(feature = "download-binaries")))]
fn newest_tree_mtime(root: &Path) -> Option<SystemTime> {
    fn walk(path: &Path, newest: &mut Option<SystemTime>) {
        let Ok(entries) = std::fs::read_dir(path) else {
            return;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(metadata) = entry.metadata() else {
                continue;
            };
            if metadata.is_dir() {
                walk(&path, newest);
            } else if let Ok(modified) = metadata.modified()
                && newest.is_none_or(|current| modified > current)
            {
                *newest = Some(modified);
            }
        }
    }

    let mut newest = None;
    walk(root, &mut newest);
    newest
}

#[cfg(feature = "download-binaries")]
fn download_to(url: &str, destination: &Path) {
    use std::io::Write as _;

    println!("cargo:warning=downloading agentd from {url}");
    let part_path = destination.with_extension("part");
    let response = http_client()
        .get(url)
        .call()
        .unwrap_or_else(|error| panic!("failed to download {url}: {error}"));
    let mut reader = response.into_body().into_reader();
    let mut file = std::fs::File::create(&part_path)
        .unwrap_or_else(|error| panic!("failed to create {}: {error}", part_path.display()));
    std::io::copy(&mut reader, &mut file)
        .unwrap_or_else(|error| panic!("failed to write {}: {error}", part_path.display()));
    file.flush()
        .unwrap_or_else(|error| panic!("failed to flush {}: {error}", part_path.display()));
    match std::fs::remove_file(destination) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => panic!("failed to replace {}: {error}", destination.display()),
    }
    std::fs::rename(&part_path, destination).unwrap_or_else(|error| {
        panic!(
            "failed to rename {} to {}: {error}",
            part_path.display(),
            destination.display()
        )
    });
}
