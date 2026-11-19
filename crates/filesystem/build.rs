#[cfg(feature = "embed-binaries")]
use std::path::{Path, PathBuf};

#[cfg(feature = "embed-binaries")]
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
    println!("cargo:rustc-check-cfg=cfg(msb_embedded_storage_reader_v1)");
    println!("cargo:rerun-if-env-changed=MSB_EMBED_ARTIFACTS_DIR");

    #[cfg(feature = "embed-binaries")]
    {
        let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let out_dir = PathBuf::from(std::env::var("OUT_DIR").expect("OUT_DIR is set by Cargo"));
        stage_agentd(&workspace_root, &out_dir);
        // Attribute this capability to the actual immutable embedded artifact once. Older
        // downloads can still boot normal workloads; their binaries cannot serve this protocol.
        let marker = b"microsandbox-private-storage-reader/1";
        let staged = std::fs::read(out_dir.join(AGENTD_BINARY)).expect("staged guest agent");
        if staged.windows(marker.len()).any(|bytes| bytes == marker) {
            println!("cargo:rustc-cfg=msb_embedded_storage_reader_v1");
        }
    }
}

#[cfg(feature = "embed-binaries")]
fn stage_agentd(workspace_root: &Path, out_dir: &Path) {
    let destination = out_dir.join(AGENTD_BINARY);
    let target_arch =
        std::env::var("CARGO_CFG_TARGET_ARCH").expect("Cargo target architecture is set");

    // A caller-supplied artifact is this build's guest payload, so it wins over
    // both the local artifact and the released download.
    if let Some(artifacts_dir) = std::env::var_os("MSB_EMBED_ARTIFACTS_DIR").map(PathBuf::from) {
        let source = artifacts_dir.join(AGENTD_BINARY);
        if !source.is_file() {
            panic!(
                "MSB_EMBED_ARTIFACTS_DIR does not contain {AGENTD_BINARY}: {}",
                source.display()
            );
        }
        embed_staged_agentd(&source, &destination, &target_arch);
        return;
    }
    println!("cargo:rerun-if-env-changed=MSB_EMBED_AGENTD_PATH");
    if let Some(source) = std::env::var_os("MSB_EMBED_AGENTD_PATH").map(PathBuf::from) {
        if !source.is_file() {
            panic!(
                "MSB_EMBED_AGENTD_PATH does not point to an agentd file: {}",
                source.display()
            );
        }
        println!(
            "cargo:warning=microsandbox: embedding the guest agent from \
             MSB_EMBED_AGENTD_PATH={}, not from build/{AGENTD_BINARY}",
            source.display()
        );
        embed_staged_agentd(&source, &destination, &target_arch);
        return;
    }

    let local = workspace_root.join("build").join(AGENTD_BINARY);
    if local.is_file() {
        // Source and output watches belong only to the workspace-local path. Watching a missing
        // build/agentd makes Cargo rerun this script forever for ordinary release-download builds.
        println!("cargo:rerun-if-changed=../agentd");
        println!("cargo:rerun-if-changed=../protocol");
        println!("cargo:rerun-if-changed={}", local.display());
        // Unconditional: a stale guest agent changes guest-side behaviour with
        // nothing else failing, and the released-artifact fallback must not be
        // what makes that defect observable.
        reject_stale_agentd(workspace_root, &local);
        validate_agentd_file(&local, &target_arch);
        copy_agentd(&local, &destination);
        return;
    }

    // The guest agent is compiled into the host binary. A checkout can always
    // rebuild it, so substituting the released artifact here would silently ship
    // a guest payload built from a different revision of this tree, with nothing
    // else failing. Refuse instead of downloading.
    if let Some((agentd, _protocol)) = guest_agentd_sources(workspace_root) {
        println!("cargo:rerun-if-changed={}", agentd.display());
        panic!("{}", missing_local_agentd_message(&local, &target_arch));
    }

    #[cfg(feature = "download-binaries")]
    {
        let url = agentd_download_url(PREBUILT_VERSION, &target_arch);
        println!(
            "cargo:warning=microsandbox: this build has no guest agent source tree; embedding \
             the released {AGENTD_BINARY} for v{PREBUILT_VERSION} from {url}. Guest-side \
             behaviour is that release's, not any checkout's."
        );
        download_to(&url, &destination);
        validate_agentd_file(&destination, &target_arch);
    }

    #[cfg(not(feature = "download-binaries"))]
    panic!("{}", missing_local_agentd_message(&local, &target_arch));
}

/// Copy and validate an artifact an explicit caller staged.
#[cfg(feature = "embed-binaries")]
fn embed_staged_agentd(source: &Path, destination: &Path, target_arch: &str) {
    println!("cargo:rerun-if-changed={}", source.display());
    validate_agentd_file(source, target_arch);
    copy_agentd(source, destination);
}

/// The guest agent source directories, present only inside a checkout.
///
/// A published crate carries neither directory, which is the difference between
/// a build that can rebuild the guest agent and one that can only consume a
/// released artifact.
#[cfg(feature = "embed-binaries")]
fn guest_agentd_sources(workspace_root: &Path) -> Option<(PathBuf, PathBuf)> {
    let agentd = workspace_root.join("crates/agentd");
    let protocol = workspace_root.join("crates/protocol");
    (agentd.is_dir() && protocol.is_dir()).then_some((agentd, protocol))
}

/// The refusal a checkout with no local `agentd` gets, naming every route back.
///
/// The guest agent is a static Linux binary for the guest architecture, so a host
/// `cargo build` of `crates/agentd` produces a payload this build rejects. The
/// direct route therefore spells out the musl target and its linker requirement.
#[cfg(feature = "embed-binaries")]
fn missing_local_agentd_message(local: &Path, target_arch: &str) -> String {
    let target = format!("{target_arch}-unknown-linux-musl");
    format!(
        "{} is missing, but this tree has the guest agent sources, so this build will not \
         embed a released {AGENTD_BINARY}. The guest agent is compiled into the host binary, \
         and a released artifact comes from a different revision of this tree.\n\
         Build it first: `just build-agentd`.\n\
         Without `just`, cross-build the guest target (needs the musl target and a musl \
         linker, and `just build-agentd` uses Docker on macOS and Windows):\n\
           cargo build --release --target {target} --manifest-path crates/agentd/Cargo.toml\n\
           cp target/{target}/release/agentd {}\n\
         To embed an artifact built elsewhere, set MSB_EMBED_ARTIFACTS_DIR to its directory or \
         MSB_EMBED_AGENTD_PATH to the file.",
        local.display(),
        local.display(),
    )
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

#[cfg(feature = "embed-binaries")]
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

#[cfg(feature = "embed-binaries")]
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
