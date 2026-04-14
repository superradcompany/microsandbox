use std::path::{Path, PathBuf};
#[cfg(not(feature = "prebuilt"))]
use std::time::SystemTime;

use microsandbox_utils::AGENTD_BINARY;
#[cfg(feature = "prebuilt")]
use microsandbox_utils::{PREBUILT_VERSION, agentd_download_url};

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../utils/lib/lib.rs");
    // Invalidate the embedded agentd when its source changes.
    // This won't auto-rebuild agentd (that requires `just build-agentd`),
    // but it forces cargo to re-check that `build/agentd` is fresh.
    println!("cargo:rerun-if-changed=../agentd");
    println!("cargo:rerun-if-changed=../protocol");

    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    build_agentd(&workspace_root, &out_dir);
}

fn build_agentd(workspace_root: &Path, out_dir: &Path) {
    #[cfg(feature = "prebuilt")]
    {
        let dest = out_dir.join(AGENTD_BINARY);
        if dest.exists() {
            return;
        }

       // In CI, prefer the locally-built agentd from workspace build/.
        if std::env::var_os("CI").is_some() {
            let local = workspace_root.join("build").join(AGENTD_BINARY);
            if local.is_file() {
                std::fs::copy(&local, &dest).expect("failed to copy agentd from build/");
                return;
            }
        }
        let _ = workspace_root;
        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        let url = agentd_download_url(PREBUILT_VERSION, &arch);

        download_to(&url, &dest);
    }

    #[cfg(not(feature = "prebuilt"))]
    {
        let source = workspace_root.join("build").join(AGENTD_BINARY);
        println!("cargo:rerun-if-changed={}", source.display());

        if !source.exists() {
            panic!(
                "{AGENTD_BINARY} binary not found at `{}`.\n\
                 Run `just build-deps` first.",
                source.display()
            );
        }

        // Fail fast if build/agentd is stale relative to the guest source tree.
        // A warning is too easy to miss and leads to confusing runtime behavior
        // when msb embeds an older guest payload than the source implies.
        let agentd_src = workspace_root.join("crates/agentd");
        let protocol_src = workspace_root.join("crates/protocol");
        if let Ok(bin_time) = std::fs::metadata(&source).and_then(|m| m.modified())
            && newest_tree_mtime(&agentd_src)
                .into_iter()
                .chain(newest_tree_mtime(&protocol_src))
                .any(|src_time| src_time > bin_time)
        {
            panic!(
                "build/{AGENTD_BINARY} is older than crates/agentd or crates/protocol source.\n\
                 Run `just build-agentd` to rebuild the guest agent binary."
            );
        }

        let dest = out_dir.join(AGENTD_BINARY);
        std::fs::copy(&source, &dest).expect("failed to copy agentd to OUT_DIR");
    }
}

#[cfg(not(feature = "prebuilt"))]
fn newest_tree_mtime(root: &Path) -> Option<SystemTime> {
    fn walk(path: &Path, newest: &mut Option<SystemTime>) {
        let entries = match std::fs::read_dir(path) {
            Ok(entries) => entries,
            Err(_) => return,
        };

        for entry in entries.flatten() {
            let entry_path = entry.path();
            let meta = match entry.metadata() {
                Ok(meta) => meta,
                Err(_) => continue,
            };

            if meta.is_dir() {
                walk(&entry_path, newest);
                continue;
            }

            let modified = match meta.modified() {
                Ok(modified) => modified,
                Err(_) => continue,
            };

            match newest {
                Some(current) if *current >= modified => {}
                _ => *newest = Some(modified),
            }
        }
    }

    let mut newest = None;
    walk(root, &mut newest);
    newest
}

#[cfg(feature = "prebuilt")]
fn download_to(url: &str, dest: &Path) {
    eprintln!("Downloading {url}");

    let part_path = {
        let mut s = dest.as_os_str().to_os_string();
        s.push(".part");
        PathBuf::from(s)
    };

    let response = ureq::get(url).call().unwrap_or_else(|e| {
        panic!("failed to download {url}: {e}");
    });

    let mut reader = response.into_body().into_reader();
    let mut file = std::fs::File::create(&part_path).unwrap_or_else(|e| {
        panic!("failed to create {}: {e}", part_path.display());
    });

    std::io::copy(&mut reader, &mut file).unwrap_or_else(|e| {
        panic!("failed to write {}: {e}", part_path.display());
    });

    std::fs::rename(&part_path, dest).unwrap_or_else(|e| {
        panic!(
            "failed to rename {} to {}: {e}",
            part_path.display(),
            dest.display()
        );
    });
}
