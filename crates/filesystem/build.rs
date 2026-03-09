use std::path::{Path, PathBuf};

use microsandbox_utils::AGENTD_BINARY;
#[cfg(feature = "prebuilt")]
use microsandbox_utils::agentd_download_url;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../utils/lib/lib.rs");
    // Invalidate the embedded agentd when its source changes.
    // This won't auto-rebuild agentd (that requires `just build-agentd`),
    // but it forces cargo to re-check that `build/agentd` is fresh.
    println!("cargo:rerun-if-changed=../agentd");

    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    build_agentd(&workspace_root, &out_dir);
}

fn build_agentd(workspace_root: &Path, out_dir: &Path) {
    #[cfg(feature = "prebuilt")]
    {
        let _ = workspace_root;
        let dest = out_dir.join(AGENTD_BINARY);
        if dest.exists() {
            return;
        }

        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        let url = agentd_download_url(env!("CARGO_PKG_VERSION"), &arch);

        download_to(&url, &dest);
        return;
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

        // Warn if the binary is older than the agentd source directory.
        let agentd_src = workspace_root.join("crates/agentd");
        if let (Ok(bin_meta), Ok(src_meta)) =
            (std::fs::metadata(&source), std::fs::metadata(&agentd_src))
        {
            if let (Ok(bin_time), Ok(src_time)) = (bin_meta.modified(), src_meta.modified()) {
                if src_time > bin_time {
                    println!(
                        "cargo:warning=build/{AGENTD_BINARY} is older than crates/agentd source. \
                         Run `just build-agentd` to rebuild."
                    );
                }
            }
        }

        let dest = out_dir.join(AGENTD_BINARY);
        std::fs::copy(&source, &dest).expect("failed to copy agentd to OUT_DIR");
    }
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
