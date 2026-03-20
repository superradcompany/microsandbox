use std::path::{Path, PathBuf};

#[cfg(feature = "prebuilt")]
use microsandbox_utils::libkrunfw_download_url;
use microsandbox_utils::libkrunfw_filename;

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../utils/lib/lib.rs");

    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());

    build_libkrunfw(&workspace_root, &out_dir);
}

fn build_libkrunfw(workspace_root: &Path, out_dir: &Path) {
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();
    let lib_name = libkrunfw_filename(&os);

    #[cfg(feature = "prebuilt")]
    {
        let _ = workspace_root;
        let dest = out_dir.join(&lib_name);
        if dest.exists() {
            return;
        }

        let arch = std::env::var("CARGO_CFG_TARGET_ARCH").unwrap();
        let url = libkrunfw_download_url(env!("CARGO_PKG_VERSION"), &arch, &os);

        download_to(&url, &dest);
        return;
    }

    #[cfg(not(feature = "prebuilt"))]
    {
        let source = workspace_root.join("build").join(&lib_name);
        println!("cargo:rerun-if-changed={}", source.display());

        if !source.exists() {
            panic!(
                "libkrunfw binary not found at `{}`.\n\
                 Run `just build-deps` first.",
                source.display()
            );
        }

        let dest = out_dir.join(&lib_name);
        std::fs::copy(&source, &dest).expect("failed to copy libkrunfw to OUT_DIR");
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

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&part_path, std::fs::Permissions::from_mode(0o755)).unwrap();
    }

    std::fs::rename(&part_path, dest).unwrap_or_else(|e| {
        panic!(
            "failed to rename {} to {}: {e}",
            part_path.display(),
            dest.display()
        );
    });
}
