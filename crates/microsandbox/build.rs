//! Build script — downloads prebuilt msb + libkrunfw to ~/.microsandbox/{bin,lib}/.

use std::fs;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};

const PREBUILT_VERSION: &str = "0.3.5";
const LIBKRUNFW_ABI: &str = "5";
const LIBKRUNFW_VERSION: &str = "5.2.1";
const GITHUB_ORG: &str = "superradcompany";
const REPO: &str = "microsandbox";
const MSB_BINARY: &str = "msb";

fn main() {
    // Re-run if the binaries are deleted so we can re-download.
    let home = home_dir();
    if let Some(ref home) = home {
        let base_dir = home.join(".microsandbox");
        println!(
            "cargo:rerun-if-changed={}",
            base_dir.join("bin").join(MSB_BINARY).display()
        );
        println!(
            "cargo:rerun-if-changed={}",
            base_dir.join("lib").join(libkrunfw_filename()).display()
        );
    }

    // Only download when the prebuilt feature is enabled.
    if std::env::var("CARGO_FEATURE_PREBUILT").is_err() {
        return;
    }

    let Some(home) = home else {
        println!("cargo:warning=could not determine home directory, skipping prebuilt download");
        return;
    };

    let base_dir = home.join(".microsandbox");
    let bin_dir = base_dir.join("bin");
    let lib_dir = base_dir.join("lib");

    let libkrunfw_name = libkrunfw_filename();

    // Skip if both binaries already exist.
    if bin_dir.join(MSB_BINARY).exists() && lib_dir.join(&libkrunfw_name).exists() {
        return;
    }

    fs::create_dir_all(&bin_dir).expect("failed to create bin dir");
    fs::create_dir_all(&lib_dir).expect("failed to create lib dir");

    let url = bundle_url();
    println!(
        "cargo:warning=downloading microsandbox runtime dependencies (v{PREBUILT_VERSION})..."
    );

    let data = download(&url).expect("failed to download microsandbox bundle");
    extract_bundle(&data, &bin_dir, &lib_dir).expect("failed to extract bundle");
    create_symlinks(&lib_dir, &libkrunfw_name);

    // Verify.
    assert!(
        bin_dir.join(MSB_BINARY).exists(),
        "msb binary not found after extraction"
    );
    assert!(
        lib_dir.join(&libkrunfw_name).exists(),
        "{libkrunfw_name} not found after extraction"
    );
}

fn home_dir() -> Option<PathBuf> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        std::env::var("HOME").ok().map(PathBuf::from)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

fn libkrunfw_filename() -> String {
    if cfg!(target_os = "macos") {
        format!("libkrunfw.{LIBKRUNFW_ABI}.dylib")
    } else {
        format!("libkrunfw.so.{LIBKRUNFW_VERSION}")
    }
}

fn bundle_url() -> String {
    let arch = std::env::consts::ARCH;
    let target_os = if cfg!(target_os = "macos") {
        "darwin"
    } else {
        "linux"
    };
    format!(
        "https://github.com/{GITHUB_ORG}/{REPO}/releases/download/v{PREBUILT_VERSION}/{REPO}-{target_os}-{arch}.tar.gz"
    )
}

fn download(url: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let resp = ureq::get(url).call()?;
    let mut buf = Vec::new();
    resp.into_body().into_reader().read_to_end(&mut buf)?;
    Ok(buf)
}

fn extract_bundle(data: &[u8], bin_dir: &Path, lib_dir: &Path) -> io::Result<()> {
    let decoder = flate2::read::GzDecoder::new(Cursor::new(data));
    let mut archive = tar::Archive::new(decoder);

    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;
        let Some(filename) = path.file_name().and_then(|f| f.to_str()) else {
            continue;
        };

        let dest = if filename.starts_with("libkrunfw") {
            lib_dir.join(filename)
        } else {
            bin_dir.join(filename)
        };

        entry.unpack(&dest)?;

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dest, fs::Permissions::from_mode(0o755))?;
        }
    }

    Ok(())
}

fn create_symlinks(lib_dir: &Path, libkrunfw_name: &str) {
    #[cfg(unix)]
    {
        let symlinks: Vec<(String, String)> = if cfg!(target_os = "macos") {
            vec![("libkrunfw.dylib".to_string(), libkrunfw_name.to_string())]
        } else {
            let soname = format!("libkrunfw.so.{LIBKRUNFW_ABI}");
            vec![
                (soname.clone(), libkrunfw_name.to_string()),
                ("libkrunfw.so".to_string(), soname),
            ]
        };

        for (link_name, target) in &symlinks {
            let link_path = lib_dir.join(link_name);
            if link_path.exists() || link_path.is_symlink() {
                let _ = fs::remove_file(&link_path);
            }
            std::os::unix::fs::symlink(target, &link_path).ok();
        }
    }
}
