//! Build script — downloads prebuilt msb + libkrunfw to ~/.microsandbox/{bin,lib}/.

use std::fs;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::process::Command;

use microsandbox_utils::{
    LIBKRUNFW_ABI, MSB_BINARY, PREBUILT_VERSION, bundle_download_url,
    libkrunfw_filename as utils_libkrunfw_filename,
};

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

    // Skip if both binaries already exist and the installed msb version
    // matches this package version.
    if lib_dir.join(&libkrunfw_name).exists()
        && installed_msb_version(&bin_dir.join(MSB_BINARY)).as_deref() == Some(PREBUILT_VERSION)
    {
        return;
    }

    fs::create_dir_all(&bin_dir).expect("failed to create bin dir");
    fs::create_dir_all(&lib_dir).expect("failed to create lib dir");

    if install_ci_local_bundle(&bin_dir, &lib_dir, &libkrunfw_name)
        .expect("failed to install CI local microsandbox bundle")
    {
        return;
    }

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
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    utils_libkrunfw_filename(os)
}

fn bundle_url() -> String {
    let arch = std::env::consts::ARCH;
    let os = if cfg!(target_os = "macos") {
        "macos"
    } else {
        "linux"
    };
    bundle_download_url(PREBUILT_VERSION, arch, os)
}

fn installed_msb_version(path: &Path) -> Option<String> {
    if !path.exists() {
        return None;
    }

    let output = Command::new(path).arg("--version").output().ok()?;
    if !output.status.success() {
        return None;
    }

    let stdout = String::from_utf8(output.stdout).ok()?;
    stdout
        .trim()
        .strip_prefix("msb ")
        .map(std::string::ToString::to_string)
}

fn install_ci_local_bundle(
    bin_dir: &Path,
    lib_dir: &Path,
    libkrunfw_name: &str,
) -> io::Result<bool> {
    if std::env::var_os("CI").is_none() && std::env::var_os("GITHUB_ACTIONS").is_none() {
        return Ok(false);
    }

    let Some(build_dir) = workspace_build_dir() else {
        return Ok(false);
    };

    let msb_src = build_dir.join(MSB_BINARY);
    let lib_src = build_dir.join(libkrunfw_name);
    if !msb_src.is_file() || !lib_src.is_file() {
        return Ok(false);
    }

    fs::copy(&msb_src, bin_dir.join(MSB_BINARY))?;
    fs::copy(&lib_src, lib_dir.join(libkrunfw_name))?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(bin_dir.join(MSB_BINARY), fs::Permissions::from_mode(0o755))?;
        fs::set_permissions(
            lib_dir.join(libkrunfw_name),
            fs::Permissions::from_mode(0o755),
        )?;
    }

    create_symlinks(lib_dir, libkrunfw_name);
    println!("cargo:warning=installed microsandbox runtime dependencies from local CI build/");
    Ok(true)
}

fn workspace_build_dir() -> Option<PathBuf> {
    let manifest_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let workspace_root = manifest_dir.parent()?.parent()?;
    if !workspace_root.join("Cargo.toml").is_file() {
        return None;
    }
    Some(workspace_root.join("build"))
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
