//! Thin shim that forwards all arguments to the installed `msb` binary.
//!
//! Self-heals on first run if `msb` isn't where we expect (e.g. `build.rs`
//! was skipped, shared install dir was wiped, or another install path ran).
//!
//! Stays deliberately std-only: no HTTP client, tar, or gzip crate is
//! linked into the shim. Shells out to `curl` and `tar` for the one-time
//! download — the same tools `scripts/install.sh` and
//! `sdk/node-ts/postinstall.js` already require.
//!
//! Resolution order:
//! 1. `MSB_PATH` environment variable
//! 2. `~/.microsandbox/bin/msb` (populated by `build.rs` at compile time or
//!    by on-demand self-heal below)

use std::env;
use std::fs;
use std::io::{IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const PREBUILT_VERSION: &str = env!("CARGO_PKG_VERSION");
const LIBKRUNFW_ABI: &str = "5";
const LIBKRUNFW_VERSION: &str = "5.2.1";
const GITHUB_ORG: &str = "superradcompany";
const REPO: &str = "microsandbox";
const MSB_BINARY: &str = "msb";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn main() -> ExitCode {
    let msb = match resolve_or_install() {
        Ok(p) => p,
        Err(code) => return code,
    };

    let args: Vec<_> = env::args_os().skip(1).collect();

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = Command::new(&msb).args(&args).exec();
        eprintln!("microsandbox: failed to exec {}: {err}", msb.display());
        ExitCode::from(127)
    }

    #[cfg(not(unix))]
    {
        match Command::new(&msb).args(&args).status() {
            Ok(status) => ExitCode::from(status.code().unwrap_or(1) as u8),
            Err(err) => {
                eprintln!("microsandbox: failed to run {}: {err}", msb.display());
                ExitCode::from(127)
            }
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Functions: Helpers
//--------------------------------------------------------------------------------------------------

fn resolve_or_install() -> Result<PathBuf, ExitCode> {
    // MSB_PATH override: honor exactly what the user set; do not attempt to
    // create or download something at an arbitrary user-specified path.
    if let Ok(path) = env::var("MSB_PATH") {
        let p = PathBuf::from(&path);
        if p.is_file() {
            return Ok(p);
        }
        eprintln!("microsandbox: MSB_PATH points at nonexistent {path}");
        return Err(ExitCode::from(127));
    }

    let Some(home) = env::var("HOME").ok().map(PathBuf::from) else {
        eprintln!("microsandbox: HOME is not set; cannot locate msb");
        return Err(ExitCode::from(127));
    };

    let base_dir = home.join(".microsandbox");
    let bin_dir = base_dir.join("bin");
    let lib_dir = base_dir.join("lib");
    let msb_path = bin_dir.join(MSB_BINARY);

    if msb_path.is_file() {
        return Ok(msb_path);
    }

    // Save the cursor before the first status line so we can wipe all of
    // our own output (plus curl's progress bar) once the download succeeds.
    // Only on a TTY; otherwise leave stderr untouched so piped output stays
    // clean.
    let mut stderr = std::io::stderr();
    let ansi = stderr.is_terminal();
    if ansi {
        let _ = stderr.write_all(b"\x1b[s");
    }

    let _ = writeln!(
        stderr,
        "microsandbox: preparing runtime v{PREBUILT_VERSION} (first run only)..."
    );

    if let Err(err) = install_runtime(&bin_dir, &lib_dir) {
        let _ = writeln!(stderr, "microsandbox: failed to download runtime: {err}");
        let _ = writeln!(
            stderr,
            "microsandbox: retry, or set MSB_PATH to an existing msb binary, \
             or install manually: curl -fsSL https://install.microsandbox.dev | sh"
        );
        return Err(ExitCode::from(127));
    }

    if msb_path.is_file() {
        // Success: wipe our status + curl's final progress line. On
        // non-TTY we leave a single confirmation line so logs still record
        // what happened.
        if ansi {
            let _ = stderr.write_all(b"\x1b[u\x1b[J");
        } else {
            let _ = writeln!(stderr, "microsandbox: runtime ready.");
        }
        Ok(msb_path)
    } else {
        let _ = writeln!(
            stderr,
            "microsandbox: install reported success but {} is still missing",
            msb_path.display()
        );
        Err(ExitCode::from(127))
    }
}

fn install_runtime(bin_dir: &Path, lib_dir: &Path) -> Result<(), String> {
    fs::create_dir_all(bin_dir).map_err(|e| format!("mkdir {}: {e}", bin_dir.display()))?;
    fs::create_dir_all(lib_dir).map_err(|e| format!("mkdir {}: {e}", lib_dir.display()))?;

    let target_os = if cfg!(target_os = "macos") {
        "darwin"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        return Err("unsupported operating system".into());
    };

    let arch = match env::consts::ARCH {
        "aarch64" => "aarch64",
        "x86_64" => "x86_64",
        other => return Err(format!("unsupported architecture: {other}")),
    };

    let libkrunfw_name = if target_os == "darwin" {
        format!("libkrunfw.{LIBKRUNFW_ABI}.dylib")
    } else {
        format!("libkrunfw.so.{LIBKRUNFW_VERSION}")
    };

    let url = format!(
        "https://github.com/{GITHUB_ORG}/{REPO}/releases/download/v{PREBUILT_VERSION}/\
         {REPO}-{target_os}-{arch}.tar.gz"
    );

    let tmp_dir = env::temp_dir().join(format!(
        "microsandbox-install-{}-{}",
        std::process::id(),
        PREBUILT_VERSION,
    ));
    // Best-effort cleanup of any prior attempt.
    let _ = fs::remove_dir_all(&tmp_dir);
    fs::create_dir_all(&tmp_dir).map_err(|e| format!("mkdir tmp: {e}"))?;
    let tarball = tmp_dir.join("bundle.tar.gz");

    // Download via curl — curl renders its own progress bar on the user's TTY.
    let curl_status = Command::new("curl")
        .args(["-fSL", "--progress-bar", "-o"])
        .arg(&tarball)
        .arg(&url)
        .status()
        .map_err(|e| format!("curl is required for runtime download but was not found: {e}"))?;
    if !curl_status.success() {
        return Err(format!("curl failed ({curl_status}) downloading {url}"));
    }

    // Extract with tar.
    let tar_status = Command::new("tar")
        .args(["xzf"])
        .arg(&tarball)
        .arg("-C")
        .arg(&tmp_dir)
        .status()
        .map_err(|e| format!("tar not found: {e}"))?;
    if !tar_status.success() {
        return Err(format!("tar failed ({tar_status})"));
    }

    // Route each extracted file to bin/ or lib/ with an atomic rename so a
    // concurrent shim can't observe a half-written binary.
    for entry in fs::read_dir(&tmp_dir).map_err(|e| format!("read {}: {e}", tmp_dir.display()))? {
        let entry = entry.map_err(|e| format!("read entry: {e}"))?;
        let src = entry.path();
        if !src.is_file() {
            continue;
        }
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        if name_str.ends_with(".tar.gz") {
            continue;
        }
        let dest = if name_str.starts_with("libkrunfw") {
            lib_dir.join(&*name_str)
        } else {
            bin_dir.join(&*name_str)
        };
        let tmp_dest = dest.with_extension(format!("tmp-{}", std::process::id()));
        fs::copy(&src, &tmp_dest).map_err(|e| format!("copy {}: {e}", src.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&tmp_dest, fs::Permissions::from_mode(0o755))
                .map_err(|e| format!("chmod {}: {e}", tmp_dest.display()))?;
        }
        fs::rename(&tmp_dest, &dest).map_err(|e| format!("rename to {}: {e}", dest.display()))?;
    }

    // libkrunfw symlinks.
    #[cfg(unix)]
    {
        let symlinks: Vec<(String, String)> = if target_os == "darwin" {
            vec![("libkrunfw.dylib".into(), libkrunfw_name.clone())]
        } else {
            let soname = format!("libkrunfw.so.{LIBKRUNFW_ABI}");
            vec![
                (soname.clone(), libkrunfw_name.clone()),
                ("libkrunfw.so".into(), soname),
            ]
        };
        for (link_name, target) in &symlinks {
            let link_path = lib_dir.join(link_name);
            if link_path.exists() || link_path.is_symlink() {
                let _ = fs::remove_file(&link_path);
            }
            std::os::unix::fs::symlink(target, &link_path)
                .map_err(|e| format!("symlink {link_name} -> {target}: {e}"))?;
        }
    }

    let _ = fs::remove_dir_all(&tmp_dir);
    Ok(())
}
