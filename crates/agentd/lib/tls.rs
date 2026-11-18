//! Guest-side CA certificate installation for TLS interception.
//!
//! When the sandbox process places a CA certificate at `/.msb/tls/ca.pem` via the
//! runtime virtiofs mount, this module detects it during init and:
//!
//! 1. Copies the CA PEM to distro-specific trust directories.
//! 2. Appends the CA PEM to the system CA bundle.
//! 3. Sets environment variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, etc.)
//!    so that common runtimes trust the microsandbox CA.

use std::ffi::OsString;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt, fchown};
use std::path::{Path, PathBuf};
use std::{env, fs};

use crate::AgentdResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Distro-specific CA trust directories. These are created if missing so a
/// later `ca-certificates` install/update can pick up the microsandbox CA.
const CA_TRUST_DIRS: &[&str] = &[
    "/usr/local/share/ca-certificates", // Debian, Ubuntu, Alpine
    "/etc/pki/ca-trust/source/anchors", // RHEL, Fedora, CentOS
];

/// Known CA bundle files, tried in order. The CA PEM is appended to the first
/// existing bundle.
const CA_BUNDLE_PATHS: &[&str] = &[
    "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Alpine
    "/etc/pki/tls/certs/ca-bundle.crt",   // RHEL, Fedora, CentOS
    "/etc/ssl/cert.pem",                  // Alpine fallback
];

/// Fallback path to create if no existing bundle is found.
const FALLBACK_BUNDLE_PATH: &str = "/etc/ssl/certs/ca-certificates.crt";

/// Filenames for the microsandbox MITM CA when copied to distro trust directories.
/// Both extensions for broad tool compatibility (`.crt` for `update-ca-certificates`).
const CA_CERT_FILENAMES: &[&str] = &["microsandbox-ca.pem", "microsandbox-ca.crt"];

/// Filenames for the host-CA bundle when copied to distro trust directories.
const HOST_CAS_FILENAMES: &[&str] = &["microsandbox-host-cas.pem", "microsandbox-host-cas.crt"];

/// Directory mode for trust-store paths created by agentd.
const CA_TRUST_DIR_MODE: u32 = 0o755;

/// Suffix of the temporary file a CA bundle is written to before it is
/// renamed over the bundle.
const BUNDLE_TMP_SUFFIX: &str = ".msb-tmp";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Installs the microsandbox CA certificate into the guest trust store.
///
/// No-op if `/.msb/tls/ca.pem` does not exist (TLS interception disabled).
pub fn install_ca_cert() -> AgentdResult<()> {
    let ca_path = Path::new(microsandbox_protocol::GUEST_TLS_CA_PATH);
    if !ca_path.exists() {
        return Ok(());
    }

    let ca_pem = fs::read_to_string(ca_path)?;
    eprintln!(
        "tls: CA cert found at {}, installing into guest trust store",
        ca_path.display()
    );

    // Copy to distro-specific trust directories.
    copy_to_trust_dirs(&ca_pem, CA_CERT_FILENAMES);

    // Append to the system CA bundle.
    let bundle_path = append_to_bundle(&ca_pem)?;

    // Set environment variables for common runtimes.
    // SAFETY: agentd is PID 1, single-threaded at this point in init.
    unsafe {
        env::set_var("SSL_CERT_FILE", &bundle_path);
        env::set_var("REQUESTS_CA_BUNDLE", &bundle_path);
        env::set_var("CURL_CA_BUNDLE", &bundle_path);
        // Node.js appends (does not replace), so point at the raw CA PEM.
        env::set_var(
            "NODE_EXTRA_CA_CERTS",
            microsandbox_protocol::GUEST_TLS_CA_PATH,
        );
    }

    eprintln!("tls: CA cert installed, bundle={bundle_path}");
    Ok(())
}

/// Installs the host's extra trusted CAs into the guest trust store so
/// outbound TLS works behind corporate MITM proxies (Warp Zero Trust,
/// Zscaler, etc.) whose gateway CA is trusted on the host but not in the
/// guest's Mozilla root bundle.
///
/// No-op if `/.msb/tls/host-cas.pem` does not exist (host-CA shipping
/// disabled or host store empty).
pub fn install_host_cas() -> AgentdResult<()> {
    let path = Path::new(microsandbox_protocol::GUEST_TLS_HOST_CAS_PATH);
    if !path.exists() {
        return Ok(());
    }

    let pem = fs::read_to_string(path)?;
    eprintln!(
        "tls: host CA bundle found at {}, installing into guest trust store",
        path.display()
    );

    copy_to_trust_dirs(&pem, HOST_CAS_FILENAMES);
    let bundle_path = append_to_bundle(&pem)?;

    eprintln!("tls: host CA bundle installed, bundle={bundle_path}");
    Ok(())
}

/// Copies a PEM to distro-specific trust directories, under
/// each of the given filenames. Both `.pem` and `.crt` are typically
/// passed so tools that scan by extension pick one up.
///
/// Best-effort: logs warnings on failure but does not abort.
fn copy_to_trust_dirs(pem: &str, filenames: &[&str]) {
    for &dir in CA_TRUST_DIRS {
        copy_to_trust_dir(Path::new(dir), pem, filenames);
    }
}

fn copy_to_trust_dir(dir_path: &Path, pem: &str, filenames: &[&str]) {
    let missing_dirs = missing_ancestors(dir_path);

    if let Err(e) = fs::create_dir_all(dir_path) {
        eprintln!(
            "tls: failed to create CA trust directory {}: {e}",
            dir_path.display()
        );
        return;
    }

    for dir in missing_dirs {
        if let Err(e) = fs::set_permissions(&dir, fs::Permissions::from_mode(CA_TRUST_DIR_MODE)) {
            eprintln!(
                "tls: failed to set CA trust directory permissions on {}: {e}",
                dir.display()
            );
            return;
        }
    }

    for &filename in filenames {
        let dest = dir_path.join(filename);
        match fs::write(&dest, pem) {
            Ok(()) => eprintln!("tls: copied CA cert to {}", dest.display()),
            Err(e) => eprintln!("tls: failed to copy CA cert to {}: {e}", dest.display()),
        }
    }
}

fn missing_ancestors(path: &Path) -> Vec<PathBuf> {
    let mut missing = Vec::new();
    let mut current = path;

    while !current.exists() {
        missing.push(current.to_path_buf());
        match current.parent() {
            Some(parent) => current = parent,
            None => break,
        }
    }

    missing.reverse();
    missing
}

/// Appends the CA PEM to the first found CA bundle, or creates a fallback.
/// A bundle that already holds the PEM is left unchanged.
///
/// Returns the path to the bundle that was modified.
fn append_to_bundle(ca_pem: &str) -> AgentdResult<String> {
    append_to_bundle_at(ca_pem, CA_BUNDLE_PATHS, FALLBACK_BUNDLE_PATH)
}

fn append_to_bundle_at(
    ca_pem: &str,
    bundle_paths: &[&str],
    fallback_path: &str,
) -> AgentdResult<String> {
    for &path in bundle_paths {
        if Path::new(path).exists() {
            let mut contents = fs::read_to_string(path)?;
            if contents.contains(ca_pem) {
                return Ok(path.to_string());
            }
            // Ensure a newline before appending.
            if !contents.ends_with('\n') {
                contents.push('\n');
            }
            contents.push_str(ca_pem);
            // Replace the symlink target, so a symlinked bundle stays a symlink.
            replace_file(&fs::canonicalize(path)?, &contents)?;
            return Ok(path.to_string());
        }
    }

    // No existing bundle found — create the fallback.
    replace_file(Path::new(fallback_path), ca_pem)?;
    Ok(fallback_path.to_string())
}

/// Replaces `path` with `contents` through a synced temporary file and a
/// rename, so a crash leaves the old or the new file, never a partial one.
fn replace_file(path: &Path, contents: &str) -> io::Result<()> {
    let (Some(dir), Some(name)) = (path.parent(), path.file_name()) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid CA bundle path {}", path.display()),
        ));
    };
    fs::create_dir_all(dir)?;

    let mut tmp_name = OsString::from(".");
    tmp_name.push(name);
    tmp_name.push(BUNDLE_TMP_SUFFIX);
    let tmp_path = dir.join(tmp_name);

    let replaced = write_temp(&tmp_path, path, contents).and_then(|()| fs::rename(&tmp_path, path));
    if replaced.is_err() {
        let _ = fs::remove_file(&tmp_path);
    }
    replaced?;

    if let Err(e) = File::open(dir).and_then(|dir| dir.sync_all()) {
        eprintln!("agentd: failed to sync {}: {e}", dir.display());
    }
    Ok(())
}

/// Writes `contents` to a new file at `tmp_path` with `path`'s owner and mode,
/// and syncs it.
fn write_temp(tmp_path: &Path, path: &Path, contents: &str) -> io::Result<()> {
    match fs::remove_file(tmp_path) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        _ => {}
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(tmp_path)?;
    match fs::metadata(path) {
        Ok(old) => {
            // Some mounts refuse any chown, so change the owner only when it differs.
            let new = file.metadata()?;
            if (new.uid(), new.gid()) != (old.uid(), old.gid()) {
                fchown(&file, Some(old.uid()), Some(old.gid()))?;
            }
            file.set_permissions(old.permissions())?;
        }
        Err(e) if e.kind() != io::ErrorKind::NotFound => return Err(e),
        Err(_) => {}
    }
    file.write_all(contents.as_bytes())?;
    file.sync_all()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ca_cert_filenames_cover_both_extensions() {
        assert!(CA_CERT_FILENAMES.contains(&"microsandbox-ca.pem"));
        assert!(CA_CERT_FILENAMES.contains(&"microsandbox-ca.crt"));
    }

    #[test]
    fn copy_to_trust_dir_creates_missing_dir_with_mode() {
        let root = std::env::temp_dir().join(format!(
            "microsandbox-agentd-ca-test-{}",
            std::process::id()
        ));
        let dir = root.join("usr/local/share/ca-certificates");
        let _ = fs::remove_dir_all(&root);

        copy_to_trust_dir(&dir, "test pem", &["microsandbox-ca.crt"]);

        assert_eq!(
            fs::read_to_string(dir.join("microsandbox-ca.crt")).unwrap(),
            "test pem"
        );
        assert_eq!(
            fs::metadata(&dir).unwrap().permissions().mode() & 0o777,
            CA_TRUST_DIR_MODE
        );
        let _ = fs::remove_dir_all(&root);
    }

    fn bundle_test_root(name: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "microsandbox-agentd-bundle-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn append_to_bundle_replaces_the_bundle_instead_of_rewriting_it() {
        let root = bundle_test_root("replace");
        let bundle = root.join("ca-certificates.crt");
        let old = root.join("old");
        fs::write(&bundle, "OLD CERTS").unwrap();
        // A second link to the old file shows it was never truncated.
        fs::hard_link(&bundle, &old).unwrap();

        let fallback = root.join("fallback.crt");
        append_to_bundle_at(
            "NEW CA\n",
            &[bundle.to_str().unwrap()],
            fallback.to_str().unwrap(),
        )
        .unwrap();

        assert_eq!(fs::read_to_string(&bundle).unwrap(), "OLD CERTS\nNEW CA\n");
        assert_eq!(fs::read_to_string(&old).unwrap(), "OLD CERTS");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn append_to_bundle_skips_a_ca_already_in_the_bundle() {
        let root = bundle_test_root("idempotent");
        let bundle = root.join("ca-certificates.crt");
        fs::write(&bundle, "OLD CERTS\n").unwrap();

        let path = bundle.to_str().unwrap();
        let fallback = root.join("fallback.crt");
        append_to_bundle_at("NEW CA\n", &[path], fallback.to_str().unwrap()).unwrap();
        append_to_bundle_at("NEW CA\n", &[path], fallback.to_str().unwrap()).unwrap();

        assert_eq!(fs::read_to_string(&bundle).unwrap(), "OLD CERTS\nNEW CA\n");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn replace_file_does_not_write_through_a_link_at_the_temp_path() {
        let root = bundle_test_root("stale-temp");
        let bundle = root.join("bundle.crt");
        let other = root.join("other");
        let temp = root.join(".bundle.crt.msb-tmp");
        fs::write(&bundle, "OLD CERTS\n").unwrap();
        fs::write(&other, "UNTOUCHED").unwrap();
        std::os::unix::fs::symlink(&other, &temp).unwrap();

        replace_file(&bundle, "NEW CERTS\n").unwrap();

        assert_eq!(fs::read_to_string(&bundle).unwrap(), "NEW CERTS\n");
        assert_eq!(fs::read_to_string(&other).unwrap(), "UNTOUCHED");
        assert!(fs::symlink_metadata(&temp).is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
