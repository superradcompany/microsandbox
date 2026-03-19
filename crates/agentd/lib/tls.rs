//! Guest-side CA certificate installation for TLS interception.
//!
//! When the supervisor places a CA certificate at `/.msb/tls/ca.pem` via the
//! runtime virtiofs mount, this module detects it during init and:
//!
//! 1. Copies the CA PEM to distro-specific trust directories (if they exist).
//! 2. Appends the CA PEM to the system CA bundle.
//! 3. Sets environment variables (`SSL_CERT_FILE`, `NODE_EXTRA_CA_CERTS`, etc.)
//!    so that common runtimes trust the microsandbox CA.

use std::path::Path;

use crate::AgentdResult;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Distro-specific CA trust directories. If the directory exists, the CA cert
/// is copied into it. This covers programs that scan the directory rather than
/// reading the bundle file directly.
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

/// Filename for the CA cert when copied to distro trust directories.
const CA_CERT_FILENAME: &str = "microsandbox-ca.pem";

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Installs the microsandbox CA certificate into the guest trust store.
///
/// No-op if `/.msb/tls/ca.pem` does not exist (TLS interception disabled).
#[cfg(target_os = "linux")]
pub fn install_ca_cert() -> AgentdResult<()> {
    let ca_path = Path::new(microsandbox_protocol::GUEST_TLS_CA_PATH);
    if !ca_path.exists() {
        return Ok(());
    }

    let ca_pem = std::fs::read_to_string(ca_path)?;
    eprintln!(
        "tls: CA cert found at {}, installing into guest trust store",
        ca_path.display()
    );

    // Copy to distro-specific trust directories (if they exist).
    copy_to_trust_dirs(&ca_pem);

    // Append to the system CA bundle.
    let bundle_path = append_to_bundle(&ca_pem)?;

    // Set environment variables for common runtimes.
    // SAFETY: agentd is PID 1, single-threaded at this point in init.
    unsafe {
        std::env::set_var("SSL_CERT_FILE", &bundle_path);
        std::env::set_var("REQUESTS_CA_BUNDLE", &bundle_path);
        std::env::set_var("CURL_CA_BUNDLE", &bundle_path);
        // Node.js appends (does not replace), so point at the raw CA PEM.
        std::env::set_var(
            "NODE_EXTRA_CA_CERTS",
            microsandbox_protocol::GUEST_TLS_CA_PATH,
        );
    }

    eprintln!("tls: CA cert installed, bundle={bundle_path}");
    Ok(())
}

/// No-op on non-Linux platforms.
#[cfg(not(target_os = "linux"))]
pub fn install_ca_cert() -> AgentdResult<()> {
    Ok(())
}

/// Copies the CA PEM to distro-specific trust directories that exist.
///
/// Best-effort: logs warnings on failure but does not abort.
#[cfg(target_os = "linux")]
fn copy_to_trust_dirs(ca_pem: &str) {
    for &dir in CA_TRUST_DIRS {
        let dir_path = Path::new(dir);
        if dir_path.is_dir() {
            let dest = dir_path.join(CA_CERT_FILENAME);
            match std::fs::write(&dest, ca_pem) {
                Ok(()) => eprintln!("tls: copied CA cert to {}", dest.display()),
                Err(e) => eprintln!("tls: failed to copy CA cert to {}: {e}", dest.display()),
            }
        }
    }
}

/// Appends the CA PEM to the first found CA bundle, or creates a fallback.
///
/// Returns the path to the bundle that was modified.
#[cfg(target_os = "linux")]
fn append_to_bundle(ca_pem: &str) -> AgentdResult<String> {
    for &path in CA_BUNDLE_PATHS {
        if Path::new(path).exists() {
            let mut contents = std::fs::read_to_string(path)?;
            // Ensure a newline before appending.
            if !contents.ends_with('\n') {
                contents.push('\n');
            }
            contents.push_str(ca_pem);
            std::fs::write(path, contents)?;
            return Ok(path.to_string());
        }
    }

    // No existing bundle found — create the fallback.
    if let Some(parent) = Path::new(FALLBACK_BUNDLE_PATH).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(FALLBACK_BUNDLE_PATH, ca_pem)?;
    Ok(FALLBACK_BUNDLE_PATH.to_string())
}
