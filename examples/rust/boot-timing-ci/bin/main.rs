use microsandbox::Sandbox;
use serde_json::json;
use std::path::{Path, PathBuf};

const SANDBOX_NAME: &str = "boot-timing-ci";
const ROOTFS_ENV_VAR: &str = "MICROSANDBOX_BOOT_TIMING_ROOTFS";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::builder(SANDBOX_NAME)
        .image(rootfs_path())
        .cpus(1)
        .memory(256)
        .quiet_logs()
        .replace()
        .create()
        .await?;

    let timings = sandbox.boot_timings();
    sandbox.stop_and_wait().await?;
    sandbox.remove_persisted().await?;

    println!(
        "{}",
        serde_json::to_string(&json!({
            "enter_to_boot_ns": timings.enter_to_boot_ns,
            "boot_to_init_ns": timings.boot_to_init_ns,
            "boot_to_ready_ns": timings.boot_to_ready_ns,
            "enter_to_ready_ns": timings.enter_to_ready_ns,
            "enter_to_boot_ms": ns_to_ms(timings.enter_to_boot_ns),
            "boot_to_init_ms": ns_to_ms(timings.boot_to_init_ns),
            "boot_to_ready_ms": ns_to_ms(timings.boot_to_ready_ns),
            "enter_to_ready_ms": ns_to_ms(timings.enter_to_ready_ns),
        }))?
    );

    Ok(())
}

fn ns_to_ms(value: u64) -> f64 {
    value as f64 / 1_000_000.0
}

fn rootfs_path() -> String {
    let arch = std::env::consts::ARCH;
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    let relative_rootfs = Path::new("examples/rust/root-bind/rootfs-alpine").join(arch);

    if let Some(path) = std::env::var_os(ROOTFS_ENV_VAR) {
        let candidate = PathBuf::from(path);
        return resolve_rootfs_candidate(candidate)
            .unwrap_or_else(|reason| {
                panic!(
                    "{ROOTFS_ENV_VAR} is set but unusable: {reason}. Set it to a populated {arch} rootfs directory."
                )
            })
            .display()
            .to_string();
    }

    let mut candidates = Vec::new();
    candidates.push(manifest_dir.join("../root-bind/rootfs-alpine").join(arch));

    for ancestor in manifest_dir.ancestors() {
        candidates.push(ancestor.join(&relative_rootfs));
        if let Some(parent) = ancestor.parent() {
            candidates.push(parent.join("microsandbox").join(&relative_rootfs));
        }
    }

    for candidate in candidates {
        if resolve_rootfs_candidate(candidate.clone()).is_ok() {
            return candidate.display().to_string();
        }
    }

    panic!(
        "unable to find a populated {arch} rootfs for {SANDBOX_NAME}. \
expected the root-bind submodule at ../root-bind/rootfs-alpine/{arch}, \
but it is missing in this checkout. Run `git submodule update --init --recursive` \
or set {ROOTFS_ENV_VAR} to a populated {arch} rootfs directory."
    );
}

fn resolve_rootfs_candidate(candidate: PathBuf) -> Result<PathBuf, String> {
    if !candidate.exists() {
        return Err(format!("path does not exist: {}", candidate.display()));
    }

    if !candidate.is_dir() {
        return Err(format!("path is not a directory: {}", candidate.display()));
    }

    let mut entries = candidate
        .read_dir()
        .map_err(|err| format!("failed to read {}: {err}", candidate.display()))?;
    if entries.next().is_none() {
        return Err(format!("path is empty: {}", candidate.display()));
    }

    Ok(candidate)
}
