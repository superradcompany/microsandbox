//! Basic example demonstrating the microsandbox SDK.
//!
//! Prerequisites:
//! - `just build-deps && just build` (builds agentd, libkrunfw, and msb)
//! - The rootfs-alpine git submodule initialized (`git submodule update --init`)
//!
//! Usage:
//!   cargo run -p basic-example
//!
//! On macOS, the binary must be codesigned with the hypervisor entitlement:
//!   codesign --entitlements ../../entitlements.plist --force -s - target/debug/basic-example

use std::path::PathBuf;

use microsandbox::sandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rootfs_path = std::env::var("ROOTFS_PATH")
        .map(PathBuf::from)
        .unwrap_or_else(|_| {
            format!(
                "{}/rootfs-alpine/{}",
                env!("CARGO_MANIFEST_DIR"),
                std::env::consts::ARCH,
            )
            .into()
        });

    eprintln!("Creating sandbox (rootfs={rootfs_path:?})");

    // Create a sandbox with a bind-mounted rootfs.
    let sandbox = Sandbox::builder("basic-example")
        .image(rootfs_path)
        .cpus(1)
        .memory(512)
        .create()
        .await?;

    // Run a command.
    let output = sandbox.shell("echo 'Hello from microsandbox!'", ()).await?;
    println!("stdout: {}", String::from_utf8_lossy(&output.stdout));
    println!("stderr: {}", String::from_utf8_lossy(&output.stderr));
    println!("exit code: {}", output.status.code);

    // Run a few more commands.
    let output = sandbox.shell("uname -a", ()).await?;
    println!("uname: {}", String::from_utf8_lossy(&output.stdout));

    let output = sandbox.shell("cat /etc/os-release", ()).await?;
    println!("os-release:\n{}", String::from_utf8_lossy(&output.stdout));

    // Stop the sandbox gracefully.
    sandbox.stop().await?;
    sandbox.wait().await?;

    eprintln!("Sandbox stopped.");
    Ok(())
}
