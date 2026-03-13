//! Basic example demonstrating the microsandbox SDK.
//!
//! See [examples/README.md](../../README.md) for prerequisites and usage.

use microsandbox::sandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rootfs_path = rootfs_path();
    println!("Creating sandbox (rootfs={rootfs_path:?})");

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

    println!("Sandbox stopped.");
    Ok(())
}

fn rootfs_path() -> String {
    format!(
        "{}/rootfs-alpine/{}",
        env!("CARGO_MANIFEST_DIR"),
        std::env::consts::ARCH,
    )
}
