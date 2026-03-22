//! Bind-root example demonstrating the microsandbox SDK with a local directory.
//!
//! See [examples/README.md](../../README.md) for prerequisites and usage.

use microsandbox::sandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rootfs_path = rootfs_path();
    println!("Creating sandbox (rootfs={rootfs_path:?})");

    // Create a sandbox with a bind-mounted rootfs.
    let sandbox = Sandbox::builder("bind-root")
        .image(rootfs_path)
        .cpus(1)
        .memory(512)
        .overwrite()
        .create()
        .await?;

    // Run a command.
    let output = sandbox.shell("echo 'Hello from microsandbox!'", ()).await?;
    println!("stdout: {}", output.stdout()?);
    println!("stderr: {}", output.stderr()?);
    println!("exit code: {}", output.status().code);

    // Run a few more commands.
    let output = sandbox.shell("uname -a", ()).await?;
    println!("uname: {}", output.stdout()?);

    let output = sandbox.shell("cat /etc/os-release", ()).await?;
    println!("os-release:\n{}", output.stdout()?);

    // Stop the sandbox gracefully.
    sandbox.stop_and_wait().await?;

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
