//! Block-root example demonstrating the microsandbox SDK with a qcow2 disk image.
//!
//! See [examples/README.md](../../README.md) for prerequisites and usage.

use microsandbox::sandbox::{ImageBuilder, Sandbox};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let image_path = image_path();
    println!("Creating sandbox (image={image_path:?})");

    // Create a sandbox with a qcow2 disk image rootfs.
    let sandbox = Sandbox::builder("block-root")
        .image(|image: ImageBuilder| image.disk(image_path).fstype("ext4"))
        .cpus(1)
        .memory(512)
        .overwrite()
        .create()
        .await?;

    // Run a command.
    let output = sandbox.shell("echo 'Hello from microsandbox!'").await?;
    println!("stdout: {}", output.stdout()?);
    println!("stderr: {}", output.stderr()?);
    println!("exit code: {}", output.status().code);

    // Run a few more commands.
    let output = sandbox.shell("uname -a").await?;
    println!("uname: {}", output.stdout()?);

    let output = sandbox.shell("cat /etc/os-release").await?;
    println!("os-release:\n{}", output.stdout()?);

    // Stop the sandbox gracefully.
    sandbox.stop_and_wait().await?;

    println!("Sandbox stopped.");
    Ok(())
}

fn image_path() -> String {
    format!(
        "{}/qcow2-alpine/{}.qcow2",
        env!("CARGO_MANIFEST_DIR"),
        std::env::consts::ARCH,
    )
}
