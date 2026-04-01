//! OCI root example demonstrating the microsandbox SDK with an OCI image.
//!
//! See [examples/README.md](../../../README.md) for prerequisites and usage.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating sandbox (image=alpine)");

    // Create a sandbox with an OCI image rootfs.
    let sandbox = Sandbox::builder("oci-root")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .log_level(microsandbox::LogLevel::Debug)
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
