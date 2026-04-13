//! Rootfs patch example demonstrating pre-boot filesystem modifications.
//!
//! See [examples/README.md](../../../README.md) for prerequisites and usage.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating sandbox with rootfs patches (image=alpine)");

    // Create a sandbox with patches applied before the VM boots.
    let sandbox = Sandbox::builder("rootfs-patch")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .patch(|p| {
            p.text(
                "/etc/greeting.txt",
                "Hello from a patched rootfs!\n",
                None,
                false,
            )
            .text(
                "/etc/motd",
                "Welcome to a patched microsandbox.\n",
                None,
                true, // replace — /etc/motd exists in alpine
            )
            .mkdir("/app", Some(0o755))
            .text(
                "/app/config.json",
                r#"{"version": "1.0", "debug": true}"#,
                Some(0o644),
                false,
            )
            .append("/etc/profile", "\nexport MSB_PATCHED=1\n")
        })
        .create()
        .await?;

    // Verify the patches were applied.
    let output = sandbox.shell("cat /etc/greeting.txt").await?;
    println!("greeting: {}", output.stdout()?.trim_end());

    let output = sandbox.shell("cat /etc/motd").await?;
    println!("motd: {}", output.stdout()?.trim_end());

    let output = sandbox.shell("cat /app/config.json").await?;
    println!("config: {}", output.stdout()?.trim_end());

    let output = sandbox.shell("grep MSB_PATCHED /etc/profile").await?;
    println!("profile append: {}", output.stdout()?.trim_end());

    let output = sandbox.shell("stat -c '%a' /app").await?;
    println!("/app permissions: {}", output.stdout()?.trim_end());

    // Stop the sandbox gracefully.
    sandbox.stop_and_wait().await?;

    println!("Sandbox stopped.");
    Ok(())
}
