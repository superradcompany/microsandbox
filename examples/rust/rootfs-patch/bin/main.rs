//! Rootfs patches: pre-boot filesystem modifications.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
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
            // /etc/motd exists in alpine, so set replace=true
            .text(
                "/etc/motd",
                "Welcome to a patched microsandbox.\n",
                None,
                true,
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

    sandbox.stop_and_wait().await?;
    Ok(())
}
