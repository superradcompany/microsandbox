//! Bind-root example: sandbox from a local directory.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let rootfs_path = rootfs_path();

    let sandbox = Sandbox::builder("bind-root")
        .image(rootfs_path)
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await?;

    let output = sandbox.shell("echo 'Hello from microsandbox!'").await?;
    println!("stdout: {}", output.stdout()?);
    println!("stderr: {}", output.stderr()?);
    println!("exit code: {}", output.status().code);

    let output = sandbox.shell("uname -a").await?;
    println!("uname: {}", output.stdout()?);

    let output = sandbox.shell("cat /etc/os-release").await?;
    println!("os-release:\n{}", output.stdout()?);

    sandbox.stop_and_wait().await?;
    Ok(())
}

fn rootfs_path() -> String {
    format!(
        "{}/rootfs-alpine/{}",
        env!("CARGO_MANIFEST_DIR"),
        std::env::consts::ARCH,
    )
}
