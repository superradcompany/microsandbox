//! Block-root example: sandbox from a qcow2 disk image.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let image_path = image_path();

    let sandbox = Sandbox::builder("block-root")
        .image_with(|image| image.disk(image_path).fstype("ext4"))
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

fn image_path() -> String {
    format!(
        "{}/qcow2-alpine/{}.qcow2",
        env!("CARGO_MANIFEST_DIR"),
        std::env::consts::ARCH,
    )
}
