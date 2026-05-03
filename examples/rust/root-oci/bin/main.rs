//! OCI root example: sandbox from an OCI image.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::builder("oci-root")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .log_level(microsandbox::LogLevel::Debug)
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
