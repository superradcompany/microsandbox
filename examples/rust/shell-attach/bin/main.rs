//! Interactive attach — bridge your terminal to a shell inside the sandbox.
//!
//! Press Ctrl+] to detach, or type `exit` to end the session.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating sandbox (image=alpine)");

    let sandbox = Sandbox::builder("attach-example")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await?;

    println!("Attaching to shell (press Ctrl+] to detach)...");

    let exit_code = sandbox.attach_shell().await?;
    println!("Shell exited with code {exit_code}");

    sandbox.stop_and_wait().await?;
    println!("Sandbox stopped.");

    Ok(())
}
