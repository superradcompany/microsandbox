//! Interactive attach — bridge your terminal to a shell inside the sandbox.
//!
//! Press Ctrl+] to detach, or type `exit` to end the session.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Connecting to or creating sandbox (image=alpine on first creation)");

    // An interactive workspace is useful across runs. Builder options seed only the first creation;
    // later runs reconnect to the persisted sandbox and preserve its files and configuration.
    let sandbox = Sandbox::builder("attach-example")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .connect_or_create()
        .await?;

    println!("Attaching to shell (press Ctrl+] to detach)...");

    let exit_code = sandbox.attach_shell().await?;
    println!("Shell exited with code {exit_code}");

    sandbox.stop().await?;
    println!("Sandbox stopped.");

    Ok(())
}
