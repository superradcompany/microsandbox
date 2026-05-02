//! Init-handoff example: hand PID 1 inside the guest off to systemd.
//!
//! See [examples/README.md](../../../README.md) for prerequisites and usage.
//!
//! Note: this uses `mirror.gcr.io/jrei/systemd-debian:12`, a community-built
//! Debian image with systemd preinstalled. Most slim base images
//! (`debian:bookworm-slim`, `ubuntu:24.04`, etc.) strip systemd entirely;
//! see docs/sandboxes/customization.mdx for image-picking guidance.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("Creating sandbox with init handoff (image=jrei/systemd-debian:12)");

    // Boot a microVM and hand PID 1 off to systemd after agentd's setup.
    // The agent forks; the parent execve's into systemd and becomes PID 1,
    // and the child stays alive serving host requests.
    let sandbox = Sandbox::builder("init-handoff")
        .image("mirror.gcr.io/jrei/systemd-debian:12")
        .cpus(2)
        .memory(1024)
        .replace()
        .init("/lib/systemd/systemd", Vec::<String>::new())
        .create()
        .await?;

    // Verify the handoff worked: PID 1 should now be systemd.
    let comm = sandbox.shell("cat /proc/1/comm").await?;
    println!("/proc/1/comm: {}", comm.stdout()?.trim_end());

    let exe = sandbox.shell("readlink /proc/1/exe").await?;
    println!("/proc/1/exe -> {}", exe.stdout()?.trim_end());

    // Wait for systemd to reach a steady state.
    let status = sandbox.shell("systemctl is-system-running --wait").await?;
    println!(
        "systemctl is-system-running: {}",
        status.stdout()?.trim_end()
    );

    // Show running services to prove systemd is actually managing the system.
    let services = sandbox
        .shell("systemctl list-units --type=service --state=running --no-legend --no-pager")
        .await?;
    println!("Running services:\n{}", services.stdout()?.trim_end());

    // Graceful shutdown takes the signal-based path (SIGRTMIN+4 -> systemd
    // shutdown -> kernel exit). Slower than the no-handoff reboot path
    // but the right thing semantically when systemd is in charge.
    sandbox.stop_and_wait().await?;
    println!("Sandbox stopped.");

    Ok(())
}
