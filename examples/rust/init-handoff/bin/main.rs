//! Init-handoff example: hand PID 1 off to systemd.
//!
//! Uses `jrei/systemd-debian:12` — most slim base images strip systemd.

use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // `"auto"` probes /sbin/init, /lib/systemd/systemd, /usr/lib/systemd/systemd.
    // `[""; 0]` is a typed empty array; bare `[]` can't infer the item type.
    let sandbox = Sandbox::builder("init-handoff")
        .image("mirror.gcr.io/jrei/systemd-debian:12")
        .cpus(2)
        .memory(1024)
        .replace()
        .init("auto", [""; 0])
        .create()
        .await?;

    let comm = sandbox.shell("cat /proc/1/comm").await?;
    println!("/proc/1/comm: {}", comm.stdout()?.trim_end());

    let exe = sandbox.shell("readlink /proc/1/exe").await?;
    println!("/proc/1/exe -> {}", exe.stdout()?.trim_end());

    let status = sandbox.shell("systemctl is-system-running --wait").await?;
    println!(
        "systemctl is-system-running: {}",
        status.stdout()?.trim_end()
    );

    let services = sandbox
        .shell("systemctl list-units --type=service --state=running --no-legend --no-pager")
        .await?;
    println!("Running services:\n{}", services.stdout()?.trim_end());

    sandbox.stop_and_wait().await?;
    Ok(())
}
