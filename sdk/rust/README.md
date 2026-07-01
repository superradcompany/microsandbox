# microsandbox

Lightweight VM sandboxes for Rust applications that need hardware-level isolation for AI agents, tools, tests, and untrusted code.

`microsandbox` is the Rust SDK for the [microsandbox](https://github.com/superradcompany/microsandbox) runtime. It exposes an async API for creating microVM-backed sandboxes, running commands, reading and writing guest files, managing volumes, configuring network policy, and working with secrets.

For full API documentation, use the docs site and generated Rust docs:

- [Rust SDK guide](https://docs.microsandbox.dev/sdk/rust/sandbox)
- [SDK overview](https://docs.microsandbox.dev/sdk/overview)
- [Repository examples](../../examples/rust)

## Features

- Hardware VM isolation with a guest Linux kernel
- OCI image, bind-rootfs, disk-image, and snapshot-based sandboxes
- Collected and streaming command execution
- Guest filesystem read, write, list, copy, stat, and stream operations
- Named volumes, bind mounts, tmpfs mounts, and disk-image mounts
- Network policies, DNS filtering, TLS interception, secrets, and port publishing
- Rootfs patches before boot
- Detached sandboxes that can outlive the Rust process
- Metrics, logs, snapshots, SSH/SFTP, image cache, and local/cloud backend helpers

## Requirements

- Rust toolchain with Rust 2024 edition support
- Linux with KVM, macOS with Apple Silicon, or Windows with Windows Hypervisor Platform
- Windows support is currently preview; see the [Windows troubleshooting guide](https://docs.microsandbox.dev/getting-started/windows-troubleshooting) for WHP and runtime setup notes.

## Installation

```bash
cargo add microsandbox
```

### Cargo Features

| Feature | Default | Description |
| --- | --- | --- |
| `keyring` | yes | Registry credential lookup through the platform keyring |
| `net` | yes | Networking, port publishing, policies, TLS interception, and secrets |
| `prebuilt` | yes | Use prebuilt runtime artifacts where available |
| `ssh` | no | SSH, SFTP, and interactive SSH helpers |

To build without the networking stack while keeping the default keyring and prebuilt-runtime behavior:

```bash
cargo add microsandbox --no-default-features --features keyring,prebuilt
```

## Quick Start

```rust
use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::builder("rust-readme")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .replace()
        .create()
        .await?;

    let output = sandbox.shell("echo 'Hello from microsandbox!'").await?;
    println!("{}", output.stdout()?.trim());

    sandbox.stop().await?;
    Sandbox::remove("rust-readme").await?;

    Ok(())
}
```

## Common Examples

These snippets assume you already have a live `sandbox: Sandbox`. See [examples/rust](../../examples/rust) for complete runnable crates.

### Command Execution

```rust
use microsandbox::ExecEvent;

let output = sandbox.exec("python3", ["-c", "print(1 + 1)"]).await?;
println!("stdout: {}", output.stdout()?);
println!("exit code: {}", output.status().code);

let mut handle = sandbox.exec_stream("tail", ["-f", "/var/log/app.log"]).await?;
while let Some(event) = handle.recv().await {
    match event {
        ExecEvent::Stdout(data) => print!("{}", String::from_utf8_lossy(&data)),
        ExecEvent::Stderr(data) => eprint!("{}", String::from_utf8_lossy(&data)),
        ExecEvent::Exited { code } => {
            println!("exited with {code}");
            break;
        }
        ExecEvent::Started { .. } => {}
        ExecEvent::Failed(err) => {
            eprintln!("exec failed: {err:?}");
            break;
        }
        ExecEvent::StdinError(err) => eprintln!("stdin error: {err:?}"),
    }
}
```

### Filesystem Operations

```rust
let fs = sandbox.fs();

fs.write("/tmp/config.json", br#"{"debug": true}"#).await?;

let data = fs.read("/tmp/config.json").await?;
println!("{}", String::from_utf8_lossy(&data));

for entry in fs.list("/etc").await? {
    println!("{} ({:?})", entry.path, entry.kind);
}
```

### Named Volumes

```rust
use microsandbox::{Sandbox, Volume, size::SizeExt};

let data = Volume::builder("readme-data").quota(100.mib()).create().await?;

let writer = Sandbox::builder("readme-writer")
    .image("alpine")
    .volume("/data", |v| v.named(data.name()))
    .replace()
    .create()
    .await?;

writer.shell("echo 'hello' > /data/message.txt").await?;
writer.stop().await?;

let reader = Sandbox::builder("readme-reader")
    .image("alpine")
    .volume("/data", |v| v.named(data.name()).readonly())
    .replace()
    .create()
    .await?;

let output = reader.shell("cat /data/message.txt").await?;
println!("{}", output.stdout()?.trim());
```

### Network Policies

```rust
use microsandbox::{NetworkPolicy, Sandbox};

let isolated = Sandbox::builder("readme-isolated")
    .image("alpine")
    .network(|n| n.policy(NetworkPolicy::none()))
    .replace()
    .create()
    .await?;

let filtered_policy = NetworkPolicy::builder()
    .default_allow()
    .rule(|r| r.egress().deny().domain("blocked.example.com"))
    .rule(|r| r.egress().deny().domain_suffix(".evil.com"))
    .build()?;

let filtered = Sandbox::builder("readme-filtered")
    .image("alpine")
    .network(|n| n.policy(filtered_policy))
    .replace()
    .create()
    .await?;
```

Use `.disable_network()` when the sandbox should not receive a network interface at all. Use `NetworkPolicy::none()` when the interface should exist but policy should deny traffic.

### Port Publishing

```rust
let sandbox = Sandbox::builder("readme-web")
    .image("python")
    .port(8080, 80)
    .replace()
    .create()
    .await?;
```

### Secrets

Secrets use placeholder substitution. The real value stays on the host and is substituted only for allowed network destinations.

```rust
let sandbox = Sandbox::builder("readme-agent")
    .image("python")
    .secret_env("OPENAI_API_KEY", "sk-real-secret-123", "api.openai.com")
    .replace()
    .create()
    .await?;
```

### Rootfs Patches

```rust
let sandbox = Sandbox::builder("readme-patched")
    .image("alpine")
    .patch(|p| {
        p.text("/etc/greeting.txt", "Hello!\n", None, false)
            .mkdir("/app", Some(0o755))
            .append("/etc/hosts", "127.0.0.1 myapp.local\n")
    })
    .replace()
    .create()
    .await?;
```

### Detached Mode

```rust
let sandbox = Sandbox::builder("readme-background")
    .image("python")
    .detached(true)
    .replace()
    .create()
    .await?;

sandbox.detach().await;

let handle = Sandbox::get("readme-background").await?;
let reconnected = handle.connect().await?;
let output = reconnected.shell("echo reconnected").await?;
println!("{}", output.stdout()?.trim());
```

## More Documentation

- [Sandbox lifecycle](https://docs.microsandbox.dev/sdk/rust/sandbox)
- [Execution](https://docs.microsandbox.dev/sdk/rust/execution)
- [Filesystem](https://docs.microsandbox.dev/sdk/rust/filesystem)
- [Networking](https://docs.microsandbox.dev/sdk/rust/networking)
- [Secrets](https://docs.microsandbox.dev/sdk/rust/secrets)
- [Volumes](https://docs.microsandbox.dev/sdk/rust/volumes)
- [Snapshots](https://docs.microsandbox.dev/sdk/rust/snapshots)
- [SSH](https://docs.microsandbox.dev/sdk/rust/ssh)

## License

Apache-2.0
