# microsandbox

Lightweight VM sandboxes for running AI agents and untrusted code with hardware-level isolation.

`microsandbox` is the core Rust library for the [microsandbox](https://github.com/superradcompany/microsandbox) project. It provides a high-level async API for creating, managing, and interacting with microVM sandboxes — real virtual machines that boot in under 100ms and run standard OCI (Docker) images.

## Features

- **Hardware isolation** — Each sandbox is a real VM with its own Linux kernel, not a container
- **Sub-100ms boot** — MicroVMs start nearly instantly, no daemon or server required
- **OCI image support** — Pull and run images from Docker Hub, GHCR, ECR, or any OCI registry
- **Command execution** — Run commands with streaming or collected output, interactive shells
- **Guest filesystem access** — Read, write, list, copy files inside a running sandbox
- **Named volumes** — Persistent storage that survives sandbox restarts, with quotas
- **Network policies** — Control outbound access: public-only (default), allow-all, or fully airgapped
- **DNS filtering** — Block specific domains or domain suffixes
- **TLS interception** — Transparent MITM proxy for HTTPS inspection and secret substitution
- **Secrets** — Credentials that never enter the VM; placeholder substitution at the network layer
- **Port publishing** — Expose guest TCP/UDP services on host ports
- **Rootfs patches** — Modify the filesystem before the VM boots
- **Detached mode** — Sandboxes can outlive the parent process
- **Metrics** — CPU, memory, disk I/O, and network I/O per sandbox

## Requirements

- **Linux** with KVM enabled, or **macOS** with Apple Silicon (M-series)
- Rust 2024 edition

## Installation

```toml
[dependencies]
microsandbox = "0.4"
```

### Cargo Features

| Feature    | Default | Description                                         |
| ---------- | ------- | --------------------------------------------------- |
| `prebuilt` | yes     | Use pre-built runtime binaries                      |
| `net`      | yes     | Networking: port publishing, policies, TLS, secrets |

To disable networking:

```toml
[dependencies]
microsandbox = { version = "0.4", default-features = false, features = ["prebuilt"] }
```

## Quick Start

```rust
use microsandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Create a sandbox from an OCI image.
    let sandbox = Sandbox::builder("my-sandbox")
        .image("alpine")
        .cpus(1)
        .memory(512)
        .create()
        .await?;

    // Run a command.
    let output = sandbox.shell("echo 'Hello from microsandbox!'").await?;
    println!("{}", output.stdout()?);

    // Stop the sandbox.
    sandbox.stop_and_wait().await?;
    Ok(())
}
```

## Examples

### Command Execution

```rust
use microsandbox::Sandbox;

// Collected output.
let output = sandbox.exec("python3", ["-c", "print(1 + 1)"]).await?;
println!("stdout: {}", output.stdout()?);
println!("exit code: {}", output.status().code);

// Streaming output.
let mut handle = sandbox.exec_stream("tail", ["-f", "/var/log/app.log"]).await?;
while let Some(event) = handle.recv().await {
    match event {
        ExecEvent::Stdout(data) => print!("{}", String::from_utf8_lossy(&data)),
        ExecEvent::Stderr(data) => eprint!("{}", String::from_utf8_lossy(&data)),
        ExecEvent::Exited { code } => break,
        _ => {}
    }
}
```

### Filesystem Operations

```rust
let fs = sandbox.fs();

// Write a file.
fs.write("/tmp/config.json", b"{\"debug\": true}").await?;

// Read it back.
let data = fs.read("/tmp/config.json").await?;
println!("{}", String::from_utf8_lossy(&data));

// List a directory.
for entry in fs.list("/etc").await? {
    println!("{} ({:?})", entry.path, entry.kind);
}
```

### Named Volumes

```rust
use microsandbox::{Sandbox, Volume, size::SizeExt};

// Create a 100 MiB named volume.
let data = Volume::builder("my-data").quota(100.mib()).create().await?;

// Mount it in a sandbox.
let sandbox = Sandbox::builder("writer")
    .image("alpine")
    .volume("/data", |v| v.named(data.name()))
    .create()
    .await?;

sandbox.shell("echo 'hello' > /data/message.txt").await?;
sandbox.stop_and_wait().await?;

// Mount the same volume in another sandbox (read-only).
let reader = Sandbox::builder("reader")
    .image("alpine")
    .volume("/data", |v| v.named(data.name()).readonly())
    .create()
    .await?;

let output = reader.shell("cat /data/message.txt").await?;
println!("{}", output.stdout()?); // "hello"
```

### Network Policies

```rust
use microsandbox::{Sandbox, NetworkPolicy};

// Default: public internet only (blocks private ranges).
let sandbox = Sandbox::builder("public")
    .image("alpine")
    .create()
    .await?;

// Fully airgapped.
let sandbox = Sandbox::builder("isolated")
    .image("alpine")
    .network(|n| n.policy(NetworkPolicy::none()))
    .create()
    .await?;

// DNS filtering.
let sandbox = Sandbox::builder("filtered")
    .image("alpine")
    .network(|n| {
        n.dns(|d| d
            .block_domain("blocked.example.com")
            .block_domain_suffix(".evil.com"))
    })
    .create()
    .await?;
```

### Port Publishing

```rust
let sandbox = Sandbox::builder("web")
    .image("python")
    .port(8080, 80) // host:8080 → guest:80
    .create()
    .await?;
```

### Secrets

Secrets use placeholder substitution — the real value never enters the VM. It is only swapped in at the network layer for HTTPS requests to allowed hosts.

```rust
let sandbox = Sandbox::builder("agent")
    .image("python")
    .secret_env("API_KEY", "sk-real-secret-123", "api.openai.com")
    .create()
    .await?;

// Guest sees: API_KEY=$MSB_API_KEY (a placeholder)
// HTTPS to api.openai.com: placeholder is transparently replaced with the real key
// HTTPS to any other host with the placeholder: request is blocked
```

### Rootfs Patches

Modify the filesystem before the VM boots:

```rust
let sandbox = Sandbox::builder("patched")
    .image("alpine")
    .patch(|p| {
        p.text("/etc/greeting.txt", "Hello!\n", None, false)
         .mkdir("/app", Some(0o755))
         .append("/etc/hosts", "127.0.0.1 myapp.local\n")
    })
    .create()
    .await?;
```

### Detached Mode

Sandboxes in detached mode survive the parent process:

```rust
// Create and detach.
let sandbox = Sandbox::builder("background")
    .image("python")
    .create_detached()
    .await?;

// Later, from another process:
let sandbox = Sandbox::start("background").await?;
let output = sandbox.shell("echo reconnected").await?;
```

### Image Sources

```rust
use microsandbox::Sandbox;

// OCI image (most common).
Sandbox::builder("a").image("python")

// Local bind-mounted rootfs.
Sandbox::builder("b").image("/path/to/rootfs")

// QCOW2 disk image.
Sandbox::builder("c").image_with(|img| img.disk("/path/to/disk.qcow2").fstype("ext4"))
```

## API Overview

### Core Types

| Type             | Description                                                         |
| ---------------- | ------------------------------------------------------------------- |
| `Sandbox`        | Live handle to a running sandbox — lifecycle, execution, filesystem |
| `SandboxBuilder` | Fluent builder for configuring and creating sandboxes               |
| `SandboxConfig`  | Serializable sandbox configuration                                  |
| `SandboxHandle`  | Lightweight metadata handle from the database                       |
| `Volume`         | Persistent named volume                                             |
| `VolumeBuilder`  | Fluent builder for creating volumes                                 |
| `Image`          | OCI image metadata and inspection                                   |

### Execution Types

| Type                                 | Description                                                |
| ------------------------------------ | ---------------------------------------------------------- |
| `ExecOutput`                         | Captured stdout/stderr with exit status                    |
| `ExecHandle`                         | Streaming execution handle with event channel              |
| `ExecOptions` / `ExecOptionsBuilder` | Execution configuration (args, env, cwd, timeout, rlimits) |
| `ExecEvent`                          | Stream event: `Started`, `Stdout`, `Stderr`, `Exited`      |
| `ExecSink`                           | Writable stdin channel for streaming exec                  |
| `ExitStatus`                         | Exit code and success flag                                 |

### Filesystem Types

| Type         | Description                              |
| ------------ | ---------------------------------------- |
| `SandboxFs`  | Gateway for guest filesystem operations  |
| `FsEntry`    | Directory entry (name, kind, size, mode) |
| `FsMetadata` | File metadata (size, mode, timestamps)   |

### Configuration Types

| Type                     | Description                                         |
| ------------------------ | --------------------------------------------------- |
| `RootfsSource`           | Image source: `Oci`, `Bind`, or `DiskImage`         |
| `VolumeMount`            | Mount type: `Bind`, `Named`, or `Tmpfs`             |
| `Patch` / `PatchBuilder` | Pre-boot filesystem modifications                   |
| `NetworkPolicy`          | Network access control (requires `net` feature)     |
| `RegistryAuth`           | Docker registry credentials                         |
| `PullPolicy`             | Image pull strategy: `Always`, `IfMissing`, `Never` |
| `LogLevel`               | Logging verbosity                                   |

### Error Handling

All fallible operations return `MicrosandboxResult<T>`, which uses `MicrosandboxError` — an enum covering I/O, network, database, configuration, runtime, and timeout errors.

## License

Apache-2.0
