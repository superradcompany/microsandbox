<div align="center">
    <a href="./#gh-dark-mode-only" target="_blank" align="center">
        <img width="35%" src="./assets/microsandbox-gh-banner-light.png" alt="microsandbox-banner-xl-dark">
    </a>
</div>

<div align="center">
    <a href="./#gh-light-mode-only" target="_blank">
        <img width="35%" src="./assets/microsandbox-gh-banner-dark.png" alt="microsandbox-banner-xl">
    </a>
</div>

<h3 align="center"><b>——&nbsp;&nbsp;&nbsp;Every Agent Deserves its Own Computer&nbsp;&nbsp;&nbsp;——</b></h3>

<br />

<div align='center'>
  <a href="https://discord.gg/T95Y3XnEAK" target="_blank">
    <img src="https://img.shields.io/badge/join discord-%2300acee.svg?color=mediumslateblue&style=for-the-badge&logo=discord&logoColor=white" alt=discord style="margin-bottom: 5px;"/>
  </a>

  <a href="https://x.com/microsandbox" target="_blank">
    <img src="https://img.shields.io/badge/follow on X-%2300acee.svg?color=000000&style=for-the-badge&logo=X&logoColor=white" alt=discourse style="margin-bottom: 5px;"/>
  </a>
</div>

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/package/ffffff" alt="package-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/package/000000" alt="package"></a>&nbsp;&nbsp;Microsandbox

Microsandbox spins up lightweight microVMs in **under a second**, right from your code. No servers, no daemons, no infrastructure to manage.

AI agents operate with whatever permissions you give them, and that's usually _too much_. They can see _API keys_ in the environment, reach the network without restriction, and a single prompt injection _can execute destructive commands_ on your host. Containers help, but they share the host kernel, making _namespace escapes_ a known risk. Microsandbox solves this with **hardware-level VM isolation** that's fast enough to use in every request.

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/sparkle/ffffff" alt="sparkle-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/sparkle/000000" alt="sparkle"></a>&nbsp;&nbsp;Key Features

- <img height="15" src="https://octicons-col.vercel.app/shield-lock/A770EF"> **Hardware Isolation**: Each sandbox is a real [microVM](https://docs2.microsandbox.dev/sandboxes/overview). No container. Hypervisor-level isolation.
- <img height="15" src="https://octicons-col.vercel.app/zap/A770EF"> **Sub-Second Boot**: Sandboxes boot in under 100 milliseconds.
- <img height="15" src="https://octicons-col.vercel.app/plug/A770EF"> **Embeddable**: The SDK boots VMs as child processes. No setup server. No long-running daemon.
- <img height="15" src="https://octicons-col.vercel.app/lock/A770EF"> **Secrets That Can't Leak**: Secrets never enter the VM. The guest sees a placeholder.
- <img height="15" src="https://octicons-col.vercel.app/globe/A770EF"> **Programmable Filesystem & Networking**: Custom filesystem hooks and network policy enforcement guests can't bypass.
- <img height="15" src="https://octicons-col.vercel.app/package/A770EF"> **OCI Compatible**: Run standard container images from Docker Hub, GHCR, ECR, or any OCI registry.
- <img height="15" src="https://octicons-col.vercel.app/database/A770EF"> **Long-Running**: Sandboxes can run as long-lived services with [named volumes](https://docs2.microsandbox.dev/sandboxes/volumes) that persist across restarts.
- <img height="15" src="https://octicons-col.vercel.app/terminal/A770EF"> **Full CLI**: Manage sandboxes, images, and volumes from the terminal with `msb`.

> Microsandbox is still **beta software**. Expect breaking changes, missing features, and rough edges.

## <a href="./#gh-dark-mode-only" target="_blank"><img height="13" src="https://octicons-col.vercel.app/rocket/ffffff" alt="rocket-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="13" src="https://octicons-col.vercel.app/rocket/000000" alt="rocket"></a>&nbsp;&nbsp;Getting Started

#### <img height="14" src="https://octicons-col.vercel.app/move-to-bottom/A770EF">&nbsp;&nbsp;Install the SDK

```sh
cargo add microsandbox
```

#### <img height="14" src="https://octicons-col.vercel.app/download/A770EF">&nbsp;&nbsp;Install the CLI (optional)

The `msb` CLI is useful for managing images, volumes, and sandboxes from the terminal:

```sh
curl -fsSL https://install.microsandbox.dev | sh
```

> **Requirements**: Linux with KVM enabled, or macOS with Apple Silicon.

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/package-dependencies/ffffff" alt="sdk-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/package-dependencies/000000" alt="sdk"></a>&nbsp;&nbsp;SDK

The SDK lets you create and control sandboxes directly from your application. `Sandbox::builder(...)` boots a microVM as a child process. No infrastructure required.

#### <img height="14" src="https://octicons-col.vercel.app/play/A770EF">&nbsp;&nbsp;Run Code in a Sandbox

```rs
use microsandbox::sandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::builder("my-sandbox")
        .image("python")
        .cpus(1)
        .memory(512)
        .create()
        .await?;

    let output = sandbox.shell("print('Hello from a microVM!')").await?;
    println!("{}", output.stdout()?);

    sandbox.stop_and_wait().await?;
    Ok(())
}
```

Behind the scenes, `create()` pulls the image (if not cached), assembles the filesystem, boots a microVM, and opens a communication channel. All in under a second.

#### <img height="14" src="https://octicons-col.vercel.app/lock/A770EF">&nbsp;&nbsp;Secrets That Never Enter the VM

Secrets are injected via placeholder substitution. The guest environment only ever sees a random placeholder. The real value is swapped in at the network level, and only for requests to hosts you allow.

```rs
let sandbox = Sandbox::builder("api-client")
    .image("python")
    .secret_env("OPENAI_API_KEY", "sk-real-secret-123", "api.openai.com")
    .create()
    .await?;

// Inside the VM: $OPENAI_API_KEY = "$MSB_OPENAI_API_KEY" (placeholder)
// Requests to api.openai.com: placeholder is replaced with the real key
// Requests to any other host: placeholder stays, secret never leaks
```

#### <img height="14" src="https://octicons-col.vercel.app/globe/A770EF">&nbsp;&nbsp;Network Policy

Control exactly what the sandbox can reach. The in-process networking stack enforces policy at the IP, DNS, and HTTP level. There's no host network to bridge to, so guests can't bypass the filter.

```rs
use microsandbox::sandbox::{NetworkPolicy, Sandbox};

let sandbox = Sandbox::builder("restricted")
    .image("alpine")
    .network(|n| {
        n.policy(NetworkPolicy::public_only())  // blocks private/loopback
         .block_domain_suffix(".evil.com")       // DNS-level blocking
    })
    .create()
    .await?;
```

Three built-in policies: `NetworkPolicy::public_only()` (default, blocks private IPs), `NetworkPolicy::allow_all()`, and `NetworkPolicy::none()` (fully airgapped).

#### <img height="14" src="https://octicons-col.vercel.app/upload/A770EF">&nbsp;&nbsp;Port Publishing

Expose guest services on host ports:

```rs
let sandbox = Sandbox::builder("web-server")
    .image("alpine")
    .port(8080, 80)  // host:8080 → guest:80
    .create()
    .await?;
```

#### <img height="14" src="https://octicons-col.vercel.app/database/A770EF">&nbsp;&nbsp;Named Volumes

Persistent storage that survives sandbox restarts and can be shared across sandboxes:

```rs
use microsandbox::{sandbox::Sandbox, size::SizeExt, volume::Volume};

// Create a volume with a quota.
let data = Volume::builder("shared-data").quota(100.mib()).create().await?;

// Sandbox A writes to it.
let writer = Sandbox::builder("writer")
    .image("alpine")
    .volume("/data", |v| v.named(data.name()))
    .create()
    .await?;

writer.shell("echo 'hello' > /data/message.txt").await?;
writer.stop_and_wait().await?;

// Sandbox B reads from it.
let reader = Sandbox::builder("reader")
    .image("alpine")
    .volume("/data", |v| v.named(data.name()).readonly())
    .create()
    .await?;

let output = reader.shell("cat /data/message.txt").await?;
println!("{}", output.stdout()?); // hello
```

#### <img height="14" src="https://octicons-col.vercel.app/pencil/A770EF">&nbsp;&nbsp;Scripts & Patches

Register named scripts that get mounted at `/.msb/scripts/` and added to `PATH`, so you can invoke them by name:

```rs
let sandbox = Sandbox::builder("worker")
    .image("ubuntu")
    .script("setup", "#!/bin/bash\napt-get update && apt-get install -y python3 curl")
    .script("start", "#!/bin/bash\nexec python3 /app/main.py")
    .create()
    .await?;

sandbox.shell("setup").await?;
let output = sandbox.shell("start").await?;
```

Patches modify the filesystem before the VM boots. Inject config files, create directories, append to existing files:

```rs
let sandbox = Sandbox::builder("configured")
    .image("alpine")
    .patch(|p| {
        p.text("/etc/app.conf", "key=value\n", None, false)
         .mkdir("/app", Some(0o755))
         .append("/etc/hosts", "127.0.0.1 myapp.local\n")
    })
    .create()
    .await?;
```

#### <img height="14" src="https://octicons-col.vercel.app/file-binary/A770EF">&nbsp;&nbsp;Flexible Rootfs Sources

Boot from an OCI image, a local directory, or a disk image:

```rs
// OCI image (default)
Sandbox::builder("oci").image("python:3.12")

// Local directory
Sandbox::builder("bind").image("./my-rootfs")

// QCOW2 disk image
use microsandbox::sandbox::ImageBuilder;
Sandbox::builder("block").image(|img: ImageBuilder| img.disk("./disk.qcow2").fstype("ext4"))
```

#### <img height="14" src="https://octicons-col.vercel.app/file/A770EF">&nbsp;&nbsp;Guest Filesystem Access

Read and write files inside the running sandbox from the host side:

```rs
// Write a file into the sandbox.
sandbox.fs().write("/tmp/input.txt", b"some data").await?;

// Read a file from the sandbox.
let content = sandbox.fs().read_to_string("/tmp/output.txt").await?;

// List directory contents.
let entries = sandbox.fs().list("/tmp").await?;
```

#### <img height="14" src="https://octicons-col.vercel.app/meter/A770EF">&nbsp;&nbsp;Streaming Execution

For long-running commands, stream stdout/stderr events in real time:

```rs
use microsandbox::sandbox::exec::ExecEvent;

let mut handle = sandbox.exec_streaming("python train.py").await?;

while let Some(event) = handle.events().await {
    match event {
        ExecEvent::Stdout(data) => print!("{}", String::from_utf8_lossy(&data)),
        ExecEvent::Stderr(data) => eprint!("{}", String::from_utf8_lossy(&data)),
        ExecEvent::Exited { code } => println!("Process exited: {code}"),
        _ => {}
    }
}
```

<a href="https://docs2.microsandbox.dev/sdk/overview"><img src="https://img.shields.io/badge/SDK_Docs-%E2%86%92-A770EF?style=flat-square&labelColor=2b2b2b" alt="SDK Docs"></a>

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/terminal/ffffff" alt="cli-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/terminal/000000" alt="cli"></a>&nbsp;&nbsp;CLI

The `msb` CLI provides a complete interface for managing sandboxes, images, and volumes.

#### <img height="14" src="https://octicons-col.vercel.app/play/A770EF">&nbsp;&nbsp;Run a Command

```sh
msb run python:3.12 -- python3 -c "print('Hello from a microVM!')"
```

#### <img height="14" src="https://octicons-col.vercel.app/stopwatch/A770EF">&nbsp;&nbsp;Named Sandboxes

Create a sandbox, exec into it, and manage its lifecycle:

```sh
# Create and run detached
msb run --name my-app -d python:3.12

# Execute commands
msb exec my-app -- pip install requests
msb exec my-app -- python3 main.py

# Interactive shell into a running sandbox
msb shell my-app

# Lifecycle
msb stop my-app
msb start my-app
msb rm my-app
```

#### <img height="14" src="https://octicons-col.vercel.app/cache/A770EF">&nbsp;&nbsp;Image Management

```sh
msb pull python:3.12           # Pull an image
msb image ls                   # List cached images
msb image rm python:3.12       # Remove an image
```

#### <img height="14" src="https://octicons-col.vercel.app/database/A770EF">&nbsp;&nbsp;Volume Management

```sh
msb volume create my-data      # Create a volume
msb volume ls                  # List volumes
msb volume rm my-data          # Remove a volume
```

#### <img height="14" src="https://octicons-col.vercel.app/list-unordered/A770EF">&nbsp;&nbsp;Status & Inspection

```sh
msb ls                         # List all sandboxes
msb ps my-app                  # Show sandbox status
msb inspect my-app             # Detailed sandbox info
msb metrics my-app             # Live CPU/memory/network stats
```

> [!TIP]
>
> Run `msb --tree` to see all available commands and their options.

<a href="https://docs2.microsandbox.dev/cli/overview"><img src="https://img.shields.io/badge/CLI_Docs-%E2%86%92-A770EF?style=flat-square&labelColor=2b2b2b" alt="CLI Docs"></a>

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/light-bulb/ffffff" alt="uninstall-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/light-bulb/000000" alt="uninstall"></a>&nbsp;&nbsp;Uninstall

To uninstall microsandbox, run: `msb self uninstall`.

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/gear/ffffff" alt="contributing-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/gear/000000" alt="contributing"></a>&nbsp;&nbsp;Contributing

Interested in contributing to `microsandbox`? Check out our [Development Guide](./DEVELOPMENT.md) for instructions on setting up your development environment, building the project, running tests, and creating releases. For contribution guidelines, please refer to [CONTRIBUTING.md](./CONTRIBUTING.md).

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/law/ffffff" alt="license-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/law/000000" alt="license"></a>&nbsp;&nbsp;License

This project is licensed under the [Apache License 2.0](./LICENSE).

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/heart/ffffff" alt="acknowledgements-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/heart/000000" alt="acknowledgements"></a>&nbsp;&nbsp;Acknowledgements

Special thanks to all our contributors, testers, and community members who help make microsandbox better every day! We'd like to thank the following projects and communities that made `microsandbox` possible: [libkrun](https://github.com/containers/libkrun) and [smoltcp](https://github.com/smoltcp-rs/smoltcp)
