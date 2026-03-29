<a href="./#gh-dark-mode-only" target="_blank">
<img width="100%" src="./assets/microsandbox-banner-xl-dark.png" alt="microsandbox-banner-xl-dark">
</a>
<a href="./#gh-light-mode-only" target="_blank">
<img width="100%" src="./assets/microsandbox-banner-xl.png" alt="microsandbox-banner-xl">
</a>

<div align="center"><b>———&nbsp;&nbsp;&nbsp;every agent deserves its own computer&nbsp;&nbsp;&nbsp;———</b></div>
<br />
<div align='center'>
  <a href="https://docs2.microsandbox.dev" target="_blank">
    <img src="https://img.shields.io/badge/documentation-%2300acee.svg?color=ff4500&style=for-the-badge&logo=gitbook&logoColor=white" alt=documentation style="margin-bottom: 5px;"/>
  </a>
  <a href="https://discord.gg/T95Y3XnEAK" target="_blank">
    <img src="https://img.shields.io/badge/discord -%2300acee.svg?color=mediumslateblue&style=for-the-badge&logo=discord&logoColor=white" alt=discord style="margin-bottom: 5px;"/>
  </a>
</div>

<div align='center'>
  <img src="https://img.shields.io/badge/macos-working-green?style=for-the-badge" alt=macos style="margin-bottom: 5px;"/>
  <img src="https://img.shields.io/badge/linux-working-green?style=for-the-badge" alt=linux style="margin-bottom: 5px;"/>
  <img src="https://img.shields.io/badge/windows-wip-red?style=for-the-badge" alt=windows style="margin-bottom: 5px;"/>
</div>
<br/>

## <img height="20" src="https://octicons-col.vercel.app/package/A770EF">&nbsp;Microsandbox

Microsandbox spins up lightweight microVMs in **under a second**, right from your code. No servers, no daemons, no infrastructure to manage. Just a library call that boots a real virtual machine with its own Linux kernel, filesystem, and network stack.

AI agents operate with whatever permissions you give them, and that's usually too much. They can see API keys in the environment, reach the network without restriction, and a single prompt injection can execute destructive commands on your host. Containers help, but they share the host kernel, making namespace escapes a known risk. Microsandbox solves this with **hardware-level VM isolation** that's fast enough to use in every request.

> [!WARNING]
> Microsandbox is still **experimental software**. Expect breaking changes, missing features, and rough edges.

<br/>

## <img height="18" src="https://octicons-col.vercel.app/sparkle/A770EF">&nbsp;&nbsp;Key Features

- <img height="15" src="https://octicons-col.vercel.app/shield-lock/A770EF"> **Hardware Isolation**: Each sandbox is a real [microVM](https://docs2.microsandbox.dev/sandboxes/overview). Not a container, not a namespace. Hypervisor-level separation.
- <img height="15" src="https://octicons-col.vercel.app/zap/A770EF"> **Sub-Second Boot**: Sandboxes start in under a second. Fast enough to spin one up per request.
- <img height="15" src="https://octicons-col.vercel.app/plug/A770EF"> **Embeddable**: The SDK boots VMs as child processes. No daemon, no server, no socket. Just `cargo add microsandbox`.
- <img height="15" src="https://octicons-col.vercel.app/globe/A770EF"> **Programmable Networking**: Every packet passes through a host-side [network stack](https://docs2.microsandbox.dev/sandboxes/networking) with policy enforcement, DNS interception, and TLS MITM. Guests can't bypass it.
- <img height="15" src="https://octicons-col.vercel.app/lock/A770EF"> **Secrets That Can't Leak**: Secrets never enter the VM. The guest sees a [placeholder](https://docs2.microsandbox.dev/sdk/networking); the real value is only substituted when a request hits an allowed host.
- <img height="15" src="https://octicons-col.vercel.app/package/A770EF"> **OCI Compatible**: Run standard container images from Docker Hub, GHCR, ECR, or any OCI registry. Shared layers are deduplicated.
- <img height="15" src="https://octicons-col.vercel.app/file-directory/A770EF"> **Flexible Rootfs**: Boot from [OCI images](https://docs2.microsandbox.dev/images/overview), local directories, or [disk images](https://docs2.microsandbox.dev/images/disk-images) (QCOW2, Raw, VMDK).
- <img height="15" src="https://octicons-col.vercel.app/database/A770EF"> **Persistent Volumes**: [Named volumes](https://docs2.microsandbox.dev/sandboxes/volumes) survive sandbox restarts and can be shared across multiple sandboxes.
- <img height="15" src="https://octicons-col.vercel.app/terminal/A770EF"> **Full CLI**: Manage sandboxes, images, and volumes from the terminal with `msb`.

<br/>

## <img height="13" src="https://octicons-col.vercel.app/north-star/A770EF">&nbsp;&nbsp;Getting Started

### <img height="14" src="https://octicons-col.vercel.app/move-to-bottom/A770EF">&nbsp;&nbsp;Install the SDK

```sh
cargo add microsandbox
```

> The SDK embeds the runtime directly. No separate server or daemon needed.

### <img height="14" src="https://octicons-col.vercel.app/download/A770EF">&nbsp;&nbsp;Install the CLI (optional)

The `msb` CLI is useful for managing images, volumes, and sandboxes from the terminal:

```sh
curl -fsSL https://install.microsandbox.dev | sh
```

> **Requirements**: Linux with KVM enabled, or macOS with Apple Silicon.

<br/>

## <img height="18" src="https://octicons-col.vercel.app/package-dependencies/A770EF">&nbsp;&nbsp;SDK

The SDK lets you create and control sandboxes directly from your application. `Sandbox::builder(...)` boots a microVM as a child process. No infrastructure required.

##### <img height="14" src="https://octicons-col.vercel.app/play/A770EF">&nbsp;&nbsp;Run Code in a Sandbox

```rs
use microsandbox::sandbox::Sandbox;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let sandbox = Sandbox::builder("my-sandbox")
        .image("python:3.12")
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

##### <img height="14" src="https://octicons-col.vercel.app/lock/A770EF">&nbsp;&nbsp;Secrets That Never Enter the VM

Secrets are injected via placeholder substitution. The guest environment only ever sees a random placeholder. The real value is swapped in at the network level, and only for requests to hosts you allow.

```rs
let sandbox = Sandbox::builder("api-client")
    .image("python:3.12")
    .secret_env("OPENAI_API_KEY", "sk-real-secret-123", "api.openai.com")
    .create()
    .await?;

// Inside the VM: $OPENAI_API_KEY = "$MSB_OPENAI_API_KEY" (placeholder)
// Requests to api.openai.com: placeholder is replaced with the real key
// Requests to any other host: placeholder stays, secret never leaks
```

##### <img height="14" src="https://octicons-col.vercel.app/globe/A770EF">&nbsp;&nbsp;Network Policy

Control exactly what the sandbox can reach. The in-process networking stack enforces policy at the IP, DNS, and HTTP level. There's no host network to bridge to, so guests can't bypass the filter.

```rs
use microsandbox::sandbox::{NetworkPolicy, Sandbox};

let sandbox = Sandbox::builder("restricted")
    .image("alpine:latest")
    .network(|n| {
        n.policy(NetworkPolicy::public_only())  // blocks private/loopback
         .block_domain_suffix(".evil.com")       // DNS-level blocking
    })
    .create()
    .await?;
```

Three built-in policies: `NetworkPolicy::public_only()` (default, blocks private IPs), `NetworkPolicy::allow_all()`, and `NetworkPolicy::none()` (fully airgapped).

##### <img height="14" src="https://octicons-col.vercel.app/upload/A770EF">&nbsp;&nbsp;Port Publishing

Expose guest services on host ports:

```rs
let sandbox = Sandbox::builder("web-server")
    .image("alpine:latest")
    .port(8080, 80)  // host:8080 → guest:80
    .create()
    .await?;
```

##### <img height="14" src="https://octicons-col.vercel.app/database/A770EF">&nbsp;&nbsp;Named Volumes

Persistent storage that survives sandbox restarts and can be shared across sandboxes:

```rs
use microsandbox::{sandbox::Sandbox, size::SizeExt, volume::Volume};

// Create a volume with a quota.
let data = Volume::builder("shared-data").quota(100.mib()).create().await?;

// Sandbox A writes to it.
let writer = Sandbox::builder("writer")
    .image("alpine:latest")
    .volume("/data", |v| v.named(data.name()))
    .create()
    .await?;

writer.shell("echo 'hello' > /data/message.txt").await?;
writer.stop_and_wait().await?;

// Sandbox B reads from it.
let reader = Sandbox::builder("reader")
    .image("alpine:latest")
    .volume("/data", |v| v.named(data.name()).readonly())
    .create()
    .await?;

let output = reader.shell("cat /data/message.txt").await?;
println!("{}", output.stdout()?); // hello
```

##### <img height="14" src="https://octicons-col.vercel.app/pencil/A770EF">&nbsp;&nbsp;Rootfs Patches

Modify the filesystem before the VM boots. Inject config files, create directories, append to existing files:

```rs
let sandbox = Sandbox::builder("configured")
    .image("alpine:latest")
    .patch(|p| {
        p.text("/etc/app.conf", "key=value\n", None, false)
         .mkdir("/app", Some(0o755))
         .append("/etc/hosts", "127.0.0.1 myapp.local\n")
    })
    .create()
    .await?;
```

##### <img height="14" src="https://octicons-col.vercel.app/file-binary/A770EF">&nbsp;&nbsp;Flexible Rootfs Sources

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

##### <img height="14" src="https://octicons-col.vercel.app/file/A770EF">&nbsp;&nbsp;Guest Filesystem Access

Read and write files inside the running sandbox from the host side:

```rs
// Write a file into the sandbox.
sandbox.fs().write("/tmp/input.txt", b"some data").await?;

// Read a file from the sandbox.
let content = sandbox.fs().read_to_string("/tmp/output.txt").await?;

// List directory contents.
let entries = sandbox.fs().list("/tmp").await?;
```

##### <img height="14" src="https://octicons-col.vercel.app/meter/A770EF">&nbsp;&nbsp;Streaming Execution

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

<br/>

## <img height="18" src="https://octicons-col.vercel.app/terminal/A770EF">&nbsp;&nbsp;CLI

The `msb` CLI provides a complete interface for managing sandboxes, images, and volumes.

##### <img height="14" src="https://octicons-col.vercel.app/play/A770EF">&nbsp;&nbsp;Run a Command

```sh
msb run python:3.12 -- python3 -c "print('Hello from a microVM!')"
```

##### <img height="14" src="https://octicons-col.vercel.app/stopwatch/A770EF">&nbsp;&nbsp;Named Sandboxes

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

##### <img height="14" src="https://octicons-col.vercel.app/cache/A770EF">&nbsp;&nbsp;Image Management

```sh
msb pull python:3.12           # Pull an image
msb image ls                   # List cached images
msb image rm python:3.12       # Remove an image
```

##### <img height="14" src="https://octicons-col.vercel.app/database/A770EF">&nbsp;&nbsp;Volume Management

```sh
msb volume create my-data      # Create a volume
msb volume ls                  # List volumes
msb volume rm my-data          # Remove a volume
```

##### <img height="14" src="https://octicons-col.vercel.app/list-unordered/A770EF">&nbsp;&nbsp;Status & Inspection

```sh
msb ls                         # List all sandboxes
msb ps my-app                  # Show sandbox status
msb inspect my-app             # Detailed sandbox info
msb metrics my-app             # Live CPU/memory/network stats
```

> [!TIP]
>
> Run `msb <subcommand> --help` to see all available options for a subcommand.

<a href="https://docs2.microsandbox.dev/cli/overview"><img src="https://img.shields.io/badge/CLI_Docs-%E2%86%92-A770EF?style=flat-square&labelColor=2b2b2b" alt="CLI Docs"></a>

<br/>

## <img height="18" src="https://octicons-col.vercel.app/light-bulb/A770EF">&nbsp;&nbsp;Uninstall

To uninstall microsandbox, run: `msb self uninstall`.

<br/>

## <img height="18" src="https://octicons-col.vercel.app/gear/A770EF">&nbsp;&nbsp;Contributing

Interested in contributing to `microsandbox`? Check out our [Development Guide](./DEVELOPMENT.md) for instructions on setting up your development environment, building the project, running tests, and creating releases. For contribution guidelines, please refer to [CONTRIBUTING.md](./CONTRIBUTING.md).

<br/>

## <img height="18" src="https://octicons-col.vercel.app/law/A770EF">&nbsp;&nbsp;License

This project is licensed under the [Apache License 2.0](./LICENSE).

<br/>

## <img height="18" src="https://octicons-col.vercel.app/heart/A770EF">&nbsp;&nbsp;Acknowledgements

Special thanks to all our contributors, testers, and community members who help make microsandbox better every day! We'd like to thank the following projects and communities that made `microsandbox` possible: [libkrun](https://github.com/containers/libkrun) and [smoltcp](https://github.com/smoltcp-rs/smoltcp)
