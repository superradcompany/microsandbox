<div align="center">
    <a href="./#gh-dark-mode-only" target="_blank" align="center">
        <img width="35%" src="./assets/microsandbox-gh-banner-dark.png" alt="microsandbox-banner-xl-dark">
    </a>
</div>

<div align="center">
    <a href="./#gh-light-mode-only" target="_blank">
        <img width="35%" src="./assets/microsandbox-gh-banner-light.png" alt="microsandbox-banner-xl">
    </a>
</div>

<br />

<div align="center"><b>——&nbsp;&nbsp;&nbsp;every agent deserves its own computer&nbsp;&nbsp;&nbsp;——</b></div>

<br />
<br />

<div align='center'>
  <a href="https://github.com/superradcompany/microsandbox/releases"><img src="https://img.shields.io/github/v/release/superradcompany/microsandbox?include_prereleases&style=for-the-badge" alt="GitHub release"></a>
  <a href="https://discord.gg/T95Y3XnEAK"><img src="https://img.shields.io/discord/1315784565562019870?label=Discord&logo=discord&logoColor=white&color=5865F2&style=for-the-badge" alt="Discord"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache 2.0-blue.svg?style=for-the-badge" alt="Apache 2.0 License"></a>
</div>

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/package/ffffff" alt="package-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/package/000000" alt="package"></a>&nbsp;&nbsp;Microsandbox

Microsandbox spins up **lightweight VMs in milliseconds** from our SDKs. Runs locally on your machine. No server to set up. No lingering daemon. It is all embedded and rootless!

Today, AI agents operate with whatever permissions you give them, and that's usually _too much_. They can see _API keys_ in the environment, reach the network without restriction, and a single prompt injection _can execute destructive commands_ on your host. Containers help, but they share the host kernel, making _namespace escapes_ a known risk. Microsandbox solves this with **hardware-level VM isolation** that boots in milliseconds.

- <img height="15" src="https://octicons-col.vercel.app/shield-lock/A770EF"> **Hardware Isolation**: Hypervisor-level isolation with microVM technology.
- <img height="15" src="https://octicons-col.vercel.app/zap/A770EF"> **Instant Startup**: Boot times under 100 milliseconds.
- <img height="15" src="https://octicons-col.vercel.app/plug/A770EF"> **Embeddable**: Spawn VMs right within your code. No setup server. No long-running daemon.
- <img height="15" src="https://octicons-col.vercel.app/lock/A770EF"> **Secrets That Can't Leak**: Secret keys never enter the VM. The guest VM only sees placeholders.
- <img height="15" src="https://octicons-col.vercel.app/globe/A770EF"> **Programmable Filesystem & Network Stack**: Customizable filesystems and network operations.
- <img height="15" src="https://octicons-col.vercel.app/package/A770EF"> **OCI Compatible**: Runs standard container images from Docker Hub, GHCR, or any OCI registry.
- <img height="15" src="https://octicons-col.vercel.app/database/A770EF"> **Long-Running**: Sandboxes can run in detached mode. They are great for long-lived sessions.
- <img height="15" src="https://octicons-col.vercel.app/terminal/A770EF"> **Agent-Ready**: Your agents can create their own sandboxes with our [Agent Skills](https://github.com/superradcompany/skills) and [MCP server](https://github.com/superradcompany/microsandbox-mcp).

> Microsandbox is still **beta software**. Expect breaking changes, missing features, and rough edges.

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="13" src="https://octicons-col.vercel.app/rocket/ffffff" alt="rocket-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="13" src="https://octicons-col.vercel.app/rocket/000000" alt="rocket"></a>&nbsp;&nbsp;Getting Started

#### <img height="14" src="https://octicons-col.vercel.app/move-to-bottom/A770EF">&nbsp;&nbsp;Install the SDK

> ```sh
> cargo add microsandbox    # Rust
> ```
> ```sh
> npm i microsandbox        # TypeScript
> ```

#### <img height="14" src="https://octicons-col.vercel.app/download/A770EF">&nbsp;&nbsp;Install the CLI

The `msb` CLI is useful for managing images, volumes, and sandboxes from the terminal:

> ```sh
> curl -fsSL https://install.microsandbox.dev | sh
> ```

> **Requirements**: Linux with KVM enabled, or macOS with Apple Silicon.

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/package-dependencies/ffffff" alt="sdk-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/package-dependencies/000000" alt="sdk"></a>&nbsp;&nbsp;SDK

The SDK lets you create and control sandboxes directly from your application. `Sandbox::builder("...").create()` boots a microVM as a child process. No infrastructure required.

#### <img height="14" src="https://octicons-col.vercel.app/play/A770EF">&nbsp;&nbsp;Run Code in a Sandbox

> ```rs
> use microsandbox::Sandbox;
>
> #[tokio::main]
> async fn main() -> Result<(), Box<dyn std::error::Error>> {
>     let sandbox = Sandbox::builder("my-sandbox")
>         .image("python")
>         .cpus(1)
>         .memory(512)
>         .create()
>         .await?;
>
>     let output = sandbox.shell("print('Hello from a microVM!')").await?;
>     println!("{}", output.stdout()?);
>
>     sandbox.stop_and_wait().await?;
>     Ok(())
> }
> ```
>
> <div align="left">
>   <a href="./typescript_examples.md#run-code-in-a-sandbox"><img src="https://img.shields.io/badge/-→ Typescript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"></a>&nbsp;<a href="./python_examples.md"><img src="https://img.shields.io/badge/-→ Python-FFD43B?style=flat-square&logo=python&logoColor=306998" alt="Python"></a>
> </div>
>
> Behind the scenes, `create()` pulls the image (if not cached), assembles the filesystem, boots a microVM. All in under a second.

#### <img height="14" src="https://octicons-col.vercel.app/lock/A770EF">&nbsp;&nbsp;Secrets That Never Enter the VM

> Secrets are injected via placeholder substitution. The guest environment only ever sees a random placeholder. The real value is swapped in at the network level.
>
> ```rs
> let sandbox = Sandbox::builder("api-client")
>     .image("python")
>     .secret_env("OPENAI_API_KEY", "sk-real-secret-123", "api.openai.com")
>     .create()
>     .await?;
>
> // Inside the VM: $OPENAI_API_KEY = "$MSB_OPENAI_API_KEY" (placeholder)
> // Requests to api.openai.com: placeholder is replaced with the real key
> // Requests to any other host: placeholder stays, secret never leaks
> ```
>
> <div align="left">
>   <a href="./typescript_examples.md#secrets-that-never-enter-the-vm"><img src="https://img.shields.io/badge/-→ Typescript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"></a>&nbsp;<a href="./python_examples.md"><img src="https://img.shields.io/badge/-→ Python-FFD43B?style=flat-square&logo=python&logoColor=306998" alt="Python"></a>
> </div>

#### <img height="14" src="https://octicons-col.vercel.app/globe/A770EF">&nbsp;&nbsp;Network Policy

> Control exactly what the sandbox can reach. The in-process networking stack enforces policy at the IP, DNS, and HTTP level. There's no host network to bridge to, so guests can't bypass the filter.
>
> ```rs
> use microsandbox::{NetworkPolicy, Sandbox};
>
> let sandbox = Sandbox::builder("restricted")
>     .image("alpine")
>     .network(|n| {
>         n.policy(NetworkPolicy::public_only())  // blocks private/loopback
>          .block_domain_suffix(".evil.com")       // DNS-level blocking
>     })
>     .create()
>     .await?;
> ```
>
> <div align="left">
>   <a href="./typescript_examples.md#network-policy"><img src="https://img.shields.io/badge/-→ Typescript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"></a>&nbsp;<a href="./python_examples.md"><img src="https://img.shields.io/badge/-→ Python-FFD43B?style=flat-square&logo=python&logoColor=306998" alt="Python"></a>
> </div>
>
> Three built-in policies: `NetworkPolicy::public_only()` (default, blocks private IPs), `NetworkPolicy::allow_all()`, and `NetworkPolicy::none()` (fully airgapped).

#### <img height="14" src="https://octicons-col.vercel.app/upload/A770EF">&nbsp;&nbsp;Port Publishing

> Expose guest services on host ports:
>
> ```rs
> let sandbox = Sandbox::builder("web-server")
>     .image("alpine")
>     .port(8080, 80)  // host:8080 → guest:80
>     .create()
>     .await?;
> ```
>
> <div align="left">
>   <a href="./typescript_examples.md#port-publishing"><img src="https://img.shields.io/badge/-→ Typescript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"></a>&nbsp;<a href="./python_examples.md"><img src="https://img.shields.io/badge/-→ Python-FFD43B?style=flat-square&logo=python&logoColor=306998" alt="Python"></a>
> </div>

#### <img height="14" src="https://octicons-col.vercel.app/pencil/A770EF">&nbsp;&nbsp;Scripts & Patches

> Register named scripts that get mounted at `/.msb/scripts/` and added to `PATH`, so you can invoke them by name:
>
> ```rs
> let sandbox = Sandbox::builder("worker")
>     .image("ubuntu")
>     .script("setup", "#!/bin/bash\napt-get update && apt-get install -y python3 curl")
>     .script("start", "#!/bin/bash\nexec python3 /app/main.py")
>     .create()
>     .await?;
>
> sandbox.shell("setup").await?;
> let output = sandbox.shell("start").await?;
> ```
>
> <div align="left">
>   <a href="./typescript_examples.md#scripts"><img src="https://img.shields.io/badge/-→ Typescript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"></a>&nbsp;<a href="./python_examples.md"><img src="https://img.shields.io/badge/-→ Python-FFD43B?style=flat-square&logo=python&logoColor=306998" alt="Python"></a>
> </div>
>
> Patches modify the filesystem before the VM boots. Inject config files, create directories, append to existing files:
>
> ```rs
> let sandbox = Sandbox::builder("configured")
>     .image("alpine")
>     .patch(|p| {
>         p.text("/etc/app.conf", "key=value\n", None, false)
>          .mkdir("/app", Some(0o755))
>          .append("/etc/hosts", "127.0.0.1 myapp.local\n")
>     })
>     .create()
>     .await?;
> ```
>
> <div align="left">
>   <a href="./typescript_examples.md#patches"><img src="https://img.shields.io/badge/-→ Typescript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"></a>&nbsp;<a href="./python_examples.md"><img src="https://img.shields.io/badge/-→ Python-FFD43B?style=flat-square&logo=python&logoColor=306998" alt="Python"></a>
> </div>

#### <img height="14" src="https://octicons-col.vercel.app/file-binary/A770EF">&nbsp;&nbsp;Flexible Rootfs Sources

> Boot from an OCI image, a local directory, or a disk image:
>
> ```rs
> // OCI image (default)
> Sandbox::builder("oci").image("python")
>
> // Local directory
> Sandbox::builder("bind").image("./my-rootfs")
>
> // QCOW2 disk image
> Sandbox::builder("block").image_with(|img| img.disk("./disk.qcow2").fstype("ext4"))
> ```
>
> <div align="left">
>   <a href="./typescript_examples.md#flexible-rootfs-sources"><img src="https://img.shields.io/badge/-→ Typescript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"></a>&nbsp;<a href="./python_examples.md"><img src="https://img.shields.io/badge/-→ Python-FFD43B?style=flat-square&logo=python&logoColor=306998" alt="Python"></a>
> </div>

#### <img height="14" src="https://octicons-col.vercel.app/file/A770EF">&nbsp;&nbsp;Guest Filesystem Access

> Read and write files inside the running sandbox from the host side:
>
> ```rs
> // Write a file into the sandbox.
> sandbox.fs().write("/tmp/input.txt", b"some data").await?;
>
> // Read a file from the sandbox.
> let content = sandbox.fs().read_to_string("/tmp/output.txt").await?;
>
> // List directory contents.
> let entries = sandbox.fs().list("/tmp").await?;
> ```
>
> <div align="left">
>   <a href="./typescript_examples.md#guest-filesystem-access"><img src="https://img.shields.io/badge/-→ Typescript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"></a>&nbsp;<a href="./python_examples.md"><img src="https://img.shields.io/badge/-→ Python-FFD43B?style=flat-square&logo=python&logoColor=306998" alt="Python"></a>
> </div>

#### <img height="14" src="https://octicons-col.vercel.app/meter/A770EF">&nbsp;&nbsp;Streaming Execution

> For long-running commands, stream stdout/stderr events in real time:
>
> ```rs
> use microsandbox::ExecEvent;
>
> let mut handle = sandbox.shell_stream("python train.py").await?;
>
> while let Some(event) = handle.recv().await {
>     match event {
>         ExecEvent::Stdout(data) => print!("{}", String::from_utf8_lossy(&data)),
>         ExecEvent::Stderr(data) => eprint!("{}", String::from_utf8_lossy(&data)),
>         ExecEvent::Exited { code } => println!("Process exited: {code}"),
>         _ => {}
>     }
> }
> ```
>
> <div align="left">
>   <a href="./typescript_examples.md#streaming-execution"><img src="https://img.shields.io/badge/-→ Typescript-3178C6?style=flat-square&logo=typescript&logoColor=white" alt="TypeScript"></a>&nbsp;<a href="./python_examples.md"><img src="https://img.shields.io/badge/-→ Python-FFD43B?style=flat-square&logo=python&logoColor=306998" alt="Python"></a>
> </div>

<br />

<a href="https://docs2.microsandbox.dev/sdk/overview"><img src="https://img.shields.io/badge/SDK_Docs-%E2%86%92-A770EF?style=flat-square&labelColor=2b2b2b" alt="SDK Docs"></a>

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/terminal/ffffff" alt="cli-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/terminal/000000" alt="cli"></a>&nbsp;&nbsp;CLI

The `msb` CLI provides a complete interface for managing sandboxes, images, and volumes.

#### <img height="14" src="https://octicons-col.vercel.app/play/A770EF">&nbsp;&nbsp;Run a Command

> ```sh
> msb run python -- python3 -c "print('Hello from a microVM!')"
> ```

#### <img height="14" src="https://octicons-col.vercel.app/stopwatch/A770EF">&nbsp;&nbsp;Named Sandboxes

> ```sh
> # Create and run detached
> msb run --name my-app -d python
>
> # Execute commands
> msb exec my-app -- pip install requests
> msb exec my-app -- python3 main.py
>
> # Interactive shell into a running sandbox
> msb shell my-app
>
> # Lifecycle
> msb stop my-app
> msb start my-app
> msb rm my-app
> ```

#### <img height="14" src="https://octicons-col.vercel.app/cache/A770EF">&nbsp;&nbsp;Image Management

> ```sh
> msb pull python           # Pull an image
> msb image ls              # List cached images
> msb image rm python       # Remove an image
> ```

#### <img height="14" src="https://octicons-col.vercel.app/download/A770EF">&nbsp;&nbsp;Install & Uninstall Sandboxes

> ```sh
> msb install ubuntu               # Install ubuntu sandbox as 'ubuntu' command
> ubuntu                           # Opens Ubuntu in a microVM
> ```

> ```sh
> msb install --name nodebox node  # Custom command name
> msb install --tmp alpine         # Ephemeral: fresh sandbox every run
> msb install --list               # List installed commands
> msb uninstall nodebox            # Remove an installed command
> ```

#### <img height="14" src="https://octicons-col.vercel.app/database/A770EF">&nbsp;&nbsp;Volume Management

> ```sh
> msb volume create my-data      # Create a volume
> msb volume ls                  # List volumes
> msb volume rm my-data          # Remove a volume
> ```

#### <img height="14" src="https://octicons-col.vercel.app/list-unordered/A770EF">&nbsp;&nbsp;Status & Inspection

> ```sh
> msb ls                         # List all sandboxes
> msb ps my-app                  # Show sandbox status
> msb inspect my-app             # Detailed sandbox info
> msb metrics my-app             # Live CPU/memory/network stats
> ```

> [!TIP]
>
> Run `msb --tree` to see all available commands and their options.

<br />

<a href="https://docs2.microsandbox.dev/cli/overview"><img src="https://img.shields.io/badge/CLI_Docs-%E2%86%92-A770EF?style=flat-square&labelColor=2b2b2b" alt="CLI Docs"></a>

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/gear/ffffff" alt="contributing-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/gear/000000" alt="contributing"></a>&nbsp;&nbsp;Contributing

Interested in contributing to `microsandbox`? Check out our [Development Guide](./DEVELOPMENT.md) for instructions on setting up your development environment, building the project, running tests, and creating releases. For contribution guidelines, please refer to [CONTRIBUTING.md](./CONTRIBUTING.md).

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/law/ffffff" alt="license-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/law/000000" alt="license"></a>&nbsp;&nbsp;License

This project is licensed under the [Apache License 2.0](./LICENSE).

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/heart/ffffff" alt="acknowledgements-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/heart/000000" alt="acknowledgements"></a>&nbsp;&nbsp;Acknowledgements

Special thanks to all our contributors, testers, and community members who help make microsandbox better every day! We'd like to thank the following projects and communities that made `microsandbox` possible: [libkrun](https://github.com/containers/libkrun) and [smoltcp](https://github.com/smoltcp-rs/smoltcp)
