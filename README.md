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
  <a href="https://discord.gg/T95Y3XnEAK" target="_blank">
    <img src="https://img.shields.io/badge/join discord-%2300acee.svg?color=mediumslateblue&style=for-the-badge&logo=discord&logoColor=white" alt=discord style="margin-bottom: 5px;"/>
  </a>

  <a href="https://x.com/microsandbox" target="_blank">
    <img src="https://img.shields.io/badge/follow on X-%2300acee.svg?color=000000&style=for-the-badge&logo=X&logoColor=white" alt=discourse style="margin-bottom: 5px;"/>
  </a>
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
- <img height="15" src="https://octicons-col.vercel.app/terminal/A770EF"> **Agent-Ready**: Your agents can create their own sandboxes with our [Agent Skills] and [MCP server].

> Microsandbox is still **beta software**. Expect breaking changes, missing features, and rough edges.

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="13" src="https://octicons-col.vercel.app/rocket/ffffff" alt="rocket-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="13" src="https://octicons-col.vercel.app/rocket/000000" alt="rocket"></a>&nbsp;&nbsp;Getting Started

#### <img height="14" src="https://octicons-col.vercel.app/move-to-bottom/A770EF">&nbsp;&nbsp;Install the SDK

> ```sh
> cargo add microsandbox
> ```

#### <img height="14" src="https://octicons-col.vercel.app/download/A770EF">&nbsp;&nbsp;Install the CLI (optional)

The `msb` CLI is useful for managing images, volumes, and sandboxes from the terminal:

> ```sh
> curl -fsSL https://install.microsandbox.dev | sh
> ```

> **Requirements**: Linux with KVM enabled, or macOS with Apple Silicon.

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/package-dependencies/ffffff" alt="sdk-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/package-dependencies/000000" alt="sdk"></a>&nbsp;&nbsp;SDK

The SDK lets you create and control sandboxes directly from your application. `Sandbox::builder(...)` boots a microVM as a child process. No infrastructure required.

#### <img height="14" src="https://octicons-col.vercel.app/play/A770EF">&nbsp;&nbsp;Run Code in a Sandbox

>  <details open>
>    <summary>&nbsp;Typescript</summary>
>
> ```typescript
> import { Sandbox } from "microsandbox";
>
> const sandbox = await Sandbox.create({
>   name: "my-sandbox",
>   image: "python",
>   cpus: 1,
>   memoryMib: 512,
> });
>
> const output = await sandbox.shell("print('Hello from a microVM!')");
> console.log(output.stdout());
>
> await sandbox.stopAndWait();
> ```
>  </details>
>
>  <details>
>    <summary>&nbsp;Rust</summary>
>
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
>  </details>
>
>
> Behind the scenes, `create()` pulls the image (if not cached), assembles the filesystem, boots a microVM. All in under a second.

#### <img height="14" src="https://octicons-col.vercel.app/lock/A770EF">&nbsp;&nbsp;Secrets That Never Enter the VM

> Secrets are injected via placeholder substitution. The guest environment only ever sees a random placeholder. The real value is swapped in at the network level.
>
>  <details open>
>    <summary>&nbsp;Typescript</summary>
>
> ```typescript
> const sandbox = await Sandbox.create({
>   name: "api-client",
>   image: "python",
>   secretEnv: { OPENAI_API_KEY: { value: "sk-real-secret-123", domain: "api.openai.com" } },
> });
>
> // Inside the VM: $OPENAI_API_KEY = "$MSB_OPENAI_API_KEY" (placeholder)
> // Requests to api.openai.com: placeholder is replaced with the real key
> // Requests to any other host: placeholder stays, secret never leaks
> ```
>  </details>
>
>  <details>
>    <summary>&nbsp;Rust</summary>
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
>  </details>

#### <img height="14" src="https://octicons-col.vercel.app/globe/A770EF">&nbsp;&nbsp;Network Policy

> Control exactly what the sandbox can reach. The in-process networking stack enforces policy at the IP, DNS, and HTTP level. There's no host network to bridge to, so guests can't bypass the filter.
>
>  <details open>
>    <summary>&nbsp;Typescript</summary>
>
> ```typescript
> import { Sandbox } from "microsandbox";
>
> const sandbox = await Sandbox.create({
>   name: "restricted",
>   image: "alpine",
>   network: {
>     policy: "public-only",            // blocks private/loopback
>     blockDomainSuffixes: [".evil.com"] // DNS-level blocking
>   },
> });
> ```
>  </details>
>
>  <details>
>    <summary>&nbsp;Rust</summary>
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
>  </details>
>
> Three built-in policies: `NetworkPolicy::public_only()` (default, blocks private IPs), `NetworkPolicy::allow_all()`, and `NetworkPolicy::none()` (fully airgapped).

#### <img height="14" src="https://octicons-col.vercel.app/upload/A770EF">&nbsp;&nbsp;Port Publishing

> Expose guest services on host ports:
>
>  <details open>
>    <summary>&nbsp;Typescript</summary>
>
> ```typescript
> const sandbox = await Sandbox.create({
>   name: "web-server",
>   image: "alpine",
>   ports: { 8080: 80 }, // host:8080 → guest:80
> });
> ```
>  </details>
>
>  <details>
>    <summary>&nbsp;Rust</summary>
>
> ```rs
> let sandbox = Sandbox::builder("web-server")
>     .image("alpine")
>     .port(8080, 80)  // host:8080 → guest:80
>     .create()
>     .await?;
> ```
>  </details>

#### <img height="14" src="https://octicons-col.vercel.app/database/A770EF">&nbsp;&nbsp;Named Volumes

> Persistent storage that survives sandbox restarts and can be shared across sandboxes:
>
>  <details open>
>    <summary>&nbsp;Typescript</summary>
>
> ```typescript
> import { Sandbox, Volume } from "microsandbox";
>
> // Create a volume with a quota.
> const data = await Volume.create({ name: "shared-data", quotaMib: 100 });
>
> // Sandbox A writes to it.
> const writer = await Sandbox.create({
>   name: "writer",
>   image: "alpine",
>   volumes: { "/data": { named: data.name } },
> });
>
> await writer.shell("echo 'hello' > /data/message.txt");
> await writer.stopAndWait();
>
> // Sandbox B reads from it.
> const reader = await Sandbox.create({
>   name: "reader",
>   image: "alpine",
>   volumes: { "/data": { named: data.name, readonly: true } },
> });
>
> const output = await reader.shell("cat /data/message.txt");
> console.log(output.stdout()); // hello
> ```
>  </details>
>
>  <details>
>    <summary>&nbsp;Rust</summary>
>
> ```rs
> use microsandbox::{Sandbox, Volume, size::SizeExt};
>
> // Create a volume with a quota.
> let data = Volume::builder("shared-data").quota(100.mib()).create().await?;
>
> // Sandbox A writes to it.
> let writer = Sandbox::builder("writer")
>     .image("alpine")
>     .volume("/data", |v| v.named(data.name()))
>     .create()
>     .await?;
>
> writer.shell("echo 'hello' > /data/message.txt").await?;
> writer.stop_and_wait().await?;
>
> // Sandbox B reads from it.
> let reader = Sandbox::builder("reader")
>     .image("alpine")
>     .volume("/data", |v| v.named(data.name()).readonly())
>     .create()
>     .await?;
>
> let output = reader.shell("cat /data/message.txt").await?;
> println!("{}", output.stdout()?); // hello
> ```
>  </details>

#### <img height="14" src="https://octicons-col.vercel.app/pencil/A770EF">&nbsp;&nbsp;Scripts & Patches

> Register named scripts that get mounted at `/.msb/scripts/` and added to `PATH`, so you can invoke them by name:
>
>  <details open>
>    <summary>&nbsp;Typescript</summary>
>
> ```typescript
> const sandbox = await Sandbox.create({
>   name: "worker",
>   image: "ubuntu",
>   scripts: {
>     setup: "#!/bin/bash\napt-get update && apt-get install -y python3 curl",
>     start: "#!/bin/bash\nexec python3 /app/main.py",
>   },
> });
>
> await sandbox.shell("setup");
> const output = await sandbox.shell("start");
> ```
>  </details>
>
>  <details>
>    <summary>&nbsp;Rust</summary>
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
>  </details>
>
> Patches modify the filesystem before the VM boots. Inject config files, create directories, append to existing files:
>
>  <details open>
>    <summary>&nbsp;Typescript</summary>
>
> ```typescript
> const sandbox = await Sandbox.create({
>   name: "configured",
>   image: "alpine",
>   patches: [
>     { kind: "text", path: "/etc/app.conf", content: "key=value\n" },
>     { kind: "mkdir", path: "/app", mode: 0o755 },
>     { kind: "append", path: "/etc/hosts", content: "127.0.0.1 myapp.local\n" },
>   ],
> });
> ```
>  </details>
>
>  <details>
>    <summary>&nbsp;Rust</summary>
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
>  </details>

#### <img height="14" src="https://octicons-col.vercel.app/file-binary/A770EF">&nbsp;&nbsp;Flexible Rootfs Sources

> Boot from an OCI image, a local directory, or a disk image:
>
>  <details open>
>    <summary>&nbsp;Typescript</summary>
>
> ```typescript
> // OCI image (default)
> await Sandbox.create({ name: "oci", image: "python:3.12" });
>
> // Local directory
> await Sandbox.create({ name: "bind", image: "./my-rootfs" });
> ```
>  </details>
>
>  <details>
>    <summary>&nbsp;Rust</summary>
>
> ```rs
> // OCI image (default)
> Sandbox::builder("oci").image("python:3.12")
>
> // Local directory
> Sandbox::builder("bind").image("./my-rootfs")
>
> // QCOW2 disk image
> use microsandbox::sandbox::ImageBuilder;
> Sandbox::builder("block").image(|img: ImageBuilder| img.disk("./disk.qcow2").fstype("ext4"))
> ```
>  </details>

#### <img height="14" src="https://octicons-col.vercel.app/file/A770EF">&nbsp;&nbsp;Guest Filesystem Access

> Read and write files inside the running sandbox from the host side:
>
>  <details open>
>    <summary>&nbsp;Typescript</summary>
>
> ```typescript
> // Write a file into the sandbox.
> await sandbox.fs().write("/tmp/input.txt", Buffer.from("some data"));
>
> // Read a file from the sandbox.
> const content = await sandbox.fs().readString("/tmp/output.txt");
>
> // List directory contents.
> const entries = await sandbox.fs().list("/tmp");
> ```
>  </details>
>
>  <details>
>    <summary>&nbsp;Rust</summary>
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
>  </details>

#### <img height="14" src="https://octicons-col.vercel.app/meter/A770EF">&nbsp;&nbsp;Streaming Execution

> For long-running commands, stream stdout/stderr events in real time:
>
>  <details open>
>    <summary>&nbsp;Typescript</summary>
>
> ```typescript
> const handle = await sandbox.shellStream("python train.py");
>
> let event;
> while ((event = await handle.recv()) !== null) {
>   if (event.eventType === "stdout") process.stdout.write(event.data);
>   if (event.eventType === "stderr") process.stderr.write(event.data);
>   if (event.eventType === "exited") console.log(`Process exited: ${event.code}`);
> }
> ```
>  </details>
>
>  <details>
>    <summary>&nbsp;Rust</summary>
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
>  </details>

<a href="https://docs2.microsandbox.dev/sdk/overview"><img src="https://img.shields.io/badge/SDK_Docs-%E2%86%92-A770EF?style=flat-square&labelColor=2b2b2b" alt="SDK Docs"></a>

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/terminal/ffffff" alt="cli-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/terminal/000000" alt="cli"></a>&nbsp;&nbsp;CLI

The `msb` CLI provides a complete interface for managing sandboxes, images, and volumes.

#### <img height="14" src="https://octicons-col.vercel.app/play/A770EF">&nbsp;&nbsp;Run a Command

> ```sh
> msb run python:3.12 -- python3 -c "print('Hello from a microVM!')"
> ```

#### <img height="14" src="https://octicons-col.vercel.app/stopwatch/A770EF">&nbsp;&nbsp;Named Sandboxes

> ```sh
> # Create and run detached
> msb run --name my-app -d python:3.12
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
> msb pull python:3.12           # Pull an image
> msb image ls                   # List cached images
> msb image rm python:3.12       # Remove an image
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

<a href="https://docs2.microsandbox.dev/cli/overview"><img src="https://img.shields.io/badge/CLI_Docs-%E2%86%92-A770EF?style=flat-square&labelColor=2b2b2b" alt="CLI Docs"></a>

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/light-bulb/ffffff" alt="uninstall-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/light-bulb/000000" alt="uninstall"></a>&nbsp;&nbsp;Uninstall

To uninstall microsandbox, run: `msb self uninstall`.

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/gear/ffffff" alt="contributing-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/gear/000000" alt="contributing"></a>&nbsp;&nbsp;Contributing

Interested in contributing to `microsandbox`? Check out our [Development Guide](./DEVELOPMENT.md) for instructions on setting up your development environment, building the project, running tests, and creating releases. For contribution guidelines, please refer to [CONTRIBUTING.md](./CONTRIBUTING.md).

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/law/ffffff" alt="license-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/law/000000" alt="license"></a>&nbsp;&nbsp;License

This project is licensed under the [Apache License 2.0](./LICENSE).

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/heart/ffffff" alt="acknowledgements-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/heart/000000" alt="acknowledgements"></a>&nbsp;&nbsp;Acknowledgements

Special thanks to all our contributors, testers, and community members who help make microsandbox better every day! We'd like to thank the following projects and communities that made `microsandbox` possible: [libkrun](https://github.com/containers/libkrun) and [smoltcp](https://github.com/smoltcp-rs/smoltcp)
