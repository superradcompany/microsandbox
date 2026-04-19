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

**Microsandbox** spins up **lightweight VMs in milliseconds** from our SDKs. Runs locally on your machine. No server to set up. No lingering daemon. It is all embedded and rootless!

##

- <img height="14" src="https://octicons-col.vercel.app/shield-lock/A770EF"> **Hardware Isolation**: Hardware-level isolation with microVM technology.
- <img height="14" src="https://octicons-col.vercel.app/zap/A770EF"> **Instant Startup**: Average boot times under 100 milliseconds.
- <img height="14" src="https://octicons-col.vercel.app/plug/A770EF"> **Embeddable**: Spawn VMs right within your code. No setup server. No long-running daemon.
- <img height="14" src="https://octicons-col.vercel.app/lock/A770EF"> **Secrets That Can't Leak**: Unexploitable secret keys that never enter the VM.
- <img height="14" src="https://octicons-col.vercel.app/package/A770EF"> **OCI Compatible**: Runs standard container images from Docker Hub, GHCR, or any OCI registry.
- <img height="14" src="https://octicons-col.vercel.app/database/A770EF"> **Long-Running**: Sandboxes can run in detached mode. Great for long-lived sessions.
- <img height="14" src="https://octicons-col.vercel.app/terminal/A770EF"> **Agent-Ready**: Your agents can create their own sandboxes with our [Agent Skills](https://github.com/superradcompany/skills) and [MCP server](https://github.com/superradcompany/microsandbox-mcp).


<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="13" src="https://octicons-col.vercel.app/rocket/ffffff" alt="rocket-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="13" src="https://octicons-col.vercel.app/rocket/000000" alt="rocket"></a>&nbsp;&nbsp;Getting Started

#### <img height="14" src="https://octicons-col.vercel.app/move-to-bottom/A770EF">&nbsp;&nbsp;Install the SDK

> ```sh
> cargo add microsandbox    # 🦀 Rust
> ```
> ```sh
> uv add microsandbox       # 🐍 Python
> ```
> ```sh
> npm i microsandbox        # 🟦 TypeScript
> ```

#### <img height="14" src="https://octicons-col.vercel.app/download/A770EF">&nbsp;&nbsp;Install the CLI **(Optional)**

> Boot a  microVM in one command.
>
> ```sh
> npx microsandbox run debian
> ```
>
> Or install the `msb` command globally:
>
> ```sh
> curl -fsSL https://install.microsandbox.dev | sh
> ```
>
> ```sh
> msb run debian
> ```

##

> **Requirements**: Linux with KVM enabled, or macOS with Apple Silicon.<br />
> **Warning**: Microsandbox is still **beta software**. Expect breaking changes, missing features, and rough edges.

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
>     let output = sandbox
>         .exec("python", ["-c", "print('Hello from a microVM!')"])
>         .await?;
>
>     println!("{}", output.stdout()?);
>
>     sandbox.stop_and_wait().await?;
>
>     Ok(())
> }
> ```
>
> <details>
> <summary><b>&nbsp;Python Example →</b></summary>
>
> ```python
> import asyncio
> from microsandbox import Sandbox
>
> async def main():
>     sandbox = await Sandbox.create(
>         "my-sandbox",
>         image="python",
>         cpus=1,
>         memory=512,
>     )
>
>     output = await sandbox.exec("python", ["-c", "print('Hello from a microVM!')"])
>
>     print(output.stdout_text)
>
>     await sandbox.stop_and_wait()
>
> asyncio.run(main())
> ```
>
> </details>
>
> <details>
> <summary><b>&nbsp;TypeScript Example →</b></summary>
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
> const output = await sandbox.exec("python", ["-c", "print('Hello from a microVM!')"]);
>
> console.log(output.stdout());
>
> await sandbox.stopAndWait();
> ```
>
> </details>


> The first call to `create()` pulls the image if it isn't cached locally, so it may take longer depending on your connection. Subsequent runs reuse the cache.

<br />

<a href="https://docs.microsandbox.dev/sdk/overview"><img src="https://img.shields.io/badge/SDK_Docs-%E2%86%92-A770EF?style=flat-square&labelColor=2b2b2b" alt="SDK Docs"></a>

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/terminal/ffffff" alt="cli-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/terminal/000000" alt="cli"></a>&nbsp;&nbsp;CLI

The `msb` CLI provides a complete interface for managing sandboxes, images, and volumes.

#### <img height="14" src="https://octicons-col.vercel.app/play/A770EF">&nbsp;&nbsp;Run a Command

> ```sh
> msb run python -- python3 -c "print('Hello from a microVM!')"
> ```

#### <img height="14" src="https://octicons-col.vercel.app/stopwatch/A770EF">&nbsp;&nbsp;Named Sandboxes

> ```sh
> # Create and start a named sandbox
> msb create --name my-app python
> ```
>
> ```sh
> # Execute commands
> msb exec my-app -- python -c "import this"
> msb exec my-app -- curl https://example.com
> ```
>
> ```sh
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
> msb uninstall ubuntu             # Uninstall the ubuntu sandbox
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

<a href="https://docs.microsandbox.dev/cli/overview"><img src="https://img.shields.io/badge/CLI_Docs-%E2%86%92-A770EF?style=flat-square&labelColor=2b2b2b" alt="CLI Docs"></a>

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/dependabot/ffffff" alt="agents-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/dependabot/000000" alt="agents"></a>&nbsp;&nbsp;AI Agents

Give your AI agents the ability to create and manage their own sandboxes.

#### <img height="14" src="https://octicons-col.vercel.app/book/A770EF">&nbsp;&nbsp;Agent Skills

> Teach any AI coding agent how to use microsandbox by installing the [Agent Skills](https://github.com/superradcompany/skills). Works with Claude Code, Cursor, Codex, Gemini CLI, GitHub Copilot, and more.
>
> ```sh
> npx skills add superradcompany/skills
> ```

#### <img height="14" src="https://octicons-col.vercel.app/plug/A770EF">&nbsp;&nbsp;MCP Server

> Connect any MCP-compatible agent to microsandbox with the [MCP server](https://github.com/superradcompany/microsandbox-mcp). Provides structured tool calls for sandbox lifecycle, command execution, filesystem access, volumes, and monitoring.
>
> ```sh
> # Claude Code
> claude mcp add --transport stdio microsandbox -- npx -y microsandbox-mcp
> ```

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/book/ffffff" alt="docs-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/book/000000" alt="docs"></a>&nbsp;&nbsp;Documentation

For guides, API references, and examples, visit the [microsandbox documentation](https://docs.microsandbox.dev).

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/gear/ffffff" alt="contributing-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/gear/000000" alt="contributing"></a>&nbsp;&nbsp;Contributing

Interested in contributing to `microsandbox`? Check out our [CONTRIBUTING.md](./CONTRIBUTING.md) for guidelines and [DEVELOPMENT.md](./DEVELOPMENT.md) for build, test, and release instructions.

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/law/ffffff" alt="license-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/law/000000" alt="license"></a>&nbsp;&nbsp;License

This project is licensed under the [Apache License 2.0](./LICENSE).

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/heart/ffffff" alt="acknowledgements-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/heart/000000" alt="acknowledgements"></a>&nbsp;&nbsp;Acknowledgements

Special thanks to all our contributors, testers, and community members who help make microsandbox better every day! We'd like to thank the following projects and communities that made `microsandbox` possible: [libkrun](https://github.com/containers/libkrun) and [smoltcp](https://github.com/smoltcp-rs/smoltcp)

<br />
<br />
<br />

<div align='center'>
  <a href="https://www.ycombinator.com/"><img src="https://img.shields.io/badge/BACKED%20BY-Y%20COMBINATOR-F26522?style=for-the-badge&logo=ycombinator&logoColor=white" alt="Backed by Y Combinator"></a>
</div>
