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

<div align="center"><b>——&nbsp;&nbsp;&nbsp;easy, fast, local microVMs for untrusted workloads&nbsp;&nbsp;&nbsp;——</b></div>

<br />
<br />

<div align='center'>
  <a href="https://github.com/superradcompany/microsandbox/releases"><img src="https://img.shields.io/github/v/release/superradcompany/microsandbox?include_prereleases&style=for-the-badge" alt="GitHub release"></a>
  <a href="https://discord.gg/T95Y3XnEAK"><img src="https://img.shields.io/discord/1315784565562019870?label=Discord&logo=discord&logoColor=white&color=5865F2&style=for-the-badge" alt="Discord"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache 2.0-blue.svg?style=for-the-badge" alt="Apache 2.0 License"></a>
</div>

<br />

**Microsandbox** runs **untrusted workloads** inside fast, local microVMs: AI agents, user code, plugins, CI jobs, dev environments, scrapers, and automation.

##

- <img height="14" src="https://octicons-col.vercel.app/shield-lock/A770EF"> **Hardware Isolation**: Hardware-level isolation with microVM technology.
- <img height="14" src="https://octicons-col.vercel.app/globe/A770EF"> **Cross Platform**: Runs on Linux, macOS, and Windows.
- <img height="14" src="https://octicons-col.vercel.app/package/A770EF"> **OCI Compatible**: Runs standard container images from Docker Hub, GHCR, or any OCI registry.
- <img height="14" src="https://octicons-col.vercel.app/container/A770EF"> **Docker-Like Workflows**: Familiar image, command, shell, and volume workflows.
- <img height="14" src="https://octicons-col.vercel.app/zap/A770EF"> **Instant Startup**: Average boot times[^boot-time] under 100 milliseconds.
- <img height="14" src="https://octicons-col.vercel.app/plug/A770EF"> **Embeddable**: Spawn VMs right within your code. No setup server. No long-running daemon.
- <img height="14" src="https://octicons-col.vercel.app/lock/A770EF"> **Secrets That Can't Leak**: Unexploitable secret keys that never enter the VM.
- <img height="14" src="https://octicons-col.vercel.app/database/A770EF"> **Long-Running**: Sandboxes can run in detached mode. Great for long-lived sessions.
- <img height="14" src="https://octicons-col.vercel.app/terminal/A770EF"> **Agent-Ready**: Your agents can create their own sandboxes with our [Agent Skills](https://github.com/superradcompany/skills) and [MCP server](https://github.com/superradcompany/microsandbox-mcp).

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="13" src="https://octicons-col.vercel.app/rocket/ffffff" alt="rocket-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="13" src="https://octicons-col.vercel.app/rocket/000000" alt="rocket"></a>&nbsp;&nbsp;Getting Started

#### <img height="14" src="https://octicons-col.vercel.app/move-to-bottom/A770EF">&nbsp;&nbsp;Install the SDK

> ```sh
> cargo add microsandbox                                   # 🦀 Rust
> ```
>
> ```sh
> uv add microsandbox                                      # 🐍 Python
> ```
>
> ```sh
> npm i microsandbox                                       # 🟦 TypeScript
> ```
>
> ```sh
> go get github.com/superradcompany/microsandbox/sdk/go    # 🐹 Go
> ```

#### <img height="14" src="https://octicons-col.vercel.app/download/A770EF">&nbsp;&nbsp;Install the CLI

> Boot a microVM in a single command:
>
> ```sh
> npx microsandbox run debian
> ```
>
> ##
>
> Or install the `msb` command globally:
>
> ```sh
> curl -fsSL https://install.microsandbox.dev | sh        # 🍎 macOS / 🐧 Linux
> ```
>
> ```powershell
> irm https://install.microsandbox.dev/windows | iex      # 🪟 Windows
> ```
>
> <details>
> <summary><em>&nbsp;We also support other package managers  →</em></summary>
>
> ##
>
> ```sh
> brew install superradcompany/tap/microsandbox
> ```
>
> ```sh
> npm i -g microsandbox
> ```
>
> ```sh
> uv tool install microsandbox
> ```
>
> ```sh
> cargo install microsandbox
> ```
>
> </details>
>
> ##
>
> Then you can run `msb` directly:
>
> ```sh
> msb run debian
> ```

##

> **Requirements**:
>
> - <img height="14" src="https://api.iconify.design/simple-icons:apple.svg?color=%23A770EF" alt="macOS"> **macOS**: Apple Silicon.
> - <img height="14" src="https://api.iconify.design/simple-icons:linux.svg?color=%23A770EF" alt="Linux"> **Linux**: KVM enabled.
> - <img height="14" src="https://api.iconify.design/simple-icons:windows.svg?color=%23A770EF" alt="Windows"> **Windows**: WHP enabled.
>
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
>     sandbox.stop().await?;
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
>     await sandbox.stop()
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
> await using sandbox = await Sandbox.builder("my-sandbox")
>   .image("python")
>   .cpus(1)
>   .memory(512)
>   .create();
>
> const output = await sandbox.exec("python", [
>   "-c",
>   "print('Hello from a microVM!')",
> ]);
>
> console.log(output.stdout());
> ```
>
> </details>
>
> <details>
> <summary><b>&nbsp;Go Example →</b></summary>
>
> ```go
> package main
>
> import (
>     "context"
>     "fmt"
>     "log"
>
>     microsandbox "github.com/superradcompany/microsandbox/sdk/go"
> )
>
> func main() {
>     ctx := context.Background()
>
>     // Downloads the microsandbox runtime to ~/.microsandbox/ on first run.
>     if err := microsandbox.EnsureInstalled(ctx); err != nil {
>         log.Fatal(err)
>     }
>
>     sandbox, err := microsandbox.CreateSandbox(ctx, "my-sandbox",
>         microsandbox.WithImage("python"),
>         microsandbox.WithCPUs(1),
>         microsandbox.WithMemory(512),
>     )
>     if err != nil {
>         log.Fatal(err)
>     }
>     defer sandbox.Stop(ctx)
>
>     output, err := sandbox.Exec(ctx, "python", []string{"-c", "print('Hello from a microVM!')"})
>     if err != nil {
>         log.Fatal(err)
>     }
>
>     fmt.Println(output.Stdout())
> }
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
> msb create --name app python
> ```
>
> ```sh
> # Execute commands
> msb exec app -- python -c "import this"
> msb exec app -- curl https://example.com
> ```
>
> ```sh
> # Lifecycle
> msb stop app
> msb start app
> msb rm app
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
> msb ps app                     # Show sandbox status
> msb inspect app                # Detailed sandbox info
> msb metrics app                # Live CPU/memory/network stats
> ```

> [!TIP]
>
> Run:<br />
> · `msb --help` for quick help menu. <br />
> · `msb --tree` for complete command hierarchy and descriptions. <br />
> · `msb <command> --tree` for a specific command tree.

<br />

<a href="https://docs.microsandbox.dev/cli/overview"><img src="https://img.shields.io/badge/CLI_Docs-%E2%86%92-A770EF?style=flat-square&labelColor=2b2b2b" alt="CLI Docs"></a>

<br />

## <a href="./#gh-dark-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/dependabot/ffffff" alt="agents-dark"></a><a href="./#gh-light-mode-only" target="_blank"><img height="18" src="https://octicons-col.vercel.app/dependabot/000000" alt="agents"></a>&nbsp;&nbsp;AI Agents

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

<div align='center'>
  <a href="https://www.ycombinator.com/"><img src="https://img.shields.io/badge/BACKED%20BY-Y%20COMBINATOR-F26522?style=for-the-badge&logo=ycombinator&logoColor=white" alt="Backed by Y Combinator"></a>
</div>

<br />
<br />

[^boot-time]: Boot time refers to guest boot on an M1 machine.
