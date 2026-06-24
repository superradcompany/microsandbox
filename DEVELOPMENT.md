# Developing Microsandbox

This guide covers everything you need to build, test, and release microsandbox from source.

For contribution guidelines (forking, commit signing, pull requests), see [CONTRIBUTING.md](./CONTRIBUTING.md).

## Prerequisites

- **Operating System**:
  - macOS with Apple Silicon (M1/M2/M3/M4)
  - Linux with KVM enabled
  - Windows 11, or Windows Server with nested virtualization, with Windows Hypervisor Platform enabled
- **Tools**: [`just`](https://github.com/casey/just), `git`, and `pre-commit`
  - Linux: `sudo apt install just git` and `pip install pre-commit` (or `sudo apt install pre-commit`)
  - macOS: `brew install just git pre-commit`
  - Windows: install Git for Windows, `just`, Visual Studio Build Tools with MSVC, and Windows SDK; install `pre-commit` with `pip install pre-commit` if you want `just setup` to install Git hooks
- **Linux build backend** (macOS and Windows): Required for building the Linux guest `agentd` binary from non-Linux hosts and for building the libkrunfw kernel bundle when it has not already been generated. On Windows, Docker Desktop with Linux containers is preferred when available; Windows Server can use Ubuntu WSL instead.
- **Rust**: Installed automatically by `just setup` if missing, or install via [rustup](https://rustup.rs)

## Initial Setup

Clone the repository and run the one-time setup:

```bash
git clone https://github.com/microsandbox/microsandbox.git
cd microsandbox
just setup
```

`just setup` does the following:

1. Installs or checks system dependencies (build tools, musl toolchain, Visual Studio toolchain, etc.)
2. Initializes git submodules (`vendor/libkrunfw`, etc.)
3. Builds binary dependencies (`agentd` and `libkrunfw`)
4. Builds the `msb` CLI
5. Installs binaries to `~/.microsandbox/bin/` and libraries to `~/.microsandbox/lib/` on Unix, or `%USERPROFILE%\.microsandbox\{bin,lib}\` on Windows
6. Installs pre-commit hooks when `pre-commit` is available

> During the build, kernel config prompts may appear — press **Enter** to accept defaults.

On Linux and macOS, add these to your shell profile (e.g. `~/.bashrc`, `~/.zshrc`):

```bash
export PATH="$HOME/.microsandbox/bin:$PATH"
```

On Windows, `just install` places `%USERPROFILE%\.microsandbox\bin` first in the persistent user `PATH`; open a new PowerShell, Command Prompt, or Windows Terminal tab before running `msb` from a fresh shell. Already-open shells keep their old process-local `PATH`.

Verify the installation:

```bash
msb --version
```

## Build & Install Loop

The core development cycle is:

```bash
just build && just install
```

This rebuilds the `msb` CLI (and ensures `agentd` and `libkrunfw` are up to date) then installs the updated binaries to `~/.microsandbox/` on Unix or `%USERPROFILE%\.microsandbox\` on Windows.

On Windows, `just build-msb` targets the native MSVC Rust target (`aarch64-pc-windows-msvc` on Windows ARM64 or `x86_64-pc-windows-msvc` on Windows x64). `just build-agentd` and `just build-libkrunfw` use a Linux build backend for the guest/kernel artifacts, then link/install Windows-native outputs. The backend is selected with `MSB_WINDOWS_LINUX_BUILD_BACKEND=auto|docker|wsl` and defaults to `auto`, which prefers Docker Linux containers and falls back to Ubuntu WSL. Set `MSB_WSL_DISTRO=<name>` when your WSL distro is not named `Ubuntu`. Set `MSB_WINDOWS_TARGET_ARCH=arm64` or `MSB_WINDOWS_TARGET_ARCH=amd64` before running `just build-msb` if you need to override native target detection.

For Windows Server development, use Ubuntu WSL as the Linux build backend:

```powershell
$env:MSB_WINDOWS_LINUX_BUILD_BACKEND = "wsl"
wsl --install -d Ubuntu
wsl -d Ubuntu -- bash -lc "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
wsl -d Ubuntu -- bash -lc "sudo apt update && sudo apt install -y build-essential musl-tools flex bison libelf-dev libssl-dev bc python3 python3-pyelftools curl xz-utils patch"
```

For a release-optimized build:

```bash
just build release && just install
```

### Individual Build Targets

| Command | Description |
| --- | --- |
| `just build` | Build everything (agentd + libkrunfw + msb) in debug mode |
| `just build release` | Build everything in release mode |
| `just build-msb` | Build only the `msb` CLI (debug) |
| `just build-msb release` | Build only the `msb` CLI (release) |
| `just build-deps` | Build only binary dependencies (agentd + libkrunfw) |
| `just build-agentd` | Build only the Linux guest agentd binary; Windows uses Docker Linux containers or WSL |
| `just build-libkrunfw` | Build only libkrunfw; Windows builds `kernel.c` through Docker Linux containers or WSL and links `libkrunfw.dll` natively |
| `just install` | Install msb + libkrunfw to `~/.microsandbox/` on Unix or `%USERPROFILE%\.microsandbox\` on Windows |
| `just uninstall` | Remove installed binaries |
| `just clean` | Remove `build/` artifacts and clean libkrunfw |

## Project Structure

### Workspace Crates

The project is a Cargo workspace with these crates (in dependency order):

| Crate | Path | Description |
| --- | --- | --- |
| `microsandbox-utils` | `crates/utils` | Shared utilities |
| `microsandbox-protocol` | `crates/protocol` | Wire protocol definitions ([versioning](./crates/protocol/VERSIONING.md)) |
| `microsandbox-db` | `crates/db` | Database layer |
| `microsandbox-migration` | `crates/migration` | Database migrations |
| `microsandbox-image` | `crates/image` | OCI image handling |
| `microsandbox-filesystem` | `crates/filesystem` | Filesystem composition |
| `microsandbox-network` | `crates/network` | smoltcp-based networking |
| `microsandbox-runtime` | `crates/runtime` | VM runtime (libkrun integration) |
| `microsandbox` | `sdk/rust` | Public SDK crate |
| `microsandbox-cli` | `crates/cli` | `msb` CLI binary |
| `agentd` | `crates/agentd` | In-guest agent (workspace member, built separately for musl) |

### Other Packages

| Package | Path | Description |
| --- | --- | --- |
| `microsandbox` (npm) | `sdk/node-ts` | TypeScript/Node.js SDK (NAPI bindings) |
| `microsandbox-mcp` (npm) | `mcp/` | MCP server for AI agents |

### Key Directories

- `vendor/libkrunfw` — Submodule for the kernel firmware library
- `build/` — Build output (agentd binary, libkrunfw shared library, msb binary)
- `examples/rust/` — Rust example projects
- `examples/typescript/` — TypeScript example projects

## Testing

Run all workspace tests:

```bash
cargo test --workspace
```

Run tests for a specific crate:

```bash
cargo test -p microsandbox-runtime
```

Run a specific test:

```bash
cargo test -p microsandbox test_name
```

## Benchmarking

```bash
just bench-fs
```

Runs Docker-vs-Microsandbox filesystem benchmarks (14 workloads covering metadata, reads,
writes, deletes, renames, mmap, and concurrent I/O). Results are written as JSON to
`build/bench/fs/`. See [`benchmarks/README.md`](benchmarks/README.md) for full usage,
workload descriptions, multi-image runs, and baseline comparison.

## Code Quality

### Pre-commit Hooks

Pre-commit hooks are installed by `just setup`. They run automatically on every commit and check:

- `cargo fmt --all --check` — formatting
- `cargo clippy --workspace -- -D warnings` — lints
- `cargo doc` — documentation builds without warnings
- `cargo build -p microsandbox-cli` — CLI compiles
- Standard checks (trailing whitespace, merge conflicts, TOML/YAML validity)
- Blocks direct commits to `main`

To run all checks manually:

```bash
pre-commit run --all-files
```

> It is recommended to run this once before your first commit.

If pre-commit is not installed, install it with `pip install pre-commit` (or `brew install pre-commit` on macOS) and then run `pre-commit install`.

### Formatting and Linting

```bash
cargo fmt --all           # Format code
cargo clippy --workspace  # Run lints
```

## Releasing

Microsandbox releases are automated via CI. The process has two steps:

### 1. Version Bump PR

Create a PR that bumps the version across all crates and packages. All crates and packages share the same version number:

- `Cargo.toml` (workspace `version` field — all crates inherit from this)
- `sdk/node-ts/package.json`
- `mcp/package.json`

The PR title should follow the format: `chore: bump version to X.Y.Z`

### 2. Tag and Release

After the version bump PR is merged, create a signed tag on `main` to trigger the release CI:

```bash
git tag -a v0.X.Y -m "v0.X.Y"
git push origin v0.X.Y
```

The release workflow (`.github/workflows/release.yml`) will:

1. Build `msb`, `agentd`, and `libkrunfw` for release platforms (linux-x86_64, linux-aarch64, darwin-aarch64, windows-x86_64, windows-aarch64)
2. Create Unix platform bundles (`.tar.gz`) and Windows platform bundles (`.zip`) with SHA256 checksums
3. Create a GitHub release with the bundles and installer scripts (`install.sh` and `install.ps1`)
4. Publish the Node.js SDK to npm (`microsandbox` + platform packages)
5. Publish the MCP server to npm (`microsandbox-mcp`)
6. Publish Rust crates to crates.io (in dependency order, 10 crates)

## Additional Resources

- [CONTRIBUTING.md](./CONTRIBUTING.md) — How to contribute
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) — Community code of conduct
- [SECURITY.md](./SECURITY.md) — Security policies and reporting vulnerabilities
