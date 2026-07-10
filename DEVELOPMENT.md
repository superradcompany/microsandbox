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

The project is a Cargo workspace. Published crates (in dependency order):

| Crate | Path | Description |
| --- | --- | --- |
| `microsandbox-utils` | `crates/utils` | Shared utilities |
| `microsandbox-types` | `packages/microsandbox-types/rust` | Shared task and wire contract types |
| `microsandbox-protocol` | `crates/protocol` | Wire protocol definitions ([versioning](./crates/protocol/VERSIONING.md)) |
| `microsandbox-agent-client` | `packages/agent-client/rust` | Transport-agnostic client for the agent protocol |
| `microsandbox-agentd` | `crates/agentd` | In-guest agent (guest binary is built separately for musl) |
| `microsandbox-db` | `crates/db` | Database layer |
| `microsandbox-migration` | `crates/migration` | Database migrations |
| `microsandbox-image` | `crates/image` | OCI image handling |
| `microsandbox-filesystem` | `crates/filesystem` | Filesystem composition |
| `microsandbox-network` | `crates/network` | smoltcp-based networking |
| `microsandbox-metrics` | `crates/metrics` | Shared-memory live metrics registry |
| `microsandbox-metrics-collector` | `crates/metrics-collector` | Metrics collector orchestrator and `msb-metrics` binary |
| `microsandbox-runtime` | `crates/runtime` | VM runtime (libkrun integration) |
| `microsandbox` | `sdk/rust` | Public SDK crate |
| `microsandbox-cli` | `crates/cli` | `msb` CLI binary |

Internal (unpublished) workspace members:

| Crate | Path | Description |
| --- | --- | --- |
| `test-utils` | `crates/test-utils` | Internal test helpers and the `#[msb_test]` attribute |
| `test-macros` | `crates/test-macros` | Proc-macro behind `#[msb_test]` (re-exported by `test-utils`) |
| `test-init` | `crates/test-init` | Tiny static guest init binary for handoff integration tests |
| `microsandbox-node` | `sdk/node-ts` | NAPI bindings behind the Node.js SDK |
| `microsandbox-py` | `sdk/python` | PyO3 bindings behind the Python SDK |
| `microsandbox-go` | `sdk/go/native` | C-ABI FFI layer behind the Go SDK |

The `examples/rust/*` projects are workspace members as well.

### Other Packages

| Package | Path | Description |
| --- | --- | --- |
| `microsandbox` (npm) | `sdk/node-ts` | TypeScript/Node.js SDK (NAPI bindings, plus per-platform sub-packages) |
| `microsandbox` (PyPI) | `sdk/python` | Python SDK (PyO3 bindings) |
| `github.com/superradcompany/microsandbox/sdk/go` | `sdk/go` | Go SDK (CGO over `microsandbox-go`), versioned via `sdk/go/vX.Y.Z` tags |
| `@microsandbox/agent-client` (npm) | `packages/agent-client/typescript` | Transport-agnostic client for the agent protocol |
| `@microsandbox/types` (npm) | `packages/microsandbox-types/typescript` | Shared task and wire contract types |
| `microsandbox-mcp` (npm) | `mcp/` (submodule) | MCP server for AI agents |

### Key Directories

- `vendor/libkrunfw` — Submodule for the kernel firmware library
- `build/` — Build output (agentd binary, libkrunfw shared library, msb binary)
- `examples/rust/` — Rust example projects
- `examples/python/` — Python example projects
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

The benchmark suite lives in its own repository:
[superradcompany/microvm-benchmarks](https://github.com/superradcompany/microvm-benchmarks).
See that repository's README for setup, workload descriptions, and usage.

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

Microsandbox releases are automated via CI. All crates and packages share the same version number. The process has two steps:

### 1. Version Bump PR

Dispatch the **Release version bump** workflow (`.github/workflows/release-bump.yml`) with the target version. It runs `scripts/bump-version.sh`, which bumps:

- `Cargo.toml` (workspace `version` field and path-dependency versions — all crates inherit from this)
- `sdk/node-ts/package.json` and its per-platform sub-packages
- `packages/agent-client/typescript/package.json`
- `packages/microsandbox-types/typescript/package.json`
- `sdk/go/setup.go` (`sdkVersion`)
- `examples/typescript/*/package.json` (`microsandbox` dependency pins)

The workflow then regenerates `Cargo.lock` and the npm lockfiles and opens a PR titled `chore: release vX.Y.Z`.

`microsandbox-mcp` is versioned in its own repository (the `mcp/` submodule). Bump it there and advance the `mcp/` (and, when changed, `skills/`) submodule pointers in the release PR — `release.yml` publishes whatever `microsandbox-mcp` version the submodule pointer holds.

### 2. Tag and Release

After the version bump PR is merged, create a signed tag on `main` to trigger the release CI:

```bash
git tag -a v0.X.Y -m "v0.X.Y"
git push origin v0.X.Y
```

The release workflow (`.github/workflows/release.yml`) will:

1. Build `msb`, `agentd`, `msb-metrics`, and `libkrunfw` for release platforms (linux-x86_64, linux-aarch64, darwin-aarch64, windows-x86_64, windows-aarch64)
2. Create Unix platform bundles (`.tar.gz`) and Windows platform bundles (`.zip`) with SHA256 checksums
3. Create a GitHub release with the bundles and installer scripts (`install.sh` and `install.ps1`)
4. Publish the npm packages: `microsandbox` (+ platform sub-packages), `@microsandbox/agent-client`, and `@microsandbox/types`
5. Publish the MCP server to npm (`microsandbox-mcp`, from the `mcp/` submodule)
6. Publish Rust crates to crates.io (in dependency order, 15 crates)
7. Publish the Python SDK to PyPI (`microsandbox`)
8. Tag the Go SDK (`sdk/go/vX.Y.Z`)
9. Build and publish Docker images to GHCR
10. Update the Homebrew tap and winget manifests
11. Sync docs to Mintlify and refresh the npm lockfile on `main`

## Additional Resources

- [CONTRIBUTING.md](./CONTRIBUTING.md) — How to contribute
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) — Community code of conduct
- [SECURITY.md](./SECURITY.md) — Security policies and reporting vulnerabilities
