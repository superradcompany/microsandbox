# Developing Microsandbox

This guide covers everything you need to build, test, and release microsandbox from source.

For contribution guidelines (forking, commit signing, pull requests), see [CONTRIBUTING.md](./CONTRIBUTING.md).

## Prerequisites

- **Operating System**:
  - macOS with Apple Silicon (M1/M2/M3/M4)
  - Linux with KVM enabled
- **Tools**: [`just`](https://github.com/casey/just), `git`, and `pre-commit`
  - Linux: `sudo apt install just git` and `pip install pre-commit` (or `sudo apt install pre-commit`)
  - macOS: `brew install just git pre-commit`
- **Docker** (macOS only): Required for cross-compiling `agentd` and building the kernel
- **Rust**: Installed automatically by `just setup` if missing, or install via [rustup](https://rustup.rs)

## Initial Setup

Clone the repository and run the one-time setup:

```bash
git clone https://github.com/microsandbox/microsandbox.git
cd microsandbox
just setup
```

`just setup` does the following:

1. Installs system dependencies (build tools, musl toolchain, etc.)
2. Initializes git submodules (`vendor/libkrunfw`, etc.)
3. Builds binary dependencies (`agentd` and `libkrunfw`)
4. Builds the `msb` CLI
5. Installs binaries to `~/.microsandbox/bin/` and libraries to `~/.microsandbox/lib/`
6. Installs pre-commit hooks

> During the build, kernel config prompts may appear — press **Enter** to accept defaults.

After setup, add these to your shell profile (e.g. `~/.bashrc`, `~/.zshrc`):

```bash
# Linux
export PATH="$HOME/.microsandbox/bin:$PATH"
export LD_LIBRARY_PATH="$HOME/.microsandbox/lib:$LD_LIBRARY_PATH"

# macOS
export PATH="$HOME/.microsandbox/bin:$PATH"
export DYLD_LIBRARY_PATH="$HOME/.microsandbox/lib:$DYLD_LIBRARY_PATH"
```

Verify the installation:

```bash
msb --version
```

## Build & Install Loop

The core development cycle is:

```bash
just build && just install
```

This rebuilds the `msb` CLI (and ensures `agentd` and `libkrunfw` are up to date) then installs the updated binaries to `~/.microsandbox/`.

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
| `just build-agentd` | Build only agentd |
| `just build-libkrunfw` | Build only libkrunfw |
| `just install` | Install msb + libkrunfw to `~/.microsandbox/` |
| `just uninstall` | Remove installed binaries |
| `just clean` | Remove `build/` artifacts and clean libkrunfw |

## Project Structure

### Workspace Crates

The project is a Cargo workspace with these crates (in dependency order):

| Crate | Path | Description |
| --- | --- | --- |
| `microsandbox-utils` | `crates/utils` | Shared utilities |
| `microsandbox-protocol` | `crates/protocol` | Wire protocol definitions |
| `microsandbox-db` | `crates/db` | Database layer |
| `microsandbox-migration` | `crates/migration` | Database migrations |
| `microsandbox-image` | `crates/image` | OCI image handling |
| `microsandbox-filesystem` | `crates/filesystem` | Filesystem composition |
| `microsandbox-network` | `crates/network` | smoltcp-based networking |
| `microsandbox-runtime` | `crates/runtime` | VM runtime (libkrun integration) |
| `microsandbox` | `crates/microsandbox` | Public SDK crate |
| `microsandbox-cli` | `crates/cli` | `msb` CLI binary |
| `agentd` | `crates/agentd` | In-guest agent (excluded from workspace, built separately for musl) |

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

1. Build `msb`, `agentd`, and `libkrunfw` for all platforms (linux-x86_64, linux-aarch64, darwin-aarch64)
2. Create platform bundles (`.tar.gz`) with SHA256 checksums
3. Create a GitHub release with the bundles
4. Publish the Node.js SDK to npm (`microsandbox` + platform packages)
5. Publish the MCP server to npm (`microsandbox-mcp`)
6. Publish Rust crates to crates.io (in dependency order, 10 crates)

## Additional Resources

- [CONTRIBUTING.md](./CONTRIBUTING.md) — How to contribute
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) — Community code of conduct
- [SECURITY.md](./SECURITY.md) — Security policies and reporting vulnerabilities
