# Developing Microsandbox

This guide covers everything you need to build, test, and release microsandbox from source.

For contribution guidelines (forking, commit signing, pull requests), see [CONTRIBUTING.md](./CONTRIBUTING.md).

## v0.7.0 CLI migration

Sandbox commands share one definition and dispatcher under `crates/cli/lib/commands/sandbox.rs`. `msb sandbox <command>` is the canonical group, `msb sbx <command>` is its visible alias, and `msb <command>` is the recommended everyday shortcut. Keep all forms equivalent when adding commands or flags; README and quickstart examples should continue to prefer the top-level verbs.

The hidden VM process entry point is now `msb machine`, implemented in `crates/cli/lib/machine_cmd.rs`. The SDK invokes it directly, and it must still execute before the CLI's async runtime starts. This is a coordinated v0.7.0 launcher rename: use a matching SDK/runtime pair, including when setting `MSB_PATH` or supplying a runtime through SDK configuration. The old internal `msb sandbox [flags]` invocation is no longer accepted. Guest configuration transport and the boot/restore intent checks are unchanged.

Regenerate installed shell completion scripts after upgrading so they include the new group and alias. See [the launcher compatibility contract](COMPATIBILITY.md#5-launcher-to-runtime-process-protocol).

## Prerequisites

- **Operating System**:
  - macOS with Apple Silicon (M1/M2/M3/M4)
  - Linux with KVM enabled
  - Windows 11 (x64 or ARM64) with Windows Hypervisor Platform enabled; Windows Server also needs nested virtualization
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

### Selecting Embedded Binaries

`microsandbox-filesystem` enables both `download-binaries` and `embed-binaries` by default. `download-binaries` permits Cargo build scripts to fetch missing official artifacts and implies `embed-binaries`; `embed-binaries` controls whether Agentd bytes are compiled into the host binary.

Set `MSB_EMBED_ARTIFACTS_DIR` at build time to an unpacked directory containing `agentd`, `msb`, and the platform `libkrunfw` filename. The repository-local `build/` directory is the next source, followed by an official download when `download-binaries` is enabled. The Rust SDK also accepts `MSB_EMBED_RUNTIME_BUNDLE_PATH` as an exact compressed `msb` plus `libkrunfw` archive when its `embed-binaries` feature is enabled.

```bash
MSB_EMBED_ARTIFACTS_DIR=/path/to/artifacts cargo build
```

At runtime, `MSB_AGENTD_PATH` selects an external Agentd executable instead of global `paths.agentd` or the embedded fallback. The file is eagerly read and validated before VM construction; it is never downloaded or copied into `MSB_HOME`.

## Project Structure

### Workspace Crates

The project is a Cargo workspace. Published crates (in dependency order):

| Crate | Path | Description |
| --- | --- | --- |
| `microsandbox-utils` | `crates/utils` | Shared utilities |
| `microsandbox-types` | `packages/microsandbox-types/rust` | Shared task and wire contract types |
| `microsandbox-protocol` | `crates/protocol` | Wire protocol definitions ([versioning](./crates/protocol/VERSIONING.md)) |
| `microsandbox-protocol-client` | `packages/protocol-client/rust` | Generic framed protocol engine and byte transports |
| `microsandbox-control-client` | `packages/control-client/rust` | Framed control and explicit JSON compatibility |
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
| `test-utils` | `crates/testing/utils` | Internal test helpers and the `#[msb_test]` attribute |
| `test-macros` | `crates/testing/macros` | Proc-macro behind `#[msb_test]` (re-exported by `test-utils`) |
| `test-init` | `crates/testing/init` | Tiny static guest init binary for handoff integration tests |
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
| `@microsandbox/protocol-client` (npm) | `packages/protocol-client/typescript` | Generic framed protocol engine and byte transports |
| `@microsandbox/control-client` (npm) | `packages/control-client/typescript` | Framed control and explicit JSON compatibility |
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

### Snapshot and branch checks

Run the focused logic suite without starting VMs:

```bash
just test-snapshot
```

This covers snapshot archives/groups, dependency validation, checkpoint logic, snapshot CLI parsing, and the live-smoke runner's own unit tests. The Rust tests already run in the normal Linux workspace CI lane. Cached test execution is much shorter than a first build; Cargo compilation and dependency setup are additional costs, not snapshot-operation timings.

For a compact end-to-end check, build a matching runtime bundle with `just build`, then run:

```bash
just test-snapshot-live
just test-snapshot-live --layout flat
just test-snapshot-live --binary /path/to/msb --output /tmp/snapshot-smoke-new
```

The live check requires working virtualization and Python (`python3` on Linux/macOS, `python` on Windows). macOS binaries must be codesigned with `msb-entitlements.plist`; `just build` does this. It uses a new isolated `MSB_HOME`, stops its own VMs, verifies host-process exit, and retains a report and logs in the printed output directory. Successful runs remove their temporary RAM/disk artifacts; failed runs retain their home for investigation. An explicit `--output` directory must not exist; choose a short path under `/tmp` on Unix to stay within socket-path limits. Use `--help` for image and timeout options.

The warm live target is under 60 seconds per layout, excluding compilation and image-pull setup; this is a target, not a guarantee or a performance benchmark. Per-command and suite deadlines bound failures separately. The existing Linux/KVM CLI smoke CI job runs managed and flat layouts and uploads reports/logs even on failure. This compact check complements, rather than replaces, the larger live invariant and benchmark matrices under `scripts/smoke/cli/`.

For inherited-memory branch coverage, run `python3 scripts/smoke/cli/branch-preparation.py --binary build/msb --require-inherited-baseline`. This checks continuous RAM/disk writes, first-grandchild incremental capture, further descendants after source deletion, growth before a child's first branch, paused sources, interleaved durable capture, optional RAM-cache fallback, compaction, and cold restart. It retains runtime phase logs and checks the actual capture mode, not just command success.

For Linux descriptor-backed branching, also run the runtime `memory_handoff::`, `control::`, `launch::`, and `checkpoint::` unit tests. Live qualification must verify sealed memfd ownership, source deletion, private-write isolation, further descendants, and cancellation. Measure concurrent fan-out separately from single-branch latency; report proportional set size and unique backing allocation separately, since adding them would count shared RAM twice.

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

### Self-hosted CI disk space

The Linux integration runners share a disk. `scripts/ci/clean-runner-disk.sh` removes job artifacts and prunes oversized per-user caches: uv above 1 GiB, npm's download cache above 512 MiB, and Go's build cache above 512 MiB. Small caches, installed toolchains, and npm diagnostic logs are retained. Use `--finish` for end-of-job cleanup; startup additionally requires 25 GiB free (`MSB_CI_MIN_FREE_GIB` overrides the threshold).

This check is a headroom floor, not a disk reservation. If concurrent jobs still exhaust the disk, reduce host concurrency or increase capacity. Do not prune another runner user's files or remove installed tools while jobs are active. Python integration uses its bounded local cache instead of restoring a multi-gigabyte Actions cache.

## Releasing

Microsandbox releases are automated via CI. All crates and packages share the same version number. The process has two steps:

### 1. Version Bump PR

Dispatch the **Release version bump** workflow (`.github/workflows/release-bump.yml`) with the target version. It runs `scripts/bump-version.sh`, which bumps:

- `Cargo.toml` (workspace `version` field and path-dependency versions — all crates inherit from this)
- `sdk/node-ts/package.json` and its per-platform sub-packages
- `packages/protocol-client/typescript/package.json`
- `packages/agent-client/typescript/package.json`
- `packages/control-client/typescript/package.json`
- `packages/microsandbox-types/typescript/package.json`
- `sdk/go/setup.go` (`sdkVersion`)
- `examples/typescript/*/package.json` (`microsandbox` dependency pins)

The workflow then regenerates `Cargo.lock`, the shared `packages/package-lock.json`, and the SDK npm lockfile and opens a PR titled `chore: release vX.Y.Z`.

`microsandbox-mcp` is versioned in its own repository (the `mcp/` submodule). Bump it there and advance the `mcp/` (and, when changed, `skills/`) submodule pointers in the release PR — `release.yml` publishes whatever `microsandbox-mcp` version the submodule pointer holds.

### 2. Tag and Release

After the version bump PR is merged, create a signed tag on `main` to trigger the release CI:

```bash
git tag -a v0.X.Y -m "v0.X.Y"
git push origin v0.X.Y
```

The release workflow (`.github/workflows/release.yml`) will:

1. Build shared `agentd` and `libkrunfw` artifacts once, then build full-release `msb`, `msb-metrics`, Go FFI, Node, and Python artifacts in parallel for each release platform (linux-x86_64, linux-aarch64, darwin-aarch64, windows-x86_64, windows-aarch64)
2. Create Unix platform bundles (`.tar.gz`) and Windows platform bundles (`.zip`) with SHA256 checksums
3. Create a GitHub release with the bundles and installer scripts (`install.sh` and `install.ps1`)
4. Build all shared TypeScript packages through the `packages` workspace; publish `@microsandbox/types` and `@microsandbox/protocol-client`, wait for indexing, then publish `@microsandbox/agent-client` and `@microsandbox/control-client` and wait for indexing before the existing platform and root SDK publication steps
5. Publish the MCP server to npm (`microsandbox-mcp`, from the `mcp/` submodule)
6. Discover and publish all 18 Rust crates to crates.io in dependency waves, waiting only for the sparse-index entries required by the next wave
7. Publish the Python SDK to PyPI (`microsandbox`)
8. Tag the Go SDK (`sdk/go/vX.Y.Z`)
9. Build and publish Docker images to GHCR
10. Update the Homebrew tap and winget manifests
11. Sync docs to Mintlify and refresh the npm lockfile on `main`

### npm publishing and provenance

The Node SDK, shared packages, and native platform packages publish with npm provenance from the GitHub-hosted `npm-publish` job. The job retains `NPM_TOKEN` authentication and requests `id-token: write` only for signing the provenance statement. Each package's repository metadata points to this public repository. MCP remains a separate token-based publication because its source lives in the `microsandbox-mcp` submodule repository.

Pre-publication validation temporarily removes only the SDK's native platform dependencies while installing locked build tools, then restores the original manifest and lockfile before packing. Publication waits for the platform versions to be indexed before refreshing the SDK lockfile, running `npm ci`, and building the SDK. The existing post-release lockfile PR persists registry integrity entries on `main`. Already-published versions are skipped on retries; provenance is not retroactively added to those versions.

Trusted publishing can replace `NPM_TOKEN` later: configure `superradcompany/microsandbox` and workflow filename `release.yml` in each package's npm trusted-publisher settings, and use npm 11.5.1+ with Node 22.14.0+. That switch requires npm-side configuration; this workflow change does not enable it. See [npm provenance](https://docs.npmjs.com/generating-provenance-statements/) and [trusted publishing](https://docs.npmjs.com/trusted-publishers/).

### Production SDK smoke gate

Add the repository Actions secret `MSB_API_KEY` in
`superradcompany/microsandbox`. Its value must be a production Microsandbox API
key for a dedicated test organization with permission and quota to create, run,
stop, and delete a sandbox. CI sets `MSB_API_KEY`, `MSB_BACKEND=cloud`, and
`MSB_API_URL=https://api.microsandbox.dev` so the SDK uses its normal environment
configuration to select production.

Before any publisher runs, `release-ready` installs the candidate TypeScript SDK and Linux x86_64 native
npm tarballs built from that same workflow, creates a 1-vCPU/512-MiB Alpine sandbox, checks exact
command output, and confirms removal. The sandbox name includes the run ID and
attempt. Cleanup runs even when the smoke step fails; an ephemeral lifecycle,
10-minute maximum duration, and 2-minute idle timeout bound running resources if
the runner disappears. Missing credentials or smoke/cleanup failure blocks
publishing. Production outages can therefore block a release.

The live gate runs on release tag pushes and manual Release runs on `main`.
Pull requests and manual runs on other branches run the credential-free checks
without accessing production. No published microsandbox package is fetched from npm in place of the
candidate tarballs. This is a shared SDK-to-Cloud path check, not exhaustive testing
of every language binding or new Cloud feature.

## Additional Resources

- [CONTRIBUTING.md](./CONTRIBUTING.md) — How to contribute
- [CODE_OF_CONDUCT.md](./CODE_OF_CONDUCT.md) — Community code of conduct
- [SECURITY.md](./SECURITY.md) — Security policies and reporting vulnerabilities
