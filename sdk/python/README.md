# microsandbox

Lightweight VM sandboxes for Python — run AI agents and untrusted code with hardware-level isolation.

The `microsandbox` Python package provides native bindings to the [microsandbox](https://github.com/superradcompany/microsandbox) runtime via pyo3. It spins up real microVMs (not containers) in under 100ms, runs standard OCI (Docker) images, and gives you full control over execution, filesystem, networking, and secrets — all from a simple async API.

## Features

- **Hardware isolation** — Each sandbox is a real VM with its own Linux kernel
- **Sub-100ms boot** — No daemon, no server setup, embedded directly in your app
- **OCI image support** — Pull and run images from Docker Hub, GHCR, ECR, or any OCI registry
- **Command execution** — Run commands with collected or streaming output, interactive shells
- **Guest filesystem access** — Read, write, list, copy files inside a running sandbox
- **Named volumes** — Persistent storage across sandbox restarts, with quotas
- **Network policies** — Public-only (default), allow-all, or fully airgapped
- **DNS filtering** — Block specific domains or domain suffixes
- **TLS interception** — Transparent HTTPS inspection and secret substitution
- **Secrets** — Credentials that never enter the VM; placeholder substitution at the network layer
- **Port publishing** — Expose guest TCP/UDP services on host ports
- **Rootfs patches** — Modify the filesystem before the VM boots
- **Detached mode** — Sandboxes can outlive the Python process
- **Metrics** — CPU, memory, disk I/O, and network I/O per sandbox
- **Typed** — Frozen dataclasses, `StrEnum`s, sealed event unions, `.pyi` stubs

## Requirements

- **Python** >= 3.10
- **Linux** with KVM enabled, or **macOS** with Apple Silicon (M-series)

## Supported Platforms

| Platform | Architecture | Wheel tag |
|----------|-------------|-----------|
| macOS | ARM64 (Apple Silicon) | `macosx_11_0_arm64` |
| Linux | x86_64 | `manylinux_2_28_x86_64` |
| Linux | ARM64 | `manylinux_2_28_aarch64` |

Runtime binaries (`msb` + `libkrunfw`) are bundled in the wheel. One wheel per platform, all Python 3.10+ versions via `abi3`.

## Installation

```bash
pip install microsandbox
```

## Quick Start

```python
import asyncio
from microsandbox import Sandbox

async def main():
    # Create a sandbox from an OCI image.
    sandbox = await Sandbox.create(
        "my-sandbox",
        image="alpine",
        cpus=1,
        memory=512,
    )

    # Run a command.
    output = await sandbox.shell("echo 'Hello from microsandbox!'")
    print(output.stdout_text)

    # Stop the sandbox.
    await sandbox.stop_and_wait()

asyncio.run(main())
```

## Examples

### Command Execution

```python
from microsandbox import Sandbox

# Collected output.
output = await sandbox.exec("python3", ["-c", "print(1 + 1)"])
print(output.stdout_text)   # "2\n"
print(output.exit_code)      # 0

# Shell command (pipes, redirects, etc.).
output = await sandbox.shell("echo hello && pwd")
print(output.stdout_text)

# Full configuration via ExecOptions dict.
output = await sandbox.exec("python3", {
    "args": ["script.py"],
    "cwd": "/app",
    "env": {"PYTHONPATH": "/app/lib"},
    "timeout": 30.0,
})

# Streaming output.
handle = await sandbox.exec_stream("tail", ["-f", "/var/log/app.log"])
async for event in handle:
    match event.event_type:
        case "stdout": sys.stdout.buffer.write(event.data)
        case "stderr": sys.stderr.buffer.write(event.data)
        case "exited": break

await sandbox.stop_and_wait()
```

### Filesystem Operations

```python
fs = sandbox.fs

# Write and read files.
await fs.write("/tmp/config.json", b'{"debug": true}')
content = await fs.read_text("/tmp/config.json")

# List a directory.
entries = await fs.list("/etc")
for entry in entries:
    print(f"{entry.path} ({entry.kind})")

# Copy between host and guest.
await fs.copy_from_host("./local-file.txt", "/tmp/file.txt")
await fs.copy_to_host("/tmp/output.txt", "./output.txt")

# Check existence and metadata.
if await fs.exists("/tmp/config.json"):
    meta = await fs.stat("/tmp/config.json")
    print(f"size: {meta.size}, kind: {meta.kind}")

# Streaming read.
async for chunk in await fs.read_stream("/tmp/large-file.bin"):
    process(chunk)
```

### Named Volumes

```python
from microsandbox import Sandbox, Volume

# Create a 100 MiB named volume.
data = await Volume.create("my-data", quota_mib=100)

# Mount it in a sandbox.
writer = await Sandbox.create(
    "writer",
    image="alpine",
    volumes={"/data": Volume.named(data.name)},
    replace=True,
)

await writer.shell("echo 'hello' > /data/message.txt")
await writer.stop_and_wait()

# Mount the same volume in another sandbox (read-only).
reader = await Sandbox.create(
    "reader",
    image="alpine",
    volumes={"/data": Volume.named(data.name, readonly=True)},
    replace=True,
)

output = await reader.shell("cat /data/message.txt")
print(output.stdout_text)  # "hello\n"

await reader.stop_and_wait()

# Cleanup.
await Sandbox.remove("writer")
await Sandbox.remove("reader")
await Volume.remove("my-data")
```

### Disk Image Volumes

```python
from microsandbox import Sandbox, Volume, DiskImageFormat

# Mount a host disk image at a guest path. Format is inferred from the
# extension; pass `format=` to override. `fstype` is the inner FS agentd
# will mount; omit to let agentd autodetect.
sb = await Sandbox.create(
    "worker",
    image="alpine",
    volumes={
        "/data": Volume.disk("./data.qcow2", format=DiskImageFormat.QCOW2, fstype="ext4"),
        "/seed": Volume.disk("./seed.raw", readonly=True),
        "/scratch": Volume.tmpfs(size_mib=128, readonly=True),
    },
    replace=True,
)
```

### Network Policies

```python
from microsandbox import Network, Sandbox

# Default: public internet only (blocks private ranges).
sandbox = await Sandbox.create("public", image="alpine")

# Fully airgapped.
sandbox = await Sandbox.create(
    "isolated",
    image="alpine",
    network=Network.none(),
)

# Unrestricted.
sandbox = await Sandbox.create(
    "open",
    image="alpine",
    network=Network.allow_all(),
)

# DNS filtering.
sandbox = await Sandbox.create(
    "filtered",
    image="alpine",
    network=Network(
        deny_domains=("blocked.example.com",),
        deny_domain_suffixes=(".evil.com",),
    ),
)
```

### Port Publishing

```python
sandbox = await Sandbox.create(
    "web",
    image="python",
    ports={8080: 80},  # host:8080 → guest:80
)
```

### Secrets

Secrets use placeholder substitution — the real value never enters the VM. It is only swapped in at the network layer for HTTPS requests to allowed hosts.

```python
from microsandbox import Sandbox, Secret

sandbox = await Sandbox.create(
    "agent",
    image="python",
    secrets=[
        Secret.env("OPENAI_API_KEY",
                    value=os.environ["OPENAI_API_KEY"],
                    allow_hosts=["api.openai.com"]),
    ],
)

# Guest sees: OPENAI_API_KEY=$MSB_OPENAI_API_KEY (a placeholder)
# HTTPS to api.openai.com: placeholder is transparently replaced with the real key
# HTTPS to any other host with the placeholder: request is blocked
```

### Rootfs Patches

Modify the filesystem before the VM boots:

```python
from microsandbox import Patch, Sandbox

sandbox = await Sandbox.create(
    "patched",
    image="alpine",
    patches=[
        Patch.text("/etc/greeting.txt", "Hello!\n"),
        Patch.mkdir("/app", mode=0o755),
        Patch.text("/app/config.json", '{"debug": true}', mode=0o644),
        Patch.copy_dir("./scripts", "/app/scripts"),
        Patch.append("/etc/hosts", "127.0.0.1 myapp.local\n"),
    ],
)
```

### Detached Mode

Sandboxes in detached mode survive the Python process:

```python
# Create in detached mode.
sandbox = await Sandbox.create(
    "background",
    image="python",
    detached=True,
)
await sandbox.detach()

# Later, from another process:
handle = await Sandbox.get("background")
reconnected = await handle.connect()
output = await reconnected.shell("echo reconnected")
```

### Context Manager

```python
async with await Sandbox.create("temp", image="alpine", replace=True) as sb:
    output = await sb.shell("echo hello")
    print(output.stdout_text)
# Sandbox is automatically killed and removed on exit.
```

### TLS Interception

```python
from microsandbox import Network, Sandbox, TlsConfig

sandbox = await Sandbox.create(
    "tls-inspect",
    image="python",
    network=Network(
        tls=TlsConfig(
            bypass=("*.googleapis.com",),
            verify_upstream=True,
            intercepted_ports=(443,),
        ),
    ),
)
```

### Metrics

```python
from microsandbox import Sandbox, all_sandbox_metrics, MiB

sandbox = await Sandbox.create("metrics-demo", image="python")

# Per-sandbox metrics.
m = await sandbox.metrics()
print(f"CPU: {m.cpu_percent:.1f}%")
print(f"Memory: {m.memory_bytes // MiB} MiB")
print(f"Uptime: {m.uptime_ms / 1000:.1f}s")

# Streaming metrics.
async for m in sandbox.metrics_stream(interval=1.0):
    print(f"CPU: {m.cpu_percent:.1f}%")

# All sandboxes at once.
all_metrics = await all_sandbox_metrics()
for name, metrics in all_metrics.items():
    print(f"{name}: {metrics.cpu_percent:.1f}%")
```

### Runtime Setup

```python
from microsandbox import is_installed, install

if not is_installed():
    await install()  # Downloads msb + libkrunfw to ~/.microsandbox/
```

## API Reference

### Classes (native)

| Class | Description |
|-------|-------------|
| `Sandbox` | Live handle to a running sandbox — lifecycle, execution, filesystem |
| `SandboxHandle` | Lightweight database handle — use `connect()` or `start()` to get a live `Sandbox` |
| `ExecOutput` | Captured stdout/stderr with exit status |
| `ExecHandle` | Streaming execution handle — async iterator over events |
| `ExecSink` | Writable stdin channel for streaming exec |
| `SandboxFs` | Guest filesystem operations (read, write, list, copy, stat) |
| `FsReadStream` | Async iterator over file data chunks |
| `FsWriteSink` | Async context manager for streaming writes |
| `Volume` | Persistent named volume |
| `VolumeHandle` | Lightweight volume handle from the database |
| `MetricsStream` | Async iterator over metrics snapshots |
| `PullSession` | Async context manager for creation with pull progress |

### Factories (Python)

| Class | Description |
|-------|-------------|
| `Volume.bind()` / `.named()` / `.tmpfs()` / `.disk()` | Volume mount configuration |
| `Network.none()` / `.public_only()` / `.allow_all()` | Network presets |
| `Secret.env()` | Secret entry with host allowlist |
| `Patch.text()` / `.mkdir()` / `.copy_file()` / `.append()` / ... | Pre-boot filesystem modifications |
| `Image.oci()` / `.bind()` / `.disk()` | Explicit rootfs source configuration |
| `Rlimit.nofile()` / `.cpu()` / `.as_()` / ... | POSIX resource limits |

### Enums (Python `StrEnum`)

| Enum | Values |
|------|--------|
| `PullPolicy` | `ALWAYS`, `IF_MISSING`, `NEVER` |
| `LogLevel` | `TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR` |
| `SandboxStatus` | `RUNNING`, `STOPPED`, `CRASHED`, `DRAINING`, `PAUSED` |
| `Action` | `ALLOW`, `DENY` |
| `Direction` | `EGRESS`, `INGRESS` |
| `Protocol` | `TCP`, `UDP`, `ICMPV4`, `ICMPV6` |
| `DestGroup` | `LOOPBACK`, `PRIVATE`, `LINK_LOCAL`, `METADATA`, `MULTICAST` |
| `ViolationAction` | `BLOCK`, `BLOCK_AND_LOG`, `BLOCK_AND_TERMINATE` |
| `FsEntryKind` | `FILE`, `DIRECTORY`, `SYMLINK`, `OTHER` |
| `RlimitResource` | `CPU`, `FSIZE`, `NOFILE`, `AS`, ... (16 variants) |

### Dataclasses (Python, frozen)

| Type | Description |
|------|-------------|
| `ExecOptions` | Full execution options (args, cwd, env, timeout, tty, rlimits) |
| `AttachOptions` | Attach options (args, cwd, env, detach_keys) |
| `ExitStatus` | Exit code and success flag |
| `MountConfig` | Volume mount (bind, named, or tmpfs) |
| `PatchConfig` | Pre-boot filesystem modification |
| `SecretEntry` | Secret binding to env var with host allowlist |
| `NetworkPolicy` | Custom network policy with rules |
| `TlsConfig` | TLS interception options |
| `Network` | Full network configuration |
| `Rule` | Network policy rule |
| `RegistryAuth` | Docker registry credentials |
| `Size` | Memory/storage size value type |
| `Rlimit` | POSIX resource limit |

### Event Types (Python, sealed unions)

| Type | Variants |
|------|----------|
| `ExecEvent` | `StartedEvent`, `StdoutEvent`, `StderrEvent`, `ExitedEvent` |
| `PullProgress` | `Resolving`, `Resolved`, `LayerDownloadProgress`, `LayerDownloadComplete`, `LayerExtractStarted`, `LayerExtractProgress`, `LayerExtractComplete`, `LayerIndexStarted`, `LayerIndexComplete`, `PullComplete` |

### Functions

| Function | Description |
|----------|-------------|
| `is_installed()` | Check if `msb` and `libkrunfw` are available |
| `install()` | Download and install runtime dependencies |
| `all_sandbox_metrics()` | Get metrics for all running sandboxes |
| `version()` | Return the SDK version string |

## Development

### Prerequisites

- [Rust](https://rustup.rs/) (2024 edition)
- [uv](https://docs.astral.sh/uv/) (Python package manager)
- [maturin](https://www.maturin.rs/) (`uv tool install maturin`)

### Setup

```bash
cd sdk/python
uv sync --group dev
```

### Build the extension

```bash
maturin develop --release
```

### Run tests

```bash
uv run pytest tests/
```

### Run an example

```bash
uv run --project sdk/python python examples/python/root-oci/main.py
```

### Lint

```bash
uv run ruff check .
```

## License

Apache-2.0
