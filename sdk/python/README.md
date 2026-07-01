# microsandbox

Lightweight VM sandboxes for Python applications that need hardware-level isolation for AI agents, tools, tests, and untrusted code.

The `microsandbox` Python package provides async Python bindings to the [microsandbox](https://github.com/superradcompany/microsandbox) runtime. It creates microVM-backed sandboxes from OCI images or other rootfs sources, then exposes command execution, guest filesystem access, networking, secrets, volumes, metrics, logs, snapshots, and SSH/SFTP through Python-friendly classes and dataclasses.

For the full API reference and longer guides, use the docs site:

- [Python SDK guide](https://docs.microsandbox.dev/sdk/python/sandbox)
- [SDK overview](https://docs.microsandbox.dev/sdk/overview)
- [Repository examples](../../examples/python)

## Features

- Hardware VM isolation with a guest Linux kernel
- Async sandbox lifecycle, execution, filesystem, metrics, and logs APIs
- OCI image, bind-rootfs, disk-image, and snapshot-based sandboxes
- Named volumes, bind mounts, tmpfs mounts, and disk-image mounts
- Network policies, DNS filtering, TLS interception, secrets, and port publishing
- Rootfs patches before boot
- Detached sandboxes that can outlive the Python process
- Typed Python surface with `StrEnum`s, frozen dataclasses, event objects, `.pyi` stubs, and `py.typed`

## Requirements

- Python 3.10+
- Linux with KVM, macOS with Apple Silicon, or Windows with Windows Hypervisor Platform
- Windows support is currently preview; see the [Windows troubleshooting guide](https://docs.microsandbox.dev/getting-started/windows-troubleshooting) for WHP and runtime setup notes.

## Supported Platforms

| Platform | Architecture | Notes |
| --- | --- | --- |
| macOS | ARM64 / Apple Silicon | Wheel bundles `msb` and `libkrunfw` |
| Linux | x86_64 | Wheel bundles `msb` and `libkrunfw` |
| Linux | ARM64 | Wheel bundles `msb` and `libkrunfw` |
| Windows | x86_64, ARM64 | Preview; requires WHP |

Python wheels bundle the matching `msb` runtime and `libkrunfw` library. Source checkouts and unreleased local builds can override runtime paths with `MSB_PATH`, `MSB_LIBKRUNFW_PATH`, or `microsandbox.set_libkrunfw_path(...)`.

## Installation

```bash
pip install microsandbox
```

## Quick Start

```python
import asyncio

from microsandbox import Sandbox


async def main() -> None:
    async with await Sandbox.create("python-readme", image="alpine", replace=True) as sandbox:
        output = await sandbox.shell("echo 'Hello from microsandbox!'")
        print(output.stdout_text.strip())


asyncio.run(main())
```

`async with` stops and removes the sandbox when the block exits. Use `Sandbox.create(...)` without a context manager when you want to control `stop()`, `kill()`, or `remove()` yourself.

## Common Examples

These snippets assume you already have a live `sandbox: Sandbox`.

### Command Execution

```python
import sys

output = await sandbox.exec("python3", ["-c", "print(1 + 1)"])
print(output.stdout_text)
print(output.exit_code)

output = await sandbox.shell("echo hello && pwd")
print(output.stdout_text)

output = await sandbox.exec(
    "python3",
    ["script.py"],
    cwd="/app",
    env={"PYTHONPATH": "/app/lib"},
    timeout=30.0,
)

handle = await sandbox.exec_stream("tail", ["-f", "/var/log/app.log"])
async for event in handle:
    match event.event_type:
        case "stdout":
            sys.stdout.buffer.write(event.data)
        case "stderr":
            sys.stderr.buffer.write(event.data)
        case "exited":
            break
```

### Filesystem Operations

```python
fs = sandbox.fs

await fs.write("/tmp/config.json", b'{"debug": true}')
print(await fs.read_text("/tmp/config.json"))

for entry in await fs.list("/etc"):
    print(f"{entry.path} ({entry.kind})")

await fs.copy_from_host("./local-file.txt", "/tmp/file.txt")
await fs.copy_to_host("/tmp/output.txt", "./output.txt")

if await fs.exists("/tmp/config.json"):
    meta = await fs.stat("/tmp/config.json")
    print(f"size: {meta.size}, kind: {meta.kind}")
```

### Named Volumes

```python
from microsandbox import Sandbox, Volume

data = await Volume.create("python-readme-data", quota_mib=100)

writer = await Sandbox.create(
    "python-readme-writer",
    image="alpine",
    volumes={"/data": Volume.named(data.name)},
    replace=True,
)
await writer.shell("echo 'hello' > /data/message.txt")
await writer.stop()

reader = await Sandbox.create(
    "python-readme-reader",
    image="alpine",
    volumes={"/data": Volume.named(data.name, readonly=True)},
    replace=True,
)
output = await reader.shell("cat /data/message.txt")
print(output.stdout_text.strip())
await reader.stop()
```

### Network, DNS, and Ports

```python
from microsandbox import Network, Sandbox
from microsandbox.types import DnsConfig

isolated = await Sandbox.create(
    "python-readme-isolated",
    image="alpine",
    network=Network.none(),
    replace=True,
)

filtered = await Sandbox.create(
    "python-readme-filtered",
    image="alpine",
    network=Network(
        deny_domains=("blocked.example.com",),
        deny_domain_suffixes=(".evil.com",),
        dns=DnsConfig(nameservers=("1.1.1.1:53",)),
    ),
    replace=True,
)

web = await Sandbox.create(
    "python-readme-web",
    image="python",
    ports={8080: 80},
    network=Network.public_only(),
    replace=True,
)
```

### Secrets

Secrets use placeholder substitution. The real value stays on the host and is substituted only for allowed network destinations.

```python
import os

from microsandbox import Sandbox, Secret

sandbox = await Sandbox.create(
    "python-readme-agent",
    image="python",
    secrets=[
        Secret.env(
            "OPENAI_API_KEY",
            value=os.environ["OPENAI_API_KEY"],
            allow_hosts=["api.openai.com"],
        ),
    ],
    replace=True,
)
```

### Rootfs Patches

```python
from microsandbox import Patch, Sandbox

sandbox = await Sandbox.create(
    "python-readme-patched",
    image="alpine",
    patches=[
        Patch.text("/etc/greeting.txt", "Hello!\n"),
        Patch.mkdir("/app", mode=0o755),
        Patch.text("/app/config.json", '{"debug": true}', mode=0o644),
        Patch.append("/etc/hosts", "127.0.0.1 myapp.local\n"),
    ],
    replace=True,
)
```

### Detached Mode

```python
sandbox = await Sandbox.create(
    "python-readme-background",
    image="python",
    detached=True,
    replace=True,
)

handle = await Sandbox.get("python-readme-background")
reconnected = await handle.connect()
output = await reconnected.shell("echo reconnected")
print(output.stdout_text.strip())
```

### Metrics

```python
from microsandbox import MiB, all_sandbox_metrics

metrics = await sandbox.metrics()
print(f"CPU: {metrics.cpu_percent:.1f}%")
print(f"Memory: {metrics.memory_bytes // MiB} MiB")

async for sample in sandbox.metrics_stream(interval=1.0):
    print(f"CPU: {sample.cpu_percent:.1f}%")
    break

for name, sample in (await all_sandbox_metrics()).items():
    print(f"{name}: {sample.cpu_percent:.1f}%")
```

### Typed Errors

Python exports typed errors for the common SDK categories and falls back to `MicrosandboxError` for unmapped runtime variants. Catch specific errors when you need category-specific handling, and catch `MicrosandboxError` as the broad SDK base class.

```python
from microsandbox import MicrosandboxError, Sandbox, SandboxAlreadyExistsError

try:
    await Sandbox.create("worker", image="alpine")
except SandboxAlreadyExistsError:
    print("already exists; resume it or pass replace=True")
except MicrosandboxError as exc:
    print(f"microsandbox error: {exc}")
```

## Runtime Setup

Installed wheels bundle the runtime files. The setup helpers are useful for source checkouts, shared runtime installs, and surfacing setup failures at process startup.

```python
from microsandbox import install, is_installed

if not is_installed():
    await install()
```

## More Documentation

- [Sandbox lifecycle](https://docs.microsandbox.dev/sdk/python/sandbox)
- [Execution](https://docs.microsandbox.dev/sdk/python/execution)
- [Filesystem](https://docs.microsandbox.dev/sdk/python/filesystem)
- [Networking](https://docs.microsandbox.dev/sdk/python/networking)
- [Secrets](https://docs.microsandbox.dev/sdk/python/secrets)
- [Volumes](https://docs.microsandbox.dev/sdk/python/volumes)
- [Snapshots](https://docs.microsandbox.dev/sdk/python/snapshots)
- [Images](https://docs.microsandbox.dev/sdk/python/images)
- [SSH](https://docs.microsandbox.dev/sdk/python/ssh)
- [Agent client](https://docs.microsandbox.dev/sdk/python/agent-client)

## Development

From `sdk/python`:

```bash
uv sync --group dev
uv run maturin develop --release
uv run pytest tests
uv run ruff check .
```

From the repository root, run an example against the SDK project:

```bash
uv run --project sdk/python python examples/python/root-oci/main.py
```

Runtime integration tests require local virtualization support and runtime artifacts:

```bash
cd sdk/python
uv run pytest integration/test_create_kwargs.py integration/test_exec.py
```

## License

Apache-2.0
