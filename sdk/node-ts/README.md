# microsandbox

Lightweight VM sandboxes for Node.js — run AI agents and untrusted code with hardware-level isolation.

The `microsandbox` npm package provides native bindings to the [microsandbox](https://github.com/superradcompany/microsandbox) runtime. It spins up real microVMs (not containers) in under 100ms, runs standard OCI (Docker) images, and gives you full control over execution, filesystem, networking, and secrets — all from a simple async API.

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
- **Detached mode** — Sandboxes can outlive the Node.js process
- **Metrics** — CPU, memory, disk I/O, and network I/O per sandbox

## Requirements

- **Node.js** >= 18
- **Linux** with KVM enabled, or **macOS** with Apple Silicon (M-series)

## Supported Platforms

| Platform | Architecture | Package |
|----------|-------------|---------|
| macOS | ARM64 (Apple Silicon) | `@superradcompany/microsandbox-darwin-arm64` |
| Linux | x86_64 | `@superradcompany/microsandbox-linux-x64-gnu` |
| Linux | ARM64 | `@superradcompany/microsandbox-linux-arm64-gnu` |

Platform-specific binaries are installed automatically via optional dependencies.

## Installation

```bash
npm install microsandbox
```

The postinstall script automatically downloads the `msb` binary and `libkrunfw` library to `~/.microsandbox/`.

## Quick Start

```typescript
import { Sandbox } from "microsandbox";

// Create a sandbox from an OCI image.
const sandbox = await Sandbox.create({
  name: "my-sandbox",
  image: "alpine",
  cpus: 1,
  memoryMib: 512,
});

// Run a command.
const output = await sandbox.shell("echo 'Hello from microsandbox!'");
console.log(output.stdout());

// Stop the sandbox.
await sandbox.stopAndWait();
```

## Examples

### Command Execution

```typescript
import { Sandbox } from "microsandbox";

const sandbox = await Sandbox.create({
  name: "exec-demo",
  image: "python",
  replace: true,
});

// Collected output.
const result = await sandbox.exec("python3", ["-c", "print(1 + 1)"]);
console.log(result.stdout());  // "2\n"
console.log(result.code);      // 0

// Shell command (pipes, redirects, etc.).
const output = await sandbox.shell("echo hello && pwd");
console.log(output.stdout());

// Full configuration.
const configured = await sandbox.execWithConfig({
  cmd: "python3",
  args: ["script.py"],
  cwd: "/app",
  env: { PYTHONPATH: "/app/lib" },
  timeoutMs: 30000,
});

// Streaming output.
const handle = await sandbox.execStream("tail", ["-f", "/var/log/app.log"]);
let event;
while ((event = await handle.recv()) !== null) {
  if (event.eventType === "stdout") process.stdout.write(event.data);
}

await sandbox.stopAndWait();
```

### Filesystem Operations

```typescript
const fs = sandbox.fs();

// Write and read files.
await fs.write("/tmp/config.json", Buffer.from('{"debug": true}'));
const content = await fs.readString("/tmp/config.json");

// List a directory.
const entries = await fs.list("/etc");
for (const entry of entries) {
  console.log(`${entry.path} (${entry.kind})`);
}

// Copy between host and guest.
await fs.copyFromHost("./local-file.txt", "/tmp/file.txt");
await fs.copyToHost("/tmp/output.txt", "./output.txt");

// Check existence and metadata.
if (await fs.exists("/tmp/config.json")) {
  const meta = await fs.stat("/tmp/config.json");
  console.log(`size: ${meta.size}, kind: ${meta.kind}`);
}
```

### Named Volumes

```typescript
import { Sandbox, Volume, Mount } from "microsandbox";

// Create a 100 MiB named volume.
const data = await Volume.create({ name: "my-data", quotaMib: 100 });

// Mount it in a sandbox.
const writer = await Sandbox.create({
  name: "writer",
  image: "alpine",
  volumes: { "/data": Mount.named(data.name) },
  replace: true,
});

await writer.shell("echo 'hello' > /data/message.txt");
await writer.stopAndWait();

// Mount the same volume in another sandbox (read-only).
const reader = await Sandbox.create({
  name: "reader",
  image: "alpine",
  volumes: { "/data": Mount.named(data.name, { readonly: true }) },
  replace: true,
});

const output = await reader.shell("cat /data/message.txt");
console.log(output.stdout()); // "hello\n"

await reader.stopAndWait();

// Cleanup.
await Sandbox.remove("writer");
await Sandbox.remove("reader");
await Volume.remove("my-data");
```

### Disk Image Volumes

```typescript
import { Sandbox, Mount } from "microsandbox";

// Mount a host disk image at a guest path. Format defaults to the file
// extension; pass `format` to override. `fstype` is the inner filesystem
// agentd will mount; omit to let agentd autodetect.
const sb = await Sandbox.create({
  name: "worker",
  image: "alpine",
  volumes: {
    "/data": Mount.disk("./data.qcow2", { format: "qcow2", fstype: "ext4" }),
    "/seed": Mount.disk("./seed.raw", { readonly: true }),
    "/scratch": Mount.tmpfs({ sizeMib: 128, readonly: true }),
  },
  replace: true,
});
```

### Network Policies

```typescript
import { Sandbox, NetworkPolicy } from "microsandbox";

// Default: public internet only (blocks private ranges).
const publicOnly = await Sandbox.create({
  name: "public",
  image: "alpine",
});

// Fully airgapped.
const isolated = await Sandbox.create({
  name: "isolated",
  image: "alpine",
  network: NetworkPolicy.none(),
});

// Unrestricted.
const open = await Sandbox.create({
  name: "open",
  image: "alpine",
  network: NetworkPolicy.allowAll(),
});

// DNS filtering.
const filtered = await Sandbox.create({
  name: "filtered",
  image: "alpine",
  network: {
    blockDomains: ["blocked.example.com"],
    blockDomainSuffixes: [".evil.com"],
  },
});
```

### Port Publishing

```typescript
const sandbox = await Sandbox.create({
  name: "web",
  image: "python",
  ports: { "8080": 80 }, // host:8080 -> guest:80
});
```

### Secrets

Secrets use placeholder substitution — the real value never enters the VM. It is only swapped in at the network layer for HTTPS requests to allowed hosts.

```typescript
import { Sandbox, Secret } from "microsandbox";

const sandbox = await Sandbox.create({
  name: "agent",
  image: "python",
  secrets: [
    Secret.env("OPENAI_API_KEY", {
      value: process.env.OPENAI_API_KEY!,
      allowHosts: ["api.openai.com"],
    }),
  ],
});

// Guest sees: OPENAI_API_KEY=$MSB_OPENAI_API_KEY (a placeholder)
// HTTPS to api.openai.com: placeholder is transparently replaced with the real key
// HTTPS to any other host with the placeholder: request is blocked
```

### Rootfs Patches

Modify the filesystem before the VM boots:

```typescript
import { Patch, Sandbox } from "microsandbox";

const sandbox = await Sandbox.create({
  name: "patched",
  image: "alpine",
  patches: [
    Patch.text("/etc/greeting.txt", "Hello!\n"),
    Patch.mkdir("/app", { mode: 0o755 }),
    Patch.text("/app/config.json", '{"debug": true}', { mode: 0o644 }),
    Patch.copyDir("./scripts", "/app/scripts"),
    Patch.append("/etc/hosts", "127.0.0.1 myapp.local\n"),
  ],
});
```

### Detached Mode

Sandboxes in detached mode survive the Node.js process:

```typescript
// Create and detach.
const sandbox = await Sandbox.createDetached({
  name: "background",
  image: "python",
});
await sandbox.detach();

// Later, from another process:
const handle = await Sandbox.get("background");
const reconnected = await handle.connect();
const output = await reconnected.shell("echo reconnected");
```

### TLS Interception

```typescript
const sandbox = await Sandbox.create({
  name: "tls-inspect",
  image: "python",
  network: {
    tls: {
      bypass: ["*.googleapis.com"],
      verifyUpstream: true,
      interceptedPorts: [443],
    },
  },
});
```

### Metrics

```typescript
import { Sandbox, allSandboxMetrics } from "microsandbox";

const sandbox = await Sandbox.create({
  name: "metrics-demo",
  image: "python",
});

// Per-sandbox metrics.
const m = await sandbox.metrics();
console.log(`CPU: ${m.cpuPercent.toFixed(1)}%`);
console.log(`Memory: ${(m.memoryBytes / 1024 / 1024).toFixed(1)} MiB`);
console.log(`Uptime: ${(m.uptimeMs / 1000).toFixed(1)}s`);

// All sandboxes at once.
const all = await allSandboxMetrics();
for (const [name, metrics] of Object.entries(all)) {
  console.log(`${name}: ${metrics.cpuPercent.toFixed(1)}%`);
}
```

### Runtime Setup

```typescript
import { isInstalled, install } from "microsandbox";

if (!isInstalled()) {
  await install(); // Downloads msb + libkrunfw to ~/.microsandbox/
}
```

## API Reference

### Classes

| Class | Description |
|-------|-------------|
| `Sandbox` | Live handle to a running sandbox — lifecycle, execution, filesystem |
| `SandboxHandle` | Lightweight database handle — use `connect()` or `start()` to get a live `Sandbox` |
| `ExecOutput` | Captured stdout/stderr with exit status |
| `ExecHandle` | Streaming execution handle — call `recv()` for events |
| `ExecSink` | Writable stdin channel for streaming exec |
| `SandboxFs` | Guest filesystem operations (read, write, list, copy, stat) |
| `Volume` | Persistent named volume |
| `VolumeHandle` | Lightweight volume handle from the database |

### Factories

| Class | Description |
|-------|-------------|
| `Mount` | Volume mount configuration — `Mount.bind()`, `Mount.named()`, `Mount.tmpfs()`, `Mount.disk()` |
| `NetworkPolicy` | Network presets — `NetworkPolicy.none()`, `NetworkPolicy.publicOnly()`, `NetworkPolicy.allowAll()` |
| `Secret` | Secret entry — `Secret.env(name, options)` |

### Interfaces

| Interface | Description |
|-----------|-------------|
| `SandboxConfig` | Sandbox creation configuration |
| `ExecConfig` | Full command execution options (cmd, args, cwd, env, timeout, tty) |
| `NetworkConfig` | Network policy with rules, DNS blocking, TLS interception |
| `MountConfig` | Volume mount (bind, named, or tmpfs) |
| `PatchConfig` | Pre-boot filesystem modification |
| `VolumeConfig` | Volume creation options (name, quota, labels) |
| `SecretEntry` / `SecretEnvOptions` | Secret binding to env var with host allowlist |
| `ExecEvent` | Stream event: `"started"`, `"stdout"`, `"stderr"`, `"exited"` |
| `ExitStatus` | Exit code and success flag |
| `FsEntry` / `FsMetadata` | Filesystem entry info and metadata |
| `SandboxInfo` | Sandbox listing info (name, status, timestamps) |
| `SandboxMetrics` | Resource metrics (CPU, memory, disk I/O, network I/O, uptime) |
| `TlsConfig` | TLS interception options (bypass domains, upstream verification) |

### Functions

| Function | Description |
|----------|-------------|
| `isInstalled()` | Check if `msb` and `libkrunfw` are available |
| `install()` | Download and install runtime dependencies |
| `allSandboxMetrics()` | Get metrics for all running sandboxes |

### Enums

| Enum | Values |
|------|--------|
| `LogLevel` | `"trace"`, `"debug"`, `"info"`, `"warn"`, `"error"` |
| `PullPolicy` | `"always"`, `"if-missing"`, `"never"` |

## License

Apache-2.0
