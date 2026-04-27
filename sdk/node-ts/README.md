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

- **Node.js** >= 22 (the SDK relies on `Symbol.asyncDispose` and `await using`)
- **Linux** with KVM enabled, or **macOS** with Apple Silicon (M-series)
- The `msb` runtime ships inside the matching `@superradcompany/microsandbox-<triple>` platform package. If your install resolved without one, run `npx microsandbox install` once or set `MSB_PATH` to a working binary.

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

The matching platform package (`@superradcompany/microsandbox-<triple>`) carries the `msb` binary and the `libkrunfw` shared library. If your install resolves without one (rare — typically a manual `--no-optional` install), run `npx microsandbox install` once to populate `~/.microsandbox/` or set `MSB_PATH` to a working binary.

## Quick Start

```typescript
import { Sandbox } from "microsandbox";

// Build and boot a sandbox in attached mode (auto-disposed at scope exit).
await using sandbox = await Sandbox.builder("my-sandbox")
  .image("alpine")
  .cpus(1)
  .memory(512)
  .create();

const output = await sandbox.shell("echo 'Hello from microsandbox!'");
console.log(output.stdout());
```

The `await using` form (Node.js 22+) automatically calls `Sandbox.stop` when
`sandbox` falls out of scope. If you need finer control, drop the `using` and
call `sandbox.stopAndWait()` explicitly.

## Examples

### Command Execution

```typescript
import { Sandbox } from "microsandbox";

await using sandbox = await Sandbox.builder("exec-demo")
  .image("python")
  .replace()
  .create();

// Collected output.
const result = await sandbox.exec("python3", ["-c", "print(1 + 1)"]);
console.log(result.stdout()); // "2\n"
console.log(result.code);     // 0

// Shell command (pipes, redirects, etc.).
const output = await sandbox.shell("echo hello && pwd");
console.log(output.stdout());

// Full configuration via the chainable options builder.
const configured = await sandbox.execWith("python3", (e) =>
  e.args(["script.py"])
    .cwd("/app")
    .env("PYTHONPATH", "/app/lib")
    .timeout(30_000),
);

// Streaming output. ExecHandle is AsyncIterable<ExecEvent>; the union
// is discriminated on `kind` so `event.data` narrows correctly.
const handle = await sandbox.execStream("tail", ["-f", "/var/log/app.log"]);
for await (const event of handle) {
  if (event.kind === "stdout") process.stdout.write(event.data);
  if (event.kind === "exited") break;
}
```

### Filesystem Operations

```typescript
const fs = sandbox.fs();

// Write and read files. write() accepts Uint8Array or string.
await fs.write("/tmp/config.json", '{"debug": true}');
const content = await fs.readToString("/tmp/config.json");

// List a directory. `entry.kind` narrows to "file" | "directory" | "symlink" | "other".
const entries = await fs.list("/etc");
for (const entry of entries) {
  console.log(`${entry.path} (${entry.kind})`);
}

// Streaming reads/writes (e.g. for large files).
for await (const chunk of await fs.readStream("/var/log/syslog")) {
  process.stdout.write(chunk); // chunk is a Uint8Array
}

await using sink = await fs.writeStream("/tmp/big.bin");
await sink.write(new Uint8Array(1 << 20));
// `await using` calls sink.close() automatically.

// Copy between host and guest.
await fs.copyFromHost("./local-file.txt", "/tmp/file.txt");
await fs.copyToHost("/tmp/output.txt", "./output.txt");

// Check existence and metadata.
if (await fs.exists("/tmp/config.json")) {
  const meta = await fs.stat("/tmp/config.json");
  console.log(`size: ${meta.size}, kind: ${meta.kind}, modified: ${meta.modified}`);
}
```

### Named Volumes

```typescript
import { Sandbox, Volume } from "microsandbox";

// Create a 100 MiB named volume.
const data = await Volume.builder("my-data").quota(100).create();

// Writer sandbox.
{
  await using writer = await Sandbox.builder("writer")
    .image("alpine")
    .volume("/data", (m) => m.named(data.name))
    .replace()
    .create();
  await writer.shell("echo 'hello' > /data/message.txt");
}

// Reader sandbox — same volume mounted read-only.
{
  await using reader = await Sandbox.builder("reader")
    .image("alpine")
    .volume("/data", (m) => m.named(data.name).readonly())
    .replace()
    .create();
  console.log((await reader.shell("cat /data/message.txt")).stdout());
}

// Host-side filesystem ops on the volume — no sandbox needed.
const vfs = data.fs();
console.log(await vfs.list("")); // ["message.txt"]

// Cleanup.
await Sandbox.remove("writer");
await Sandbox.remove("reader");
await Volume.remove("my-data");
```

### Disk Image Volumes

Mount a host disk image at a guest path. Format defaults to the file
extension; call `.format(...)` to override. `.fstype(...)` is the inner
filesystem agentd will mount; omit to let agentd autodetect.

```typescript
import { Sandbox } from "microsandbox";

await using sb = await Sandbox.builder("worker")
  .image("alpine")
  .volume("/data",    (m) => m.disk("./data.qcow2").fstype("ext4"))
  .volume("/seed",    (m) => m.disk("./seed.raw").readonly())
  .volume("/scratch", (m) => m.tmpfs().size(128).readonly())
  .replace()
  .create();
```

### Network Policies

```typescript
import { Sandbox, NetworkPolicy, Rule, Destination, PortRange } from "microsandbox";

// Default — public internet only (blocks private ranges).
await using publicOnly = await Sandbox.builder("public").image("alpine").create();

// Fully airgapped.
await using isolated = await Sandbox.builder("isolated")
  .image("alpine")
  .network((n) => n.policy(NetworkPolicy.none()))
  .create();

// Unrestricted.
await using open = await Sandbox.builder("open")
  .image("alpine")
  .network((n) => n.policy(NetworkPolicy.allowAll()))
  .create();

// DNS filtering.
await using filtered = await Sandbox.builder("filtered")
  .image("alpine")
  .network((n) => n.dns((d) =>
    d.blockDomain("blocked.example.com").blockDomainSuffix(".evil.com"),
  ))
  .create();

// Custom rule list — first match wins, evaluated independently per direction.
await using custom = await Sandbox.builder("custom")
  .image("alpine")
  .network((n) => n.policy({
    defaultEgress: "deny",
    defaultIngress: "allow",
    rules: [
      Rule.allowEgress(Destination.domain("api.openai.com")),
      Rule.denyEgress(Destination.group("metadata")),
    ],
  }))
  .create();
```

### Port Publishing

```typescript
await using sb = await Sandbox.builder("web")
  .image("python")
  .port(8080, 80)        // TCP host:8080 -> guest:80
  .portUdp(5353, 5353)   // UDP host:5353 -> guest:5353
  .create();
```

### Secrets

Secrets use placeholder substitution — the real value never enters the VM. It is only swapped in at the network layer for HTTPS requests to allowed hosts.

```typescript
import { Sandbox } from "microsandbox";

// Shorthand: auto-generates the placeholder as `$MSB_<ENV_VAR>`.
await using sb = await Sandbox.builder("agent")
  .image("python")
  .secretEnv("OPENAI_API_KEY", process.env.OPENAI_API_KEY!, "api.openai.com")
  .create();

// Or with full control via SecretBuilder.
await using sb2 = await Sandbox.builder("agent2")
  .image("python")
  .secret((s) =>
    s.env("STRIPE_KEY")
      .value(process.env.STRIPE_KEY!)
      .allowHost("api.stripe.com")
      .allowHostPattern("*.stripe.com")
      .injectHeaders(true)
      .injectQuery(false),
  )
  .create();

// Guest sees: OPENAI_API_KEY=$MSB_OPENAI_API_KEY (a placeholder).
// HTTPS to api.openai.com  → placeholder transparently replaced with the real key.
// HTTPS anywhere else      → request blocked.
```

### Rootfs Patches

Modify the filesystem before the VM boots:

```typescript
import { Sandbox } from "microsandbox";

await using sandbox = await Sandbox.builder("patched")
  .image("alpine")
  .patch((p) => p
    .text("/etc/greeting.txt", "Hello!\n")
    .mkdir("/app", { mode: 0o755 })
    .text("/app/config.json", '{"debug": true}', { mode: 0o644 })
    .copyDir("./scripts", "/app/scripts")
    .append("/etc/hosts", "127.0.0.1 myapp.local\n"),
  )
  .create();
```

### Detached Mode

Detached sandboxes survive the Node.js process:

```typescript
// Create detached — drops the lifecycle on this handle's `Symbol.asyncDispose`.
const sb = await Sandbox.builder("background")
  .image("python")
  .createDetached();

// Later, from another process:
const handle = await Sandbox.get("background");
const live = await handle.connect();              // no lifecycle ownership
await live.shell("echo reconnected");
```

### TLS Interception

```typescript
await using sandbox = await Sandbox.builder("tls-inspect")
  .image("python")
  .network((n) => n.tls((t) =>
    t.bypass("*.googleapis.com")
      .verifyUpstream(true)
      .interceptedPorts([443]),
  ))
  .create();
```

### Metrics

```typescript
import { allSandboxMetrics, Sandbox } from "microsandbox";

await using sandbox = await Sandbox.builder("metrics-demo")
  .image("python")
  .create();

const m = await sandbox.metrics();
console.log(`CPU: ${m.cpuPercent.toFixed(1)}%`);
console.log(`Memory: ${(m.memoryBytes / 1024 / 1024).toFixed(1)} MiB`);
console.log(`Uptime: ${(m.uptimeMs / 1000).toFixed(1)}s`);

// Stream snapshots every second.
for await (const sample of await sandbox.metricsStream(1000)) {
  console.log(sample.timestamp.toISOString(), sample.cpuPercent);
  if (sample.uptimeMs > 10_000) break;
}

// All sandboxes at once.
const all = await allSandboxMetrics();
for (const [name, metrics] of Object.entries(all)) {
  console.log(`${name}: ${metrics.cpuPercent.toFixed(1)}%`);
}
```

### Image Cache

```typescript
import { Image } from "microsandbox";

const cached = await Image.list();
for (const h of cached) console.log(h.reference, h.architecture, h.layerCount);

const detail = await Image.inspect("python:3.12");
console.log(detail.config?.entrypoint, detail.config?.workingDir);

await Image.remove("old:tag", { force: true });
const reclaimed = await Image.gcLayers();
console.log(`reclaimed ${reclaimed} orphaned layers`);
```

### Typed Errors

Every `MicrosandboxError` variant has a dedicated subclass — use
`instanceof` instead of parsing message strings.

```typescript
import { ExecTimeoutError, Sandbox, SandboxNotFoundError } from "microsandbox";

try {
  await Sandbox.remove("ghost");
} catch (e) {
  if (e instanceof SandboxNotFoundError) {
    console.log("nothing to remove:", e.message);
  } else {
    throw e;
  }
}

try {
  await sandbox.execWith("sleep", (e) => e.args(["10"]).timeout(500));
} catch (e) {
  if (e instanceof ExecTimeoutError) {
    console.log(`timed out after ${e.timeoutMs}ms`);
  }
}
```

### Runtime Setup

```typescript
import { install, isInstalled, setup } from "microsandbox";

if (!isInstalled()) {
  await install();        // simple — bundled version, default location
}

// Or with full control:
await setup()
  .baseDir("/opt/microsandbox")
  .skipVerify(false)
  .force(false)
  .install();
```

## API Reference

### Lifecycle

| Symbol | Description |
|---|---|
| `Sandbox` | Live sandbox — lifecycle, exec, fs, metrics. Implements `AsyncDisposable`. |
| `SandboxBuilder` | Fluent builder — every Rust setter, terminal `.create()` / `.createDetached()`. |
| `SandboxHandle` | Lightweight DB handle — `connect()`, `start()`, `stop()`, `kill()`. |
| `SandboxConfig` | Built sandbox configuration (output of `SandboxBuilder.build()`). |
| `SandboxStatus` | `"running" \| "stopped" \| "crashed" \| "draining"` |

### Execution

| Symbol | Description |
|---|---|
| `ExecOutput` | Captured stdout/stderr + exit status. |
| `ExecHandle` | Streaming handle — `AsyncIterable<ExecEvent>`, `recv()`, `wait()`, `collect()`, `Symbol.asyncDispose`. |
| `ExecSink` | Stdin sink — `write()`, `close()`. |
| `ExecOptionsBuilder` / `ExecOptions` | Chained options used by `Sandbox.execWith` / `execStreamWith`. |
| `AttachOptionsBuilder` / `AttachOptions` | PTY-attach options. |
| `ExecEvent` | Discriminated union: `{kind:"started", pid}` \| `{kind:"stdout", data}` \| `{kind:"stderr", data}` \| `{kind:"exited", code}`. |
| `Stdin` | Factory for `StdinMode`: `Stdin.null()`, `Stdin.pipe()`, `Stdin.bytes(...)`. |
| `Rlimit` / `RlimitResource` | Per-exec resource limits. |
| `ExitStatus` | `{ code, success }`. |

### Filesystem

| Symbol | Description |
|---|---|
| `SandboxFs` | Guest fs ops (read, write, list, mkdir, copy, rename, stat, exists, copyFromHost, copyToHost, readStream, writeStream). |
| `FsReadStream` | Streaming reader — `AsyncIterable<Uint8Array>`. |
| `FsWriteSink` | Streaming writer — `write()`, `close()`, `Symbol.asyncDispose`. |
| `FsEntry` / `FsMetadata` / `FsEntryKind` | Listing entry, stat metadata, kind union. |

### Volumes

| Symbol | Description |
|---|---|
| `Volume` / `VolumeBuilder` / `VolumeHandle` | Named persistent storage with quotas and labels. |
| `VolumeFs` | Host-side fs ops on a volume's directory (no sandbox required). |
| `VolumeFsReadStream` / `VolumeFsWriteSink` | Streaming variants. |
| `MountBuilder` | Mount-spec builder — `bind`, `named`, `tmpfs`, `disk`, `format`, `fstype`, `readonly`, `size`. |
| `VolumeMount` | Discriminated union of mount kinds. |

### Image Cache

| Symbol | Description |
|---|---|
| `Image` | Static API: `get`, `list`, `inspect`, `remove`, `gcLayers`, `gc`. |
| `ImageHandle` / `ImageDetail` / `ImageConfigDetail` / `ImageLayerDetail` | Cached image metadata. |
| `RootfsSource` / `DiskImageFormat` | Discriminated rootfs union and disk format literal type. |
| `intoRootfsSource(input)` | Resolve a string into the right `RootfsSource`. |

### Networking

| Symbol | Description |
|---|---|
| `NetworkBuilder` / `NetworkConfig` | Top-level network builder — ports, policy, DNS, TLS, secrets. |
| `DnsBuilder` / `DnsConfig` | DNS interception (block lists, nameservers, query timeout). |
| `TlsBuilder` / `TlsConfig` | TLS interception (bypass list, intercepted ports, custom CAs). |
| `SecretBuilder` / `SecretEntry` / `SecretInjection` / `ViolationAction` | Secret entries with host allowlists and injection points. |
| `NetworkPolicy` | Factory + interface — `NetworkPolicy.none()` / `.allowAll()` / `.publicOnly()` / `.nonLocal()`. |
| `Rule` | Factory + interface — `Rule.allowEgress(...)`, `Rule.denyIngress(...)`, `Rule.allowAny(...)`, etc. |
| `Destination` / `DestinationGroup` | Factory + union for rule destinations. |
| `PortRange` | `PortRange.single(port)`, `PortRange.range(start, end)`. |
| `Action` / `Direction` / `Protocol` | String-literal unions used by rules. |

### Patches & Registry

| Symbol | Description |
|---|---|
| `PatchBuilder` / `Patch` | Pre-boot rootfs modifications — `text`, `file`, `copyFile`, `copyDir`, `symlink`, `mkdir`, `remove`, `append`. |
| `RegistryConfigBuilder` / `RegistryConfig` / `RegistryAuth` | Registry connection (auth, insecure, CA certs). |
| `PullPolicy` | `"always" \| "if-missing" \| "never"`. |

### Metrics & Setup

| Symbol | Description |
|---|---|
| `SandboxMetrics` | CPU%, memory, disk I/O, net I/O, uptime, timestamp. |
| `MetricsStream` | `AsyncIterable<SandboxMetrics>` returned by `Sandbox.metricsStream(intervalMs)`. |
| `allSandboxMetrics()` | Snapshot of metrics for every running sandbox. |
| `Setup` / `setup()` | Builder for advanced installs (custom base dir, version, force). |
| `install()` / `isInstalled()` | Simple bootstrapping helpers. |

### Sizes & Logging

| Symbol | Description |
|---|---|
| `Mebibytes` (branded type) + `KiB` / `MiB` / `GiB` / `TiB` | Type-safe size helpers; bare numbers are accepted as MiB. |
| `LogLevel` | `"trace" \| "debug" \| "info" \| "warn" \| "error"`. |

### Errors

`MicrosandboxError` is the base class; every Rust variant has a typed subclass:

`IoError`, `HttpError`, `LibkrunfwNotFoundError`, `DatabaseError`, `InvalidConfigError`, `SandboxNotFoundError`, `SandboxStillRunningError`, `RuntimeError`, `JsonError`, `ProtocolError`, `NixError`, `ExecTimeoutError` (carries `timeoutMs`), `TerminalError`, `SandboxFsError`, `ImageNotFoundError`, `ImageInUseError`, `VolumeNotFoundError`, `VolumeAlreadyExistsError`, `ImageError`, `PatchFailedError`, `CustomError`.

## License

Apache-2.0
