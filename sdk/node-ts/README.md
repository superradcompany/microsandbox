# microsandbox

Lightweight VM sandboxes for Node.js and TypeScript applications that need hardware-level isolation for AI agents, tools, tests, and untrusted code.

The `microsandbox` npm package provides TypeScript bindings to the [microsandbox](https://github.com/superradcompany/microsandbox) runtime through a native addon. It creates microVM-backed sandboxes from OCI images or other rootfs sources, then exposes command execution, guest filesystem access, networking, secrets, volumes, metrics, logs, snapshots, and SSH/SFTP through an async TypeScript API.

For the full API reference and longer guides, use the docs site:

- [TypeScript SDK guide](https://docs.microsandbox.dev/sdk/typescript/sandbox)
- [SDK overview](https://docs.microsandbox.dev/sdk/overview)
- [Repository examples](../../examples/typescript)

## Features

- Hardware VM isolation with a guest Linux kernel
- ESM-first TypeScript API with generated native bindings
- Collected and streaming command execution
- Guest filesystem read, write, list, copy, stat, and stream operations
- Named volumes, bind mounts, tmpfs mounts, and disk-image mounts
- Network policies, DNS filtering, TLS interception, secrets, and port publishing
- Rootfs patches before boot
- Detached sandboxes that can outlive the Node.js process
- Metrics, logs, snapshots, SSH/SFTP, image cache, and local/cloud backend helpers

## Requirements

- Node.js 22+
- Linux with KVM, macOS with Apple Silicon, or Windows with Windows Hypervisor Platform
- Windows support is currently preview; see the [Windows troubleshooting guide](https://docs.microsandbox.dev/getting-started/windows-troubleshooting) for WHP and runtime setup notes.

The package root is ESM-only for normal imports:

```typescript
import { Sandbox } from "microsandbox";
```

## Supported Platforms

| Platform | Architecture | Platform package |
| --- | --- | --- |
| macOS | ARM64 / Apple Silicon | `@superradcompany/microsandbox-darwin-arm64` |
| Linux | x86_64 | `@superradcompany/microsandbox-linux-x64-gnu` |
| Linux | ARM64 | `@superradcompany/microsandbox-linux-arm64-gnu` |
| Windows | x86_64 | `@superradcompany/microsandbox-win32-x64-msvc` |
| Windows | ARM64 | `@superradcompany/microsandbox-win32-arm64-msvc` |

The matching platform package is installed through npm optional dependencies and carries the native addon plus runtime binaries. If optional dependencies are omitted, reinstall with optional dependencies enabled, install the matching platform package explicitly, or set `MSB_PATH` to a working `msb` binary.

## Installation

```bash
npm install microsandbox
```

## Quick Start

```typescript
import { MiB, Sandbox } from "microsandbox";

await using sandbox = await Sandbox.builder("ts-readme")
  .image("alpine")
  .cpus(1)
  .memory(MiB(512))
  .replace()
  .create();

const output = await sandbox.shell("echo 'Hello from microsandbox!'");
console.log(output.stdout().trim());
```

`await using` calls `Sandbox.stop()` when the handle leaves scope. Use a plain `const sandbox = ...` and call lifecycle methods yourself when you need finer control.

## Common Examples

These snippets assume you already have a live `sandbox: Sandbox`.

### Command Execution

```typescript
const result = await sandbox.exec("python3", ["-c", "print(1 + 1)"]);
console.log(result.stdout());
console.log(result.code);

const output = await sandbox.shell("echo hello && pwd");
console.log(output.stdout());

const configured = await sandbox.execWith("python3", (exec) =>
  exec
    .args(["script.py"])
    .cwd("/app")
    .env("PYTHONPATH", "/app/lib")
    .timeout(30_000),
);

const handle = await sandbox.execStream("tail", ["-f", "/var/log/app.log"]);
for await (const event of handle) {
  if (event.kind === "stdout") process.stdout.write(event.data);
  if (event.kind === "stderr") process.stderr.write(event.data);
  if (event.kind === "exited") break;
}
```

### Filesystem Operations

```typescript
const fs = sandbox.fs();

await fs.write("/tmp/config.json", '{"debug": true}');
console.log(await fs.readToString("/tmp/config.json"));

for (const entry of await fs.list("/etc")) {
  console.log(`${entry.path} (${entry.kind})`);
}

await fs.copyFromHost("./local-file.txt", "/tmp/file.txt");
await fs.copyToHost("/tmp/output.txt", "./output.txt");

if (await fs.exists("/tmp/config.json")) {
  const meta = await fs.stat("/tmp/config.json");
  console.log(`size: ${meta.size}, kind: ${meta.kind}`);
}
```

### Named Volumes

```typescript
import { MiB, Sandbox, Volume } from "microsandbox";

const data = await Volume.builder("ts-readme-data").quota(MiB(100)).create();

{
  await using writer = await Sandbox.builder("ts-readme-writer")
    .image("alpine")
    .volume("/data", (mount) => mount.named(data.name))
    .replace()
    .create();
  await writer.shell("echo 'hello' > /data/message.txt");
}

{
  await using reader = await Sandbox.builder("ts-readme-reader")
    .image("alpine")
    .volume("/data", (mount) => mount.named(data.name).readonly())
    .replace()
    .create();
  console.log((await reader.shell("cat /data/message.txt")).stdout().trim());
}

const entries = await data.fs().list("");
for (const entry of entries) {
  console.log(`${entry.path} (${entry.kind})`);
}
```

### Network, DNS, and Ports

```typescript
import { NetworkPolicy, Rule, Destination, Sandbox } from "microsandbox";

await using isolated = await Sandbox.builder("ts-readme-isolated")
  .image("alpine")
  .network((network) => network.policy(NetworkPolicy.none()))
  .replace()
  .create();

const filteredPolicy = NetworkPolicy.builder()
  .defaultAllow()
  .egress((egress) =>
    egress
      .denyDomain("blocked.example.com")
      .denyDomainSuffix(".evil.com"),
  )
  .build();

await using filtered = await Sandbox.builder("ts-readme-filtered")
  .image("alpine")
  .network((network) => network.policy(filteredPolicy))
  .replace()
  .create();

const allowlisted = {
  defaultEgress: "deny",
  defaultIngress: "allow",
  rules: [
    Rule.allowEgress(Destination.domain("api.openai.com")),
  ],
} satisfies NetworkPolicy;

await using web = await Sandbox.builder("ts-readme-web")
  .image("python")
  .network((network) => network.policy(allowlisted))
  .port(8080, 80)
  .create();
```

Domain blocking is network policy behavior. `DnsBuilder` configures DNS resolver behavior such as rebinding protection, nameservers, and query timeouts.

### Secrets

Secrets use placeholder substitution. The real value stays on the host and is substituted only for allowed network destinations.

```typescript
import { Sandbox } from "microsandbox";

await using sandbox = await Sandbox.builder("ts-readme-agent")
  .image("python")
  .secretEnv("OPENAI_API_KEY", process.env.OPENAI_API_KEY!, "api.openai.com")
  .replace()
  .create();
```

### Rootfs Patches

```typescript
await using sandbox = await Sandbox.builder("ts-readme-patched")
  .image("alpine")
  .patch((patch) =>
    patch
      .text("/etc/greeting.txt", "Hello!\n")
      .mkdir("/app", { mode: 0o755 })
      .text("/app/config.json", '{"debug": true}', { mode: 0o644 })
      .append("/etc/hosts", "127.0.0.1 myapp.local\n"),
  )
  .replace()
  .create();
```

### Detached Mode

```typescript
const sandbox = await Sandbox.builder("ts-readme-background")
  .image("python")
  .detached(true)
  .replace()
  .create();
await sandbox.detach();

const handle = await Sandbox.get("ts-readme-background");
const reconnected = await handle.connect();
const output = await reconnected.shell("echo reconnected");
console.log(output.stdout().trim());
```

### TLS Interception

```typescript
await using sandbox = await Sandbox.builder("tls-inspect")
  .image("python")
  .network((n) => n.tls((t) =>
    t.bypass("*.googleapis.com")
      .verifyUpstream(true)
      .interceptedPorts([443])
      .upstreamCaCert("/etc/ssl/corp-root.pem")
      .upstreamCaCertFor("api.internal", "./certs/api-ca.pem")
      .verifyUpstreamFor("*.preview.internal", false),
  ))
  .create();
```

### Metrics

```typescript
import { allSandboxMetrics } from "microsandbox";

const metrics = await sandbox.metrics();
console.log(`CPU: ${metrics.cpuPercent.toFixed(1)}%`);
console.log(`Memory: ${(metrics.memoryBytes / 1024 / 1024).toFixed(1)} MiB`);

for await (const sample of await sandbox.metricsStream(1000)) {
  console.log(sample.timestamp.toISOString(), sample.cpuPercent);
  break;
}

for (const [name, sample] of Object.entries(await allSandboxMetrics())) {
  console.log(`${name}: ${sample.cpuPercent.toFixed(1)}%`);
}
```

### Typed Errors

TypeScript exports typed errors for the common SDK categories and falls back to `MicrosandboxError` for unmapped runtime variants. Catch specific errors when you need category-specific handling, and catch `MicrosandboxError` as the broad SDK base class.

```typescript
import {
  MicrosandboxError,
  Sandbox,
  SandboxAlreadyExistsError,
} from "microsandbox";

try {
  await Sandbox.builder("worker").image("alpine").create();
} catch (error) {
  if (error instanceof SandboxAlreadyExistsError) {
    console.log("already exists; resume it or pass replace()");
  } else if (error instanceof MicrosandboxError) {
    console.log(`microsandbox error: ${error.message}`);
  } else {
    throw error;
  }
}
```

## Runtime Notes

- The `microsandbox` package depends on platform packages through optional dependencies.
- The platform package carries the native addon, `msb`, and `libkrunfw`.
- The `microsandbox` and `msb` bin shims forward to the resolved `msb` binary. They do not install runtime files.
- If no platform package is present, reinstall with optional dependencies enabled, install the matching `@superradcompany/microsandbox-<platform>` package, or set `MSB_PATH`.

## More Documentation

- [Sandbox lifecycle](https://docs.microsandbox.dev/sdk/typescript/sandbox)
- [Execution](https://docs.microsandbox.dev/sdk/typescript/execution)
- [Filesystem](https://docs.microsandbox.dev/sdk/typescript/filesystem)
- [Networking](https://docs.microsandbox.dev/sdk/typescript/networking)
- [Secrets](https://docs.microsandbox.dev/sdk/typescript/secrets)
- [Volumes](https://docs.microsandbox.dev/sdk/typescript/volumes)
- [Snapshots](https://docs.microsandbox.dev/sdk/typescript/snapshots)
- [SSH](https://docs.microsandbox.dev/sdk/typescript/ssh)
- [Agent client](https://docs.microsandbox.dev/sdk/typescript/agent-client)

## Development

From `sdk/node-ts`:

```bash
npm ci
npm run build
npm run typecheck
npm test
```

Run repository examples from the specific example directory:

```bash
cd examples/typescript/root-oci
npm install
npm start
```

## License

Apache-2.0
