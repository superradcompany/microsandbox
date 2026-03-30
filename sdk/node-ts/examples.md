# Microsandbox Node.js SDK — Examples

## Quick Start

```typescript
import { Sandbox, isInstalled, install } from "microsandbox";

// Auto-install runtime if needed
if (!isInstalled()) {
  await install();
}

const sandbox = await Sandbox.create({
  name: "quickstart",
  image: "python:3.12",
  memoryMib: 512,
  cpus: 2,
});

const result = await sandbox.exec("python", ["-c", "print('Hello from microsandbox!')"]);
console.log(result.stdout.toString()); // "Hello from microsandbox!\n"

await sandbox.stopAndWait();
await Sandbox.remove("quickstart");
```

---

## Command Execution

### Simple exec

```typescript
const sandbox = await Sandbox.create({
  name: "exec-demo",
  image: "alpine:latest",
  replace: true,
});

// Command with args
const result = await sandbox.exec("ls", ["-la", "/etc"]);
console.log("exit code:", result.code);
console.log("stdout:", result.stdout.toString());
console.log("stderr:", result.stderr.toString());
console.log("success:", result.success);

// Shell command (uses sandbox's configured shell)
const uname = await sandbox.shell("uname -a && cat /etc/os-release | head -1");
console.log(uname.stdout.toString());
```

### Exec with full config

```typescript
const result = await sandbox.execWithConfig({
  cmd: "python",
  args: ["compute.py"],
  cwd: "/app",
  user: "appuser",
  env: { PYTHONPATH: "/app/lib", DEBUG: "1" },
  timeoutMs: 30_000,
  tty: false,
});
```

### Streaming exec

```typescript
const handle = await sandbox.execStream("sh", [
  "-c",
  "for i in 1 2 3; do echo line $i; sleep 0.5; done; echo done >&2",
]);

let event;
while ((event = await handle.recv()) !== null) {
  switch (event.eventType) {
    case "started":
      console.log("PID:", event.pid);
      break;
    case "stdout":
      process.stdout.write(event.data!);
      break;
    case "stderr":
      process.stderr.write(event.data!);
      break;
    case "exited":
      console.log("Exit code:", event.code);
      break;
  }
}
```

### Streaming exec with stdin

```typescript
const handle = await sandbox.execStream("cat", []);
const stdin = await handle.takeStdin();

await stdin!.write(Buffer.from("hello from stdin\n"));
await stdin!.write(Buffer.from("another line\n"));
await stdin!.close(); // sends EOF

const output = await handle.collect();
console.log(output.stdout.toString());
// "hello from stdin\n"
// "another line\n"
```

### Streaming shell

```typescript
const handle = await sandbox.shellStream("while true; do date; sleep 1; done");

// Read 5 events then kill
let count = 0;
let event;
while ((event = await handle.recv()) !== null) {
  if (event.eventType === "stdout") {
    console.log(event.data!.toString().trim());
    if (++count >= 5) {
      await handle.kill();
      break;
    }
  }
}
```

### Collect streaming output

```typescript
const handle = await sandbox.execStream("find", ["/etc", "-name", "*.conf"]);
const output = await handle.collect();
console.log("Files found:", output.stdout.toString().trim().split("\n").length);
```

---

## Filesystem

```typescript
const sandbox = await Sandbox.create({
  name: "fs-demo",
  image: "alpine:latest",
  replace: true,
});

const fs = sandbox.fs();

// Write and read
await fs.write("/tmp/config.json", Buffer.from(JSON.stringify({ debug: true })));
const content = await fs.readString("/tmp/config.json");
console.log("Config:", JSON.parse(content)); // { debug: true }

// Read as Buffer
const raw = await fs.read("/tmp/config.json");
console.log("Bytes:", raw.length);

// Directory operations
await fs.mkdir("/app/data");
await fs.write("/app/data/file1.txt", Buffer.from("hello"));
await fs.write("/app/data/file2.txt", Buffer.from("world"));

const entries = await fs.list("/app/data");
for (const entry of entries) {
  console.log(`${entry.kind} ${entry.path} (${entry.size} bytes, mode=${entry.mode.toString(8)})`);
}
// file /app/data/file1.txt (5 bytes, mode=100644)
// file /app/data/file2.txt (5 bytes, mode=100644)

// Metadata
const stat = await fs.stat("/app/data/file1.txt");
console.log("Size:", stat.size, "Kind:", stat.kind, "Readonly:", stat.readonly);

// Check existence
console.log("Exists:", await fs.exists("/app/data/file1.txt")); // true
console.log("Exists:", await fs.exists("/nonexistent")); // false

// Copy, rename, remove
await fs.copy("/app/data/file1.txt", "/app/data/backup.txt");
await fs.rename("/app/data/backup.txt", "/app/data/file1.bak");
await fs.remove("/app/data/file1.bak");
await fs.removeDir("/app/data");

// Host ↔ sandbox transfer
await fs.write("/tmp/export.txt", Buffer.from("export data"));
await fs.copyToHost("/tmp/export.txt", "/tmp/from-sandbox.txt");

const { readFileSync, unlinkSync } = require("fs");
console.log("Host file:", readFileSync("/tmp/from-sandbox.txt", "utf-8"));
unlinkSync("/tmp/from-sandbox.txt");

await fs.copyFromHost("/etc/hosts", "/tmp/host-hosts");
console.log("Copied hosts file:", (await fs.readString("/tmp/host-hosts")).split("\n").length, "lines");
```

---

## Volumes

```typescript
import { Sandbox, Volume } from "microsandbox";

// Create a named volume with quota
const vol = await Volume.create({
  name: "app-data",
  quotaMib: 256,
  labels: { env: "dev", team: "backend" },
});

console.log("Created:", vol.name, "at", vol.path);

// Use volume in a sandbox
const sandbox = await Sandbox.create({
  name: "vol-demo",
  image: "alpine:latest",
  replace: true,
  volumes: {
    "/data": { named: "app-data" },
    "/src": { bind: "./src", readonly: true },
    "/tmp/scratch": { tmpfs: true, sizeMib: 64 },
  },
});

// Data persists across sandbox restarts
await sandbox.shell("echo 'persistent' > /data/state.txt");
await sandbox.stopAndWait();

const sandbox2 = await Sandbox.create({
  name: "vol-demo-2",
  image: "alpine:latest",
  replace: true,
  volumes: { "/data": { named: "app-data" } },
});

const content = await sandbox2.shell("cat /data/state.txt");
console.log(content.stdout.toString().trim()); // "persistent"
await sandbox2.stopAndWait();
await Sandbox.remove("vol-demo-2");

// List and inspect volumes
const volumes = await Volume.list();
for (const v of volumes) {
  console.log(`${v.name}: ${v.usedBytes} bytes, quota=${v.quotaMib ?? "unlimited"}`);
}

const handle = await Volume.get("app-data");
console.log("Labels:", handle.labels);

// Cleanup
await Volume.remove("app-data");
```

---

## Network Policy

### Preset policies

```typescript
// No network access (airgapped)
const isolated = await Sandbox.create({
  name: "isolated",
  image: "alpine:latest",
  replace: true,
  network: { policy: "none" },
});

// Public internet only (blocks private IPs, cloud metadata)
const publicOnly = await Sandbox.create({
  name: "public-only",
  image: "alpine:latest",
  replace: true,
  network: { policy: "public-only" },
});

// Allow everything
const open = await Sandbox.create({
  name: "open",
  image: "alpine:latest",
  replace: true,
  network: { policy: "allow-all" },
});
```

### Custom policy rules

```typescript
const sandbox = await Sandbox.create({
  name: "custom-policy",
  image: "python:3.12",
  replace: true,
  network: {
    // Default: deny everything
    defaultAction: "deny",
    rules: [
      // Allow HTTPS to any destination
      { action: "allow", destination: "*", protocol: "tcp", port: "443" },
      // Allow DNS
      { action: "allow", destination: "*", protocol: "udp", port: "53" },
      // Block cloud metadata endpoint
      { action: "deny", destination: "metadata" },
      // Block all private networks
      { action: "deny", destination: "private" },
      // Allow specific API
      { action: "allow", destination: "api.openai.com", protocol: "tcp" },
      // Allow a CIDR range
      { action: "allow", destination: "10.0.1.0/24", protocol: "tcp", port: "8000-9000" },
      // Block a domain suffix
      { action: "deny", destination: ".malware.com" },
    ],
  },
});
```

### DNS blocking

```typescript
const sandbox = await Sandbox.create({
  name: "dns-filtered",
  image: "alpine:latest",
  replace: true,
  network: {
    policy: "public-only",
    blockDomains: ["evil.com", "tracking.example.com"],
    blockDomainSuffixes: [".malware.net", ".adserver.com"],
    dnsRebindProtection: true,
  },
});
```

### Port mapping

```typescript
const sandbox = await Sandbox.create({
  name: "web-server",
  image: "python:3.12",
  replace: true,
  ports: {
    "8080": 80,   // host:8080 → guest:80
    "8443": 443,  // host:8443 → guest:443
  },
  network: { policy: "public-only" },
});

// Start a web server inside the sandbox
await sandbox.shell("python -m http.server 80 &");

// Access from host at http://localhost:8080
```

---

## TLS Interception

```typescript
const sandbox = await Sandbox.create({
  name: "tls-inspect",
  image: "python:3.12",
  replace: true,
  network: {
    policy: "public-only",
    tls: {
      // Intercept HTTPS traffic for inspection
      interceptedPorts: [443],
      // Bypass cert-pinned services
      bypass: ["*.googleapis.com", "pinned-api.example.com"],
      // Verify upstream certs
      verifyUpstream: true,
      // Block QUIC to force traffic through TCP (interceptable)
      blockQuic: true,
    },
  },
});
```

---

## Secrets

```typescript
const sandbox = await Sandbox.create({
  name: "agent",
  image: "python:3.12",
  replace: true,
  network: { policy: "public-only" },
  secretEnv: {
    OPENAI_API_KEY: {
      value: process.env.OPENAI_API_KEY!,
      domain: "api.openai.com",
      requireTls: true,
      onViolation: "block-and-log",
    },
    GITHUB_TOKEN: {
      value: process.env.GITHUB_TOKEN!,
      domain: "api.github.com",
      domainPattern: "*.githubusercontent.com",
    },
    INTERNAL_KEY: {
      value: "sk-internal-12345",
      domainPattern: "*.internal.corp",
      placeholder: "$INTERNAL_API_KEY", // custom placeholder
      onViolation: "block-and-terminate",
    },
  },
});

// The sandbox sees placeholder values, not real secrets
const result = await sandbox.shell("echo $OPENAI_API_KEY");
console.log(result.stdout.toString().trim()); // "$MSB_OPENAI_API_KEY"

// Secrets are only substituted when the sandbox makes HTTPS requests
// to the allowed domains
```

---

## Patches (Rootfs Customization)

```typescript
const sandbox = await Sandbox.create({
  name: "patched",
  image: "alpine:latest",
  replace: true,
  patches: [
    // Write a config file
    { kind: "text", path: "/etc/app.conf", content: "debug=true\nport=8080" },
    // Create directories
    { kind: "mkdir", path: "/app/logs" },
    { kind: "mkdir", path: "/app/data", mode: 0o755 },
    // Copy files from host
    { kind: "copyFile", src: "./config/prod.json", dst: "/app/config.json" },
    { kind: "copyDir", src: "./scripts", dst: "/app/scripts" },
    // Create symlinks
    { kind: "symlink", target: "/usr/bin/python3", link: "/usr/bin/python" },
    // Append to existing files
    { kind: "append", path: "/etc/profile", content: "\nexport PATH=$PATH:/app/scripts" },
    // Remove files
    { kind: "remove", path: "/etc/motd" },
    // Replace existing files
    { kind: "text", path: "/etc/hostname", content: "my-sandbox", replace: true },
  ],
});
```

---

## Scripts

```typescript
const sandbox = await Sandbox.create({
  name: "scripted",
  image: "python:3.12",
  replace: true,
  workdir: "/app",
  scripts: {
    setup: "#!/bin/bash\npip install requests flask",
    test: "#!/bin/bash\npython -m pytest /app/tests -v",
    serve: "#!/bin/bash\nexec python /app/server.py",
  },
});

// Scripts are mounted at /.msb/scripts/ and added to PATH
await sandbox.shell("setup");
const testResult = await sandbox.shell("test");
console.log(testResult.success ? "Tests passed" : "Tests failed");
```

---

## Metrics

```typescript
const sandbox = await Sandbox.create({
  name: "metrics-demo",
  image: "python:3.12",
  replace: true,
});

// Generate some load
sandbox.shell("python -c 'sum(range(10**7))'");

// Point-in-time metrics
const m = await sandbox.metrics();
console.log(`CPU: ${m.cpuPercent.toFixed(1)}%`);
console.log(`Memory: ${(m.memoryBytes / 1024 / 1024).toFixed(1)} MB / ${(m.memoryLimitBytes / 1024 / 1024).toFixed(0)} MB`);
console.log(`Disk I/O: ${m.diskReadBytes} read, ${m.diskWriteBytes} write`);
console.log(`Net I/O: ${m.netRxBytes} rx, ${m.netTxBytes} tx`);
console.log(`Uptime: ${(m.uptimeMs / 1000).toFixed(1)}s`);

// All sandbox metrics at once
const all = await allSandboxMetrics();
for (const [name, metrics] of Object.entries(all)) {
  console.log(`${name}: CPU ${metrics.cpuPercent.toFixed(1)}%, Mem ${(metrics.memoryBytes / 1024 / 1024).toFixed(0)} MB`);
}
```

---

## Sandbox Management

### List and inspect

```typescript
const sandboxes = await Sandbox.list();
for (const info of sandboxes) {
  console.log(`${info.name} [${info.status}] created=${new Date(info.createdAt!).toISOString()}`);
}
```

### Get handle and reconnect

```typescript
// Get a lightweight handle (no live connection)
const handle = await Sandbox.get("my-sandbox");
console.log("Status:", handle.status); // "running", "stopped", "crashed", "draining"
console.log("Config:", JSON.parse(handle.configJson));

// Connect to a running sandbox (no lifecycle ownership)
const sandbox = await handle.connect();
const result = await sandbox.exec("whoami", []);
console.log(result.stdout.toString().trim());

// Or start a stopped sandbox
const started = await handle.start();
```

### Detached mode

```typescript
// Create a sandbox that survives the Node process
const sandbox = await Sandbox.createDetached({
  name: "background-worker",
  image: "python:3.12",
  replace: true,
});

await sandbox.shell("python /app/worker.py &");
await sandbox.detach(); // don't kill on exit

// Later, in another process:
const handle = await Sandbox.get("background-worker");
const reconnected = await handle.connect();
const status = await reconnected.exec("pgrep", ["-la", "python"]);
console.log(status.stdout.toString());
```

### Lifecycle control

```typescript
const sandbox = await Sandbox.create({
  name: "lifecycle-demo",
  image: "alpine:latest",
  replace: true,
});

// Stop gracefully (SIGTERM → wait for exit)
const exitStatus = await sandbox.stopAndWait();
console.log("Exit:", exitStatus.code, exitStatus.success);

// Or stop without waiting
await sandbox.stop();

// Or kill immediately (SIGKILL)
await sandbox.kill();

// Drain (SIGUSR1 — for load balancing)
await sandbox.drain();

// Wait for process to exit
const status = await sandbox.wait();

// Remove from database
await Sandbox.remove("lifecycle-demo");

// Or stop + remove in one call
await sandbox.removePersisted();
```

---

## AI Agent Patterns

### Code interpreter

```typescript
import { Sandbox } from "microsandbox";
import { randomUUID } from "crypto";

async function executeCode(code: string, language = "python"): Promise<{ success: boolean; output: string }> {
  const name = `exec-${randomUUID().slice(0, 8)}`;

  const sandbox = await Sandbox.create({
    name,
    image: language === "python" ? "python:3.12" : "node:20-alpine",
    memoryMib: 512,
    replace: true,
    network: { policy: "none" }, // airgapped
    volumes: {
      "/workspace": { tmpfs: true, sizeMib: 64 },
    },
  });

  try {
    const ext = language === "python" ? "py" : "js";
    const cmd = language === "python" ? "python" : "node";

    await sandbox.fs().write(`/workspace/code.${ext}`, Buffer.from(code));

    const result = await sandbox.execWithConfig({
      cmd,
      args: [`/workspace/code.${ext}`],
      timeoutMs: 30_000,
      cwd: "/workspace",
    });

    return {
      success: result.success,
      output: result.success ? result.stdout.toString() : result.stderr.toString(),
    };
  } finally {
    await sandbox.kill().catch(() => {});
    await Sandbox.remove(name).catch(() => {});
  }
}

// Usage
const result = await executeCode(`
import math
print(f"Pi = {math.pi:.10f}")
print(f"e  = {math.e:.10f}")
`);
console.log(result.output);
```

### Tool-using agent with scoped API access

```typescript
const agent = await Sandbox.create({
  name: "tool-agent",
  image: "python:3.12",
  replace: true,
  memoryMib: 1024,
  network: {
    defaultAction: "deny",
    rules: [
      { action: "allow", destination: "api.openai.com", protocol: "tcp", port: "443" },
      { action: "allow", destination: "api.github.com", protocol: "tcp", port: "443" },
      { action: "allow", destination: "*", protocol: "udp", port: "53" }, // DNS
    ],
  },
  secretEnv: {
    OPENAI_API_KEY: { value: process.env.OPENAI_API_KEY!, domain: "api.openai.com" },
    GITHUB_TOKEN: { value: process.env.GITHUB_TOKEN!, domain: "api.github.com" },
  },
});
```

### Sandbox pool

```typescript
import { Sandbox } from "microsandbox";
import { randomUUID } from "crypto";

class SandboxPool {
  private available: Sandbox[] = [];
  private inUse = new Map<string, Sandbox>();

  constructor(
    private image: string,
    private maxSize: number,
  ) {}

  async acquire(): Promise<Sandbox> {
    let sb = this.available.pop();
    if (!sb) {
      if (this.inUse.size >= this.maxSize) {
        throw new Error("Pool exhausted");
      }
      sb = await Sandbox.create({
        name: `pool-${randomUUID().slice(0, 8)}`,
        image: this.image,
        network: { policy: "none" },
      });
    }
    const name = await sb.name;
    this.inUse.set(name, sb);
    return sb;
  }

  async release(sb: Sandbox): Promise<void> {
    const name = await sb.name;
    this.inUse.delete(name);
    // Clean temp files before returning to pool
    await sb.shell("rm -rf /tmp/* /workspace/*").catch(() => {});
    this.available.push(sb);
  }

  async shutdown(): Promise<void> {
    for (const sb of [...this.available, ...this.inUse.values()]) {
      const name = await sb.name;
      await sb.kill().catch(() => {});
      await Sandbox.remove(name).catch(() => {});
    }
    this.available = [];
    this.inUse.clear();
  }
}
```

---

## Private Registry

```typescript
const sandbox = await Sandbox.create({
  name: "private-image",
  image: "registry.corp.io/team/ml-runner:v2",
  registryAuth: {
    username: "deploy",
    password: process.env.REGISTRY_TOKEN!,
  },
  pullPolicy: "always",
});
```

---

## Error Handling

```typescript
import { Sandbox } from "microsandbox";

try {
  const sandbox = await Sandbox.create({
    name: "error-demo",
    image: "alpine:latest",
    replace: true,
  });

  const result = await sandbox.exec("sh", ["-c", "exit 42"]);
  if (!result.success) {
    console.error(`Command failed with exit code ${result.code}`);
    console.error("stderr:", result.stderr.toString());
  }

  await sandbox.stopAndWait();
  await Sandbox.remove("error-demo");
} catch (err: any) {
  // Error messages include a type tag: [ErrorType] message
  // Common types: SandboxNotFound, InvalidConfig, ExecTimeout, Runtime
  console.error(err.message);

  if (err.message.includes("[SandboxNotFound]")) {
    console.error("Sandbox does not exist");
  } else if (err.message.includes("[ExecTimeout]")) {
    console.error("Command timed out");
  } else if (err.message.includes("[InvalidConfig]")) {
    console.error("Bad configuration");
  }
}
```

---

## Full Configuration Reference

```typescript
const sandbox = await Sandbox.create({
  // Required
  name: "full-config",
  image: "python:3.12",

  // Resources
  memoryMib: 1024,
  cpus: 4,

  // Guest configuration
  workdir: "/app",
  shell: "/bin/bash",
  entrypoint: ["/usr/local/bin/python3"],
  cmd: ["server.py"],
  hostname: "my-sandbox",
  user: "appuser",

  // Environment
  env: {
    NODE_ENV: "production",
    DEBUG: "app:*",
  },

  // Scripts (mounted at /.msb/scripts/, added to PATH)
  scripts: {
    setup: "#!/bin/bash\napt-get update && apt-get install -y curl",
    start: "#!/bin/bash\nexec python /app/main.py",
  },

  // Volumes
  volumes: {
    "/app/src": { bind: "./src", readonly: true },
    "/data": { named: "app-data" },
    "/tmp/cache": { tmpfs: true, sizeMib: 128 },
  },

  // Patches (rootfs modifications before boot)
  patches: [
    { kind: "text", path: "/etc/app.conf", content: "key=value" },
    { kind: "mkdir", path: "/app/logs" },
    { kind: "copyDir", src: "./config", dst: "/app/config" },
  ],

  // Networking
  ports: { "8080": 80, "8443": 443 },
  network: {
    policy: "public-only",
    blockDomains: ["evil.com"],
    blockDomainSuffixes: [".tracking.com"],
    dnsRebindProtection: true,
    tls: {
      bypass: ["*.internal.corp"],
      verifyUpstream: true,
      blockQuic: true,
    },
    maxConnections: 128,
  },

  // Secrets
  secretEnv: {
    API_KEY: {
      value: "sk-real-secret",
      domain: "api.example.com",
      requireTls: true,
      onViolation: "block-and-log",
    },
  },

  // Registry
  registryAuth: { username: "user", password: "token" },
  pullPolicy: "if-missing",

  // Behavior
  replace: true,
  quietLogs: false,
  logLevel: "info",
  labels: { env: "prod", version: "1.2.3" },
  stopSignal: "SIGTERM",
  maxDurationSecs: 3600,
});
```
