# microsandbox

Lightweight VM sandboxes for Go — run AI agents and untrusted code with hardware-level isolation.

The `microsandbox` Go module provides native bindings to the [microsandbox](https://github.com/superradcompany/microsandbox) runtime. It spins up real microVMs (not containers) in under 100ms, runs standard OCI (Docker) images, and gives you full control over execution, filesystem, networking, and secrets — all from a simple, idiomatic Go API.

## Features

- **Hardware isolation** — Each sandbox is a real VM with its own Linux kernel
- **Sub-100ms boot** — No daemon, no server setup, embedded directly in your app
- **OCI image support** — Pull and run images from Docker Hub, GHCR, ECR, or any OCI registry
- **Command execution** — Run commands with collected or streaming output
- **Guest filesystem access** — Read, write, list, copy files inside a running sandbox
- **Named volumes** — Persistent storage across sandbox restarts, with quotas
- **Network policies** — Public-only (default), allow-all, or fully airgapped
- **DNS filtering** — Block specific domains or domain suffixes
- **TLS interception** — Transparent HTTPS inspection and secret substitution
- **Secrets** — Credentials that never enter the VM; placeholder substitution at the network layer
- **Port publishing** — Expose guest TCP services on host ports
- **Rootfs patches** — Modify the filesystem before the VM boots
- **Detached mode** — Sandboxes can outlive the Go process
- **Metrics** — CPU, memory, disk I/O, and network I/O per sandbox

## Requirements

- **Go** >= 1.21
- **Linux** with KVM enabled, or **macOS** with Apple Silicon (M-series)

## Supported Platforms

| Platform | Architecture |
|----------|-------------|
| macOS    | ARM64 (Apple Silicon) |
| Linux    | x86_64 |
| Linux    | ARM64 |

## Installation

```bash
go get github.com/superradcompany/microsandbox/sdk/go
```

At program startup, call `EnsureInstalled` once before any other SDK function. It downloads the `msb` binary, `libkrunfw`, and the native FFI library to `~/.microsandbox/` the first time it runs; subsequent calls are no-ops.

```go
import microsandbox "github.com/superradcompany/microsandbox/sdk/go"

func main() {
    ctx := context.Background()
    if err := microsandbox.EnsureInstalled(ctx); err != nil {
        log.Fatalf("microsandbox setup: %v", err)
    }
    // ...
}
```

## Quick Start

```go
import (
    "context"
    "fmt"
    "log"

    microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
    ctx := context.Background()

    if err := microsandbox.EnsureInstalled(ctx); err != nil {
        log.Fatal(err)
    }

    sb, err := microsandbox.NewSandbox(ctx, "my-sandbox",
        microsandbox.WithImage("alpine:3.19"),
        microsandbox.WithMemory(512),
        microsandbox.WithCPUs(1),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer sb.StopAndWait(ctx)

    out, err := sb.Shell(ctx, "echo 'Hello from microsandbox!'")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(out.Stdout())
}
```

## Examples

### Command Execution

```go
// Exec: explicit binary + args.
out, err := sb.Exec(ctx, "python3", []string{"-c", "print(1 + 1)"})
if err != nil {
    log.Fatal(err)
}
fmt.Println(out.Stdout())   // "2\n"
fmt.Println(out.ExitCode()) // 0

// Shell: passes command to /bin/sh -c (pipes, redirects, etc.).
out, err = sb.Shell(ctx, "echo hello && pwd")

// Non-zero exit is NOT a Go error — inspect ExitCode.
out, err = sb.Shell(ctx, "exit 42")
// err == nil, out.ExitCode() == 42, out.Success() == false

// Per-command options.
out, err = sb.Exec(ctx, "make", []string{"build"},
    microsandbox.WithExecCwd("/app"),
    microsandbox.WithExecTimeout(30*time.Second),
)
```

### Streaming Execution

```go
h, err := sb.ShellStream(ctx, "tail -f /var/log/app.log")
if err != nil {
    log.Fatal(err)
}
defer h.Close()

for {
    ev, err := h.Recv(ctx)
    if err != nil {
        break
    }
    switch ev.Kind {
    case microsandbox.ExecEventStarted:
        fmt.Printf("started pid=%d\n", ev.PID)
    case microsandbox.ExecEventStdout:
        os.Stdout.Write(ev.Data)
    case microsandbox.ExecEventStderr:
        os.Stderr.Write(ev.Data)
    case microsandbox.ExecEventExited:
        fmt.Printf("exited code=%d\n", ev.ExitCode)
    case microsandbox.ExecEventDone:
        return
    }
}

// Send a signal to the running process.
h.Signal(ctx, int(syscall.SIGTERM))
```

### Filesystem Operations

```go
fs := sb.FS()

// Write and read files.
err = fs.WriteString(ctx, "/tmp/config.json", `{"debug": true}`)
content, err := fs.ReadString(ctx, "/tmp/config.json")

// Read as bytes.
data, err := fs.Read(ctx, "/tmp/binary")

// List a directory.
entries, err := fs.List(ctx, "/etc")
for _, e := range entries {
    fmt.Printf("%s (%s)\n", e.Path, e.Kind) // Kind: "file"|"dir"|"symlink"|"other"
}

// File metadata.
stat, err := fs.Stat(ctx, "/tmp/config.json")
fmt.Printf("size=%d isDir=%v\n", stat.Size, stat.IsDir)

// Copy between host and guest.
err = fs.CopyFromHost(ctx, "./local-file.txt", "/tmp/file.txt")
err = fs.CopyToHost(ctx, "/tmp/output.txt", "./output.txt")
```

### Named Volumes

```go
// Create a 100 MiB named volume.
vol, err := microsandbox.NewVolume(ctx, "my-data",
    microsandbox.WithVolumeQuota(100),
)
if err != nil {
    log.Fatal(err)
}
defer microsandbox.RemoveVolume(ctx, "my-data")

// Mount it in a sandbox (not yet supported via functional options;
// use WithPatches or the msb CLI to pre-populate volume data).
vols, err := microsandbox.ListVolumes(ctx)

// ErrVolumeAlreadyExists on duplicate create.
_, err = microsandbox.NewVolume(ctx, "my-data")
if microsandbox.IsKind(err, microsandbox.ErrVolumeAlreadyExists) {
    // handle
}

// Remove.
err = vol.Remove(ctx)
```

### Network Policies

```go
// Default: public internet only (blocks RFC-1918 private ranges).
sb, err := microsandbox.NewSandbox(ctx, "public", microsandbox.WithImage("alpine:3.19"))

// Fully airgapped.
sb, err = microsandbox.NewSandbox(ctx, "isolated",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(&microsandbox.NetworkOptions{Policy: "none"}),
)

// Unrestricted.
sb, err = microsandbox.NewSandbox(ctx, "open",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(&microsandbox.NetworkOptions{Policy: "allow-all"}),
)

// Custom rule set.
sb, err = microsandbox.NewSandbox(ctx, "custom",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(&microsandbox.NetworkOptions{
        CustomPolicy: &microsandbox.CustomNetworkPolicy{
            DefaultAction: "deny",
            Rules: []microsandbox.NetworkRule{
                {Action: "allow", Destination: "api.openai.com", Protocol: "tcp", Port: 443},
            },
        },
    }),
)
```

### DNS Filtering

```go
sb, err := microsandbox.NewSandbox(ctx, "filtered",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(&microsandbox.NetworkOptions{
        BlockDomains:        []string{"blocked.example.com"},
        BlockDomainSuffixes: []string{".ads"},
    }),
)
```

### Port Publishing

```go
// host:8080 → guest:80
sb, err := microsandbox.NewSandbox(ctx, "web",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithPorts(map[uint16]uint16{8080: 80}),
)
```

### Secrets

Secrets use placeholder substitution — the real value never enters the VM. It is only swapped in at the network layer for HTTPS requests to allowed hosts.

```go
sb, err := microsandbox.NewSandbox(ctx, "agent",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithSecrets(microsandbox.NewSecret(
        "OPENAI_API_KEY",
        os.Getenv("OPENAI_API_KEY"),
        "api.openai.com",
    )),
)

// Guest sees: OPENAI_API_KEY=$MSB_OPENAI_API_KEY (a placeholder)
// HTTPS to api.openai.com: placeholder is transparently replaced with the real key
// HTTPS to any other host carrying the placeholder: request is blocked
```

### Rootfs Patches

Modify the filesystem before the VM boots:

```go
sb, err := microsandbox.NewSandbox(ctx, "patched",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithPatches(
        microsandbox.PatchText("/etc/greeting.txt", "Hello!\n", nil, false),
        microsandbox.PatchMkdir("/app", nil),
        microsandbox.PatchText("/app/config.json", `{"debug":true}`, nil, false),
        microsandbox.PatchCopyDir("./scripts", "/app/scripts", false),
        microsandbox.PatchAppend("/etc/hosts", "127.0.0.1 myapp.local\n"),
    ),
)
```

### Detached Mode

Sandboxes in detached mode survive the Go process:

```go
// Create and detach.
sb, err := microsandbox.NewSandbox(ctx, "background",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithDetached(),
)
if err != nil {
    log.Fatal(err)
}
sb.Detach() // release local handle; sandbox keeps running

// Later, from another process:
handle, err := microsandbox.GetSandbox(ctx, "background")
if err != nil {
    log.Fatal(err)
}
out, err := handle.Shell(ctx, "echo reconnected")
```

### TLS Interception

```go
sb, err := microsandbox.NewSandbox(ctx, "tls-inspect",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithNetwork(&microsandbox.NetworkOptions{
        TLS: &microsandbox.TLSOptions{
            Bypass:           []string{"*.googleapis.com"},
            InterceptedPorts: []uint16{443},
        },
    }),
)
```

### Metrics

```go
// Per-sandbox metrics.
m, err := sb.Metrics(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("CPU: %.1f%%\n", m.CPUPercent)
fmt.Printf("Memory: %.1f MiB\n", float64(m.MemoryBytes)/1024/1024)
fmt.Printf("Uptime: %s\n", m.Uptime)

// All sandboxes at once.
all, err := microsandbox.AllSandboxMetrics(ctx)
for name, metrics := range all {
    fmt.Printf("%s: %.1f%%\n", name, metrics.CPUPercent)
}
```

### Sandbox Listing

```go
sandboxes, err := microsandbox.ListSandboxes(ctx)
for _, info := range sandboxes {
    fmt.Printf("%s: %s\n", info.Name, info.Status)
}
```

## API Reference

### Top-level Functions

| Function | Description |
|----------|-------------|
| `EnsureInstalled(ctx)` | Download runtime dependencies to `~/.microsandbox/` (idempotent) |
| `NewSandbox(ctx, name, ...opts)` | Create and start a sandbox |
| `GetSandbox(ctx, name)` | Reattach to a detached or already-running sandbox |
| `RemoveSandbox(ctx, name)` | Remove a stopped sandbox by name |
| `ListSandboxes(ctx)` | List all known sandboxes |
| `NewVolume(ctx, name, ...opts)` | Create a named persistent volume |
| `RemoveVolume(ctx, name)` | Remove a named volume |
| `ListVolumes(ctx)` | List all named volumes |
| `AllSandboxMetrics(ctx)` | Get metrics for all running sandboxes |
| `IsKind(err, kind)` | Test an error's `ErrorKind` |

### Types

| Type | Description |
|------|-------------|
| `Sandbox` | Live handle to a running sandbox — lifecycle, execution, filesystem |
| `ExecOutput` | Captured stdout/stderr with exit status; inspect via `Stdout()`, `Stderr()`, `ExitCode()`, `Success()` |
| `ExecHandle` | Streaming execution handle — call `Recv(ctx)` for events, `Signal(ctx, sig)` to send a signal |
| `ExecEvent` | Stream event with `Kind`, `PID`, `Data`, `ExitCode` fields |
| `SandboxFs` | Guest filesystem operations — obtain via `sandbox.FS()` |
| `Volume` | Named persistent volume |
| `SandboxInfo` | Sandbox listing info (name, status, timestamps) |
| `SandboxMetrics` | Resource metrics (CPU %, memory bytes, disk I/O, network I/O, uptime) |

### Sandbox Methods

| Method | Description |
|--------|-------------|
| `Exec(ctx, cmd, args, ...opts)` | Run a command; non-zero exit is not a Go error |
| `Shell(ctx, cmd, ...opts)` | Run a shell command via `/bin/sh -c` |
| `ExecStream(ctx, cmd, args)` | Streaming exec; returns `*ExecHandle` |
| `ShellStream(ctx, cmd)` | Streaming shell; returns `*ExecHandle` |
| `FS()` | Return a `*SandboxFs` for guest filesystem access |
| `Metrics(ctx)` | Return current resource metrics |
| `StopAndWait(ctx)` | Stop the sandbox and wait for it to exit |
| `Detach()` | Release the local handle; sandbox keeps running |
| `Close()` | Release local resources (does not stop the VM) |

### Functional Options

| Option | Description |
|--------|-------------|
| `WithImage(image)` | OCI image to run (e.g. `"python:3.12"`) |
| `WithMemory(mib)` | Memory limit in MiB |
| `WithCPUs(n)` | CPU core limit |
| `WithWorkdir(path)` | Default working directory inside the sandbox |
| `WithEnv(map)` | Environment variables (merged across repeated calls) |
| `WithDetached()` | Sandbox outlives the Go process |
| `WithPorts(map)` | Publish host→guest TCP ports |
| `WithNetwork(opts)` | Network policy, DNS filtering, TLS interception |
| `WithSecrets(secrets...)` | Credential placeholders substituted at the network layer |
| `WithPatches(patches...)` | Pre-boot rootfs modifications |
| `WithVolumeQuota(mib)` | Volume quota in MiB (zero = unlimited) |
| `WithExecCwd(path)` | Working directory for a single `Exec`/`Shell` call |
| `WithExecTimeout(d)` | Per-command timeout; returns `ErrExecTimeout` on breach |

### Error Kinds

| Constant | Meaning |
|----------|---------|
| `ErrSandboxNotFound` | No sandbox with that name |
| `ErrSandboxAlreadyExists` | Sandbox name already in use |
| `ErrVolumeNotFound` | No volume with that name |
| `ErrVolumeAlreadyExists` | Volume name already in use |
| `ErrExecTimeout` | Command exceeded `WithExecTimeout` |
| `ErrLibraryNotLoaded` | `EnsureInstalled` was not called before using the SDK |

Use `microsandbox.IsKind(err, microsandbox.ErrSandboxNotFound)` to test.

## Development

To use a locally-built FFI library instead of downloading a release:

```bash
# Build the FFI crate from the repo root.
cargo build -p microsandbox-go-ffi

# Point the SDK at it.
export MICROSANDBOX_LIB_PATH=$PWD/target/debug/libmicrosandbox_go_ffi.dylib  # macOS
export MICROSANDBOX_LIB_PATH=$PWD/target/debug/libmicrosandbox_go_ffi.so     # Linux

go run ./examples/basic
```

Run the unit tests:

```bash
go test ./...
```

Run the integration tests (requires a built FFI library and a live microsandbox runtime):

```bash
go test -tags=integration ./...
```

<small>Release version pins, download URLs, and on-disk runtime layout are kept consistent across the Go, Node, and Python SDKs in this repository.</small>

## License

Apache-2.0
