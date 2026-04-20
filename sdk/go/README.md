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

    sb, err := microsandbox.CreateSandbox(ctx, "my-sandbox",
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
    fmt.Printf("%s (%s)\n", e.Path, e.Kind) // Kind: "file"|"directory"|"symlink"|"other"
}

// File metadata.
stat, err := fs.Stat(ctx, "/tmp/config.json")
fmt.Printf("size=%d isDir=%v\n", stat.Size, stat.IsDir)

// Copy between host and guest.
err = fs.CopyFromHost(ctx, "./local-file.txt", "/tmp/file.txt")
err = fs.CopyToHost(ctx, "/tmp/output.txt", "./output.txt")

// Directory and file manipulation inside the guest.
err = fs.Mkdir(ctx, "/app/data")          // creates parents as needed
err = fs.Copy(ctx, "/etc/hosts", "/tmp/hosts.bak")
err = fs.Rename(ctx, "/tmp/a.txt", "/tmp/b.txt")
ok, err := fs.Exists(ctx, "/tmp/b.txt")
err = fs.Remove(ctx, "/tmp/b.txt")        // single file
err = fs.RemoveDir(ctx, "/app/data")      // recursive
```

### Named Volumes

```go
// Create a 100 MiB named volume.
vol, err := microsandbox.CreateVolume(ctx, "my-data",
    microsandbox.WithVolumeQuota(100),
)
if err != nil {
    log.Fatal(err)
}
defer microsandbox.RemoveVolume(ctx, "my-data")

// Mount volumes into a sandbox.
sb, err := microsandbox.CreateSandbox(ctx, "worker",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithMounts(map[string]microsandbox.MountConfig{
        "/data":    microsandbox.Mount.Named("my-data"),
        "/src":     microsandbox.MountConfig{Bind: "./src", Readonly: true},
        "/scratch": microsandbox.Mount.Tmpfs(),
    }),
)

// Look up volume metadata.
handle, err := microsandbox.GetVolume(ctx, "my-data")
fmt.Println(handle.Path())       // host filesystem path
fmt.Println(handle.UsedBytes())  // bytes in use

// Direct host-side file ops via VolumeFs (no agent protocol).
vfs := handle.FS()
err = vfs.WriteString("notes.txt", "hello")
content, err := vfs.ReadString("notes.txt")

// List all volumes.
vols, err := microsandbox.ListVolumes(ctx)

// ErrVolumeAlreadyExists on duplicate create.
_, err = microsandbox.CreateVolume(ctx, "my-data")
if microsandbox.IsKind(err, microsandbox.ErrVolumeAlreadyExists) {
    // handle
}

// Remove.
err = vol.Remove(ctx)
```

### Network Policies

```go
// Default: public internet only (blocks RFC-1918 private ranges).
sb, err := microsandbox.CreateSandbox(ctx, "public", microsandbox.WithImage("alpine:3.19"))

// Fully airgapped.
sb, err = microsandbox.CreateSandbox(ctx, "isolated",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(microsandbox.NetworkPolicy.None()),
)

// Unrestricted.
sb, err = microsandbox.CreateSandbox(ctx, "open",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(microsandbox.NetworkPolicy.AllowAll()),
)

// Custom rule set.
sb, err = microsandbox.CreateSandbox(ctx, "custom",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(&microsandbox.NetworkConfig{
        DefaultAction: "deny",
        Rules: []microsandbox.PolicyRule{
            {Action: "allow", Destination: "api.openai.com", Protocol: "tcp", Port: 443},
        },
    }),
)
```

### DNS Filtering

```go
sb, err := microsandbox.CreateSandbox(ctx, "filtered",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(&microsandbox.NetworkConfig{
        BlockDomains:        []string{"blocked.example.com"},
        BlockDomainSuffixes: []string{".ads"},
    }),
)
```

### Port Publishing

```go
// host:8080 → guest:80
sb, err := microsandbox.CreateSandbox(ctx, "web",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithPorts(map[uint16]uint16{8080: 80}),
)
```

### Secrets

Secrets use placeholder substitution — the real value never enters the VM. It is only swapped in at the network layer for HTTPS requests to allowed hosts.

```go
sb, err := microsandbox.CreateSandbox(ctx, "agent",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithSecrets(microsandbox.Secret.Env(
        "OPENAI_API_KEY",
        os.Getenv("OPENAI_API_KEY"),
        microsandbox.SecretEnvOptions{AllowHosts: []string{"api.openai.com"}},
    )),
)

// Guest sees: OPENAI_API_KEY=$MSB_OPENAI_API_KEY (a placeholder)
// HTTPS to api.openai.com: placeholder is transparently replaced with the real key
// HTTPS to any other host carrying the placeholder: request is blocked
```

### Rootfs Patches

Modify the filesystem before the VM boots:

```go
sb, err := microsandbox.CreateSandbox(ctx, "patched",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithPatches(
        microsandbox.Patch.Text("/etc/greeting.txt", "Hello!\n", microsandbox.PatchOptions{}),
        microsandbox.Patch.Mkdir("/app", microsandbox.PatchOptions{}),
        microsandbox.Patch.Text("/app/config.json", `{"debug":true}`, microsandbox.PatchOptions{}),
        microsandbox.Patch.CopyDir("./scripts", "/app/scripts", microsandbox.PatchOptions{}),
        microsandbox.Patch.Append("/etc/hosts", "127.0.0.1 myapp.local\n"),
    ),
)
```

### Detached Mode

Sandboxes in detached mode survive the Go process:

```go
// Create and detach.
sb, err := microsandbox.CreateSandbox(ctx, "background",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithDetached(),
)
if err != nil {
    log.Fatal(err)
}
sb.Detach(ctx) // release local handle; sandbox keeps running

// Later, from another process — get metadata then connect:
handle, err := microsandbox.GetSandbox(ctx, "background")
if err != nil {
    log.Fatal(err)
}
sb2, err := handle.Connect(ctx)
if err != nil {
    log.Fatal(err)
}
out, err := sb2.Shell(ctx, "echo reconnected")
```

### TLS Interception

```go
sb, err := microsandbox.CreateSandbox(ctx, "tls-inspect",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithNetwork(&microsandbox.NetworkConfig{
        TLS: &microsandbox.TlsConfig{
            Bypass:           []string{"*.googleapis.com"},
            InterceptedPorts: []uint16{443},
        },
    }),
)
```

### Metrics

```go
// Point-in-time snapshot.
m, err := sb.Metrics(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("CPU: %.1f%%\n", m.CPUPercent)
fmt.Printf("Memory: %.1f MiB\n", float64(m.MemoryBytes)/1024/1024)
fmt.Printf("Uptime: %s\n", m.Uptime)

// Streaming metrics — snapshot every 500ms.
stream, err := sb.MetricsStream(ctx, 500*time.Millisecond)
if err != nil {
    log.Fatal(err)
}
defer stream.Close()

for {
    m, err := stream.Recv(ctx)
    if err != nil || m == nil {
        break
    }
    fmt.Printf("CPU: %.1f%%  Mem: %d bytes\n", m.CPUPercent, m.MemoryBytes)
}

// All running sandboxes at once.
all, err := microsandbox.AllSandboxMetrics(ctx)
for name, m := range all {
    fmt.Printf("%s: %.1f%% CPU\n", name, m.CPUPercent)
}
```

### Exec — advanced

```go
// Per-command user and environment overrides.
out, err := sb.Exec(ctx, "whoami", nil,
    microsandbox.WithExecUser("nobody"),
    microsandbox.WithExecEnv(map[string]string{"DEBUG": "1"}),
)

// ExecHandle: collect or wait.
h, err := sb.ExecStream(ctx, "sleep", []string{"10"})
if err != nil {
    log.Fatal(err)
}

// Get the correlation ID assigned by the agent.
id, err := h.ID()
fmt.Println("exec id:", id)

// Collect all output after the process finishes.
out2, err := h.Collect(ctx)
fmt.Println(out2.Stdout())

// Or just wait for the exit code, discarding output.
code, err := h.Wait(ctx)

// Kill if needed.
err = h.Kill(ctx)
h.Close()
```

### Sandbox Listing

```go
names, err := microsandbox.ListSandboxes(ctx)
for _, name := range names {
    fmt.Println(name)
}
```

## API Reference

### Top-level Functions

| Function | Description |
|----------|-------------|
| `EnsureInstalled(ctx)` | Download runtime dependencies to `~/.microsandbox/` (idempotent) |
| `CreateSandbox(ctx, name, ...opts)` | Create and start a sandbox |
| `CreateSandboxDetached(ctx, name, ...opts)` | Create a sandbox in detached mode |
| `StartSandbox(ctx, name)` | Boot a stopped sandbox by name |
| `StartSandboxDetached(ctx, name)` | Boot a stopped sandbox in detached mode |
| `GetSandbox(ctx, name)` | Fetch sandbox metadata; returns `*SandboxHandle` |
| `ListSandboxes(ctx)` | List all known sandbox names |
| `RemoveSandbox(ctx, name)` | Remove a stopped sandbox by name |
| `AllSandboxMetrics(ctx)` | Point-in-time metrics for all running sandboxes |
| `CreateVolume(ctx, name, ...opts)` | Create a named persistent volume |
| `GetVolume(ctx, name)` | Fetch volume metadata; returns `*VolumeHandle` |
| `ListVolumes(ctx)` | List all named volumes |
| `RemoveVolume(ctx, name)` | Remove a named volume |
| `IsKind(err, kind)` | Test an error's `ErrorKind` |

### Types

| Type | Description |
|------|-------------|
| `Sandbox` | Live handle to a running sandbox — lifecycle, execution, filesystem |
| `SandboxHandle` | Lightweight metadata reference; obtain via `GetSandbox`. Methods: `Connect`, `Start`, `StartDetached`, `Stop`, `Kill`, `Remove` |
| `ExecOutput` | Captured stdout/stderr with exit status; inspect via `Stdout()`, `Stderr()`, `ExitCode()`, `Success()` |
| `ExecHandle` | Streaming exec handle — `Recv`, `Collect`, `Wait`, `Kill`, `Signal`, `ID`, `TakeStdin` |
| `ExecEvent` | Stream event with `Kind`, `PID`, `Data`, `ExitCode` fields |
| `SandboxFs` | Guest filesystem operations — obtain via `sandbox.FS()` |
| `FsReadStream` | Streaming file read from guest — implements `io.WriterTo` |
| `FsWriteStream` | Streaming file write to guest — implements `io.Writer` |
| `MetricsStreamHandle` | Live metrics subscription — `Recv(ctx)`, `Close()` |
| `Volume` | Named persistent volume — `Name()`, `Path()`, `FS()` |
| `VolumeHandle` | Volume metadata from DB — `Name()`, `Path()`, `QuotaMiB()`, `UsedBytes()`, `Labels()`, `CreatedAt()`, `FS()` |
| `VolumeFs` | Host-side file ops on a volume directory — no agent protocol |
| `Metrics` | Resource metrics (CPU %, memory bytes, disk I/O, network I/O, uptime) |
| `SandboxConfig` / `NetworkConfig` / `TlsConfig` / `ExecConfig` / `VolumeConfig` | Configuration structs |
| `SecretEntry`, `PolicyRule`, `PatchConfig`, `MountConfig` | Value types for secrets, network rules, rootfs patches, and volume mounts |
| `Patch`, `Secret`, `NetworkPolicy`, `Mount` | Factory namespaces (`Patch.Text`, `Secret.Env`, `NetworkPolicy.None`, `Mount.Named`, …) |

### Sandbox Methods

| Method | Description |
|--------|-------------|
| `Exec(ctx, cmd, args, ...opts)` | Run a command; non-zero exit is not a Go error |
| `Shell(ctx, cmd, ...opts)` | Run a shell command via `/bin/sh -c` |
| `ExecStream(ctx, cmd, args)` | Streaming exec; returns `*ExecHandle` |
| `ShellStream(ctx, cmd)` | Streaming shell; returns `*ExecHandle` |
| `FS()` | Return a `*SandboxFs` for guest filesystem access |
| `Metrics(ctx)` | Return current resource metrics |
| `MetricsStream(ctx, interval)` | Live metrics subscription; returns `*MetricsStreamHandle` |
| `Attach(ctx, cmd, args...)` | Interactive PTY session; blocks until exit |
| `AttachShell(ctx)` | Interactive PTY session in the default shell |
| `Drain(ctx)` | Send graceful drain signal (SIGUSR1) |
| `Wait(ctx)` | Block until sandbox exits; returns exit code |
| `OwnsLifecycle()` | Whether this handle controls the VM process |
| `RemovePersisted(ctx)` | Remove persisted state after the sandbox is stopped |
| `Stop(ctx)` | Gracefully stop the sandbox (does not wait for VM exit) |
| `StopAndWait(ctx)` | Stop the sandbox and wait for it to exit; returns the guest exit code |
| `Kill(ctx)` | Terminate the sandbox immediately |
| `Detach(ctx)` | Release the local handle; detached sandbox keeps running |
| `Close()` | Release the Rust-side handle; for detached sandboxes prefer `Detach` |

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
| `WithHostname(hostname)` | Guest hostname |
| `WithUser(user)` | User to run the sandbox process as (UID or name) |
| `WithReplace()` | Kill any existing sandbox with the same name before creating |
| `WithMounts(map)` | Volume mounts keyed by guest path — use `Mount.Named/Bind/Tmpfs` |
| `WithExecCwd(path)` | Working directory for a single `Exec`/`Shell` call |
| `WithExecTimeout(d)` | Per-command timeout; returns `ErrExecTimeout` on breach |
| `WithExecUser(user)` | User to run a single command as |
| `WithExecEnv(map)` | Per-command environment variables (merged across repeated calls) |

### Error Kinds

| Constant | Meaning |
|----------|---------|
| `ErrSandboxNotFound` | No sandbox with that name |
| `ErrSandboxStillRunning` | Cannot remove a running sandbox |
| `ErrVolumeNotFound` | No volume with that name |
| `ErrVolumeAlreadyExists` | Volume name already in use |
| `ErrExecTimeout` | Command exceeded `WithExecTimeout` |
| `ErrFilesystem` | Guest filesystem operation failed |
| `ErrImageNotFound` | OCI image reference did not resolve |
| `ErrImageInUse` | Image is still referenced by a sandbox |
| `ErrPatchFailed` | A rootfs patch could not be applied |
| `ErrIO` | Host-side I/O error |
| `ErrInvalidConfig` | Configuration rejected by the runtime |
| `ErrInvalidArgument` | Malformed argument across the FFI boundary |
| `ErrInvalidHandle` | Handle is stale, closed, or was never valid |
| `ErrBufferTooSmall` | Response exceeded the fixed output buffer (stream instead) |
| `ErrCancelled` | Operation cancelled via the caller's context |
| `ErrLibraryNotLoaded` | `EnsureInstalled` was not called before using the SDK |
| `ErrInternal` | Catch-all for unrecognised runtime errors |

Additional kinds declared for forward compatibility with the Node/Python SDKs — currently surface as `ErrInternal` / `ErrInvalidConfig` / `ErrFilesystem` / `ErrImageNotFound`: `ErrSandboxNotRunning`, `ErrSandboxAlreadyExists`, `ErrExecFailed`, `ErrPathNotFound`, `ErrImagePullFailed`, `ErrNetworkPolicy`, `ErrSecretViolation`, `ErrTLS`.

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
