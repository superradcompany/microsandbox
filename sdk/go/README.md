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

- **Go** >= 1.22
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

The SDK works out of the box — the FFI library is embedded in the Go binary and loads on first use. The first sandbox call also downloads `msb` + `libkrunfw` to `~/.microsandbox/` if they aren't already there.

For long-lived processes, you can call `EnsureInstalled` explicitly at startup to surface any install errors up front instead of at first sandbox-spawn time. It's optional and idempotent:

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
// Create a 100 MiB named volume with labels.
vol, err := microsandbox.CreateVolume(ctx, "my-data",
    microsandbox.WithVolumeQuota(100),
    microsandbox.WithVolumeLabels(map[string]string{"team": "agents"}),
)
if err != nil {
    log.Fatal(err)
}
defer microsandbox.RemoveVolume(ctx, "my-data")

// Mount volumes into a sandbox. Mount factories take an option struct so
// readonly / size / disk format can be passed at the call site.
sb, err := microsandbox.CreateSandbox(ctx, "worker",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithMounts(map[string]microsandbox.MountConfig{
        "/data":    microsandbox.Mount.Named("my-data", microsandbox.MountOptions{}),
        "/src":     microsandbox.Mount.Bind("./src", microsandbox.MountOptions{Readonly: true}),
        "/scratch": microsandbox.Mount.Tmpfs(microsandbox.TmpfsOptions{SizeMiB: 256}),
        "/blob":    microsandbox.Mount.Disk("./pool.img", microsandbox.DiskOptions{Format: "raw"}),
    }),
)

// Look up volume metadata.
handle, err := microsandbox.GetVolume(ctx, "my-data")
fmt.Println(handle.Path())       // host filesystem path
fmt.Println(handle.UsedBytes())  // bytes in use
fmt.Println(handle.Labels())     // map[string]string

// Direct host-side file ops via VolumeFs (no agent protocol). Paths that
// would escape the volume root via "../" or absolute components return
// ErrPathEscape.
vfs := handle.FS()
err = vfs.WriteString("notes.txt", "hello")
content, err := vfs.ReadString("notes.txt")

// List all volumes — returns rich VolumeHandle metadata.
vols, err := microsandbox.ListVolumes(ctx)
for _, v := range vols {
    fmt.Println(v.Name(), v.Path(), v.QuotaMiB())
}

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

// Allow public + private/LAN, deny loopback/link-local/metadata.
sb, err = microsandbox.CreateSandbox(ctx, "lan",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(microsandbox.NetworkPolicy.NonLocal()),
)

// Custom rule set with port ranges and asymmetric defaults.
sb, err = microsandbox.CreateSandbox(ctx, "custom",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(&microsandbox.NetworkConfig{
        DefaultEgress:  microsandbox.PolicyActionDeny,
        DefaultIngress: microsandbox.PolicyActionAllow,
        Rules: []microsandbox.PolicyRule{
            {
                Action:      microsandbox.PolicyActionAllow,
                Direction:   microsandbox.PolicyDirectionEgress,
                Destination: "api.openai.com",
                Protocol:    microsandbox.PolicyProtocolTCP,
                Port:        "443",
            },
            {
                Action:      microsandbox.PolicyActionAllow,
                Direction:   microsandbox.PolicyDirectionEgress,
                Destination: ".internal",
                Ports:       []string{"8000-9000"},
                Protocols:   []microsandbox.PolicyProtocol{microsandbox.PolicyProtocolTCP},
            },
        },
    }),
)
```

### DNS Filtering

```go
sb, err := microsandbox.CreateSandbox(ctx, "filtered",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(&microsandbox.NetworkConfig{
        DenyDomains:        []string{"blocked.example.com"},
        DenyDomainSuffixes: []string{".ads"},
        DNS: &microsandbox.DNSConfig{
            Nameservers: []string{"1.1.1.1:53"},
        },
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
// ListSandboxes returns rich SandboxHandle metadata, ordered newest first.
handles, err := microsandbox.ListSandboxes(ctx)
for _, h := range handles {
    fmt.Printf("%s [%s] created %s\n", h.Name(), h.Status(), h.CreatedAt())
}

// Reattach to a running sandbox by name.
h, err := microsandbox.GetSandbox(ctx, "worker")
sb, err := h.Connect(ctx)
```

## API Reference

### Top-level Functions

| Function | Description |
|----------|-------------|
| `EnsureInstalled(ctx, opts...)` | Optional — download msb + libkrunfw to `~/.microsandbox/` up front (idempotent) |
| `CreateSandbox(ctx, name, ...opts)` | Create and start a sandbox |
| `CreateSandboxDetached(ctx, name, ...opts)` | Create a sandbox in detached mode |
| `StartSandbox(ctx, name)` | Boot a stopped sandbox by name |
| `StartSandboxDetached(ctx, name)` | Boot a stopped sandbox in detached mode |
| `GetSandbox(ctx, name)` | Fetch sandbox metadata; returns `*SandboxHandle` |
| `ListSandboxes(ctx)` | Rich metadata for all known sandboxes (newest first) |
| `SDKVersion()` / `RuntimeVersion()` | SDK and loaded-runtime versions |
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
| `Patch`, `Secret`, `NetworkPolicy`, `Mount` | Helper namespaces — `Patch.Text`, `Secret.Env`, `NetworkPolicy.None`, `Mount.Named`, etc. |

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
| `Logs(ctx, opts)` | Read persisted sandbox logs |
| `Attach(ctx, cmd, args...)` | Interactive PTY session; blocks until exit |
| `AttachShell(ctx)` | Interactive PTY session in the default shell |
| `Drain(ctx)` | Send graceful drain signal (SIGUSR1) |
| `Wait(ctx)` | Block until sandbox exits; returns exit code |
| `OwnsLifecycle()` | Whether this handle controls the VM process; returns `(bool, error)` |
| `OwnsLifecycleOrFalse()` | Best-effort variant that swallows the error |
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
| `WithImageDisk(path, fstype)` | Disk-image rootfs with optional filesystem hint |
| `WithMemory(mib)` | Memory limit in MiB |
| `WithCPUs(n)` | CPU core limit |
| `WithWorkdir(path)` | Default working directory inside the sandbox |
| `WithEnv(map)` | Environment variables (merged across repeated calls) |
| `WithDetached()` | Sandbox outlives the Go process |
| `WithPorts(map)` | Publish host→guest TCP ports |
| `WithPortsUDP(map)` | Publish host→guest UDP ports |
| `WithNetwork(opts)` | Network policy, DNS filtering, TLS interception |
| `WithSecrets(secrets...)` | Credential placeholders substituted at the network layer |
| `WithPatches(patches...)` | Pre-boot rootfs modifications |
| `WithMounts(map)` | Volume mounts keyed by guest path — use `Mount.Bind/Named/Tmpfs/Disk` |
| `WithVolumeQuota(mib)` | Volume quota in MiB (zero = unlimited) |
| `WithVolumeLabels(map)` | Key-value labels for organising volumes |
| `WithHostname(hostname)` | Guest hostname |
| `WithUser(user)` | User to run the sandbox process as (UID or name) |
| `WithReplace()` | Kill any existing sandbox with the same name before creating |
| `WithShell(path)` | Default shell binary inside the guest |
| `WithEntrypoint(cmd...)` | Override the user-workload entrypoint |
| `WithInit(cfg)` | Hand off PID 1 (use `Init.Auto()` or `Init.Cmd(...)`) |
| `WithLogLevel(level)` / `WithQuietLogs()` | Sandbox-process logging |
| `WithScripts(map)` | Named scripts the agent can run by key |
| `WithPullPolicy(p)` | `PullPolicyAlways` / `PullPolicyIfMissing` / `PullPolicyNever` |
| `WithMaxDuration(d)` / `WithIdleTimeout(d)` | Lifecycle caps |
| `WithRegistryAuth(auth)` | Credentials for private OCI registries |
| `WithMounts(map)` | Volume mounts keyed by guest path — use `Mount.Named/Bind/Tmpfs` |
| `WithExecCwd(path)` | Working directory for a single `Exec`/`Shell` call |
| `WithExecTimeout(d)` | Per-command timeout; returns `ErrExecTimeout` on breach |
| `WithExecUser(user)` | User to run a single command as |
| `WithExecEnv(map)` | Per-command environment variables (merged across repeated calls) |

### Error Kinds

| Constant | Meaning |
|----------|---------|
| `ErrSandboxNotFound` | No sandbox with that name |
| `ErrSandboxAlreadyExists` | Name is taken; pass `WithReplace()` or drop the live handle first |
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
| `ErrLibraryNotLoaded` | FFI library failed to load (e.g. unsupported platform or GLIBC too old) |
| `ErrInternal` | Catch-all for unrecognised runtime errors |

Additional kinds declared for forward compatibility with the Node/Python SDKs — currently surface as `ErrInternal` / `ErrInvalidConfig` / `ErrFilesystem` / `ErrImageNotFound`: `ErrSandboxNotRunning`, `ErrExecFailed`, `ErrPathNotFound`, `ErrImagePullFailed`, `ErrNetworkPolicy`, `ErrSecretViolation`, `ErrTLS`.

Use `microsandbox.IsKind(err, microsandbox.ErrSandboxNotFound)` to test.

## Runnable Examples

Each example is a self-contained `main.go` under `sdk/go/examples/`. Run any of them with `go run ./examples/<name>`:

| Example | Covers |
|---------|--------|
| `basic` | end-to-end smoke: create, exec, read/write, metrics, stop, remove |
| `filesystem` | Read/Write/List/Stat/Copy/Rename/Remove/Mkdir, host↔guest copy, ReadStream/WriteStream/WriterTo |
| `network` | each policy preset (`None`, `PublicOnly`, `AllowAll`, `NonLocal`) and a custom rule list with port ranges and asymmetric egress/ingress defaults |
| `ports` | TCP port publishing — listener inside the guest, dial from the host |
| `secrets` | placeholder substitution at the network proxy; verifies the real value never enters the VM |
| `patches` | each rootfs patch kind (`Text`, `Append`, `Mkdir`, `Symlink`, `CopyFile`, `CopyDir`, `Remove`) applied before boot |
| `streaming` | streaming exec: events, signals, ctx cancellation |
| `volumes` | named volumes with quotas/labels, ListVolumes, duplicate-create error |
| `disk` | builds a tiny ext4 image at runtime, mounts it via `Mount.Disk`, then re-mounts read-only |
| `detached` | detached lifecycle: detach, list, reattach by name, run, stop |
| `tls` | TLS interception with a bypass list, intercepted-port set, and HTTP/3 fallback |
| `metrics` | point-in-time `Metrics()`, streaming `MetricsStream()`, `AllSandboxMetrics()` |
| `image-cache` | `Image.List` / `Get` / `Inspect` / `GCLayers` with full handle metadata, config, and layer listing |
| `errors` | typed-error categories via `IsKind`, `errors.As`, and `*microsandbox.Error` |

## Development

The SDK embeds the FFI library at build time, so a normal `go build` /
`go test` needs no Rust toolchain. To iterate on the FFI shim itself,
build the library locally and point the SDK at it via the
`microsandbox_ffi_path` build tag:

```bash
# Build the FFI crate from the repo root.
cargo build -p microsandbox-go

# Run against the freshly-built .so instead of the embed.
export MICROSANDBOX_FFI_PATH=$PWD/target/debug/libmicrosandbox_go_ffi.dylib  # macOS
export MICROSANDBOX_FFI_PATH=$PWD/target/debug/libmicrosandbox_go_ffi.so     # Linux

go run -tags microsandbox_ffi_path ./examples/basic
```

Run the unit tests (no FFI library required):

```bash
go test ./...
```

Run the full integration suite under `sdk/go/integration/` (requires a
built FFI library and a live microsandbox runtime):

```bash
go test -tags "integration microsandbox_ffi_path" -v -count=1 ./integration/...
```

The integration package is a black-box test suite organised by feature
(`config_test.go`, `network_test.go`, `volume_test.go`, `fs_test.go`,
`exec_test.go`, `metrics_test.go`, `lifecycle_test.go`, `sandbox_test.go`)
and is built only with the `integration` tag.

<small>Release version pins, download URLs, and on-disk runtime layout are kept consistent across the Go, Node, and Python SDKs in this repository.</small>

## License

Apache-2.0
