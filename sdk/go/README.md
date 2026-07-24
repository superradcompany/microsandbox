# microsandbox

Lightweight VM sandboxes for Go applications that need hardware-level isolation for AI agents, tools, tests, and untrusted code.

The `github.com/superradcompany/microsandbox/sdk/go` module provides Go bindings to the [microsandbox](https://github.com/superradcompany/microsandbox) runtime. It creates microVM-backed sandboxes from OCI images or other rootfs sources, then exposes command execution, guest filesystem access, networking, secrets, volumes, metrics, logs, snapshots, and SSH/SFTP through an idiomatic Go API.

For the full API reference and longer guides, use Go docs and the microsandbox docs site:

- [pkg.go.dev](https://pkg.go.dev/github.com/superradcompany/microsandbox/sdk/go)
- [Go SDK guide](https://docs.microsandbox.dev/sdk/go/sandbox)
- [SDK overview](https://docs.microsandbox.dev/sdk/overview)
- [Repository examples](./examples)

## Features

- Hardware VM isolation with a guest Linux kernel
- Go API over an embedded CGO FFI library
- Collected and streaming command execution
- Guest filesystem read, write, list, copy, stat, and stream operations
- Named volumes, bind mounts, tmpfs mounts, and disk-image mounts
- Network policies, DNS filtering, TLS interception, secrets, and port publishing
- Rootfs patches before boot
- Detached sandboxes that can outlive the Go process
- Metrics, logs, snapshots, SSH/SFTP, image cache, and local/cloud backend helpers

## Requirements

- Go 1.22+
- CGO enabled and a C compiler/toolchain available
- Linux with KVM, macOS with Apple Silicon, or Windows 10/11 with Windows Hypervisor Platform enabled

## Supported Platforms

| Platform | Architecture | Notes |
| --- | --- | --- |
| macOS | ARM64 / Apple Silicon | Embedded FFI library |
| Linux | x86_64 | Embedded FFI library |
| Linux | ARM64 | Embedded FFI library |
| Windows | x86_64, ARM64 | Embedded FFI library; runtime support is in preview |

The Go binary embeds the SDK FFI library and extracts it on first use. The `msb` runtime and `libkrunfw` are installed separately into `~/.microsandbox/` by `EnsureInstalled` (`%USERPROFILE%\.microsandbox` on Windows).

## Installation

```bash
go get github.com/superradcompany/microsandbox/sdk/go
```

Call `EnsureInstalled` at process startup when your program will create local sandboxes. It is idempotent and surfaces runtime download/setup failures before the first sandbox operation.

```go
if err := microsandbox.EnsureInstalled(ctx); err != nil {
    log.Fatalf("microsandbox setup: %v", err)
}
```

Use `IsInstalled` if you only need to check whether `msb` and `libkrunfw` are already present at the SDK install location.

## Quick Start

```go
package main

import (
    "context"
    "fmt"
    "log"
    "time"

    microsandbox "github.com/superradcompany/microsandbox/sdk/go"
)

func main() {
    ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
    defer cancel()

    if err := microsandbox.EnsureInstalled(ctx); err != nil {
        log.Fatal(err)
    }

    name := "go-readme"
    sb, err := microsandbox.CreateSandbox(ctx, name,
        microsandbox.WithImage("alpine:3.19"),
        microsandbox.WithMemory(512),
        microsandbox.WithCPUs(1),
        microsandbox.WithReplace(),
    )
    if err != nil {
        log.Fatal(err)
    }
    defer func() {
        stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
        defer stopCancel()
        _ = sb.Stop(stopCtx)
        _ = sb.Close()
        _ = microsandbox.RemoveSandbox(context.Background(), name)
    }()

    out, err := sb.Shell(ctx, "echo 'Hello from microsandbox!'")
    if err != nil {
        log.Fatal(err)
    }
    fmt.Println(out.Stdout())
}
```

## Common Examples

These snippets assume you already have a live `sb *microsandbox.Sandbox` and `ctx context.Context`. See [sdk/go/examples](./examples) for complete runnable programs.

### Command Execution

```go
out, err := sb.Exec(ctx, "python3", []string{"-c", "print(1 + 1)"})
if err != nil {
    log.Fatal(err)
}
fmt.Println(out.Stdout())
fmt.Println(out.ExitCode())

out, err = sb.Shell(ctx, "echo hello && pwd")

out, err = sb.Exec(ctx, "make", []string{"build"},
    microsandbox.WithExecCwd("/app"),
    microsandbox.WithExecTimeout(30*time.Second),
)
```

Non-zero process exits are represented on `ExecOutput`; they are not Go errors by themselves.

### Streaming Execution

```go
handle, err := sb.ShellStream(ctx, "tail -f /var/log/app.log")
if err != nil {
    log.Fatal(err)
}
defer handle.Close()

for {
    event, err := handle.Recv(ctx)
    if err != nil {
        break
    }
    switch event.Kind {
    case microsandbox.ExecEventStdout:
        _, _ = os.Stdout.Write(event.Data)
    case microsandbox.ExecEventStderr:
        _, _ = os.Stderr.Write(event.Data)
    case microsandbox.ExecEventExited, microsandbox.ExecEventDone:
        return
    }
}
```

### Filesystem Operations

```go
fs := sb.FS()

if err := fs.WriteString(ctx, "/tmp/config.json", `{"debug": true}`); err != nil {
    log.Fatal(err)
}

content, err := fs.ReadString(ctx, "/tmp/config.json")
if err != nil {
    log.Fatal(err)
}
fmt.Println(content)

entries, err := fs.List(ctx, "/etc")
if err != nil {
    log.Fatal(err)
}
for _, entry := range entries {
    fmt.Printf("%s (%s)\n", entry.Path, entry.Kind)
}
```

### Named Volumes

```go
volume, err := microsandbox.CreateVolume(ctx, "go-readme-data",
    microsandbox.WithVolumeQuota(100),
    microsandbox.WithVolumeLabels(map[string]string{"purpose": "readme"}),
)
if err != nil {
    log.Fatal(err)
}
defer volume.Remove(ctx)

writer, err := microsandbox.CreateSandbox(ctx, "go-readme-writer",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithMounts(map[string]microsandbox.MountConfig{
        "/data": microsandbox.Mount.Named("go-readme-data", microsandbox.MountOptions{}),
    }),
    microsandbox.WithReplace(),
)
if err != nil {
    log.Fatal(err)
}
defer writer.Close()

_, err = writer.Shell(ctx, "echo 'hello' > /data/message.txt")
```

### Network, DNS, and Ports

```go
isolated, err := microsandbox.CreateSandbox(ctx, "go-readme-isolated",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(microsandbox.NetworkPolicy.None()),
    microsandbox.WithReplace(),
)
if err != nil {
    log.Fatal(err)
}
defer isolated.Close()

filtered, err := microsandbox.CreateSandbox(ctx, "go-readme-filtered",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithNetwork(&microsandbox.NetworkConfig{
        DenyDomains:        []string{"blocked.example.com"},
        DenyDomainSuffixes: []string{".evil.com"},
        DNS: &microsandbox.DNSConfig{
            Nameservers: []string{"1.1.1.1:53"},
        },
    }),
    microsandbox.WithReplace(),
)
if err != nil {
    log.Fatal(err)
}
defer filtered.Close()

web, err := microsandbox.CreateSandbox(ctx, "go-readme-web",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithPorts(map[uint16]uint16{8080: 80}),
    microsandbox.WithReplace(),
)
```

### Secrets

Secrets use placeholder substitution. The real value stays on the host and is substituted only for allowed network destinations.

```go
sb, err := microsandbox.CreateSandbox(ctx, "go-readme-agent",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithSecrets(microsandbox.Secret.Env(
        "OPENAI_API_KEY",
        os.Getenv("OPENAI_API_KEY"),
        microsandbox.SecretEnvOptions{AllowHosts: []string{"api.openai.com"}},
    )),
    microsandbox.WithReplace(),
)
```

### Rootfs Patches

```go
sb, err := microsandbox.CreateSandbox(ctx, "go-readme-patched",
    microsandbox.WithImage("alpine:3.19"),
    microsandbox.WithPatches(
        microsandbox.Patch.Text("/etc/greeting.txt", "Hello!\n", microsandbox.PatchOptions{}),
        microsandbox.Patch.Mkdir("/app", microsandbox.PatchOptions{}),
        microsandbox.Patch.Text("/app/config.json", `{"debug": true}`, microsandbox.PatchOptions{}),
        microsandbox.Patch.Append("/etc/hosts", "127.0.0.1 myapp.local\n"),
    ),
    microsandbox.WithReplace(),
)
```

### Detached Mode

```go
sb, err := microsandbox.CreateSandbox(ctx, "go-readme-background",
    microsandbox.WithImage("python:3.12"),
    microsandbox.WithDetached(),
    microsandbox.WithReplace(),
)
if err != nil {
    log.Fatal(err)
}
_ = sb.Detach(ctx)

handle, err := microsandbox.GetSandbox(ctx, "go-readme-background")
if err != nil {
    log.Fatal(err)
}
reconnected, err := handle.Connect(ctx)
if err != nil {
    log.Fatal(err)
}
out, err := reconnected.Shell(ctx, "echo reconnected")
```

### Metrics

```go
metrics, err := sb.Metrics(ctx)
if err != nil {
    log.Fatal(err)
}
fmt.Printf("CPU: %.1f%%\n", metrics.CPUPercent)
fmt.Printf("Memory: %.1f MiB\n", float64(metrics.MemoryBytes)/1024/1024)

stream, err := sb.MetricsStream(ctx, 500*time.Millisecond)
if err != nil {
    log.Fatal(err)
}
defer stream.Close()

sample, err := stream.Recv(ctx)
if err == nil && sample != nil {
    fmt.Printf("CPU: %.1f%%\n", sample.CPUPercent)
}
```

### Typed Errors

Go SDK errors can be checked with `IsKind` and unwrapped with `errors.As`.

```go
_, err := microsandbox.GetSandbox(ctx, "missing")
if microsandbox.IsKind(err, microsandbox.ErrSandboxNotFound) {
    fmt.Println("sandbox does not exist")
}

var msbErr *microsandbox.Error
if errors.As(err, &msbErr) {
    fmt.Printf("microsandbox error kind: %s\n", msbErr.Kind)
}
```

## Runnable Examples

Each example is a self-contained `main.go` under [sdk/go/examples](./examples). Run them from `sdk/go`:

```bash
go run ./examples/basic
go run ./examples/network
go run ./examples/snapshot-fork
```

| Example | Covers |
| --- | --- |
| `basic` | Create, exec, filesystem, metrics, stop, close, remove |
| `cloud-backend` | Cloud backend lifecycle and live logs |
| `detached` | Detached lifecycle, reattach, stop, and remove |
| `disk` | Build and mount a raw ext4 disk image |
| `errors` | Error categories with `IsKind` and `errors.As` |
| `filesystem` | Guest filesystem operations and streaming |
| `image-cache` | Cached OCI image list, inspect, remove, and prune |
| `metrics` | Point-in-time and streaming metrics |
| `network` | Presets, DNS, TLS, and custom network settings |
| `patches` | Pre-boot rootfs patches |
| `ports` | Guest TCP port publishing |
| `secrets` | Secret placeholder injection |
| `snapshot-fork` | Snapshot a stopped sandbox and boot a fork |
| `streaming` | Streaming exec, signals, and cancellation |
| `tls` | TLS interception configuration |
| `volumes` | Named volume lifecycle |

## More Documentation

- [Sandbox lifecycle](https://docs.microsandbox.dev/sdk/go/sandbox)
- [Execution](https://docs.microsandbox.dev/sdk/go/execution)
- [Filesystem](https://docs.microsandbox.dev/sdk/go/filesystem)
- [Networking](https://docs.microsandbox.dev/sdk/go/networking)
- [Secrets](https://docs.microsandbox.dev/sdk/go/secrets)
- [Volumes](https://docs.microsandbox.dev/sdk/go/volumes)
- [Snapshots](https://docs.microsandbox.dev/sdk/go/snapshots)
- [Images](https://docs.microsandbox.dev/sdk/go/images)
- [SSH](https://docs.microsandbox.dev/sdk/go/ssh)
- [Agent client](https://docs.microsandbox.dev/sdk/go/agent-client)

## Development

The SDK embeds the FFI library at build time, so normal unit tests do not require a Rust toolchain:

```bash
cd sdk/go
go test -count=1 ./...
```

To iterate on the FFI shim itself, build the native library from the repository root, then run Go commands from `sdk/go` with `MICROSANDBOX_FFI_PATH` and the `microsandbox_ffi_path` build tag:

```bash
cargo build -p microsandbox-go

cd sdk/go
export MICROSANDBOX_FFI_PATH=../../target/debug/libmicrosandbox_go_ffi.dylib
go run -tags microsandbox_ffi_path ./examples/basic
```

Use `libmicrosandbox_go_ffi.so` for Linux. Full integration tests require local virtualization support and runtime artifacts:

```bash
go test -tags "smoke microsandbox_ffi_path" -count=1 .
go test -tags "integration microsandbox_ffi_path" -v -count=1 ./integration/...
```

## License

Apache-2.0
