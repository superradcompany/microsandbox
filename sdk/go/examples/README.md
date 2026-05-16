# Go Examples

Run from `sdk/go`:

```sh
go run ./examples/basic
```

## Examples

| Example | Description |
|---------|-------------|
| `basic` | Create a sandbox, run commands, use filesystem and metrics |
| `detached` | Detached lifecycle, reattach, stop, and remove |
| `disk` | Build and mount a raw ext4 disk image |
| `errors` | Typed error handling with `IsKind` and `errors.As` |
| `filesystem` | Filesystem read/write/list/stat/copy/streaming operations |
| `image-cache` | List, get, inspect, and garbage-collect cached OCI images |
| `metrics` | Point-in-time and streaming metrics |
| `network` | Presets, DNS, TLS, and custom network settings |
| `patches` | Pre-boot rootfs patches |
| `ports` | Publish guest TCP ports on host ports |
| `secrets` | Secret placeholder injection |
| `snapshot-fork` | Create a stopped-sandbox snapshot and boot a fork from it |
| `streaming` | Streaming exec, signals, and cancellation |
| `tls` | TLS interception configuration |
| `volumes` | Named volume lifecycle |
