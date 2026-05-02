# Rust Examples

## Prerequisites

- [Rust](https://rustup.rs/) (2024 edition)
- `msb` + `libkrunfw` installed (via `cargo build` with the `prebuilt` feature, or manually)
- For `root-bind` and `root-block`: `git submodule update --init --recursive`

## Running

Each example is a standalone binary crate in the workspace:

```sh
cargo run -p <example-name>
```

For example:

```sh
cargo run -p oci-root
cargo run -p net-basic
cargo run -p fs-read-stream
```

## Examples

| Example | Command | Description |
|---------|---------|-------------|
| `root-oci` | `cargo run -p root-oci` | OCI image rootfs |
| `root-bind` | `cargo run -p root-bind` | Bind-mounted local directory |
| `root-block` | `cargo run -p root-block` | qcow2 disk image |
| `rootfs-patch` | `cargo run -p rootfs-patch` | Pre-boot filesystem patches |
| `volume-named` | `cargo run -p volume-named` | Named volumes shared across sandboxes |
| `volume-disk` | `cargo run -p volume-disk` | Disk image volumes (raw / qcow2) at guest paths |
| `snapshot-fork` | `cargo run -p snapshot-fork` | Snapshot a stopped sandbox and boot a fresh one from it |
| `fs-read-stream` | `cargo run -p fs-read-stream` | Streaming file read |
| `metrics-stream` | `cargo run -p metrics-stream` | Streaming resource metrics |
| `shell-attach` | `cargo run -p shell-attach` | Interactive shell attach |
| `net-basic` | `cargo run -p net-basic` | Basic networking |
| `net-dns` | `cargo run -p net-dns` | DNS filtering |
| `net-policy` | `cargo run -p net-policy` | Network policies |
| `net-ports` | `cargo run -p net-ports` | Port publishing |
| `net-secrets` | `cargo run -p net-secrets` | Secret injection |
| `net-tls` | `cargo run -p net-tls` | TLS interception |
