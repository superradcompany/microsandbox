# Python Examples

## Prerequisites

- Python 3.10+
- [uv](https://docs.astral.sh/uv/) and [maturin](https://www.maturin.rs/) (`uv tool install maturin`)
- `msb` + `libkrunfw` installed (bundled in the wheel, or at `~/.microsandbox/`)
- For `root-bind` and `root-block`: `git submodule update --init --recursive`

## Setup

Build the Python SDK (one-time):

```sh
cd sdk/python
uv sync --group dev
maturin develop --release
```

## Running

From the repo root:

```sh
uv run --project sdk/python python examples/python/<example>/main.py
```

For example:

```sh
uv run --project sdk/python python examples/python/root-oci/main.py
uv run --project sdk/python python examples/python/net-basic/main.py
uv run --project sdk/python python examples/python/fs-read-stream/main.py
```

## Examples

| Example | Description |
|---------|-------------|
| `root-oci` | OCI image rootfs |
| `root-bind` | Bind-mounted local directory |
| `root-block` | qcow2 disk image |
| `rootfs-patch` | Pre-boot filesystem patches |
| `init-handoff` | Hand PID 1 off to systemd |
| `volume-named` | Named volumes shared across sandboxes |
| `volume-disk` | Disk image volumes (raw / qcow2) at guest paths |
| `fs-read-stream` | Streaming file read |
| `metrics-stream` | Streaming resource metrics |
| `shell-attach` | Interactive shell attach |
| `net-basic` | Basic networking |
| `net-dns` | DNS filtering |
| `net-policy` | Network policies |
| `net-ports` | Port publishing |
| `net-secrets` | Secret injection |
| `net-tls` | TLS interception |
