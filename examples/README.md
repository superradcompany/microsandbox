# Examples

Examples showing how to use the microsandbox SDK in Rust, Python, and TypeScript.

Each language directory has its own README with setup and run instructions.

| Language | Directory | README |
|----------|-----------|--------|
| Rust | [`rust/`](./rust/) | [rust/README.md](./rust/README.md) |
| Python | [`python/`](./python/) | [python/README.md](./python/README.md) |
| TypeScript | [`typescript/`](./typescript/) | [typescript/README.md](./typescript/README.md) |

## Prerequisites

Some examples use git submodules for sample Alpine rootfs assets:

```sh
git submodule update --init --recursive
```

## Examples

| Example | Description |
|---------|-------------|
| `root-oci` | Create a sandbox from an OCI image (e.g. `alpine`) |
| `root-bind` | Create a sandbox from a local bind-mounted directory |
| `root-block` | Create a sandbox from a qcow2 disk image |
| `rootfs-patch` | Pre-boot filesystem modifications (files, dirs, appends) |
| `volume-named` | Persistent named volume shared between sandboxes |
| `fs-read-stream` | Stream a large file from the sandbox in chunks |
| `metrics-stream` | Subscribe to streaming resource metrics |
| `shell-attach` | Interactive terminal session inside a sandbox |
| `net-basic` | DNS resolution, HTTP fetch, interface status |
| `net-dns` | DNS filtering — block domains and suffixes |
| `net-policy` | Network policies — public-only, allow-all, no-network |
| `net-ports` | Port publishing — expose guest services on host ports |
| `net-secrets` | Secret injection with TLS placeholder substitution |
| `net-tls` | TLS interception with per-domain cert generation |
