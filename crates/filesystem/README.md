# microsandbox-filesystem

Filesystem backends for [microsandbox](https://github.com/zerocore-ai/microsandbox) virtual machines. This crate provides four pluggable backends that give each sandbox a complete, Linux-compatible filesystem — from bind-mounting a host directory to stacking OCI image layers with copy-on-write.

- **No root required** — runs unprivileged; guest-visible ownership and permissions are virtualized without touching the host filesystem
- **Runs on macOS too** — the guest sees a full Linux filesystem even when the host is macOS
- **Zero-copy I/O** — file reads and writes flow directly between host and guest with no intermediate allocation
- **Real OCI layer semantics** — OverlayFs handles whiteouts, opaque directories, and atomic copy-up correctly
- **Composable** — all four backends implement `DynFileSystem` and can be nested freely

## Backends

### PassthroughFs

Exposes a single host directory to the guest VM. The guest sees standard Linux ownership, permissions, and file types even when the host runs macOS.

```rust
let fs = PassthroughFs::builder()
    .root_dir("/path/to/host/dir")
    .build()?;
```

Metadata like uid, gid, and mode are stored in an extended attribute on the host, so the actual host file permissions stay untouched. Special files (devices, sockets, FIFOs) are stored as regular files with their type bits in the xattr. Path confinement prevents the guest from escaping the root directory.

### OverlayFs

Stacks N read-only layers with one writable upper layer — like Linux kernel overlayfs, but in userspace. This is how OCI container images work.

```rust
let fs = OverlayFs::builder()
    .layer("/layer0")       // bottom layer (e.g. base OS)
    .layer("/layer1")       // stacked on top (e.g. pip install)
    .writable("/upper")     // sandbox-local writable layer
    .staging("/staging")    // must be on same filesystem as upper
    .build()?;
```

When the guest modifies a file from a lower layer, it's copied to the upper layer first (copy-on-write). Deleting a lower-layer file creates a whiteout marker so it appears gone. The lower layers are never modified.

### MemFs

A pure in-memory filesystem — no host I/O at all. Good for scratch space and ephemeral workloads.

```rust
use microsandbox_filesystem::SizeExt;

let fs = MemFs::builder()
    .capacity(64.mib())
    .max_inodes(10_000)
    .build()?;
```

### DualFs

Combines two backends under a single mount point with a dispatch policy that routes each operation to the right backend.

```rust
let fs = DualFs::builder()
    .backend_a(overlay_fs)
    .backend_b(passthrough_fs)
    .policy(ReadBackendBWriteBackendA)
    .build()?;
```

Built-in policies:

| Policy | Behavior |
|---|---|
| `ReadBackendBWriteBackendA` | Reads from B, writes to A (default) |
| `BackendAOnly` | Everything goes to A |
| `BackendAFallbackToBackendBRead` | Reads try A first, fall back to B |
| `MergeReadsBackendAPrecedence` | Merge directory listings, A wins on conflicts |

When a write targets a file that lives on the other backend, DualFs copies it over automatically.

## Composability

Backends can be nested freely since they all implement `DynFileSystem`. For example, a `DualFs` can combine an `OverlayFs` with a `MemFs`:

```rust
let overlay = OverlayFs::builder()
    .layer("/layer0")
    .layer("/layer1")
    .writable("/upper")
    .staging("/staging")
    .build()?;

let mem = MemFs::builder()
    .capacity(64.mib())
    .build()?;

let dual = DualFs::builder()
    .backend_a(overlay)
    .backend_b(mem)
    .policy(ReadBackendBWriteBackendA)
    .build()?;
```

## Cache Policies

All backends support configurable kernel caching:

| Policy | Behavior |
|---|---|
| `Never` | No caching — every read hits the backend (DIRECT_IO) |
| `Auto` | Kernel decides (default for PassthroughFs, OverlayFs, DualFs) |
| `Always` | Aggressive caching (default for MemFs, since memory is authoritative) |

```rust
let fs = PassthroughFs::builder()
    .root_dir("/path/to/dir")
    .cache_policy(CachePolicy::Always)
    .build()?;
```
