# microsandbox-filesystem

Filesystem backends for [microsandbox](https://github.com/zerocore-ai/microsandbox) virtual machines. This crate gives each sandbox a complete, Linux-compatible filesystem by combining five pluggable backends that all implement the same `DynFileSystem` trait.

## Backends at a Glance

| Backend | What it does | Typical use |
|---|---|---|
| **PassthroughFs** | Exposes a single host directory to the guest | Bind-mounting a project folder into the VM |
| **OverlayFs** | Stacks read-only image layers with a writable upper layer (copy-on-write) | OCI/container images like `python:3.12` |
| **MemFs** | A pure in-memory filesystem with no host I/O | Scratch space, `/tmp`, ephemeral workloads |
| **DualFs** | Composes two backends with a pluggable dispatch policy | Combining an image (OverlayFs) with a volume (PassthroughFs) under one mount |
| **ProxyFs** | Wraps any backend with access-control, read, and write hooks | Enforcing permissions, logging, or transforming file data on the fly |

Every backend implements the `DynFileSystem` trait, so they are fully interchangeable and composable.

## How the Pieces Fit Together

```
Guest VM
  |
  | (FUSE / virtio-fs)
  v
DynFileSystem
  |
  +-- PassthroughFs        single host directory
  +-- OverlayFs            layered image with COW
  +-- MemFs                in-memory scratch space
  +-- DualFs               combines two backends
  |     +-- backend_a      (e.g. OverlayFs)
  |     +-- backend_b      (e.g. PassthroughFs)
  |
  +-- ProxyFs              wraps any backend
        +-- inner          (e.g. PassthroughFs)
```

You can nest these freely. For example, a `ProxyFs` can wrap a `DualFs` that combines an `OverlayFs` with a `MemFs`.

## Backend Details

### PassthroughFs

Maps a single host directory into the guest. The guest sees standard Linux ownership, permissions, and file types even when the host runs macOS or uses a different filesystem.

- **Stat virtualization** stores uid, gid, mode, and rdev in an extended attribute (`user.containers.override_stat`) so the host file's real metadata stays untouched.
- **Special files** (block devices, char devices, sockets, FIFOs) are stored as regular files on the host with their type bits recorded in the xattr.
- **Symlinks on Linux** are file-backed (the file content is the symlink target) to avoid permission issues with real symlinks on unprivileged hosts.
- **Path confinement** uses `openat2(RESOLVE_BENEATH)` on Linux and `O_NOFOLLOW_ANY` on macOS to prevent the guest from escaping the root directory.

```rust
let fs = PassthroughFs::builder()
    .root_dir("/path/to/host/dir")
    .build()?;
```

### OverlayFs

Implements a union filesystem with N read-only lower layers and one writable upper layer, similar to Linux kernel overlayfs but in userspace.

- **Copy-on-write**: when the guest modifies a file from a lower layer, the file is copied to the upper layer first. The lower layers are never modified.
- **Whiteouts**: deleting a lower-layer file creates a `.wh.<name>` marker in the upper layer so the file appears gone.
- **Opaque directories**: when a lower-layer directory is replaced, a `.wh..wh..opq` marker hides all its former children.
- **Atomic copy-up**: files are staged in a work directory and atomically renamed into the upper layer.

```rust
let fs = OverlayFs::builder()
    .layer("/layer0")       // bottom layer
    .layer("/layer1")       // stacked on top
    .writable("/upper")     // writable layer
    .work_dir("/work")      // staging area (must be on same filesystem as upper)
    .build()?;
```

### MemFs

A pure in-memory filesystem. Files, directories, symlinks, and metadata all live in Rust data structures with no host I/O.

- Optional **capacity limits** on total data size and inode count.
- Aggressive caching by default since the process memory is the sole owner of the data.
- Great for ephemeral workloads where persistence is not needed.

```rust
let fs = MemFs::builder()
    .capacity(64 * 1024 * 1024)   // 64 MiB limit
    .max_inodes(10_000)
    .build()?;
```

### DualFs

Combines two backends (`backend_a` and `backend_b`) under a single filesystem with a pluggable dispatch policy that decides which backend handles each operation.

Built-in policies:

| Policy | Behavior |
|---|---|
| `ReadBackendBWriteBackendA` | Reads come from B, writes go to A (default) |
| `BackendAOnly` | Everything goes to A, B is ignored |
| `BackendAFallbackToBackendBRead` | Reads try A first, fall back to B |
| `MergeReadsBackendAPrecedence` | Directories are merged from both, A wins on conflicts |

When a write targets a file that lives on the other backend, DualFs **materializes** (copies) it to the target backend automatically.

```rust
let fs = DualFs::builder()
    .backend_a(overlay_fs)
    .backend_b(passthrough_fs)
    .policy(ReadBackendBWriteBackendA)
    .build()?;
```

### ProxyFs

A transparent decorator that wraps any `DynFileSystem` and lets you attach hooks:

- **on_access**: called before `open`, `create`, and `opendir`. Return an error to deny access.
- **on_read**: called after the inner backend reads data. Use it to transform or inspect file contents.
- **on_write**: called before the inner backend writes data. Use it to transform or validate writes.

ProxyFs tracks inode-to-path mappings internally so hooks receive human-readable paths instead of raw inode numbers.

```rust
let fs = ProxyFs::builder(Box::new(passthrough_fs))
    .on_access(my_access_hook)
    .on_read(my_read_hook)
    .build()?;
```

## Shared Infrastructure

A few pieces are shared across backends:

- **MultikeyBTreeMap**: a dual-key ordered map used for inode tables, allowing lookup by either FUSE inode or host identity.
- **Stat virtualization**: the xattr-based scheme for storing Linux file metadata on any host filesystem.
- **Name validation**: rejects empty names, `..`, paths with `/` or `\`, null bytes, and `.wh.*` prefixes (reserved for whiteouts).
- **Platform abstraction**: translates between Linux and macOS error codes, xattr APIs, and path resolution strategies.
- **init.krun**: a virtual file (inode 2) containing the embedded `agentd` binary. It appears at the root of every backend and cannot be deleted or overwritten.

## Security

The filesystem layer is a trust boundary. The guest VM is untrusted, and all guest-provided names, paths, offsets, and xattr values are treated as potentially malicious.

Key protections:

- **Path confinement**: all file access uses fd-relative opens with `RESOLVE_BENEATH` (Linux) or `O_NOFOLLOW_ANY` (macOS). The guest cannot escape the designated root directory.
- **Xattr protection**: the `user.containers.override_stat` attribute is invisible to the guest. It is filtered from `listxattr` and blocked on `getxattr`, `setxattr`, and `removexattr`.
- **Whiteout injection prevention**: `validate_name()` rejects any name starting with `.wh.`, so the guest cannot forge whiteout markers.
- **Inode safety**: inode numbers are monotonically increasing and never reused, preventing stale-inode attacks.
- **No symlink following**: guest-controlled path components are opened with `O_NOFOLLOW` to prevent symlink-based escapes.
- **File descriptor hygiene**: all fds are opened with `O_CLOEXEC` and explicitly closed on release.

## Crate Structure

```
crates/filesystem/
  lib/
    lib.rs                   # public API and re-exports
    agentd.rs                # embedded agentd binary
    backends/
      mod.rs
      shared/                # inode tables, stat override, validation, platform
      passthroughfs/         # single-directory passthrough
      overlayfs/             # multi-layer copy-on-write
      memfs/                 # pure in-memory
      dualfs/                # two-backend composition
      proxy/                 # decorator with hooks
```

Each backend follows the same internal layout: `mod.rs`, `builder.rs`, `types.rs`, `inode.rs`, `file_ops.rs`, `dir_ops.rs`, `metadata.rs`, `create_ops.rs`, `remove_ops.rs`, `xattr_ops.rs`, `special.rs`, and a `tests/` directory.
