# microsandbox-filesystem

Filesystem backends for [microsandbox](https://github.com/superradcompany/microsandbox) virtual machines. This crate now exposes the three backends the runtime still uses: `PassthroughFs`, `MemFs`, and `DualFs`.

- **No root required** — runs unprivileged; guest-visible ownership and permissions are virtualized without touching the host filesystem
- **Runs on macOS too** — the guest sees a full Linux filesystem even when the host runs macOS
- **Zero-copy I/O** — file reads and writes flow directly between host and guest with no intermediate allocation
- **Composable** — all backends implement `DynFileSystem` and can be nested freely

## Backends

### PassthroughFs

Exposes a single host directory to the guest VM. The guest sees standard Linux ownership, permissions, and file types even when the host runs macOS.

```rust
let fs = PassthroughFs::builder()
    .root_dir("/path/to/host/dir")
    .build()?;
```

Metadata like uid, gid, and mode are stored in an extended attribute on the host, so the actual host file permissions stay untouched. Special files (devices, sockets, FIFOs) are stored as regular files with their type bits in the xattr. Path confinement prevents the guest from escaping the root directory.

#### Guest close policy (Unix)

`PassthroughConfig::flush_policy` and the builder's `.flush_policy(...)` control
host work for guest FUSE FLUSH requests. The default, `FlushPolicy::DupClose`,
duplicates and closes the host descriptor so backing filesystem close-time
write errors (such as ENOSPC or EIO from host FUSE FLUSH) reach guest `close()`.
Neither policy guarantees durability; explicit fsync/fdatasync is unchanged.

The runtime's Unix `--mount` option accepts `flush=dup-close|none`, defaulting to
`flush=dup-close`, alongside `stat-virt=` and `host-perms=`. For example:

```sh
--mount named-volume:/srv/juicefs/volume:flush=none
```

`flush=none` (`FlushPolicy::None`) validates the handle and returns success
without duplicating or closing its fd. On backing filesystems such as JuiceFS,
this avoids a metadata/object round trip for each synthetic close. Opt in only
where that cost warrants losing close-time write error reporting: applications
must fsync/fdatasync to detect write errors and request durability. The real fd
closes at RELEASE, whose errors cannot be reported to guest `close()`; the
current File drop discards those host close errors. This is per-mount runtime
configuration, not persisted filesystem metadata or a guest protocol change.
Older runtimes reject the new option; mount specifications omitting it retain
the original dup-close behavior.

Descriptor audit for a successful regular-file create/write sequence:

- CREATE keeps its original fd as the guest handle; no close/reopen.
- WRITE and handle-based SETATTR borrow that fd, including override-xattr work.
- Guest set/get/list/remove xattr borrow an existing handle for the inode under
  its file lock. Without a handle they open read-only and close once per request.
- SETATTR without a handle opens read-only for metadata changes; truncation
  requires one temporary writable fd. That close remains necessary when there
  is no supplied handle.
- Linux namespace resolution uses O_PATH descriptors; ordinary path-based
  metadata reopens use read-only descriptors. These do not add writable closes.
- Default FLUSH adds one synthetic close per request. With `flush=none` it adds
  none. RELEASE closes the real handle once.

The Linux `test_create_write_close_budget` traces CREATE → WRITE → handle-based
truncate → four xattr operations → four FLUSH requests → fsync/fdatasync →
RELEASE with `strace -f -yy`. It asserts **one close of the created file** with
explicit `None`, and five with the default `DupClose` (one RELEASE plus four
synthetic closes). Run with:

```sh
cargo test -p microsandbox-filesystem test_create_write_close_budget -- --nocapture
```

Install strace on Linux (`apt-get install strace`); the test **fails** if it is
missing, including in CI and Docker. The count covers this direct handler sequence,
not arbitrary guest path walks, extra opens, handleless truncates, error cleanup,
or checkpoint/unlink retention. No live JuiceFS latency improvement is claimed.

`test_flush_reports_backing_close_errors_by_default` uses strace's path-filtered
close fault injection to emulate backing FUSE FLUSH failures. It verifies that
the default reports ENOSPC/EIO and explicit `none` acknowledges the guest close.
Both Linux tests run in the ordinary crate suite:

```sh
cargo test -p microsandbox-filesystem
cargo clippy -p microsandbox-filesystem --all-targets -- -D warnings
```

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
    .backend_a(mem_fs)
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

When a write targets a file that lives on the other backend, `DualFs` copies it over automatically.

## Cache Policies

All backends support configurable kernel caching:

| Policy | Behavior |
|---|---|
| `Never` | No caching — every read hits the backend (DIRECT_IO) |
| `Auto` | Kernel decides (default for PassthroughFs and DualFs) |
| `Always` | Aggressive caching (default for MemFs, since memory is authoritative) |

```rust
let fs = PassthroughFs::builder()
    .root_dir("/path/to/dir")
    .cache_policy(CachePolicy::Always)
    .build()?;
```
