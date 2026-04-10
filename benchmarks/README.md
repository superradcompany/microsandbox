# Benchmarks

Repeatable filesystem benchmarks comparing Docker and Microsandbox. Workloads run
inside the guest and report their own timings, so results reflect the full I/O stack
as seen by the application — not just host-side wall clock.

## Quick start

```bash
just bench-fs
```

Runs all workloads against `python:3.12-slim` with 5 iterations and writes a
timestamped JSON result to `build/bench/fs/`.

## Options

```bash
# Custom image and iteration count
cd benchmarks && uv run bench_fs.py --image python:3.12-slim --iterations 10

# Run specific workloads only
cd benchmarks && uv run bench_fs.py --workload metadata_scan_stdlib --workload seq_read_16m

# Multiple images in one run
cd benchmarks && uv run bench_fs.py --image python:3.12-slim --image python:3.12

# Skip image pulls for warm-cache comparisons
cd benchmarks && uv run bench_fs.py --skip-pull
```

## Comparing builds

Save a baseline, build the new version, then compare:

```bash
# Save a baseline for the current build
cd benchmarks && uv run bench_fs.py --output baselines/before.json

# Benchmark a new binary against the baseline
cd benchmarks && uv run bench_fs.py \
  --msb-bin ../build/msb \
  --output results/after.json \
  --baseline baselines/before.json
```

## Workloads

**Rootfs / read-only:**

| Name | What it measures |
|---|---|
| `metadata_scan_stdlib` | `stat()` + `scandir()` over the Python stdlib tree |
| `read_all_py_stdlib` | Sequential read of every `.py` file in stdlib |
| `deep_tree_traverse` | Traverse a 585-dir / 2925-file tree created in `/tmp` |
| `random_read_stdlib` | Read 200 random files from stdlib (non-sequential access) |

**Write path:**

| Name | What it measures |
|---|---|
| `small_file_create_1k` | Create 1000 x 4 KB files in `/tmp` |
| `mid_file_create_100` | Create 100 x 64 KB files in `/tmp` |
| `seq_write_fsync_16m` | Write 16 MB + fsync to `/tmp` |
| `shm_write_fsync_16m` | Write 16 MB + fsync to `/dev/shm` |

**Read-back:**

| Name | What it measures |
|---|---|
| `seq_read_16m` | Sequential read of a 16 MB file from `/tmp` |
| `mmap_read_16m` | `mmap` read of a 16 MB file from `/tmp` |

**Lifecycle:**

| Name | What it measures |
|---|---|
| `file_delete_1k` | Delete 1000 files (re-created before each iteration) |
| `rename_1k` | Rename 1000 files (re-created before each iteration) |

**Mixed / concurrent:**

| Name | What it measures |
|---|---|
| `mixed_read_write` | Alternate reading rootfs files and writing temp files (500 each) |
| `concurrent_read_4t` | Read all stdlib `.py` files across 4 threads |

## Notes

- All workloads run in warm sandboxes with a warmup iteration before measured runs.
- Fresh container and sandbox per workload — no state leakage between runs.
- Image pulls are timed separately from workload measurements.
- Keep image, workloads, and iteration count the same across comparison runs.
- Files under `build/bench/` are disposable; save durable baselines to `benchmarks/baselines/`.
