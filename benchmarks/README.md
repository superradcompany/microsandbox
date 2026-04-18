# Benchmarks

Repeatable filesystem benchmarks comparing Docker and Microsandbox. Workloads run
inside the guest and report their own timings, so results reflect the full I/O stack
as seen by the application — not just host-side wall clock.

## Quick start

```bash
just bench-fs
just bench-fsmeta
```

`bench-fs` runs the general mixed filesystem suite against `python:3.12-slim`
and writes a timestamped JSON result to `build/bench/fs/`. It mounts Docker
`/tmp` as `tmpfs` so temp-file workloads match the default OCI `msb` sandbox
configuration.

`bench-fsmeta` runs the rootfs-only merged-view suite against `python:3.12`
and writes a timestamped JSON result to `build/bench/fsmeta/`.

## Options

```bash
# Custom image and iteration count
cd benchmarks && uv run bench_fs.py --image python:3.12-slim --iterations 10
cd benchmarks && uv run bench_fsmeta.py --image python:3.12 --iterations 10

# Run specific workloads only
cd benchmarks && uv run bench_fs.py --workload metadata_scan_stdlib --workload seq_read_16m
cd benchmarks && uv run bench_fsmeta.py --workload negative_lookup_stdlib --workload concurrent_readdir_4t

# Multiple images in one run
cd benchmarks && uv run bench_fs.py --image python:3.12-slim --image python:3.12
cd benchmarks && uv run bench_fsmeta.py --image python:3.12 --image python:3.13

# Skip image pulls for warm-cache comparisons
cd benchmarks && uv run bench_fs.py --skip-pull
cd benchmarks && uv run bench_fsmeta.py --skip-pull
```

## Comparing builds

Save a baseline, build the new version, then compare:

```bash
# Save a baseline for the current build
cd benchmarks && uv run bench_fs.py --output baselines/before.json
cd benchmarks && uv run bench_fsmeta.py --output baselines/fsmeta-before.json

# Benchmark a new binary against the baseline
cd benchmarks && uv run bench_fs.py \
  --msb-bin ../build/msb \
  --output results/after.json \
  --baseline baselines/before.json

cd benchmarks && uv run bench_fsmeta.py \
  --msb-bin ../build/msb \
  --output results/fsmeta-after.json \
  --baseline baselines/fsmeta-before.json
```

## Suites

`bench_fs.py` is the broad mixed filesystem suite. It includes rootfs reads,
temp-file workloads under `/tmp`, and `/dev/shm`. Docker runs with `--tmpfs /tmp`
so `/tmp` comparisons stay aligned with the default OCI `msb` runtime.

`bench_fsmeta.py` is the fsmeta-focused suite. It only measures rootfs lookup,
`readdir()`, and read patterns that depend on the merged read-only lower view.
It also prints the cached image layer count so flat images are easy to spot.

## Workloads

### `bench_fs.py`

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

### `bench_fsmeta.py`

| Name | What it measures |
|---|---|
| `metadata_scan_stdlib` | Single-pass `scandir()` + `stat()` over the Python stdlib tree |
| `readdir_rescan_stdlib` | Ten repeated `scandir()` passes across the stdlib directory tree |
| `negative_lookup_stdlib` | Guaranteed-missing `stat()` probes in every stdlib directory |
| `hit_miss_mix_stdlib` | Existing-file `stat()` plus unique missing-path probes per directory |
| `read_all_py_stdlib` | Sequential read of every `.py` file in stdlib |
| `concurrent_negative_lookup_4t` | Parallel negative lookups over the stdlib tree across 4 threads |
| `concurrent_readdir_4t` | Parallel `scandir()` passes over the stdlib tree across 4 threads |

## Notes

- All workloads run in warm sandboxes with a warmup iteration before measured runs.
- Fresh container and sandbox per workload — no state leakage between runs.
- Image pulls are timed separately from workload measurements.
- `bench_fs.py` mounts Docker `/tmp` as `tmpfs` to match the default OCI `msb`
  `/tmp` mount and keep `/tmp` workloads apples-to-apples.
- Keep image, workloads, and iteration count the same across comparison runs.
- `bench_fsmeta.py` is most informative on images with more layer fanout; 8+ layers usually gives a stronger merged-view signal than slim images.
- Files under `build/bench/` are disposable; save durable baselines to `benchmarks/baselines/`.
