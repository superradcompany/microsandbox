# Explicit disk compaction and layer export qualification

This report covers the compaction/export additions to PR #1503 (#6), based strictly on its existing `92616244` stack tip. The matching runtime dependency is libkrun `2ec13c88` and the clock-aware firmware is libkrunfw `4b334c2`. No newer `main` commits were imported. Builds used temporary path overrides for the existing companion libkrun stack, not dependency/version changes in this PR.

## Implemented surface

- CLI: `msb modify NAME --compact [--layers N] [--dry-run]`, snapshot save `--since` / `--last-layers`, snapshot load `--base`, and create/run `--snapshot-base`.
- Rust, Python, TypeScript and Go: explicit compaction, selection options/results, incremental save, explicit-base load, and direct archive-to-sandbox restore. Existing standalone load APIs remain available.
- Running/stopped managed and flat roots; base-inclusive counts with the writable head always excluded. No automatic compaction, snapshot deletion, cloud support, or user-owned disk rewriting.
- Sparse standalone qcow2 base, unchanged suffix/private-head hardlink bindings, journal-before-activation, preserved original launch binding, fresh physical IDs, and retained old snapshots.
- Dependent archives omit only selected disk-prefix payloads. Full snapshots retain all memory, execution and device objects. Bases must match the exact physical prefix and be supplied explicitly; imports and children own the resolved closure.

## Live coverage

| Check | macOS/HVF ARM64 | Linux/KVM x86-64 | Windows/WHP ARM64 |
| --- | --- | --- | --- |
| Managed and flat roots; online and stopped compaction | Pass | Pass | Pass |
| Explicit counts, no-op, dry-run and invalid selections | Pass | Pass | Pass |
| Full checkpoints; standalone, since-base and last-N exports | Pass | Pass | Pass |
| Compressed/plain archives; installed-base and base-archive resolution | Pass | Pass | Pass |
| Missing/wrong base rejected | Pass | Pass | Pass |
| Restart and old checkpoint restore after compaction | Pass | Pass | Pass |
| Direct full and disk-only dependent-archive restore | Pass | Pass | Pass |
| Volatile tmpfs marker retained by full restore, absent after cold boot | Pass | Pass | Pass |
| Concurrent guest writes/fsync during preparation and cutover | Pass | Pass | Managed pass; flat result not collected |
| Depths 1/4/16/64, then 65 → 34 → 2 layers | Pass | Pass | Managed pass; flat result not collected |
| tmpfs/user-owned rejection, truncated archive refusal, all/equal-prefix export | Pass | Pass | Not run separately |
| Independent `qemu-img info --backing-chain` inspection | Pass | Pass | Not available in this run |
| Python/TypeScript/Go native SDK workflows against live VMs | Pass | Not run separately | Not run separately |
| Cancel stopped compaction await, immediately start, verify final chain/data | Pass, both layouts | Not run separately | Not run separately |
| Previous PR6 reader rejects dependent archive | Pass | Same parser, not run separately | Same parser, not run separately |

The main macOS and Linux matrices each have 108 passing checks. Windows uses an equivalent PowerShell matrix with JSON assertions rather than `jq`. Tests use independent homes/checkouts, preserve existing machine checkouts, and stop their named VMs on exit. Archived data is retained for inspection; compaction does not promise storage reclamation while snapshots retain the old files.

## Performance samples

These are single observed release-build samples, not medians or a cold-cache throughput study. The main fixture uses a 512 MiB logical disk, 256 MiB RAM, 8 MiB incompressible guest data, and four full checkpoints. Pauses below are measured inside the runtime, from requesting pause through successful resume. CLI wall times include IPC, staging, validation and publication. Debug SDK timings must not be compared with these release numbers.

| Operation | macOS managed / flat | Linux managed / flat | Windows managed / flat |
| --- | --- | --- | --- |
| Online 5 → 3 layers: runtime total | 208 / 204 ms | 151 / 194 ms | 605 / 634 ms |
| Same operation: VM pause | 16.1 / 15.1 ms | 2.20 / 2.28 ms | 5.25 / 4.58 ms |
| Stopped compaction: CLI wall | 50 / 57 ms | 29 / 51 ms | 198 / 176 ms |
| Since-base archive export: CLI wall | 303 / 313 ms | 233 / 239 ms | 780 / 875 ms |
| Dependent archive load: CLI wall | 217 / 240 ms | 139 / 156 ms | 881 / 915 ms |
| Direct full delta restore: CLI wall | 372 / 433 ms | 291 / 307 ms | 2,189 / 1,958 ms |
| Direct disk-only delta restore: CLI wall | 504 / 586 ms | 377 / 408 ms | 2,005 / 1,956 ms |

At depth 65, merging the oldest 32 layers took 285 / 286 ms total with 17.1 / 15.1 ms pause on macOS, and 265 / 342 ms total with 25.0 / 25.3 ms pause on Linux. The following stopped 34 → 2 compaction took 36 / 54 ms on macOS and 23 / 38 ms on Linux. Those fixtures use 128 MiB RAM and 4 MiB random data. They demonstrate increasing chain depth without content loss; they do not establish a universal pause bound.

The Windows managed depth fixture passed concurrent writer sequence/hash checks, restart, and old checkpoint restore: online 65 → 34 took 705 ms total with 20.6 ms pause, followed by stopped 34 → 2 in 112 ms. The flat depth run was launched, but new SSH connections timed out before its final result could be collected. Its main short-chain matrix passed earlier; do not infer a flat depth pass from that result.

Compaction materialization runs outside the pause. Opening/rebinding the retained suffix is still inside the drained window, so depth can affect pause. Raw sparse sources currently scan their logical mappings and skip all-zero output runs; very large mostly-empty raw bases need separate throughput characterization. `materialized_bytes` is bytes written, not reclaimed bytes.

## Regressions found and fixed during qualification

- Stopped multi-layer snapshot verification still refused a chain. It now verifies every recorded ancestor binding while preserving the existing head-result projection; a corrupt ancestor fails even if the head is intact.
- A cancelled stopped-compaction SDK await could drop its lifecycle guard while the blocking worker continued. The guard now belongs to that worker. The live cancellation/start race verifies completion and byte preservation.
- Direct archive restore overflowed default worker stacks in debug Python/Node bindings. Boxing the archive and inventory-validation futures fixes the stack usage; the complete SDK workflows pass without a stack-size override.
- JavaScript numeric conversion could truncate fractional layer counts. The native boundary now checks finite whole nonnegative values before conversion. Invalid numbers and out-of-range physical selections are rejected.

## Automated checks

- Image crate: 237 passed, 4 existing ignored tests. Includes mapping equivalence, overwrite/zero/grown-tail behavior, immutable input, and checked selection boundaries.
- Rust SDK snapshot tests: 31 passed, including dependent import/direct restore, exact base matching, local closure ownership after base deletion, and corrupt-ancestor verification.
- Runtime disk tests: 4 passed, including both layouts, repeated compaction, unchanged writable bytes, old snapshot links, restart projection, and failed-preparation cleanup without journal publication.
- CLI modify tests: 10 passed.
- TypeScript: typecheck and 136 unit tests passed; generated native declarations refreshed.
- Go tests passed; generated C header refreshed. Python, Node and Go native Rust crates passed `cargo check`.
- Rust formatting and whitespace checks passed. Existing no-default-feature/platform unused-variable warnings remain; this is not a claim that workspace-wide strict Clippy is clean.

## Reproduction and limits

The scripts under `scripts/smoke/cli/disk-compaction-*` exercise the CLI matrices. Use an isolated `MSB_HOME`, a matching codesigned macOS binary or native platform build in `MSB_BIN`, matching firmware, and a fresh `QUAL_ROOT`. The Unix main matrix accepts `QUAL_PREFIX` for a fresh set of names. SDK scripts under `scripts/smoke/sdk/` consume the main matrix's snapshots; set `QUAL_SOURCE` to its managed/flat source name and use newly built native bindings. Node can take `SDK_MODULE` to locate its built SDK. Go runs from `sdk/go` with `-tags microsandbox_ffi_path` and `MICROSANDBOX_FFI_PATH` pointing at the built native library. These are debug-binding functional tests, not release benchmarks.

Local evidence: `/private/tmp/msb-compact-mac.fOFVJy`; Linux: `/home/ubuntu/msb-compact-qual.k3H6dZ`; Windows: `C:\Users\Stephen\AppData\Local\Temp\msb-compact-qual-20260905`. The Windows CLI feature build predates the last SDK-only cancellation/stack fixes; those fixes were live-qualified through macOS bindings, not a Windows language-SDK rebuild.

Not claimed: forced host power loss at every publication instruction, exhaustive disk-full/I/O fault injection, the near-256-layer limit, cold/warm random/sequential guest-I/O percentile benchmarks, all filesystems/hardlink failures, or a full per-language SDK × OS matrix. These remain extended qualification, not silently marked complete by passing unit tests.
