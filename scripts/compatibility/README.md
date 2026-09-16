# SDK/runtime compatibility gate

This gate tests the SDK/runtime boundary, not source-level API compatibility. It is called by `check.yml` for code-changing PRs, and `Check Summary` requires it to finish successfully. It publishes no packages and changes no release automation.

## Matrix

The baseline job resolves the latest stable GitHub release once and records its tag, peeled commit, runtime/firmware hashes and Go FFI hash. All language jobs consume that same artifact. New releases are picked up on the next workflow run; individual matrix cells never independently resolve `latest`.

| SDK | Runtime | Purpose |
| --- | --- | --- |
| Candidate | Released | New SDK with independently installed older `msb` |
| Released | Candidate | Existing application with updated `msb` |
| Released | Released | Baseline control |
| Candidate | Candidate | Candidate control using the same scenarios |

Each pairing runs twice: explicit `MSB_PATH` with a fresh home, then installed-runtime discovery without `MSB_PATH`/`MSB_LIBKRUNFW_PATH` in a home initialized by the released CLI. That second lane starts with an empty released catalog and tests SDK writes against its schema, not access to pre-existing user sandbox rows. Existing catalog schemas and migration histories must remain unchanged after SDK access. The CLI inspects SDK-created records while their VMs are live.

Rust, Python, Node and Go run lifecycle, environment, multiple mount cardinalities, persistent disk restart, network isolation and disk snapshot restore scenarios. Rust, Python and Node also exercise archive restore. Node is tested with Node.js, not Bun. Ruby runs its exposed lifecycle/filesystem and disabled-network operations; custom mounts and snapshot restore are not exposed by its current public API and are reported as not applicable rather than substituted with CLI calls.

As of this change, RubyGems has only the unrelated `0.1.0` SDK, below our supported compatibility floor. Candidate Ruby is tested against both runtimes, but released-Ruby coverage is explicitly unavailable. Once any modern Ruby gem is published, the matching baseline version becomes mandatory: a missing gem fails provisioning instead of silently dropping the reverse lane.

## Avoiding false passes

- Published Python wheels, npm packages/platform bindings, Go modules/FFI, Rust crates and Ruby gems stay separate from candidate artifacts. Version strings alone do not establish provenance when development and published versions match.
- Native bindings are identified and hashed. The Rust dependency graph and Go module resolution are recorded. The runner verifies its SDK artifact inventory before testing.
- After each VM launch, a helper checks `/proc` for the fixture's exact `MSB_HOME` and requested sandbox name, and verifies the actual runtime executable hash. Selecting an environment variable without observing the launched runtime is insufficient.
- Default/deny-all network checks use a local positive control where the SDK exposes one. Ruby checks that its disabled-network contract exposes no external interface.
- Missing KVM, required packages, reports, successful cases or runtime evidence are failures, not skips. The matrix continues after a case fails so other pairings still produce evidence.
- Homes are short, isolated temporary directories. Cleanup addresses catalog names only within those homes, preserves primary failures when teardown also fails, and never signals an unverified historical PID. Failed fixture data is retained for diagnosis; hosted runners are discarded after the job.

## Running and inspecting it

The live jobs use fresh GitHub-hosted Ubuntu 24.04 x86-64 runners. They require and probe `/dev/kvm`; they do not fall back to emulation or a persistent self-hosted runner. Compilation/package preparation happens separately and reuses candidate Python, Node and Go CI artifacts. Ruby and the standalone Rust fixture are built from the candidate checkout.

Run the infrastructure checks without VMs or network access:

```sh
python3 -W error -m unittest discover -s scripts/compatibility -p 'test_*.py'
```

The reusable workflow shows the exact provisioning and live commands. Each language uploads `compatibility-results-<language>` with `results.json`, SDK reports, observed runtime identities, per-cell durations, and setup/test/cleanup logs. Review missing Ruby coverage explicitly; a successful candidate-Ruby lane is not a released-Ruby pass.

## Boundaries

This is the latest-stable Linux x86-64 gate. It does not claim macOS/HVF, Windows/WHP, Linux ARM64, full-memory/branch snapshot coverage, arbitrary cross-version archives, exhaustive crash recovery, or the complete `0.6.x` support matrix. Those still require their dedicated qualification. The separate `0.6.18` catalog regression fixture introduced by #1589 must remain enabled after that PR merges; passing against the latest release cannot replace it. Broader historical and cross-platform qualification is follow-up work, not an implicit skip inside this gate.

This PR is intended to merge after #1589 and the `0.7.1` release. Until that release is published, the automatically selected baseline remains `0.7.0`.
