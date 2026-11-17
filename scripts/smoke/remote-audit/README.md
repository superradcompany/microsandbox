# Opt-in hosted remote qualification

These audits exercise the rebuilt SDK against a real provider. They create uniquely named, disposable sandboxes, volumes and snapshots, then delete them and check absence. They are not ordinary unit tests and may consume provider quota. Do not run against an account where disposable resources are prohibited.

Supply `MSB_REMOTE_AUDIT=1`, `MSB_API_KEY`, `MSB_API_URL`, and an absolute `MSB_AUDIT_REPORT` path through the environment. Never put credentials in arguments, fixtures or committed logs. Use an isolated `MSB_HOME`/`MSB_CONFIG_PATH`. Setting `MSB_BACKEND=local` deliberately verifies that explicit remote selectors and flags override ambient selection. The scripts write incremental JSON outcomes and a `.resources.json` sidecar (Python/CLI use a sibling suffix) so interrupted runs can be cleaned up by exact recorded name. Never delete resources by a broad prefix search.

Run from the repository root after building/installing the candidate bindings:

```sh
node scripts/smoke/remote-audit/typescript.mjs
python scripts/smoke/remote-audit/python.py
ruby scripts/smoke/remote-audit/ruby.rb
python scripts/smoke/remote-audit/cli.py
python scripts/smoke/remote-audit/flags.py
cargo test -p microsandbox --no-default-features --features local,cloud,net --test remote_api_live remote_api_live -- --exact --ignored --nocapture
```

The CLI scripts require `MSB_CLI` pointing to the candidate binary. The Python/Ruby import paths must select the rebuilt candidate bindings. TypeScript imports this checkout's built `sdk/node-ts/dist`. Each invocation needs its own report path; scripts overwrite that report incrementally.

JavaScript audit deadlines record a timeout without cancelling the SDK operation. The audits retain unfinished operations and wait for them before collecting resource handles for cleanup. Cleanup also waits for a timed-out deletion before deleting dependent resources or checking absence. A provider operation that never settles can therefore delay cleanup; process termination still requires recovery using the recorded sidecar. Run `node --test scripts/smoke/remote-audit/operations.test.mjs` to check late creation, late rejection and completion behavior without a provider.

For Go, set `MSB_SELECTOR_NATIVE_LIBRARY` to the rebuilt remote-capable native library, then run from `sdk/go`:

```sh
go run ../../scripts/smoke/remote-audit/go.go
```

The focused runtime-settings regression checks configured shell, default command and workdir on create-, get- and list-derived objects, then deletes its exact test resource and verifies absence:

```sh
node scripts/smoke/remote-audit/runtime-settings.mjs
```

This runtime probe does not qualify live `config()` or dependent Go shell, CLI command-resolution and SFTP configuration paths.

The cross-SDK inspection regression uses one recorded disposable sandbox. Set `MSB_INSPECTION_FIXTURE` to an absolute JSON path and use a different `MSB_AUDIT_REPORT` for each command. Setup writes the name before creation; preserve that file even if creation is interrupted. All SDK probes validate the recorded identity. Run the CLI probe after the SDK probes because `run` may change lifecycle state. Always finish with cleanup, which verifies exact identity before deletion and then verifies absence:

```sh
node scripts/smoke/remote-audit/inspection.mjs setup
node scripts/smoke/remote-audit/inspection.mjs
python scripts/smoke/remote-audit/inspection.py
ruby scripts/smoke/remote-audit/inspection.rb
cargo test -p microsandbox --no-default-features --features local,cloud,net,ssh --test remote_api_live remote_inspection_live -- --exact --ignored --nocapture
# From sdk/go, with MSB_SELECTOR_NATIVE_LIBRARY set:
go run ../../scripts/smoke/remote-audit/inspection.go
# Back at the repository root:
python scripts/smoke/remote-audit/inspection-cli.py
node scripts/smoke/remote-audit/inspection.mjs cleanup
```

These checks cover fresh inspection result shapes, configured shell/default command/workdir after get and paginated list, TypeScript SFTP relative-path initialization, and CLI explicit/default command resolution. They do not qualify every mount, secret, network setting, or backend option; redacted and unavailable projections also have separate fixture-based decoder tests. Never silently retry a failed assertion into a pass: retain the failed attempt and record any later rerun separately.

Additional investigations use separate disposable resources and report paths:

```sh
node scripts/smoke/remote-audit/probes.mjs
node scripts/smoke/remote-audit/capabilities.mjs
node scripts/smoke/remote-audit/permissions.mjs
cargo test -p microsandbox --no-default-features --features local,cloud,net --test remote_api_live remote_transport_probe -- --exact --ignored --nocapture
```

`probes.mjs` checks byte-transfer sizes, mounted storage, configured execution defaults, explicit execution timeout, SSH client opening, non-starting inspection and stale-identity rejection. `capabilities.mjs` checks progress completion, actual SFTP, following logs, outbound HTTPS, disabled networking and host-specific option boundaries. Provider bind paths are relative to the organization's storage, not the SDK client's host filesystem; the test removes its own empty bind directory. `permissions.mjs` compares API-created/replaced files with guest-created files under strict and relaxed mount presentation. It does not change account policies or suggest weakening production policy. `remote_transport_probe` records the negotiated agent version and direct-transfer sizes.

`PASS` means the particular operation/assertion completed; it is not every option combination or old/new parity. `UNSUPPORTED` records an observed capability rejection, not implemented functionality. A reported `FAIL` makes the finalized scripts exit nonzero. The CLI records an already absent cleanup target as `ABSENT` only after a separate not-found observation. Diagnostics may contain test resource identifiers but redact the supplied key. Do not distribute raw provider/account responses.

The 2026-11-17 qualification report in the planning repository contains the per-case ledger, initial harness mistakes, corrected attempts, artifact provenance, capability matrix and remaining gaps. Production SDK/provider behavior is unchanged by these audit additions.

For checkpoint-save cleanup qualification, give each language exclusive use of its own recorded fixture. Set `MSB_INSPECTION_DESTROY=1` for the Python, Ruby, or Go inspection probe to append exact-resource destruction and a not-found check. TypeScript uses `inspection.mjs cleanup`; Rust uses `remote_cleanup_live` in the same ignored integration-test binary. Do not enable destruction while another probe uses that fixture. Retain the sidecar and failed report if teardown is interrupted.

`connections.rb` repeats fresh Ruby get-to-shell connections without retries, recording elapsed times and errors. It explicitly prewarms the recorded sandbox before concurrency begins. Set `MSB_CONNECTION_CONCURRENCY` (1–4, default 1) and `MSB_CONNECTION_ATTEMPTS` (1–48, default 12); cleanup remains external. This can diagnose an intermittent connection failure but a successful rerun alone does not establish its cause or fix.
