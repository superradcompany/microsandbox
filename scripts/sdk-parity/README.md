# SDK old/new evidence audit

These tools inventory declarations and render observed test results. They do not infer end-to-end coverage from declarations, source test names, mocks, compilation, or equal failures. The 2026-11-16 evidence and verdicts live in the planning repository at `microsandbox/design/sdk/e2e-parity.md` and `e2e-parity/`.

## Prepare independent inputs

Use an explicit pre-revamp source checkout and candidate checkout. Build each Rust/Ruby native SDK from its corresponding source, and record hashes for installed Python wheels, npm native modules, Go FFI libraries and the separately installed runtime. A released package baseline is not necessarily identical to the source baseline. Do not overwrite a developer's normal SDK installation or catalog.

Create separate disposable `MSB_HOME` directories for each SDK/version, with runtime/firmware and an image cache. The audit used macOS ARM64, pre-revamp source `28bdced502513f46b2372dade590ba7e91466242`, candidate `7de3348334c112e16515eb6a3c28ef1f45e2df6a` plus the added tests, and released v0.7.15 Python/npm/Go native artifacts. All VM runs used the same released v0.7.15 runtime. `run-metadata.json` identifies exact artifacts and hashes.

No production account or endpoint is required by the local suite. Real remote-provider tests require a disposable authorized account and are blocked for this audit. Mock-server results must remain separate.

## Run suites

Run each command twice, against the corresponding installed SDK/source and independent home. Set `MSB_HOME` and `MSB_PATH` explicitly. Preserve failures before correcting any harness issue. Go fixture names require a fresh home when repeating a full suite.

| SDK | Command / setup | Evidence |
|---|---|---|
| Python | Copy `sdk/python/integration/` outside the source package; run the isolated installed wheel's `python -m pytest integration -v --junitxml=python-new.xml` with `asyncio_mode=auto` | JUnit XML plus stdout/stderr; source imports must not shadow the installed native wheel |
| TypeScript | Build candidate `dist` and native module, then `vitest run tests/smoke.test.ts tests/revamp-live.test.ts --bail=0 --reporter=junit --outputFile=node-new.xml`; baseline copies import the installed old package's `dist` | JUnit XML; omit new-only context/inspection cases from the old SDK; run the same six completion assertions on both |
| Go | `MICROSANDBOX_FFI_PATH=/absolute/native/library go test -tags 'integration microsandbox_ffi_path' -count=1 -timeout 30m -json ./integration` | JSONL includes parent tests and subtests, not just top-level tests |
| Ruby | Stage matching native extension and Ruby wrapper; `MSB_RUBY_INTEGRATION=1 ruby -Ilib test/integration_test.rb --verbose` | Verbose Test::Unit log; live tests are omitted without the opt-in |
| Rust | `RUSTC_BOOTSTRAP=1 cargo test --offline -j1 -p microsandbox --no-fail-fast --test TARGET ... -- --ignored --test-threads=1 --format=json -Z unstable-options` | JSONL stdout and separate build stderr; target names are in `rust-selected-targets.json` |
| Rust SSH | Same command with `--features ssh --test ssh` | Default features compile this target with zero cases; that is not a pass |
| Rust jobs | Provision an otherwise idle disposable running sandbox; set `MSB_JOB_TEST_SANDBOX` and `MSB_JOB_TEST_RESTART=1`; run `--test jobs` serially, then stop/remove the fixture | Ten real guest execution/control tests; the shutdown test restarts the fixture |

The audit's original Python and Go metrics checks required a bounded readiness-message correction; Go stream cancellation was made deterministic by cancelling from the first writer call. Apply those same changes to the baseline test copy. TypeScript's newly written comparison initially used the wrong output field (`exitCode`); the corrected test uses the documented `code` on both versions. These are harness corrections, not SDK fixes. Preserve first attempts in separate files.

The new completion tests intentionally fail on old SDKs: `wait()` used to lose completion after event consumption. Such failures establish the accepted behavioral change and are not candidate regressions. Other new-only tests have no baseline pass and must not be labeled replicated.

## Extract declarations

Generate Rust JSON separately in each source checkout with `RUSTC_BOOTSTRAP=1 cargo rustdoc --offline -p microsandbox --lib -- -Z unstable-options --output-format json`, saving `target/doc/microsandbox.json` as `rust-old-public.json` or `rust-new-public.json`. Reflect each staged Ruby package with `ruby -I/absolute/staged/lib scripts/sdk-parity/inventory-ruby.rb`, saving `ruby-old-public.json` / `ruby-new-public.json`.

```sh
python3 scripts/sdk-parity/inventory.py \
  --old-source /absolute/old-source \
  --new-source /absolute/candidate \
  --evidence /absolute/evidence \
  --out /absolute/inventory

python3 scripts/sdk-parity/report.py \
  --source /absolute/candidate \
  --evidence /absolute/evidence \
  --inventory /absolute/inventory \
  --roadmap /absolute/planning/microsandbox/design/sdk/cleanup-roadmap.md \
  --out /absolute/report

python3 -m unittest discover -s scripts/sdk-parity -p 'test_*.py'
```

The candidate TypeScript installation supplies the TypeScript parser. Go's standard-library AST parser inventories the root SDK package. Python parses public wrapper/stub declarations. Rust uses the selected rustdoc feature/platform surface; external re-exports remain explicitly unexpanded. Ruby reflection includes native-generated public methods. These are conservative declaration inventories, not exhaustive option combinations, target-platform exports, inherited members, or behavioral mappings. Type aliases and enum values are not fully expanded. Removed names may have approved replacements; an unmatched name alone is not a regression.

The TypeScript inventory follows the public `src/index.ts` exports through nested modules, renamed exports and namespace exports. Direct aliases to local class/interface declarations include their public members, including policy fields such as `Rule.action`; arbitrary type expressions and external native/dependency declarations remain unexpanded. Apply the same inventory script to both versions when comparing them. Older inventories made with the top-level directory scan omit nested declarations and should not be treated as exhaustive. Validate the scanner with `node --test scripts/sdk-parity/inventory-ts.test.mjs`.

The report recognizes `python-*.xml`, `node-*.xml`, `go-{old,new}{,-corrected}.jsonl`, `rust-{old,new}{,-recovered,-jobs,-ssh,-tls-retry}.jsonl`, and `ruby-{old,new}{,-additional}.log`. A `corrected` JUnit filename indicates a reviewed harness correction. Rust started-without-finished events and incomplete Ruby cases cannot become passes. Failed unmodified candidate cases that pass on retry remain intermittent. All 96 cleanup findings are listed; explicit scenario links are partial evidence, never blanket qualification.

Source test discovery is also conservative: parameterized/macro-generated cases can remain symbolic, and source presence does not prove execution. Use the executed-scenario ledger and retained raw evidence for verdicts. Do not report a coverage percentage with declaration rows or source test names as the denominator.

## Follow-up fixes and qualification

Keep the original evidence directory immutable. Put subsequent runs in a separate directory and render both rounds with `--followup-evidence /absolute/followup/evidence --resolutions /absolute/followup/evidence/resolutions.json`. The JSON mapping uses `SDK/scenario-name` keys and `verdict`, `reason`, and `requires_old_pass` fields. A reviewed resolution requires a passing latest candidate; a paired fixture resolution additionally requires a passing latest baseline. This distinguishes an implemented fix or a documented fixture change from an unchanged flaky retry. All original attempts remain in the ledger, including fixture setup failures. Preserve repeated stability probes as raw evidence; they do not add unique scenarios.

The follow-up uses an explicit reachable Cloudflare upstream for DNS transport checks, enables TLS interception for strict Ruby HTTPS allowlists, and adds a negative opaque-HTTPS case. The scoped self-signed TLS check uses a controlled host-side TLS server and an explicit Rustls crypto provider. Apply the same fixture corrections to the old-source copy. These changes do not alter production networking defaults. The original external-endpoint timeout remains recorded without claiming a proven product root cause.

Run `retained_helpers_live` with `--features ssh` to include all three owned-helper scenarios. Full-memory progress and lifecycle cases require a compatible disposable checkpoint: write `/work/data` and its checksum to `/work/hash`, capture a full snapshot with the separately installed runtime, and provide `MSB_PROGRESS_SNAPSHOT`. The cancellation case additionally requires a fresh `cbh-*` test root and its documented unpinned, prepared memory-backing fixture; never run it against a normal user catalog. Follow the guards in `creation_progress_live.rs` and `eager_lifecycle_live.rs` rather than bypassing them.

For the Python return fix, build the selected native binding and install it into an isolated wheel environment before running the copied integration suite. The follow-up's full wheel contains the fixed debug native library; optimized local/remote release variants and package-size measurements were not regenerated. Artifact hashes identify that distinction.
