# Historical snapshot qualification

`historical-snapshots.py` creates fixtures using actual released CLI/firmware pairs, then restores them with a candidate. It currently covers the single-checkpoint directory and self-contained archive cells of the lifecycle compatibility matrix. A pass is a real guest checksum/metadata check followed by a write, stop, restart and persistent-write check. Parsing, importing, or starting a VM alone is insufficient.

The selected producers are 0.6.0 (the supported floor), 0.6.6 (the final `manifest.json` release), 0.6.7 (the following `snapshot.json` format), 0.6.18 (the end of the 0.6 line), and 0.7.8 (the released group/checkpoint format before the proposed CLI restructure). This selection does not claim every patch release or full-memory checkpoint is tested. Version 0.6 disk artifacts must not be described as memory checkpoints.

## Provision a producer

Download the matching platform bundle and its checksum list from the exact release. For example, on an Apple Silicon Mac:

```sh
mkdir -p /tmp/msb-historical-release/v0.6.0
gh release download v0.6.0 --repo superradcompany/microsandbox \
  --pattern microsandbox-darwin-aarch64.tar.gz --pattern checksums.sha256 \
  --dir /tmp/msb-historical-release/v0.6.0
python3 scripts/smoke/cli/historical-snapshots.py produce \
  --version 0.6.0 --release-dir /tmp/msb-historical-release/v0.6.0 \
  --output /tmp/msb-historical-fixture-060
```

For Linux x86-64 use `microsandbox-linux-x86_64.tar.gz`. The helper verifies the bundle checksum before extracting only the CLI and matching firmware, and checks the executable's exact version before creating a sandbox. Do not substitute a current firmware or agent for the producer. The released CLI supplies its own embedded agent. On Mac, the released signature must be valid; a locally built candidate needs the repository's VM entitlement signature.

The fixture uses a private short-path home under `/tmp`, explicit runtime/firmware selection, and no ambient `MSB_*` settings. Its source contains a random 4 MiB payload, 500 named files, a hardlink, a symlink and a non-default mode. It stops the source before capture, records integrity, exports the pinned image with the archive, and removes the source sandbox. The report includes binary/firmware/bundle hashes, platform, image descriptor, commands and original artifact hashes.

## Qualify a candidate

```sh
python3 scripts/smoke/cli/historical-snapshots.py qualify \
  --fixture /tmp/msb-historical-fixture-060 \
  --candidate /absolute/path/to/msb \
  --firmware /absolute/path/to/libkrunfw.5.dylib \
  --agent /absolute/path/to/matching/agentd \
  --output /tmp/msb-historical-result-060
```

Use the Linux firmware path on Linux. Omit `--agent` only when the candidate has its matching embedded agent. Every output directory must be new; failed runs and original fixtures are retained for diagnosis. The candidate gets another private home. Archive creation uses `--pull never`; the subsequent directory case reuses the image cache installed from that archive. Thus the directory case does not independently establish an image-free or fresh-cache restore. Directory migration operates on a private copy, never a hardlink to the original. The fixture inventory is checked before and after qualification. After directory restore, the original descriptor must remain byte-for-byte intact, either under its original name or as `.manifest.json.legacy` when migration occurred. Cleanup failures cannot produce a passing case.

The harness stops/removes its candidate sandboxes after each case. It retains private homes and logs for inspection; it never operates on the caller's normal home. Non-interactive stdin is explicit so commands cannot consume a surrounding SSH script. Commands have bounded timeouts and their own process groups. Interrupted supervisors are reaped; persistent runtime cleanup is attempted in the fixture's `finally` paths. Inspect cleanup results before deleting diagnostic homes after a failure.

Candidate reports identify an explicit agent by absolute path and SHA-256, or record that the candidate's embedded agent was selected. The historical harness entry points unwind on SIGTERM, reap their owned CLI/worker process groups and attempt both stop and removal for test-owned sandboxes. Interrupted commands and cases remain failed in the saved report; a cleanup or final inventory failure does not erase the original failure. Cross-host cleanup still attempts the known sandbox when its initial catalog audit fails, then performs a separate final audit. A cross-host full-memory success must verify the captured RAM generation and checksum as well as disk contents.

## Evidence and remaining cells

Keep `fixture.json`, original archives/directories, all command logs, and `report.json`. Each case records its own pass/fail result; a failed archive case does not silently skip the directory attempt. Record the exact candidate commit separately from the binary hash. Mac and Linux fixtures are separate producers; same-host passes do not prove cross-host transfer.

The complete PR4 acceptance matrix additionally requires dependent histories and missing dependencies, installed name/ID selectors where supported, cross-host movement, populated-cache/conflicting import, reordered image metadata and foreign VMDK paths, interrupted upgrade/import/downgrade and retry, and downgrade refusal for unrepresentable newer states. These cells remain required even after every baseline case in this harness passes. New saved-config artifacts need final qualification after PR3's capture and restore paths are enabled.

VM-free harness checks:

```sh
python3 -m unittest discover -s scripts/smoke/cli -p test_historical_snapshots.py
```

## Baseline qualification on 2026-10-20

The candidate product tree `2e9553feaaf446f626391f157f7b937784feef3d` passed the following baseline on Apple Silicon macOS and x86-64 Linux. Every cell includes actual guest checksum/metadata verification, a new persistent write across restart, unchanged originals, and successful candidate stop/removal. The final harness hash was `763a00129b2760560b7cc8723483e2ad79c8b4ad7ed8f1f3422f9a339e031384`.

| Producer | Mac archive | Mac directory | Linux archive | Linux directory | Descriptor after directory restore |
| --- | --- | --- | --- | --- | --- |
| 0.6.0 | Pass | Pass | Pass | Pass | Exact original retained as `.manifest.json.legacy` |
| 0.6.6 | Pass | Pass | Pass | Pass | Exact original retained as `.manifest.json.legacy` |
| 0.6.7 | Pass | Pass | Pass | Pass | Original `snapshot.json` unchanged |
| 0.6.18 | Pass | Pass | Pass | Pass | Original `snapshot.json` unchanged |
| 0.7.8 | Pass | Pass | Pass | Pass | Original `snapshot.json` unchanged |

The complete CLI harness unit suite passed 124 tests on each host, including seven new historical-harness checks. Earlier diagnostic runs exposed inherited SSH stdin consuming later commands; the final harness uses `DEVNULL` and verifies this behavior. Existing Python SQLite resource warnings remain in the broad harness output. This evidence establishes these baseline cells, not the additional scenarios listed above. It demonstrates that no new converter is necessary for these specific historical artifacts.

## Installed historical histories

`historical-installed.py` consumes the same exact-release fixtures and tests their imported group head and stable checkpoint ID. It also tests the local name when the archive records one; an older unnamed archive is reported as having no name selector, rather than receiving an invented alias. It checks idempotent import retries, malformed multi-archive batches into existing and new groups, subsequent successful retries, and whole-group verification. Failed batches must preserve installed members and head and must not publish the new group.

```sh
python3 scripts/smoke/cli/historical-installed.py \
  --fixture /tmp/msb-historical-fixture-060 \
  --candidate /absolute/path/to/msb \
  --firmware /absolute/path/to/libkrunfw.5.dylib \
  --agent /absolute/path/to/matching/agentd \
  --output /tmp/msb-historical-installed-060
```

The harness deletes its working archive inputs before any restored sandbox starts. Each supported selector must pass the guest checksum, filesystem-metadata and persistent-write-across-restart checks with `--pull never`, followed by successful stop/removal. Original fixture bytes remain untouched. `--temp-root` selects an existing short directory for private homes; use a disk-backed directory on Linux when `/tmp` has a quota. This qualification covers installed historical selectors and import retry/failure behavior, not dependent chains, cross-host movement, image-cache collision repair or the complete migration/downgrade matrix. `--pull never` alone is not proof that the host network was disabled; record any network isolation separately in the run evidence.

### Installed/offline qualification on 2026-10-20

The integrated product tree `fbb19f49b184797559128625fdb8e42598b32580` passes 11 installed-selector restores and 112 CLI calls on each host. Every selected release passes group-head and checkpoint-ID restore; 0.7.8 additionally passes its recorded checkpoint name. The tested 0.6 archives contain no local member name, so no name-selector pass is claimed for them. Each run also passes duplicate import, malformed batch refusal into existing/new groups, retry, whole-group integrity verification, guest checksums/metadata, persistent writes across restart, unchanged originals and cleanup. All ten offline fixture catalogs contain zero sandbox rows afterward.

Mac runs inherit a per-process sandbox profile denying outbound IP traffic; IPv4 and IPv6 connection probes both fail with `EPERM`. Linux runs execute as `ubuntu` in a private network namespace with no external route; the connection probe fails with `ENETUNREACH`. The host networking configuration is unchanged. Both hosts pass 129 CLI harness tests, including five new failure-accounting checks. An initial harness assumption that every archive has a member-name file was corrected after the real 0.6.0 import; it was not a product failure. These results complete these installed/offline cells, not the remaining historical matrix above.

## Released dependent disk and full-memory histories

`historical-chains.py produce --release-dir RELEASE --kind disk|full --output FIXTURE` uses a checksum-verified 0.7.8 CLI/firmware pair to capture three generations from a real running sandbox. It exports a complete base with its pinned image and two `--since` archives. The source sandbox is removed before qualification. The selected 0.6 producers always wrote `parent: None` in their capture implementation; do not fabricate dependent fixtures or describe their disk artifacts as full-memory snapshots.

`historical-chains.py qualify --fixture FIXTURE --candidate MSB --firmware FW --agent AGENT --output RESULT` checks missing and wrong bases, reversed-order batch import, whole-history integrity, direct multi-archive and directory restore, and installed restore after deleting both ancestors and every working input. Full histories additionally restore a member that actually borrows RAM and exercise CoW memory after ancestor removal. The omitted object must be referenced by the captured memory map; a reusable device-state object alone does not qualify as RAM coverage. Guest activity can change all memory chunks in a particular generation, so the harness selects an actual RAM-dependent member rather than assuming every incremental archive has one.

Each guest must preserve the seeded checksums, 500 files, hardlink/symlink/mode and expected generation marker. Full restores also check a 32 MiB random RAM payload and its generation marker before a stop; subsequent cold restart checks durable disk writes only. Producer and candidate logs, original directories/archives and fixture/report inventories remain available. A malformed fixture, incomplete dependency test, guest failure, changed original or failed cleanup cannot count as a pass. Use `--temp-root` for short disk-backed homes where necessary, and externally isolate IP egress when qualifying offline behavior.

### Dependent-history qualification on 2026-10-20

The integrated product tree `fbb19f49b184797559128625fdb8e42598b32580` passes eight offline restores and 72 candidate CLI calls per host on Apple Silicon macOS and x86-64 Linux. Each host produced its own exact-release 0.7.8 fixtures with 31 producer CLI calls. Three disk and five full-memory restores exercise reversed archive order, missing/wrong-base refusal without publication, directory restoration, ancestor removal and eager/CoW installed restoration. The selected full-memory archive omits actual RAM objects totaling 90 MiB on Mac and 98.5625 MiB on Linux; both restored the captured RAM contents successfully.

Both hosts pass all 133 CLI harness tests, including four dependency-fixture checks. The final four harness/support source hashes match. Each producer and candidate catalog contains zero sandbox rows afterward; original fixtures remain unchanged. Mac IPv4/IPv6 egress is denied by the inherited process profile, and Linux runs as ubuntu in a private network namespace without an external route. Initial harness assumptions about the historical file-payload kind and RAM reuse in every incremental member were corrected; those failed attempts remain diagnostic evidence and are not counted as passes.

These are same-host historical dependency results. Cross-host movement, cache collisions, reordered image metadata/foreign VMDK paths, the interrupted migration/downgrade/retry matrix and PR3's final saved-config artifacts remain required. No production code or format changes were needed for these cases.

## Transferred archives and populated caches

`historical-cross-host.py` separates portable archive handling from executable restore. Transfer a verified producer's `fixture.json` and unchanged standalone archive into each of `disk-060/fixture.msb`, `disk-078/fixture.msb` and `full-078/cp1.msb`. The last directory uses a successfully produced full-history fixture's complete base archive. Keep the original producer inventory in `fixture.json`; the helper validates the selected archive against that inventory without claiming that every original file was transferred.

```sh
python3 scripts/smoke/cli/historical-cross-host.py \
  --transferred /tmp/transferred-fixtures \
  --native-fixture /tmp/local-078-fixture \
  --candidate /absolute/path/to/msb \
  --firmware /absolute/path/to/libkrunfw \
  --agent /absolute/path/to/agentd \
  --output /tmp/cross-host-results
```

Use producer fixtures from the other CPU architecture and a native 0.7.8 disk fixture for `--native-fixture`. Each transferred archive must import, inspect and verify before launch is tested. A precise architecture refusal is recorded separately from a working guest. A native agent answering requests while the saved guest binaries fail to execute is a failed restore, not compatibility. Arbitrary parse errors or missing image failures do not count as architecture refusal.

The populated-cache case installs the native fixture, rewrites only the representation of image metadata JSON, and reimports it. Equivalent local metadata bytes must remain unchanged, the group membership/head must remain stable, and imported VMDK extents must resolve inside the destination cache. Importing the foreign image under the same reference must then report the specific content conflict without publishing a new group or replacing the native metadata. Finally, the native snapshot must still verify and restore its guest checksums, files, links and permissions. All sandbox catalogs must be empty after cleanup, and all input archive bytes must be unchanged. These checks use private homes and `--pull never`; apply and record external network isolation separately when claiming an offline run.

## Interrupted legacy descriptor migration and downgrade

`historical-recovery.py` uses genuine 0.6.0 or 0.6.6 fixtures and the SDK test executable built from the candidate tree (`cargo test -p microsandbox --lib --no-run --message-format=json` reports its path). The candidate CLI and guest agent must match each other. The test executable exposes an ignored subprocess driver; the pause hooks exist only under `cfg(test)` and are absent from shipped libraries.

```sh
python3 scripts/smoke/cli/historical-recovery.py \
  --fixture /tmp/msb-historical-fixture-060 \
  --candidate /absolute/path/to/msb \
  --test-binary /absolute/path/to/microsandbox-test-executable \
  --legacy-binary /absolute/path/to/released/v0.6.0/msb \
  --firmware /absolute/path/to/libkrunfw \
  --agent /absolute/path/to/matching/agentd \
  --output /tmp/historical-recovery-060
```

The harness runs nine separate cases: four upgrade boundaries (planned, descriptor publication, index publication, legacy retirement) and five downgrade boundaries (planned, canonical backup, legacy descriptor publication, legacy index publication, canonical retirement). Each case starts from an independent sparse copy of the original. The child runs the actual migration implementation, acknowledges its selected phase only after flushing a PID/action/phase marker, and then receives `SIGKILL`. A missing, stale or mismatched marker is a test failure, not evidence of a crash at the requested point.

Recovery reruns the operation against the same database and artifact, checks SQLite integrity and descriptor/index identity, then retries again to establish idempotence. Exact original legacy descriptor bytes and disk payload bytes must survive. Downgraded artifacts are inspected with `--verify` by the exact producer CLI before the candidate restores from a separate copy. Every successful case also verifies the actual guest's checksums, files, links and permissions, then writes data and checks its persistence across stop/start. Cleanup failures and changed original fixtures fail qualification. Reports and private working directories remain available for diagnosis.

These are process-crash tests of the `manifest.json` translation family. They do not simulate power loss, prove filesystem durability on other filesystems, qualify rollback of the CLI binary/database schema, or cover interrupted archive import and every later descriptor family. Downgrade inspection by the original CLI proves that reader path; it does not claim the old runtime was used to boot the recovered artifact. Apply and verify external IP isolation separately when reporting offline execution.
