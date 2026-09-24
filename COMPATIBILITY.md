# Microsandbox Compatibility Map

This document maps Microsandbox's non-public compatibility boundaries. It exists to help contributors and agents surface backward-compatibility risks early; it does not require every previous behavior to be preserved automatically.

When a proposed change crosses one of these boundaries, identify the risk before implementation. Do not silently add a shim, migration, fallback, or legacy implementation. Explain the compatibility directions involved, the failure mode, and the available choices, then follow the change-safety rules in `AGENTS.md`.

Public SDK, CLI, and HTTP API compatibility is intentionally outside this map. The focus here is the protocols, transports, durable formats, runtime ABIs, and lifecycle contracts that make existing Microsandbox installations and sandboxes continue to work.

## Compatibility Directions

Review every direction that applies to the change:

```text
new host ---------> old running sandbox / old agentd
new release ------> old MSB_HOME / database / runtime state
new reader -------> old disk / snapshot / archive / cache / metadata
old release ------> state written by the new release
exported artifact -> another release / platform / architecture
new component ----> independently running old component during upgrade
```

A clean, early refusal may be compatible when continued operation would be unsafe. Silent reinterpretation, partial mutation before refusal, stranded durable state, and corruption are not acceptable fallback behavior.

## System Boundaries

```text
CLI / SDK
   |
   | launch JSON + inherited descriptors or Windows config file
   v
host runtime <---------- JSON-lines control socket / named pipe
   |
   | local agent socket / named pipe
   | fixed frame header + CBOR
   v
relay <---- ring buffers ----> libkrun virtio console "agent"
                                  |
                                  v
                              guest agentd
                                  |
                   +--------------+---------------+
                   |              |               |
                bootstrap      filesystem      heartbeat

MSB_HOME
   +-- SQLite database and migration history
   +-- sandbox disks and volume data
   +-- snapshots and portable archives
   +-- OCI/materialization cache
   +-- filesystem metadata xattrs, ADS, and sidecars
   +-- sockets, locks, logs, journals, and shared memory
```

## 1. Host-to-Guest Agent Protocol

The agent protocol is the most explicit cross-version boundary. Its versioning policy is defined in [`crates/protocol/VERSIONING.md`](crates/protocol/VERSIONING.md).

The immutable outer frame is:

```text
[length: u32 big-endian][id: u32 big-endian][flags: u8][CBOR envelope]

CBOR envelope = { v: generation, t: wire message name, p: encoded payload }
```

Compatibility-sensitive elements include the header size, byte order, maximum frame size, ID routing, flag bits, CBOR envelope keys, message wire names, message introduction generations, payload field names and meanings, and terminal/session/shutdown semantics. The relay routes on IDs and flags without decoding CBOR, so changing the header cannot be hidden behind payload negotiation.

Evolution rules:

- Keep the outer frame shape stable.
- Add message types; never remove, rename, or redefine shipped wire types.
- Assign every new message type an introduction generation and bump the protocol generation.
- Make new payload fields optional or defaultable.
- Do not change a shipped field's meaning or type in place; use a version-specific type and converter for a genuine format break.
- Negotiate the lower peer generation and capability-gate every newer operation before sending it.
- Keep an old codec until the supported compatibility horizon deliberately moves; the current host still understands the pre-0.5 codec and handshake.
- Make any new flag bit safe for an old relay to ignore, or use a capability-gated message instead.

Sources and checks:

- [`crates/protocol/lib/message.rs`](crates/protocol/lib/message.rs) defines the generation, frame constants, flags, wire names, and message introduction map.
- [`crates/protocol/lib/codec.rs`](crates/protocol/lib/codec.rs) defines current framing and validation.
- [`packages/agent-client/rust/lib/client.rs`](packages/agent-client/rust/lib/client.rs) performs codec detection, version negotiation, and host-side send gating.
- [`crates/runtime/lib/runner/relay.rs`](crates/runtime/lib/runner/relay.rs) depends on ID ranges and flag semantics without decoding message bodies.
- [`crates/protocol/tests/schema_snapshot.rs`](crates/protocol/tests/schema_snapshot.rs) freezes the versioned surface and checks append-only message evolution.
- [`scripts/smoke/cli/pre05-running-sandbox-compat.sh`](scripts/smoke/cli/pre05-running-sandbox-compat.sh) exercises a current host against a real pre-0.5 running sandbox.

Required review should include golden encoded payload bytes when serialization changes. Schema snapshots protect the protocol inventory, but they do not freeze every payload's encoded representation.

## 2. Bootstrap, Init, and Guest Runtime Contract

The first current-protocol host frame is `core.bootstrap` with message ID zero and no flags. The guest then reports resolved init state, the relay installs identity mappings, the host acknowledges init, and only then may the guest become ready.

```text
host                     guest agentd
 |---- core.bootstrap ------>|
 |<--- core.init.resolved ---|
 |---- core.init.ack -------->|
 |<--- core.ready -----------|
```

Compatibility-sensitive elements include bootstrap field defaults and tagged variants, first-message ordering, root/mount/network/security encoding, bind identity exchange, hostname and environment behavior, handoff state, and legacy boot-environment spellings.

Stable guest/VMM identifiers and paths include:

- Virtio-console port name `agent`.
- Runtime virtiofs tag `msb_runtime`.
- Guest runtime mount point `/.msb` and its script, TLS, and heartbeat paths.
- Root block device `/dev/vda`.
- Additional disk lookup through `/dev/disk/by-id/virtio-<id>` with the existing sysfs fallback.
- Special host and guest shutdown delays used for normal termination and handoff.

Sources: [`crates/protocol/lib/bootstrap.rs`](crates/protocol/lib/bootstrap.rs), [`crates/protocol/lib/lib.rs`](crates/protocol/lib/lib.rs), [`crates/agentd/lib/agent.rs`](crates/agentd/lib/agent.rs), [`crates/agentd/lib/init.rs`](crates/agentd/lib/init.rs), and [`crates/runtime/lib/runner/vm.rs`](crates/runtime/lib/runner/vm.rs).

## 3. Local Agent IPC and Relay Routing

Unix clients and runtimes recognize canonical hashed socket paths, legacy flat hashed paths, and an older deep sandbox path. Windows uses named pipes derived from the legacy hash. The runtime publishes compatibility symlinks where safe and must not overwrite a live endpoint.

Compatibility-sensitive elements include the hash input and truncation, directory and socket names, Unix path-length fallback, Windows pipe names, compatibility symlinks, stale-endpoint cleanup ordering, lifecycle-lock paths, and lock ownership. Relay compatibility also depends on client ID-range allocation, maximum clients, terminal routing, disconnect cleanup, and shutdown flags.

Sources: [`crates/runtime/lib/client/ipc.rs`](crates/runtime/lib/client/ipc.rs), [`crates/runtime/lib/runner/relay.rs`](crates/runtime/lib/runner/relay.rs), and [`sdk/rust/lib/runtime/spawn.rs`](sdk/rust/lib/runtime/spawn.rs).

Path changes require an old-path probe or alias for the supported horizon. Never change a path hash or delete a socket until liveness and ownership have been resolved through the existing lock and endpoint checks.

## 4. Live-Control Protocol

The host runtime exposes a separate Unix socket or Windows named pipe for live modifications. Each connection exchanges one JSON request line and one JSON response line. Operations currently cover capability discovery, CPU and memory state or targets, and secret updates.

Compatibility-sensitive elements include newline framing, the tagged `op` names, response variants, resource field meanings, capability discovery, and the distinction between an absent endpoint, an unsupported operation, and a failed operation. Older runtimes predate capability discovery, and callers intentionally use operation-specific fallback behavior.

Sources: [`crates/runtime/lib/runner/control.rs`](crates/runtime/lib/runner/control.rs) and [`sdk/rust/lib/sandbox/modify.rs`](sdk/rust/lib/sandbox/modify.rs).

Windows control clients retry missing-pipe (`ERROR_FILE_NOT_FOUND`) and busy-pipe errors before sending a request, within one total one-second connection budget. Restore's remaining startup deadline can cancel that wait sooner. Other errors still fail immediately; established requests are never replayed. This tolerates asynchronous listener creation and gaps between pipe instances without changing protocol bytes, endpoint identities, or old-runtime capability semantics. A genuinely absent endpoint may now take up to one second to report unavailable instead of failing immediately.

Add operations and optional fields rather than redefining existing ones. Capability-gate behavior whose absence cannot be interpreted safely by older clients.

Live disk-only snapshots use the distinct `disk_checkpoint_create` operation and capability. An absent capability is false: callers refuse before capture rather than silently capturing RAM or copying a writable disk. The runtime serializes the disk rollover with other control mutations and preserves a user's pause. This does not change the agent protocol or snapshot format; the result uses the existing file-state layer descriptor. Stopped disk capture retains its lifecycle lock and existing behavior.

Resident pause/resume sends one authoritative mutation rather than first observing pause state and querying capabilities. The runtime checks support before mutation, including idempotent requests, and the client requires the expected state in the response; unknown operations and incomplete replies fail. Ordinary get/list pause projection remains unchanged. Guest freezing retains one `cgroup.events` descriptor and waits for notifications with a fixed deadline; each poll timeout is capped at 1 ms so rate-limited kernel notifications cannot delay the next authoritative state check. Clock correction still precedes workload thaw, and no control or agent wire format changes.

The subsequent unreleased generation-9 transport repair routes internal freeze/thaw directly from the coordinator to the existing relay through a bounded in-process queue. Ordinary control/bulk input is gated at complete frames; admitted input remains guest-owned until consumed, while unadmitted input stays source-owned and ordered. The guest keeps stdin/TCP delivery nonblocking with respect to its control loop and preserves accepted input through restore. Private replies and cumulative credit updates never become SDK responses. The immutable frame header, released generation-8 schema, and public sockets are unchanged. Full capture requires an acknowledged bidirectional frame boundary; failure or timeout does not authorize a partial capture.

## 5. Launcher-to-Runtime Process Protocol

In v0.7.0, the private launcher is `msb machine`; `msb sandbox` is the public command group and `sbx` is its alias. The current CLI also recognizes previous internal `msb sandbox` launches. The SDK selects the tested v0.6.x launch contract for previous executables and encodes the corresponding arguments and JSON. Public top-level verbs such as `msb run` remain supported.

Complete previous invocations use the separate boot-only decoder; `msb machine` retains strict execution-intent validation. Runtime selection keeps the unified setup API and its installed-binary precedence. Launch selection uses our embedded-version reader and cached previous contracts, without additional capability/help probes.

TCP limits retain the serialized `max_connections` key despite the canonical SDK field becoming `max_tcp_connections`. Optional UDP limits use `max_udp_connections`. Previous launches retain their TCP defaults/clamps and fixed 256-session UDP budget; explicit UDP limits require the current launch contract and are rejected before launching an older runtime. This prevents either direction of SDK/runtime version skew from silently broadening previous limits or ignoring an explicit new limit.

Starting a sandbox crosses a private process boundary. On Unix, launch JSON is passed through inherited descriptor 96, the parent watchdog uses descriptor 97, startup JSON uses descriptor 98, and the lifecycle lock uses descriptor 99. Windows uses a short-lived launch-config file and platform-specific startup plumbing. Detach acknowledgement bytes and graceful-shutdown signals are also part of this contract.

Compatibility-sensitive elements include descriptor numbers, ownership and close-on-exec behavior, launch JSON field names and defaults, startup response shape, watchdog EOF meaning, signal meaning, detach acknowledgement, secret transport, and parent/child cleanup ordering.

Windows runtimes before v0.6.16 do not hold the current lifecycle lock. For SDK-launched processes, the SDK atomically records the exact Windows process creation token, PID, sandbox/run IDs, and ownership mode in `<sandbox>/runtime/sdk-process.json` after guest readiness. Old runtimes and SDKs ignore this file; SQLite schemas and configuration payloads are unchanged. Legacy graceful stop verifies the named-pipe server against a retained process handle and waits for that same process object to exit. A terminal database row or an unused lifecycle lock alone cannot complete stop. The same record protects recovery and restart from recycled PIDs. Missing ownership evidence for a live legacy process produces an error instead of false success; a malformed record is not silently ignored. These checks never grant permission to force-kill a runtime.

Released Windows v0.6.10–v0.6.13 use libkrun v0.1.31, whose console can deliver bootstrap data before guest userspace opens its port. The libkrun fix is [`933467c`](https://github.com/superradcompany/libkrun/commit/933467c0320f72b69b40fd169a1f59f887f797f4), shipped in v0.1.32 and consumed by microsandbox v0.6.14. Native qualification reproduced the v0.6.10 startup failure with both the current SDK and its matching released SDK. An SDK launch adapter does not repair this defect inside the released executable; qualifying those exact binaries remains blocked.

User-supplied OCI writable uppers (`RootfsSource::Oci` with `RootDisk::DiskImage`) participate in exclusive disk-attachment admission, including duplicate checks against additional mounts. They use the existing canonical-path resolution, platform lock and runtime handoff; OCI base layers are not locked by this rule. This rejects simultaneous attachments that previously went unchecked, without changing disk bytes or launch protocols. An older launcher that omitted the lock remains undetectable through this mechanism. Windows retains the existing canonical-path sidecar identity, which does not unify distinct hard links to the same file.

On Linux, stop and kill also pin the departing runtime with a process pidfd, validating its inherited lifecycle descriptor before following it. This waits for the whole thread group rather than treating a zombie leader or lifecycle-lock release as completed disk teardown, and does not wait on a later sandbox's attachment to the same external disk. It does not reap the SDK's child or change descriptor handoff. This path requires `pidfd_open` (Linux 5.3 or later) and permission to inspect the runtime's `/proc` descriptors; unsupported or denied probes return an error rather than silently claiming completion. Already-exited or stale PIDs without the matching inherited lifecycle descriptor retain the existing lifecycle/resource reconciliation path.

On macOS, stop and kill observe the departing process through a `kqueue` exit registration, checking its process birth identity and existing lifecycle descriptor. Exit notification follows file-table teardown, unlike lifecycle-lock release alone. If registration races an already-exiting process, birth-identified `kern.proc.pid` observation waits for zombie/disappearance rather than treating a failed process lookup as completed cleanup. Observation does not reap the child, unlock its disks, or wait for a subsequent disk owner. Inspection failures remain errors. This changes host-side completion timing only; launch descriptors, lock paths, agent messages, and persisted state are unchanged in both SDK/runtime directions. It cannot release lock copies retained by an older SDK process.

Sources: [`crates/runtime/lib/client/launch.rs`](crates/runtime/lib/client/launch.rs), [`crates/runtime/lib/runner/vm.rs`](crates/runtime/lib/runner/vm.rs), [`sdk/rust/lib/runtime/spawn.rs`](sdk/rust/lib/runtime/spawn.rs), and [`crates/cli/lib/machine_cmd.rs`](crates/cli/lib/machine_cmd.rs).

Windows disk attachment retains the existing exclusive sidecar filenames and sharing mode. The launcher duplicates non-inheritable sidecar handles into the exact spawned process and sends their values through a bounded startup-only stdin message, required by the hidden `msb machine --disk-locks-stdin` flag. The runtime adopts them before opening guest disks; successful handoff closes the launcher's copies without an unlocked interval. The SDK sends this flag only to modern runtimes; previous runtimes retain launcher-owned locks and never receive the unsupported flag. Failed or cancelled handoffs terminate the child before storage cleanup; confirmed exit also clears any remaining parent copies. Stop/start observes owned-disk sidecar release, independently of retained SDK objects. This changes the Windows private launch contract, not SDK APIs, agent framing, snapshot formats, or disk bytes.

Unix disk-lock descriptors stay close-on-exec in the SDK parent and become inheritable only in the intended child's pre-exec callback. Successful spawn closes the parent's copies without explicitly unlocking the child's shared open-file descriptions. The runtime receives the same locked descriptors; this Unix handoff preserves fixed launch descriptors, JSON and paths. Stop and terminal restart additionally observe this sandbox's owned-disk marker locks under transition/lifecycle ownership, since a zombie leader and free lifecycle lock do not prove deferred file teardown finished. Named/external disks retain ordinary conflict admission. An already-running older development SDK can still retain its own parent lock copy; the new observer waits or times out rather than forcibly unlocking that genuine holder. Drop that old handle or restart that SDK process before retesting with the corrected handoff.

Launch JSON requires an explicit `execution` intent (`boot` or `restore`) and rejects unknown fields. Restores also pass the internal `msb machine --restore` argument: a runtime predating this contract rejects the unknown argument rather than ignoring a JSON restore source and cold-booting. The argument, intent, and complete strictly validated `checkpoint_restore` source must agree before VM construction. Unsupported restore behavior is an error, never a fresh-boot fallback. These #8 development contracts replace superseded unreleased forms without shims; they do not change portable snapshot bytes.

The launcher owns the child before awaiting its initial PID reply and while awaiting agent readiness. Cancellation at either wait immediately requests termination of that exact child; while the owning Tokio runtime remains available, a reaper retains the process handle and disk locks until exit. Explicit startup failure uses bounded termination/reaping and reports pending cleanup if exit cannot be confirmed. This is rollback of an unfinished launch, not a timeout or force-stop policy for an established sandbox. A creation guard now retains transition ownership through provisional-row insertion and final catalog publication, queues reconciliation behind cancelled writes on the single database writer, and only rolls back data after acquiring runtime lifecycle ownership. If bounded cleanup cannot prove exit, durable restore intent and storage remain; this does not promise indefinite in-memory retention or complete cancellation safety before named-volume provisioning finishes.

Startup progress extends the existing private startup channel; it does not introduce another socket. Preparation EOF is ordered after structured boot-error publication, while a flushed Activating frame permits normal channel closure. Asynchronous readiness/restore-activation failures also publish their actual cause before triggering exit. Optional preparation progress is coalesced and is not part of the guest agent protocol. Full restores announce Activating only after RAM, CPU, and devices reach the construction pause, including eager loading inside `Vm::enter`. Preparation has no fixed deadline; the creator retains cancellation, process ownership, and error handling. The existing bounded identity/clock acknowledgement, thaw, and public readiness waits begin afterward. Cold-boot deadlines are unchanged. Completed RAM byte progress alone is not the activation boundary.

The child database config retains `checkpoint_restore` while construction is incomplete. Only successful restore activation and creation finalization remove it. A failed or interrupted attempt retains its child-owned staging and rejects start, auto-start through exec, modification, compaction, and snapshot creation; remove and recreate it from the intact input snapshot. This replaces the earlier unreleased #8 behavior that discarded restore intent before success. Do not reopen these development rows with older #8 binaries that skip that field. Successful restores retain the ordinary later stop/start lifecycle; no portable snapshot format or schema version changes.

## 6. Database, Configuration, and Migration History

Rust patch names now match their targets: the shared `SandboxSpecPatch` replaces the old shared `SandboxConfigPatch` name, while the SDK derives `SandboxConfigPatch` from `SandboxConfig`. Rust callers must update imports and access shared settings through `.spec` on the SDK patch. The builder accepts the full SDK patch. These source API changes do not change configuration-file, persisted sandbox, or host/guest wire formats; runtime metadata remains internal and create-time credentials remain excluded from serialization.

The `ConfigPatch` derive always names patches `TypePatch` and generates `into_config()`, requiring the target type to implement `Default`. The `name`, `skip_into_config`, and `skip_accessors` options are removed. Custom derive users must update renamed patch references and implement `Default` or write their patch manually.

Generated per-field methods now inherit the source field's visibility, including setters, clears, replacements, and collection accessors. Callers that used public methods for private or restricted fields must move that access into the permitted scope or expose the source field. Fluent and `_mut` forms remain available. These are Rust source API changes; patch serialization and merge behavior are unchanged.

User and managed config readers default an omitted version to 1 and reject invalid or unsupported versions. User config writers emit `version: 1` and reject unsupported versions before saving. Managed files use generated patches over the existing value types. The documented v0.6.16 fixture is exercised in `sdk/rust/lib/config/persistence.rs`; this is not an older-binary execution test. Older binaries ignore the user version field and do not implement managed configuration. No sandbox records, database schemas, or host/guest formats change.

On Unix, managed configuration now rejects a file or immediate parent directory that is not root-owned or is group- or world-writable. Permission-inspection errors also reject loading. This replaces warning-only behavior in the unreleased managed-config branch: affected CLI/SDK backend construction fails until an administrator corrects deployment permissions. A missing managed file remains optional. ACLs, other ancestor directories, and Windows permissions remain outside these checks; file formats and existing backend instances are unchanged.

User-file I/O belongs to `GlobalConfigPatch`; `GlobalConfig` holds resolved values. Patch saves replace the saved settings without adding defaults, preserve explicit clears, and retain the existing field shapes and custom serializers. Unknown user fields are ignored when loading and discarded when saving, matching the previous behavior. Registry edits therefore leave unrelated omitted settings absent. Runtime diagnosis uses the same resolved user, environment/SDK, and managed settings as local backend construction. Configuration errors are reported instead of showing fallback runtime paths. Downgrade maintenance continues to resolve saved user settings independently of managed policy.

`sandbox_defaults.outbound_proxy` adds an optional default using the existing `OutboundProxy` wire type. Missing fields preserve existing behavior; older readers ignore the new global setting and cannot enforce it. Resolved sandbox and launch configurations use the existing proxy fields. In Rust, exhaustive `SandboxDefaults` literals need the new field (or `..Default::default()`), and `NetworkSpecPatch.outbound_proxy` is now `Option<Option<OutboundProxy>>` to distinguish omission from explicit clearing; generated proxy setters retain their signatures.

Rust local-backend construction now reports errors in config files and global constraints immediately: `LocalBackend::lazy()` and `LocalBackendBuilder::build_lazy()` return `Result`. Callers add `?` or handle the error; `try_build_lazy()` and `LocalBackend`'s `Default` implementation are removed. Language bindings propagate construction failures through their existing error types. Database setup remains lazy. Proxy defaults are validated after sandbox layering, before network use.

Direct builder creation now retains patches through image resolution and materializes once in the backend. `build()` and the concrete create APIs keep their signatures. For local creation, a concrete `workdir: None` now becomes an omitted patch field: it honors global workdir (including an explicit clear), and inherits image workdir only when global workdir is also omitted. Previously, concrete `None` skipped global workdir and inherited directly from the image. Rust callers using `Sandbox::create(config)` or `SandboxBuilder::from(config)` should supply a concrete workdir to fix its value, or use an explicit sparse patch clear when clearing is intended. Sparse user-file and builder `workdir: null` explicitly clears image defaults; omit the field to inherit them. Older binaries may fill an explicitly cleared workdir from image metadata. Configuration, sandbox-record, and host/guest wire shapes are unchanged. User and managed config structures ignore unknown fields; managed-file loading warns with their key paths without logging values. Existing value-type validation still applies. Final validation precedes replacement and sandbox-state writes; an OCI pull may precede final validation. Non-replacement OCI creation checks name availability before pulling, then rechecks under transition ownership before writing state; concurrent conflicts can still be detected after the pull.

The public `SdkConfig` type and `load_sdk_config()` exports are removed. Rust callers reading saved `active_profile` and `profiles` use `GlobalConfigPatch::load()`; callers needing effective local settings use `LocalBackend::config()`. This is a Rust source change, not a persisted-file change. Explicit `MSB_BACKEND=local` also reports malformed user configuration instead of silently discarding it.

Concrete `SandboxConfig` values with `placement_profile: None` or `outbound_proxy: None` now inherit global defaults on local creation, as workdir does. A sparse `Some(None)` explicitly clears them, and managed values still take precedence. The global proxy default is new; placement-profile inheritance changes behavior for existing Rust callers with configured defaults.

Registry host patches now merge individual fields. A managed TLS-only entry preserves user auth and ambient or per-call credentials; explicit `auth: null` suppresses them. Auth objects remain atomic replacements. Generated registry map setters now accept `RegistryEntryPatch` values; the public `RegistryEntry` value type and `LocalBackendBuilder::registry_hosts()` signature remain available. Serializing a complete `RegistryEntry` now writes `insecure: false` explicitly so converting that value to a sparse patch does not lose the setting. Saved sparse patches still omit unspecified fields. Older binaries understand the same fields but do not enforce managed policy.

Managed `deployment_profile: null` removes host enforcement. Managed `active_profile: null` (or an empty name) clears profile selection without clearing `MSB_BACKEND`; selecting a named local profile enforces local execution. These replace the pre-release branch's earlier clearing behavior. No released managed-policy format is being migrated.

Cloud backends now capture user settings and managed overrides during construction. Cloud sandbox creation and host-side SSH use those retained sources, with managed overrides applied last. Explicit cloud credentials no longer bypass an invalid user config file. Requests use the existing cloud wire fields; unsupported sandbox options fail before HTTP dispatch. Concrete cloud requests whose maximum CPU or memory equals the requested size keep those maxima tied to the final managed size, since cloud creation does not support a separate hotplug aperture. Existing cloud sandboxes and hosted SSH gateways are unchanged. The synchronous backend construction and resolution signatures remain unchanged.

Runtime SDK and environment path inputs are captured when a local backend is constructed. Changes take effect on a new backend; path accessors use its resolved settings and filesystem fallbacks without rereading managed policy. Callers constructing a bare `GlobalConfig` for path accessors or `setup::resolve_runtime()` must provide runtime path values themselves or obtain the resolved config from a backend. Language SDK setup helpers and the Cargo-installed wrapper resolve these layers before selecting a complete runtime pair. Snapshot restore rejects managed settings that conflict with captured root-disk layout or full-checkpoint CPU and memory geometry; it does not rewrite captured state.

The SQLite database under `MSB_HOME` is a durable protocol between releases. Host and runtime processes must also agree on WAL, busy timeout, foreign-key, synchronous, and writer settings.

Compatibility-sensitive elements include migration IDs and order, migration semantics, schema columns and constraints, persisted enum/tag spellings, JSON configuration shapes, desired versus active configuration, install and maintenance leases, allocation state, recovery journals, and the downgrade floor.

Evolution rules:

- Never reorder, rename, or reuse a shipped migration ID.
- Do not edit an applied migration to produce different previous results; add a new migration.
- Require applied migrations to form the canonical prefix and refuse a schema ahead of the current binary.
- Transform every persisted representation of changed state, including desired and active configurations.
- Journal multi-artifact operations durably and refuse startup or downgrade while an incomplete operation remains.
- Make downgrade either reconstruct the older representation exactly or refuse before mutating state.
- Preserve already-running runtimes' SQL and active-file contracts during upgrades. Exclusive installation and downgrade operations retain their own admission checks.

Sources: [`crates/db/lib/pool.rs`](crates/db/lib/pool.rs), [`crates/migration/lib/lib.rs`](crates/migration/lib/lib.rs), [`crates/migration/lib/schema_metadata.rs`](crates/migration/lib/schema_metadata.rs), and [`sdk/rust/lib/backend/local/mod.rs`](sdk/rust/lib/backend/local/mod.rs).

Local startup serializes database opening, migration, and snapshot reconciliation using the existing `msb.db.migration.lock` file and shared process-lock helper (`flock` on Unix, `LockFileEx` on Windows). This replaces the former Windows no-op without changing database schemas, lease semantics, or the lock path. Genuine exclusive install/downgrade operations still refuse normal startup. Older Windows binaries that bypass this lock do not participate in the serialization; do not initialize the same home concurrently with them. The shared helper creates owner-only lock files on Unix and refuses symlink lock paths.

Tests should open copies of real older databases, migrate them, exercise the affected behavior, and test every supported reverse migration or refusal path.

SDK and user-facing CLI catalog opens apply pending recognized migrations under the migration lock and install lease, including while older runtime processes remain active. Pending SQL migrations commit together. Fresh homes use the current SDK/CLI schema independently of the selected VM executable. Private `msb machine` launches still open runtime pools without performing migrations. Already-running VMs must retain working lifecycle writes, exit recording and resource cleanup; upgrade does not restart them or reinterpret their live configuration.

The upgrade transaction reserves SQLite's writer before migration reads, so concurrent lifecycle writes cannot interleave with partial schema changes. Older runtime writes may briefly wait for commit; migration duration and shutdown races need live qualification against their busy timeouts. After an upgrader exits, the next catalog opener can reclaim its dead-owner lease under the migration lock; live owners and incomplete downgrade journals still block admission. A downgrade rejected before artifact mutation retires its journal into a hidden `.cancelled-<operation-id>` directory, preserving diagnostic files without blocking ordinary commands. Once artifact mutation may have started, explicit downgrade recovery remains required.

Older SDKs/CLIs may refuse to reopen the upgraded catalog because its migration history is newer; preserving their catalog access is not the same guarantee as keeping their already-running VMs alive. Catalog migrations normalize previous configuration JSON before current readers deserialize it, including the saved active configuration of already-running VMs. Unknown migration identities still fail even when their count matches a known schema. These catalog rules do not replace launcher, agent, or snapshot-format capability checks.

Windows abandoned-lease recovery checks whether the process has exited, not merely whether its PID can be opened: another process may retain a handle to the terminated owner. Unix retains its conservative PID-existence check during resource teardown. Both paths preserve live owners, match the observed lease before clearing it, and refuse admission while an incomplete downgrade journal exists.

Downgrade operation ownership uses the existing `db/self-downgrade/msb.db.migration.lock` path and OS lock protocol, but competing commands fail immediately instead of waiting through another command's download or confirmation prompt. Ownership lasts through staging, execution and journal retirement, separately from the catalog migration lock. Exiting releases ownership without deleting the lock file or bypassing an incomplete recovery journal; an older command's lock still excludes a newer contender.

## 7. Home and Runtime Path Layout

Directory names under `MSB_HOME` and the runtime directory are durable locators used by binaries from different releases. This includes the database, cache, sandboxes, volumes, snapshots, logs, secrets, TLS material, SSH state, sockets, locks, journals, and configuration files.

Sources: [`crates/utils/lib/lib.rs`](crates/utils/lib/lib.rs) and [`crates/runtime/lib/client/ipc.rs`](crates/runtime/lib/client/ipc.rs).

Renaming a directory or file requires migration or old-location probing. Preserve atomic publication and cleanup ordering, and never infer that an unrecognized old path is safe to delete.

## 8. Disk and Filesystem Image Formats

Disk-image bytes outlive the binary that produced them. ext4 compatibility includes superblock feature flags, group descriptors, checksums, inode size and reserved inodes, 64-bit layouts, JBD2 journal state, resize-inode behavior, clean/dirty state, and replay requirements. EROFS and VMDK constants, descriptors, block sizes, extents, device tables, adapters, and alignment rules are likewise durable formats.

Sources: [`crates/image/lib/ext4`](crates/image/lib/ext4), [`crates/image/lib/erofs/format.rs`](crates/image/lib/erofs/format.rs), and [`crates/image/lib/stitch/vmdk.rs`](crates/image/lib/stitch/vmdk.rs).

Parsers and mutators must validate the complete supported feature set before their first write. Unsupported state must fail cleanly without partially updating metadata. Tests for mutators must use multiple previous layouts, dirty and journaled images, boundary sizes, failure injection, filesystem checkers, and post-operation mount/read/write verification where the platform permits.

## 9. Snapshots, Manifests, and Portable Archives

Dedicated full restore now requires captured external filesystem and additional-disk bindings by default. `--allow-missing-resources` and the equivalent SDK restore option explicitly retain unavailable devices; neither resource inheritance nor relaxed captured-object validation waives the completeness check. This is an intentional behavior change for new restore callers, not a snapshot or database migration. Direct branching and disk-only cold boot retain their existing resource-selection semantics. The check runs in the SDK before VM launch, including when using an older runtime. Only relaxed object validation combined with required backing sends the optional `require_backing` field inside the strictly decoded external-mount launch binding. That combination probes `required_restore_backing` through the existing `__launch-protocol` command and returns an upgrade-required error when unsupported. Ordinary strict restores omit the field and need no extra probe; older SDK requests retain their existing wire interpretation. Missing root/owned payloads, malformed snapshots, and incompatible mount flags are never waived. Custom-vsock route completeness is not enforced by this storage admission check; previous captures do not contain a portable route inventory.

Disk-generation manifests now carry an exact `file_size` and an optional `integrity_root`. Root disks and copied external/named disks in new full checkpoints and local branches default to structural validation without content hashing; explicit integrity capture records roots, and recorded roots are verified on portable admission. RAM object IDs and verification remain unchanged. This replaces the unreleased disk-generation contract without a format-version bump: earlier development checkpoints missing file sizes and older readers requiring disk roots are rejected. Released disk-only descriptors are unchanged. Control capability `optional_disk_integrity` gates full/branch capture on matching running runtimes; neither SDK launch nor root-disk journal initialization implicitly computes missing disk hashes. The Go FFI retains its existing branch calling convention and adds an optional, capability-checked integrity entry point. Sandbox-owned disks retain their existing journal integrity policy and record hashes during capture. Their portable descriptors also carry exact file sizes; readers check recorded hashes and always check lengths. Hashless owned layers remain included in archives rather than becoming hash-based borrowed dependencies.

Unreleased full checkpoints require an explicit `geometry` record in `checkpoint.json`: original CPU count/capacity and initial RAM/capacity. Live resize targets cannot substitute for the original guest-physical layout. Capture writes the public requirements summary from this runtime-owned record; restore rejects disagreement before RAM preparation. CPU and virtio-mem state retain the actual/requested counts and plugged-block bitmap separately, including unfinished resize operations. Earlier development full checkpoints missing these records are rejected, not guessed or migrated. This is an approved replacement of unreleased full state; released disk-only descriptors and archives are unchanged.

Snapshot descriptors carry a stable random `snap_...` ID; their canonical bytes determine the descriptor digest, not that ID. Compatibility-sensitive elements include field order, required `null` values, map ordering, duplicate-key handling, tag spellings, schema and integrity identifiers, payload names, parent identities, state/scope/format variants, extension requirements, and translation-graph behavior.

Archive compatibility includes compression detection, `archive.json`, canonical inventory order, transport digests, accepted path grammar, legacy paths, cache-closure entries, and rejection of duplicate, missing, or escaping paths.

Installed snapshots now live under `snapshots/<group>/<snapshot_id>/`. `group.json` selects a head; `group-member.json` stores a local friendly name without changing descriptor identity. Bare selectors mean a group head, and `group:member` selects an exact member. Existing flat artifacts remain readable by explicit path; this change does not silently move their directories. The index keys local artifact paths rather than globally unique portable IDs/digests, so importing the same snapshot into two groups preserves both copies. Downgrade refuses grouped state before rewriting artifacts or rolling back the index.

Capture records the actual source snapshot lineage in the existing descriptor `parent` field. Per-sandbox cursor publication serializes captures without holding a VM pause; group head publication is locked separately. Automatic head advancement requires known ancestry, not capture timestamps, export dependency bases, or import order. An explicit head selection may rewind or choose a sibling. Missing ancestry may prevent advancement but is not a missing payload dependency. Archives optionally carry friendly names in `msb-snapshot-member-names`; their snapshot IDs, payload paths and descriptor schema are unchanged.

Capture publication and source removal/replacement share a stable lock in `run_dir/locks/<lifecycle-hash>.snapshot-lineage.lock`, outside the removable sandbox directory. A caller needing multiple ownership guards acquires transition, then lineage, then runtime lifecycle ownership. The cursor remains in the sandbox directory; its schema and portable snapshot identities are unchanged. This replaces the unreleased directory-local lock, not a shipped artifact format.

`snapshot load` accepts multiple archive paths; the former positional destination is now `--dest DIR`. Single-archive SDK methods and their return types remain; batch methods return one handle per input archive head in input order. The batch resolves exact disk-layer and RAM-object dependencies from supplied archives, the explicitly selected destination group, and an optional external base. No archive encoding changes or global snapshot search are involved. Borrowed payloads belong to destination staging and use the existing integrity codecs before publication. A compatible source may contain more layers than the omitted prefix; dependency identities still must match. Direct archive restore retains its explicit-base contract.

Batch head selection is independent of input order: one proven lineage tip uses existing fast-forward rules; ambiguous tips preserve an existing head or leave a new group headless. `--set-head` refuses an ambiguous batch. IDs, aliases, duplicate labels, and payloads are checked before member publication. An I/O failure during final publication can still leave complete additional members, as with single-archive publication, but never a head pointing at an incomplete member.

Unreleased #8 incremental exports use `completeness: "dependent"` and the must-understand `msb-snapshot-dependencies-v1` extension. `--since` records omitted physical disk-prefix layers and reusable RAM-object identities; `--last-layers` only omits disk layers. The complete target memory manifest and CPU/device state remain included. Loading and direct archive restore resolve the explicitly supplied base into owned staging before opening the complete target. This replaces the unreleased disk-only dependency encoding without a compatibility shim or snapshot descriptor change. Readers that do not understand this requirement refuse it; ordinary standalone archives are unchanged.

Full checkpoints and local branches now retain `transport_host_input`, `transport_input_credit`, and `transport_guest_bulk_bytes` in the existing `guest:agentd` resource binding. These are complete-frame cumulative positions and absolute grants, including credit still owned by pending captured input. Restore validates and seeds them before guest activation; resetting them would incorrectly grant capacity twice. Older unreleased development full snapshots missing this state are refused, and new full captures require their matching host/guest implementation. This is an approved replacement of unreleased state, not a snapshot schema bump or migration; released disk-only snapshots are unaffected.

The finalized private transport-credit contract charges stdin, inline filesystem/TCP payloads, and ordered EOF to the existing logical data (`bulk_*`) counters on either physical port. Command/control counters remain available when captured input is still awaiting consumption. Ready advertises barrier contract `2`; the superseded development contract `1` is not translated or restored. The outer frame, generation-8 data format, snapshot descriptor schema, and public SDK requests are unchanged. The ordinary writer retains bounded admission permits until physical delivery, permits unrelated metadata to pass credit-blocked payloads, and preserves per-correlation and client-disconnect ordering. Guest input processing also yields to the runtime after bounded actual reads, including partial records; this does not shrink wire records or change snapshot boundaries.

Routine host clock maintenance is independent of unrelated correlation input, but stays ordered with other clocks and true global lifecycle fences. Its timestamp is sampled at console admission, not when queued; disconnect cleanup signals fence their own session only. Maintenance remains subject to the pause gate. This bounds host-queue timestamp age, not subsequent aging of already-admitted bytes during arbitrary host suspension or the kernel-only pause fallback when the workload freezer is unavailable.

Evolution rules:

- Do not make semantically harmless serialization changes to identity-bearing bytes without treating them as an identity format change.
- Keep legacy descriptor translation explicit; do not rely on a permissive generic reader when exact reconstruction matters.
- Use additive extensions with sorted must-understand requirements, or introduce a new schema plus forward and reverse translation.
- Publish payloads first and the verified descriptor last through temporary files, fsync, and atomic rename.
- Keep downgrade refusal until durable reverse artifact migration is complete.

Sources: [`crates/image/lib/snapshot/manifest.rs`](crates/image/lib/snapshot/manifest.rs), [`crates/image/lib/snapshot/migration.rs`](crates/image/lib/snapshot/migration.rs), and [`sdk/rust/lib/snapshot/archive.rs`](sdk/rust/lib/snapshot/archive.rs).

Runtime restore checks disk structure and exact file lengths before activation, and verifies content roots when recorded. Root-disk journal creation may reuse a recorded root only for the same unchanged immutable file; it never hashes an unrecorded layer implicitly. Its in-process cache retains at most 32 file handles, preferring larger physical files. Rewritten layers with recorded integrity receive a new root; unhashed layers remain unhashed. Detected mutation of a retained admitted file fails. Candidates are opened once per lookup, with comparisons bounded by the cache size. This reuse is not a persistent "verified" flag or a path-only cache, and the cache bound does not reduce supported chain depth.

Direct local branching prepares an immutable RAM baseline before freezing the workload; the paused capture still chooses the authoritative dirty generation and discards prepared baseline bytes when a complete capture is required. Linux local copies may use kernel-assisted extent transfers, while the explicit durable sparse-copy contract remains unchanged. Preparation time and allocated baseline bytes are recorded separately from guest dirty-page capture. This changes pause duration, not the captured epoch or durable snapshot format.

Linux ephemeral branching uses the capability-gated `branch_create_memfd` operation. The launcher creates an empty sealable memfd and transfers it with the first JSON byte over the existing control socket using SCM_RIGHTS. The source validates it before capture, fills it only when exact geometry and RAM admission allow, then applies write/grow/shrink/seal seals. The launcher already owns the object before source mutation; a read-only handle is inherited by the child at descriptor 95. The strict restore envelope's `memory_descriptor` field and local handoff's `memfd_lease` field require explicit descriptor-aware readers. Missing descriptors, mismatched geometry, and unsealed backing fail rather than becoming a pathname restore or cold boot. Descriptor requests are one-shot, not replayable control envelopes. No guest protocol or portable snapshot format changes.

The first capture still uses disk backing because configured guest MiB excludes some architecture-specific mappings. A reflink-capable backend or insufficient host/cgroup headroom also retains disk backing. Allocation failure before freeze releases partial RAM before one disk attempt. Changed topology discards the bounded reservation and uses a full disk capture. Ordinary non-Linux branch requests retain their existing named backing. A new Linux SDK refuses an old source without the descriptor capability before capture; an older runtime rejects the strict new restore fields. Existing disk handoffs remain readable. This replaces the unreleased named `/dev/shm` fast path without making previous RAM files eligible for automatic removal.

Only small, owner-only accounting records and stable handoff locks live under `/tmp/microsandbox-memory-<uid>/`; guest RAM does not. Pending captures reserve full capacity, completed generations account allocated backing bytes, and concurrent captures leave headroom for private writes. Source, launcher, and child pins protect accounting across handoff and source deletion. The kernel releases memfd bytes after all descriptor/mapping references disappear; later allocations reclaim unused lease records. This is potentially swappable local backing, not durable storage, a full-host admission guarantee, or zero-copy sharing between distinct generations.

Local disk handoffs retain child-owned immutable hardlinks and confined backing-name aliases. The child adopts these files and adds its own writable head instead of relocating the chain again. Older or imported non-basename references still use per-layer relocation. Optional host-owned admission receipts reuse integrity only for the same unchanged file identity, length and modification time; missing receipts use ordinary validation. Source journal durability is unchanged, and consumed handoff cleanup retains the child's disk layers for later cold restart. Mount-warning diagnostics are atomically replaced before readiness without a durability flush; they remain outside the guest-writable runtime share.

Incremental capture retains immutable object receipts only within the owning runtime's store lifetime. Reopened stores and unadmitted objects still verify bytes. Receipts retain no file descriptors; active operations open, check and temporarily pin the exact file. Capture uses two writers and three recycled 32 MiB packs, then synchronizes new directory entries before the existing root-last publication. Eager restore and cold memory-cache construction use at most four reusable 32 MiB read/hash buffers. Errors join workers before cleanup. These changes preserve the snapshot format and restored bytes, dirty-baseline rollover, pause/publication ordering and durability barriers; summed worker timings must not be interpreted as additive wall time.

Customer checkpoint fixes retain original construction geometry separately from actual/requested hotplug state. The virtio-mem device-local payload is schema 2: unplug acknowledgement now guarantees zero-on-reuse, and capture may represent actual unplugged blocks as zero without reading the reservation. Older development schema-1 device payloads cannot prove that promise and are rejected. Shrink and replug remain dirty transitions, so a delta replaces inherited nonzero bytes rather than leaving them implicit. This does not change the outer snapshot descriptor schema or released disk-only formats.

External filesystem capture uses defaultable freeze tags and an `external_mounts_synced` acknowledgement; absence is not proof of writeback. A full checkpoint with external mounts fails closed without that proof. Restored exports retain exact transport/node/handle identities; strict is default, and relaxed mode uses explicit EIO/ESTALE backends without recreating host data. Source-local authorization and restore warning records are host-only files in the sandbox directory, not the guest-writable runtime share. Cross-host archive paths grant no host authority. Managed additional disk volumes carry standalone immutable generations and become child-private disks; incremental root-prefix selectors never omit them accidentally.

For flat roots, `--with-image` archives may contain image configuration without layered EROFS/VMDK artifacts: the snapshot already supplies the whole root disk. Managed/tmpfs image dependencies still require the complete layered cache. An included layered cache must be complete even for a flat target; malformed partial bundles are not accepted. Older development readers that require layered artifacts refuse metadata-only bundles rather than silently cold-booting or substituting an image.

## 10. OCI Cache and Materializer ABI

The cache is rebuildable, but cache entries and closures can cross releases through `MSB_HOME` and snapshot archives. OCI semantics are externally defined: compressed descriptor digests, uncompressed diff IDs, ordered layers, whiteouts, opaque directories, hardlinks, extended attributes, non-UTF-8 paths, special files, and permissions must retain their meaning.

Flat filesystem cache identity includes a materializer ABI. Bump that ABI whenever emitted filesystem bytes or interpretation can change so incompatible entries miss instead of being reused. Preserve content-addressed verification and never retain bytes under a mismatched digest or size.

Sources: [`crates/image/MATERIALIZATION.md`](crates/image/MATERIALIZATION.md), [`crates/image/lib/cache/store.rs`](crates/image/lib/cache/store.rs), and [`crates/image/lib/flat.rs`](crates/image/lib/flat.rs).

## 11. Host Filesystem Metadata

Bind mounts and volumes persist virtual Linux stat information outside the guest. Linux uses the `user.msb.override_stat` xattr with a fixed packed versioned payload. Windows uses an alternate data stream or `.msb_override_stat` sidecar. The hidden synthetic `init.krun` entry is also a reserved filesystem contract used to inject agentd.

Compatibility-sensitive elements include xattr, ADS, and sidecar names; payload version, width, and byte order; uid, gid, mode, and rdev interpretation; symlink representation; path encoding; hidden-metadata filtering; reserved inode/handle values; and whiteout immunity.

Sources: [`crates/filesystem/lib/backends/shared/stat_override.rs`](crates/filesystem/lib/backends/shared/stat_override.rs), [`crates/filesystem/lib/backends/passthroughfs/windows`](crates/filesystem/lib/backends/passthroughfs/windows), and [`crates/filesystem/lib/backends/shared/init_binary.rs`](crates/filesystem/lib/backends/shared/init_binary.rs).

New metadata layouts require a new decoder version and, when old writers must consume the state, a migration or clean refusal before mutation.

## 12. Runtime, Agentd, Libkrun, Firmware, and Kernel Bundle

The runtime, embedded agentd, exact `msb_krun` version, libkrun ABI, firmware, and patched kernel form one release unit. Their interfaces include virtio feature bits, device config layouts, console behavior, metrics and CPU-capacity devices, vsock behavior, TSI behavior, firmware filenames, and platform-specific VMM backends.

Sources: [`Cargo.toml`](Cargo.toml), [`crates/filesystem/build.rs`](crates/filesystem/build.rs), [`crates/filesystem/lib/agentd.rs`](crates/filesystem/lib/agentd.rs), [`crates/utils/lib/lib.rs`](crates/utils/lib/lib.rs), and [`vendor/libkrunfw/patches`](vendor/libkrunfw/patches).

Do not independently substitute or upgrade one component because its upstream ABI appears compatible. Verify the release bundle as a unit on every supported OS and architecture, including the embedded matching agentd, firmware/kernel, library soname, device behavior, and package-version checks.

Normal x86 boot now declares `krun.poweroff=i8042` in libkrun's default kernel command line. Matching libkrunfw registers a low-priority final poweroff handler that sends the existing i8042 exit byte after orderly Linux shutdown. Generic KVM identity is not enough to enable it. Without both the host declaration and the new kernel, Linux may halt without releasing VMM ownership; StopWithTimeout reports expiry without killing. Existing running guests and full snapshots retain their captured kernel and require a fresh boot/recapture to acquire the handler. ARM platform poweroff, explicit custom command-line replacement and SEV/TDX built-in overrides are unchanged; they are not implicitly qualified by the normal Linux x86 test.

## 13. Networking, DNS, Published Ports, and Secret Substitution

Strict hostname policy is enabled by default. The v0.6.0–v0.6.17 launch gate rejects strict policies containing outbound hostname allow rules, including domain suffixes and rules applying in both directions. Policies without those rules retain their existing behavior on older runtimes because strict enforcement is unused. Explicit `strict: false` remains supported.

Observable network behavior is an effective compatibility contract. It includes default MTU, sandbox-slot address derivation, IPv4 subnet sizing, guest and gateway offsets, IPv6 prefixes, deterministic MAC addresses, interface name `eth0`, `host.microsandbox.internal`, DNS UDP and TCP behavior, DNS-over-TLS, TLS interception and trust paths, published-port binding, TCP half-close, UDP peer lifetime, destination policy, and host-side secret placeholder substitution.

Sources: [`crates/network/lib/lib.rs`](crates/network/lib/lib.rs), [`crates/network/lib/engine/network.rs`](crates/network/lib/engine/network.rs), and the remaining modules under [`crates/network/lib`](crates/network/lib).

Address or MAC changes can create collisions or silently alter policy identity. Protocol changes should be tested with real TCP, UDP, DNS, TLS, HTTP CONNECT, published-port, and secret-substitution clients, including fragmentation, half-close, cancellation, and denied-destination cases.

## 14. Vsock and SSH Protocol Adapters

Vsock stream and datagram routes have different message-boundary and shutdown semantics, with platform-specific Unix socket and Windows named-pipe backends. SSH maps exec channels to agent exec, SFTP to agent filesystem messages, and direct TCP forwarding to agent TCP messages. These mappings inherit agent protocol generation requirements.

Compatibility-sensitive elements include vsock port and route configuration, stream half-close, datagram boundaries, backend availability, SSH host-key and known-host persistence, authentication behavior, exit status and signal mapping, SFTP file semantics, and direct-tcpip capability gating.

Sources: [`crates/vsock/lib/stream.rs`](crates/vsock/lib/stream.rs), [`crates/vsock/lib/dgram.rs`](crates/vsock/lib/dgram.rs), [`crates/runtime/lib/runner/vm.rs`](crates/runtime/lib/runner/vm.rs), and [`sdk/rust/lib/sandbox/ssh.rs`](sdk/rust/lib/sandbox/ssh.rs).

Use standards-compliant clients in tests and exercise connections against older running agentd versions when changing the adapter-to-agent mapping.

## 15. Metrics Shared-Memory ABI

Metrics use a binary shared-memory structure across independently executing processes. The header and slots have fixed sizes, magic, registry version, ABI, atomics, seqlock ordering, generation counters, lifecycle states, and reserved bytes.

Sources: [`crates/metrics/lib/layout.rs`](crates/metrics/lib/layout.rs), [`crates/metrics/lib/registry.rs`](crates/metrics/lib/registry.rs), and [`crates/utils/lib/lib.rs`](crates/utils/lib/lib.rs).

Do not reorder fields, change widths or alignment, weaken atomic ordering, or redefine slot states under the same ABI. Incompatible changes must bump the registry version or ABI so old and new processes do not map the same object. Prefer checked-in offset and binary-layout fixtures in addition to total-size assertions.

## 16. Heartbeats, Boot Errors, Logs, and Runtime Diagnostics

Operational artifacts are consumed across process boundaries and can influence lifecycle decisions. These include `/.msb/heartbeat.json`, `boot-error.json`, `exec.log`, runtime and kernel logs, temporary filenames, JSON field names, sequence numbers, timestamps, source labels, rotation suffixes, and atomic rename behavior.

Heartbeat semantics are compatibility-sensitive: missing or stale data alone is not proof that a sandbox has died, while active sessions affect idle shutdown. Boot errors must remain available before agent readiness. Log schemas and rotation ordering must remain readable by current SDK consumers.

Sources: [`crates/protocol/lib/heartbeat.rs`](crates/protocol/lib/heartbeat.rs), [`crates/runtime/lib/runner/heartbeat.rs`](crates/runtime/lib/runner/heartbeat.rs), [`crates/runtime/lib/client/boot_error.rs`](crates/runtime/lib/client/boot_error.rs), and [`crates/runtime/lib/runner/exec_log.rs`](crates/runtime/lib/runner/exec_log.rs).

Add optional fields where readers are tolerant. Rename files or fields only with dual-read or migration behavior for the supported horizon.

## 17. Lifecycle, Locks, Leases, and Ordering

Compatibility can depend on operation order even when no serialized shape changes. Lifecycle locks, database run rows, PID ownership, endpoints, metrics slots, CPU and writeback allocations, heartbeat state, maintenance leases, signals, shutdown delays, and cleanup together determine whether a sandbox is live and who may mutate it.

Compatibility-sensitive ordering includes:

- Resolving lock and process ownership before replacing or deleting endpoints.
- Preventing database and artifact migration while incompatible runtimes remain active.
- Reserving, activating, marking stale, and freeing shared resources in the established order.
- Allowing agentd and the guest filesystem to drain before forced VMM termination.
- Writing and verifying payloads before atomically publishing their identity-bearing descriptor.
- Persisting a recovery journal before the first mutation and clearing it only after durable completion.

Sources: [`crates/runtime/lib/client/ipc.rs`](crates/runtime/lib/client/ipc.rs), [`sdk/rust/lib/backend/local/mod.rs`](sdk/rust/lib/backend/local/mod.rs), [`sdk/rust/lib/runtime/handle.rs`](sdk/rust/lib/runtime/handle.rs), and artifact-specific migration and publication modules.

TCP completion follows both ordered half-closes; the first EOF alone keeps the opposite direction usable. In combined-port mode, validated guest-to-host TCP credit may pass queued host-to-guest raw data and its finish marker: it services the opposite direction without reordering input data or EOF. Opening, cancellation, ownership, and global lifecycle fences still constrain it. Raw TCP output may still be draining on the dedicated lane after its producer finishes. Decoded credit updates for a finished producer or absent TCP session are therefore no-ops, not cancellation: they cannot enable further output, and must not discard the queued tail or create a second terminal response. Active producers retain credit validation; data and finish messages retain their existing validation.

Review concurrency and crash points explicitly. A same-version happy-path test does not establish cross-version or crash compatibility.

Graceful Stop now waits for terminal state plus released lifecycle ownership of the selected local run. Its bounded variant spends one total budget, including lock acquisition and dispatch; zero expires before dispatch, and expiry/cancelling the wait never selects Kill. Normal host and guest shutdown handlers no longer install fallback kill timers. RequestStop remains dispatch-only. These guarantees require the updated runtime/agent bundle; already-running older runtimes and full snapshots retaining older agent code retain their older shutdown implementation. Independent attached-handle, parent-death, idle, maximum-duration and startup-command lifetime policies are unchanged.

## Review Triggers in Diffs

When inspecting a proposed change, treat these patterns as compatibility tripwires:

- `serde` rename, tag, default, flatten, deny-unknown-fields, enum, or numeric-type changes.
- Modified magic values, protocol versions, feature flags, message names, operation names, IDs, reserved bits, or frame limits.
- Changed path constants, filenames, extensions, hashes, truncation lengths, mount tags, interface names, device names, xattr keys, ADS names, or environment variables.
- Changed canonical serialization, field order, sorting, hashing domains, digest algorithms, UUID derivation, parent identity, or archive inventory.
- Edits to an existing migration instead of a newly appended migration.
- Changed ext4, EROFS, VMDK, OCI, journal, inode, block, descriptor, or checksum logic.
- Changed `repr(C)` structs, shared-memory fields, atomic orderings, slot states, virtio feature bits, or device config layouts.
- Changed startup, readiness, shutdown, timeout, signal, lock, lease, rename, fsync, or cleanup order.
- Changed exact internal dependency pins, embedded-agent selection, firmware versions, sonames, bundle URLs, or platform artifact names.
- Removal of a legacy parser, codec, path probe, translation, fallback, migration, or compatibility test.

## Expected Evidence Before Declaring Compatibility Safe

Choose evidence proportional to the boundary and failure risk:

1. Unit tests for parsing, validation, capability gates, and clean refusal before mutation.
2. Golden bytes or checked-in fixtures for wire, canonical, binary-layout, and identity-bearing formats.
3. Copies of artifacts produced by supported older releases: databases, ext4 images, manifests, archives, cache entries, and metadata trees.
4. Real older binaries for live host-to-agent, local IPC, launcher/runtime, and bundle interoperability.
5. Forward migration plus supported reverse migration or downgrade-refusal tests.
6. Crash and failure injection around journals, metadata writes, fsync, rename, publication, and cleanup.
7. External validators such as filesystem checkers and standards-compliant SSH, SFTP, DNS, TLS, TCP, UDP, OCI, and archive readers.
8. Platform and architecture coverage for Linux/KVM, macOS/HVF, Windows/WHP, Unix sockets, named pipes, firmware, and packaged runtime artifacts.

If an applicable direction cannot be tested locally, state exactly what remains unverified and which CI, platform, previous binary, or fixture is required.

## Guest filesystem flush policy

Capture requests carry an optional `guest_flush` field gated by `guest_flush_policy` capability. Missing fields retain the previous crash-consistent policy for old clients; explicit `auto` requires writeback for live disk-only capture. New full-capture clients may omit Auto for an older runtime because its capture contract is unchanged, but cannot downgrade Required or Skip silently. Explicit-policy pause has a separate operation so an old runtime cannot acknowledge it as ordinary pause. Legacy `Pause` and resume wire forms remain unchanged.

The existing guest freeze protocol carries `path:/` and captured storage selectors and acknowledges successful synchronization. The host retains the exact requested set only after that acknowledgement; a successful empty-set request never proves a root flush. Coverage is tied to the resident pause generation and is not serialized as a new portable snapshot format. Required writeback on a stopped guest or an unflushed paused guest fails before disk rollover; the runtime never resumes a paused guest implicitly.

The owned-block flush correction makes root and owned block writeback follow the selected policy rather than the mere presence of an owned mount. Explicit Skip disk snapshots now promise only crash-consistent block data. Auto full capture, branch, and plain pause no longer flush those block filesystems implicitly. Host-backed directory barriers and host disk drain/seal/durability remain unchanged. Older callers omitting capture policy also lose incidental owned-block writeback, retaining only their crash-consistent disk-capture contract; use a policy-aware caller with Auto or Required when guest writeback is needed. No request field, capability, guest protocol, or persisted format changes. Existing running runtimes retain their previous selection until restarted.

The Go native ABI adds an optional explicit-policy pause symbol, also used to detect support for policy fields on existing JSON capture/batch entry points. New Go clients refuse unavailable semantics rather than let an older library ignore those fields. Existing exported signatures remain unchanged. The Rust public capture configuration gains `guest_flush` with a serde default; Rust struct-literal callers must include the field. No agent protocol, archive schema, or database migration changes.

The approved Go exception covers all disk-capture entry points, including the handle convenience method and stopped sources: they require a policy-aware native library. Full Auto capture and unrelated operations remain compatible with older native libraries. This is separate from the running VM's capability gate; updating only the Go package cannot teach an old native library to enforce Auto's live-disk guarantee.

## Capture-once branch batches

`branch --names` and SDK batch methods reuse the existing local branch capture/restore envelope. The batch retains a process-local RAM pin and temporary owner-only links to immutable CPU/device/disk state; each child acquires its own links, RAM handle, writable disks, and VM generation identity. Nothing new is serialized into launch JSON, the database, or portable snapshots. Single-name branching still captures the current source state on each call. Batch names and known conflicts are checked before capture; per-child reservations remain authoritative against races. Validation/capture failures fail the call, while later startup failures return named outcomes without recapture or rollback of successful children. The Go FFI adds an optional batch symbol and refuses older native libraries without it rather than looping over single captures. Temporary batch staging is released on normal completion or cooperative cancellation; process-kill crash recovery is not a durable snapshot guarantee.

Batch startup is bounded and concurrent after the designated producer publishes its capture, including the producer child's own remaining startup. Results remain in input order, but runtime visibility, resource contention and readiness order are not ordered. Cancellation can therefore leave a different subset of already-successful detached children; unfinished children retain ordinary creation rollback ownership. No failed child retries capture. Unix disk-lock descriptors stay close-on-exec in the launcher and only the intended child inherits them; the runtime's existing lock lifetime and launch envelope are unchanged. Contended named-volume waits yield instead of blocking the startup executor, without changing their exclusion scope or persisted formats.

Named-volume provisioning now enforces that same name exclusion on Windows through the existing process-held file-lock primitive. Previously that platform's name lock was a no-op; concurrent batch children must wait for the first provisioner rather than race to create a volume or its catalog row. Unix locking and measured Linux startup behavior are unchanged.

### v0.6 secret policy translation

The catalog migration, previous launch codecs, and downgrade conversion share JSON field remapping, validated against the current types, in `microsandbox_types::compat::v0_5_0::local::secrets`. Unknown saved fields remain visible to preservation checks; the codec does not silently discard them. They translate `query_params` to `query` and merge previous `headers` and `basic_auth` into `headers` using logical OR. This approved mapping broadens substitution when the old switches differed. Explicit global passthrough defaults remain in `SecretsConfig.passthrough_hosts`; explicit per-secret passthrough remains in `SecretEntry.passthrough_hosts`. A per-secret blocking action overrides the global passthrough default. Changing the default violation action preserves passthrough settings.

The selected runtime's enforcement applies. v0.7 does not preserve the old implicit forwarding of placeholders in disabled locations, and rejects all-disabled substitution. No legacy-injection marker or generated allowed-host passthrough is retained. Modern launches materialize only explicit global defaults into per-entry destinations; persisted defaults remain available for future additions. Previous writers emit both header switches from the combined setting and reject unrepresentable policies. Catalog upgrade migrates secret policies in both `config` and `active_config` to the current format. It also normalizes older image, mount, CPU and pull-policy spellings required by current readers, retaining other supplied fields. Application readers deserialize the migrated format directly; previous records written afterward by old SDK processes are not supported. As with earlier config migrations, an already-open older SDK process is not protected from the new stored format: stop old SDK processes before sharing the upgraded catalog. This is separate from preserving already-running sandbox VMs.

`msb self downgrade` projects secret policies in both `config` and `active_config` before schema rollback. Preflight runs the same conversion on a database copy before artifact changes. Conversion and schema rollback commit together, including targets requiring no schema steps. Secret configs already in the previous format are left byte-for-byte unchanged. Failure identifies the sandbox and column without exposing secret values. The released-SDK integration test creates with the selected previous SDK, modifies/saves through the candidate SDK, invokes the CLI preflight and rollback functions, then restarts and checks data and HTTP substitution with that previous SDK. `MSB_TEST_OLD_VERSION` selects the target, defaulting to v0.6.18. It does not run the installer or change public command links.

A malformed saved row aborts the entire upgrade before any converted row is written. The error identifies the sandbox name, ID, and configuration column without including secret values. Stop SDK processes sharing that home, back up the home, and use the previous SDK/CLI to repair the named sandbox or remove it if its data is no longer needed; then retry the upgrade. Do not edit the migration history or skip the row. Valid previous policies with every substitution location disabled can migrate, but launching them under v0.7 requires enabling a substitution location or removing that secret policy.

Downgrade to v0.6.5 also restores that release's CPU and mount spellings. Its accepted image aliases are retained so older schema rollback steps can still recognize them. Migration history comparison accepts the shipped v0.6.16 ordering of the same complete migration set; missing, duplicate, or unknown migrations still refuse rollback. Isolated file mounts are supported when targeting v0.6.16–v0.6.18 and refused before creation for earlier runtimes. Linux installers accept the firmware basenames shipped by supported v0.6 releases and retain aliases for older SDK discovery; duplicate firmware entries are rejected before publication.

Downgrade to released v0.7.0–v0.7.2 also preflights both configuration columns, even without schema steps. Those targets cannot preserve a global secret passthrough default, so its presence (including an empty list or previous spelling) refuses the downgrade before changing artifacts or the live catalog. When no schema rollback is needed, this check reads the live catalog without requiring stopped sandboxes, a backup, or a preflight database copy. Schema rollbacks and v0.6 config rewrites retain their existing safeguards. Supported v0.7 configurations remain byte-for-byte unchanged; flattening the default into existing entries would lose inheritance for future secrets.

Adding `passthrough_hosts` to the public Rust `SecretsConfig` and `CloudSecretsConfig` structs is an accepted Rust source-compatibility break. Direct struct literals must initialize the field or include `..Default::default()`; exhaustive destructuring must include the field or `..`. Existing builders and literals already using defaults need no changes. The domain field remains hidden from generated TypeScript/OpenAPI because it carries previous local defaults; the cloud contract exposes its own field. This does not introduce a Python or TypeScript call-signature change.

The populated global-passthrough fixture is hand-extended from captured v0.6.18 configurations, with inherited, blocking-override, and per-entry passthrough policies. It exercises persistence and cloud round trips, runtime projection, and downgrade without claiming another released-runtime capture.

The shared cloud decoder accepts both previous and current secret field names. Cloud must adopt the updated types/runtime to support both deployed contracts; changing the SDK alone is insufficient. The cloud contract retains optional global `passthrough_hosts` through serialization and domain conversion, so later secret additions inherit the default. Per-secret blocking overrides still take precedence.

## Compatibility code organization

Apply these guidelines when implementing an approved compatibility change:

- Group previous contracts under the owning crate's `compat/v<major>_<minor>_<patch>/`, named for the release that introduced the format. Reuse that module until the format changes; do not create a directory for every supported release. These directories describe contracts, not sequential migration steps. Split `local/` and `cloud/` only where their contracts differ.
- Keep saved-config conversion in the DB crate, runtime launch readers with the runtime, SDK runtime selection with the SDK, and shared wire types in the types crate. Keep current domain types outside versioned compatibility modules.
- Keep dispatch at the boundary and version-specific conversion inside its version module. Prefer explicit format versions or capabilities; isolate field-based detection needed for existing unversioned payloads. Never retry malformed current input as an older format.
- Prefer concrete Rust types for wire formats. Use `to_current` and `to_previous_version` for conversions, `encode` and `decode` at serialization boundaries, and `deserialize_*` for serde callbacks. Reuse types where contracts match; avoid duplicate representations, marker fields, and wrappers without a concrete behavioral need.
- Rewrite saved formats through DB migrations, then use ordinary current-type deserialization for normal reads and writes. JSON remapping is appropriate for migrations that must preserve unknown fields. Assess shared `MSB_HOME` SDK processes separately from running VM processes; follow the [database migration rules](#6-database-configuration-and-migration-history).
- Preserve defaults, field presence, and global versus per-entry overrides, including defaults for entries added later. Report behavior that cannot be represented before choosing a fallback. Downgrade preflight must catch incompatible state before mutation; migration failures must remain atomic and give actionable, secret-safe recovery context.
- Follow the [validation requirements](#expected-evidence-before-declaring-compatibility-safe) using released SDKs/runtimes and version-labeled fixtures. Include upgrade → edit/save → downgrade → restart, failed-migration rollback, and older readers of newly written artifacts where supported. Check cloud deployment order separately; local compatibility does not establish cloud compatibility.

### Current module layout

| Responsibility | Location |
| --- | --- |
| Shared contracts | `packages/microsandbox-types/rust/lib/compat`: `v0_5_0/local/secrets`, `v0_6_5/cloud/create`, `v0_6_7/cloud/secrets`, and `v0_7_0/local/secrets`. |
| Saved-config migration and downgrade conversion | `crates/db/lib/compat`: dispatch and record preparation in `config.rs`; adapters in `v0_5_0/secrets`, `v0_6_5/config`, and `v0_7_0/secrets`. The CLI owns preflight and rollback transactions. |
| Cloud dispatch | The types crate's `compat/cloud.rs`. |
| SDK executable discovery, contract selection, preflight, and outgoing encoding | `sdk/rust/lib/runtime/launch_contract.rs`; `launch_input.rs` holds previous environment-encoding helpers. |
| Runtime incoming launch readers | `crates/runtime/lib/client/compat/launch.rs` selects readers and shares previous launch fields and conversion; `network.rs` shares network compatibility decoding. |

Known destination releases use `semver::Version` across CLI downgrade and SDK launch selection; each compatibility layer owns its own release boundaries. Each versioned `to_previous_version` adapter prepares that contract or rejects settings it cannot preserve; the DB's v0.7.0 adapter returns no rewrite for supported records.

Incoming unversioned launch/cloud requests retain detection of previous formats. Cloud requests continue using the existing `/v1` API without a separate body version. Readers accept previous and current request formats; additional cloud contract versioning is deferred until a concrete incompatible change requires it. Explicit launch-message versioning remains separate follow-up work.

The runtime dispatcher selects the current reader when `execution` is present, `v0_6_10/launch.rs` when `bootstrap` is present, and `v0_5_9/launch.rs` otherwise. `client/launch.rs` contains both `LaunchConfig` and the `LaunchCapabilities` probe response. The launch type remains in the runtime crate to avoid a dependency cycle. SDK tests exercise its encoder against the runtime decoder; runtime tests also consume independently captured release payloads.

Launch and cloud requests reject duplicate recognized fields and conflicting previous/current spellings. Previous saved-format decoding and the duplicate-key JSON fixture reader in the SDK are test-only.
