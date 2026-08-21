# Microsandbox Compatibility Map

This document maps Microsandbox's non-public compatibility boundaries. It exists to help contributors and agents surface backward-compatibility risks early; it does not require every historical behavior to be preserved automatically.

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
- [`crates/runtime/lib/relay.rs`](crates/runtime/lib/relay.rs) depends on ID ranges and flag semantics without decoding message bodies.
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

Sources: [`crates/protocol/lib/bootstrap.rs`](crates/protocol/lib/bootstrap.rs), [`crates/protocol/lib/lib.rs`](crates/protocol/lib/lib.rs), [`crates/agentd/lib/agent.rs`](crates/agentd/lib/agent.rs), [`crates/agentd/lib/init.rs`](crates/agentd/lib/init.rs), and [`crates/runtime/lib/vm.rs`](crates/runtime/lib/vm.rs).

## 3. Local Agent IPC and Relay Routing

Unix clients and runtimes recognize canonical hashed socket paths, legacy flat hashed paths, and an older deep sandbox path. Windows uses named pipes derived from the legacy hash. The runtime publishes compatibility symlinks where safe and must not overwrite a live endpoint.

Compatibility-sensitive elements include the hash input and truncation, directory and socket names, Unix path-length fallback, Windows pipe names, compatibility symlinks, stale-endpoint cleanup ordering, lifecycle-lock paths, and lock ownership. Relay compatibility also depends on client ID-range allocation, maximum clients, terminal routing, disconnect cleanup, and shutdown flags.

Sources: [`crates/runtime/lib/ipc.rs`](crates/runtime/lib/ipc.rs), [`crates/runtime/lib/relay.rs`](crates/runtime/lib/relay.rs), and [`sdk/rust/lib/runtime/spawn.rs`](sdk/rust/lib/runtime/spawn.rs).

Path changes require an old-path probe or alias for the supported horizon. Never change a path hash or delete a socket until liveness and ownership have been resolved through the existing lock and endpoint checks.

## 4. Live-Control Protocol

The host runtime exposes a separate Unix socket or Windows named pipe for live modifications. Each connection exchanges one JSON request line and one JSON response line. Operations currently cover capability discovery, CPU and memory state or targets, and secret updates.

Compatibility-sensitive elements include newline framing, the tagged `op` names, response variants, resource field meanings, capability discovery, and the distinction between an absent endpoint, an unsupported operation, and a failed operation. Older runtimes predate capability discovery, and callers intentionally use operation-specific fallback behavior.

Sources: [`crates/runtime/lib/control.rs`](crates/runtime/lib/control.rs) and [`sdk/rust/lib/sandbox/modify.rs`](sdk/rust/lib/sandbox/modify.rs).

Add operations and optional fields rather than redefining existing ones. Capability-gate behavior whose absence cannot be interpreted safely by older clients.

## 5. Launcher-to-Runtime Process Protocol

Starting a sandbox crosses a private process boundary. On Unix, launch JSON is passed through inherited descriptor 96, the parent watchdog uses descriptor 97, startup JSON uses descriptor 98, and the lifecycle lock uses descriptor 99. Windows uses a short-lived launch-config file and platform-specific startup plumbing. Detach acknowledgement bytes and graceful-shutdown signals are also part of this contract.

Compatibility-sensitive elements include descriptor numbers, ownership and close-on-exec behavior, launch JSON field names and defaults, startup response shape, watchdog EOF meaning, signal meaning, detach acknowledgement, secret transport, and parent/child cleanup ordering.

Sources: [`crates/runtime/lib/launch.rs`](crates/runtime/lib/launch.rs), [`crates/runtime/lib/vm.rs`](crates/runtime/lib/vm.rs), [`sdk/rust/lib/runtime/spawn.rs`](sdk/rust/lib/runtime/spawn.rs), and [`crates/cli/lib/sandbox_cmd.rs`](crates/cli/lib/sandbox_cmd.rs).

This protocol has no explicit version envelope. Treat additions as optional and consider adding explicit version or capability negotiation before allowing independently versioned launchers and runtimes.

## 6. Database, Configuration, and Migration History

The SQLite database under `MSB_HOME` is a durable protocol between releases. Host and runtime processes must also agree on WAL, busy timeout, foreign-key, synchronous, and writer settings.

Compatibility-sensitive elements include migration IDs and order, migration semantics, schema columns and constraints, persisted enum/tag spellings, JSON configuration shapes, desired versus active configuration, install and maintenance leases, allocation state, recovery journals, and the downgrade floor.

Evolution rules:

- Never reorder, rename, or reuse a shipped migration ID.
- Do not edit an applied migration to produce different historical results; add a new migration.
- Require applied migrations to form the canonical prefix and refuse a schema ahead of the current binary.
- Transform every persisted representation of changed state, including desired and active configurations.
- Journal multi-artifact operations durably and refuse startup or downgrade while an incomplete operation remains.
- Make downgrade either reconstruct the older representation exactly or refuse before mutating state.
- Resolve active runtimes and install leases before migrating shared state.

Sources: [`crates/db/lib/pool.rs`](crates/db/lib/pool.rs), [`crates/migration/lib/lib.rs`](crates/migration/lib/lib.rs), [`crates/migration/lib/schema_metadata.rs`](crates/migration/lib/schema_metadata.rs), and [`sdk/rust/lib/backend/local/mod.rs`](sdk/rust/lib/backend/local/mod.rs).

Tests should open copies of real older databases, migrate them, exercise the affected behavior, and test every supported reverse migration or refusal path.

## 7. Home and Runtime Path Layout

Directory names under `MSB_HOME` and the runtime directory are durable locators used by binaries from different releases. This includes the database, cache, sandboxes, volumes, snapshots, logs, secrets, TLS material, SSH state, sockets, locks, journals, and configuration files.

Sources: [`crates/utils/lib/lib.rs`](crates/utils/lib/lib.rs) and [`crates/runtime/lib/ipc.rs`](crates/runtime/lib/ipc.rs).

Renaming a directory or file requires migration or old-location probing. Preserve atomic publication and cleanup ordering, and never infer that an unrecognized old path is safe to delete.

## 8. Disk and Filesystem Image Formats

Disk-image bytes outlive the binary that produced them. ext4 compatibility includes superblock feature flags, group descriptors, checksums, inode size and reserved inodes, 64-bit layouts, JBD2 journal state, resize-inode behavior, clean/dirty state, and replay requirements. EROFS and VMDK constants, descriptors, block sizes, extents, device tables, adapters, and alignment rules are likewise durable formats.

Sources: [`crates/image/lib/ext4`](crates/image/lib/ext4), [`crates/image/lib/erofs/format.rs`](crates/image/lib/erofs/format.rs), and [`crates/image/lib/stitch/vmdk.rs`](crates/image/lib/stitch/vmdk.rs).

Parsers and mutators must validate the complete supported feature set before their first write. Unsupported state must fail cleanly without partially updating metadata. Tests for mutators must use multiple historical layouts, dirty and journaled images, boundary sizes, failure injection, filesystem checkers, and post-operation mount/read/write verification where the platform permits.

## 9. Snapshots, Manifests, and Portable Archives

Snapshot descriptor bytes are identity-bearing: their canonical bytes determine the snapshot ID. Compatibility-sensitive elements include field order, required `null` values, map ordering, duplicate-key handling, tag spellings, schema and integrity identifiers, payload names, parent identities, state/scope/format variants, extension requirements, and translation-graph behavior.

Archive compatibility includes compression detection, `archive.json`, canonical inventory order, transport digests, accepted path grammar, legacy paths, cache-closure entries, and rejection of duplicate, missing, or escaping paths.

Evolution rules:

- Do not make semantically harmless serialization changes to identity-bearing bytes without treating them as an identity format change.
- Keep legacy descriptor translation explicit; do not rely on a permissive generic reader when exact reconstruction matters.
- Use additive extensions with sorted must-understand requirements, or introduce a new schema plus forward and reverse translation.
- Publish payloads first and the verified descriptor last through temporary files, fsync, and atomic rename.
- Keep downgrade refusal until durable reverse artifact migration is complete.

Sources: [`crates/image/lib/snapshot/manifest.rs`](crates/image/lib/snapshot/manifest.rs), [`crates/image/lib/snapshot/migration.rs`](crates/image/lib/snapshot/migration.rs), and [`sdk/rust/lib/snapshot/archive.rs`](sdk/rust/lib/snapshot/archive.rs).

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

## 13. Networking, DNS, Published Ports, and Secret Substitution

Observable network behavior is an effective compatibility contract. It includes default MTU, sandbox-slot address derivation, IPv4 subnet sizing, guest and gateway offsets, IPv6 prefixes, deterministic MAC addresses, interface name `eth0`, `host.microsandbox.internal`, DNS UDP and TCP behavior, DNS-over-TLS, TLS interception and trust paths, published-port binding, TCP half-close, UDP peer lifetime, destination policy, and host-side secret placeholder substitution.

Sources: [`crates/network/lib/lib.rs`](crates/network/lib/lib.rs), [`crates/network/lib/network.rs`](crates/network/lib/network.rs), and the remaining modules under [`crates/network/lib`](crates/network/lib).

Address or MAC changes can create collisions or silently alter policy identity. Protocol changes should be tested with real TCP, UDP, DNS, TLS, HTTP CONNECT, published-port, and secret-substitution clients, including fragmentation, half-close, cancellation, and denied-destination cases.

## 14. Vsock and SSH Protocol Adapters

Vsock stream and datagram routes have different message-boundary and shutdown semantics, with platform-specific Unix socket and Windows named-pipe backends. SSH maps exec channels to agent exec, SFTP to agent filesystem messages, and direct TCP forwarding to agent TCP messages. These mappings inherit agent protocol generation requirements.

Compatibility-sensitive elements include vsock port and route configuration, stream half-close, datagram boundaries, backend availability, SSH host-key and known-host persistence, authentication behavior, exit status and signal mapping, SFTP file semantics, and direct-tcpip capability gating.

Sources: [`crates/vsock/lib/stream.rs`](crates/vsock/lib/stream.rs), [`crates/vsock/lib/dgram.rs`](crates/vsock/lib/dgram.rs), [`crates/runtime/lib/vm.rs`](crates/runtime/lib/vm.rs), and [`sdk/rust/lib/sandbox/ssh.rs`](sdk/rust/lib/sandbox/ssh.rs).

Use standards-compliant clients in tests and exercise connections against older running agentd versions when changing the adapter-to-agent mapping.

## 15. Metrics Shared-Memory ABI

Metrics use a binary shared-memory structure across independently executing processes. The header and slots have fixed sizes, magic, registry version, ABI, atomics, seqlock ordering, generation counters, lifecycle states, and reserved bytes.

Sources: [`crates/metrics/lib/layout.rs`](crates/metrics/lib/layout.rs), [`crates/metrics/lib/registry.rs`](crates/metrics/lib/registry.rs), and [`crates/utils/lib/lib.rs`](crates/utils/lib/lib.rs).

Do not reorder fields, change widths or alignment, weaken atomic ordering, or redefine slot states under the same ABI. Incompatible changes must bump the registry version or ABI so old and new processes do not map the same object. Prefer checked-in offset and binary-layout fixtures in addition to total-size assertions.

## 16. Heartbeats, Boot Errors, Logs, and Runtime Diagnostics

Operational artifacts are consumed across process boundaries and can influence lifecycle decisions. These include `/.msb/heartbeat.json`, `boot-error.json`, `exec.log`, runtime and kernel logs, temporary filenames, JSON field names, sequence numbers, timestamps, source labels, rotation suffixes, and atomic rename behavior.

Heartbeat semantics are compatibility-sensitive: missing or stale data alone is not proof that a sandbox has died, while active sessions affect idle shutdown. Boot errors must remain available before agent readiness. Log schemas and rotation ordering must remain readable by current SDK consumers.

Sources: [`crates/protocol/lib/heartbeat.rs`](crates/protocol/lib/heartbeat.rs), [`crates/runtime/lib/heartbeat.rs`](crates/runtime/lib/heartbeat.rs), [`crates/runtime/lib/boot_error.rs`](crates/runtime/lib/boot_error.rs), and [`crates/runtime/lib/exec_log.rs`](crates/runtime/lib/exec_log.rs).

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

Sources: [`crates/runtime/lib/ipc.rs`](crates/runtime/lib/ipc.rs), [`sdk/rust/lib/backend/local/mod.rs`](sdk/rust/lib/backend/local/mod.rs), [`sdk/rust/lib/runtime/handle.rs`](sdk/rust/lib/runtime/handle.rs), and artifact-specific migration and publication modules.

Review concurrency and crash points explicitly. A same-version happy-path test does not establish cross-version or crash compatibility.

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

If an applicable direction cannot be tested locally, state exactly what remains unverified and which CI, platform, historical binary, or fixture is required.
