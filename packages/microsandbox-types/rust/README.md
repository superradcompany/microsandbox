# microsandbox-types

Shared task and wire contract types for microsandbox.

- Package: `microsandbox-types`
- Library: `microsandbox_types`

This crate is the home of the data shapes that microsandbox components agree on, and it is the source of truth for the generated [`@microsandbox/types`](../typescript) TypeScript package. It defines a durable, backend-neutral description of a sandbox task, the HTTP wire shapes the cloud backend speaks, and a few validation helpers. It is contracts only: nothing in this crate creates, schedules, or runs a sandbox.

## When to reach for it

Depend on this crate when your code needs to construct, store, or exchange sandbox descriptions and cloud requests using the exact shapes the rest of microsandbox uses. If you only want to build and run sandboxes, use the higher-level microsandbox SDK or CLI instead; this crate is the vocabulary beneath them.

## What's inside

**The sandbox task contract.** [`SandboxSpec`](lib/domain.rs) is the durable, backend-neutral description of a sandbox task. It is deliberately a description and nothing more: local-only execution state such as resolved manifest digests, snapshot upper-layer paths, registry credentials, replace flags, and backend dispatch is kept out of it. Its fields pull in the surrounding domain types:

- Root filesystem: `RootfsSource`, `OciRootfsSource`, `DiskImageFormat`, `PullPolicy`.
- Resources and runtime: `SandboxResources`, `SandboxRuntimeOptions`, `EnvVar`, `SandboxLogLevel`.
- Storage and mounts: `VolumeMount`, `VolumeSpec`, `VolumeKind`, `NamedVolumeCreate`, `NamedVolumeMode`, `MountOptions`, `StatVirtualization`, `HostPermissions`.
- Rootfs preparation: `Patch`.
- Networking: `NetworkSpec`, `PublishedPortSpec`, `PortProtocol`.
- Resource limits: `Rlimit`, `RlimitResource`.
- Init and lifecycle: `HandoffInit`, `SandboxPolicy`, `SecurityProfile`.
- Snapshots: `SnapshotSpec`, `SnapshotDestination`.
- Logs: `LogSource`.

**Cloud wire types.** The request, response, and error shapes used by the cloud backend's sandbox HTTP endpoints: [`CloudCreateSandboxRequest`](lib/cloud.rs), [`CloudSandbox`](lib/cloud.rs), [`CloudSandboxStatus`](lib/cloud.rs), the generic page envelope `CloudPaginated<T>`, the `CloudMessageResponse` acknowledgement, and the error envelopes `CloudErrorBody` / `CloudErrorDetails`.

**Validation helpers.** [`validate_sandbox_name`](lib/validation.rs), [`validate_hostname`](lib/validation.rs), and [`hostname_from_sandbox_name`](lib/validation.rs), backed by the `MAX_SANDBOX_NAME_BYTES` and `MAX_HOSTNAME_BYTES` constants and the `TypesError` / `TypesResult` error types. The crate also exposes the `DEFAULT_SANDBOX_CPUS`, `DEFAULT_SANDBOX_MEMORY_MIB`, and `DEFAULT_METRICS_SAMPLE_INTERVAL_MS` defaults that `SandboxSpec::default()` relies on.

## Usage

Build a spec from `Default` and fill in the fields you care about, then validate the name and derive a guest hostname:

```rust
use microsandbox_types::{
    RootfsSource, SandboxSpec, hostname_from_sandbox_name, validate_sandbox_name,
};

let spec = SandboxSpec {
    name: "agent-1".to_string(),
    image: RootfsSource::oci("python:3.12"),
    ..SandboxSpec::default()
};

validate_sandbox_name(&spec.name).expect("valid sandbox name");
assert_eq!(hostname_from_sandbox_name(&spec.name), "agent-1");
```

The validation helpers encode rules worth knowing up front:

- `validate_sandbox_name` requires a non-empty name of at most 128 bytes that starts with an ASCII alphanumeric and otherwise contains only ASCII alphanumerics, dots, hyphens, and underscores.
- `validate_hostname` accepts `None`, but rejects an empty hostname and anything longer than 64 bytes.
- `hostname_from_sandbox_name` returns names that already fit in 64 bytes unchanged. For longer names it truncates on a UTF-8 character boundary and appends a hyphen plus 8 hex characters derived from a SHA-256 of the original name, so the result is deterministic, collision-resistant, and always within 64 bytes.

## Wire format notes

These are the places where the serialized shape is more subtle than the Rust type suggests. They matter when you hand-write JSON or read persisted configs.

**Enum spellings are not uniform.** Some enums serialize as lower or snake case by serde configuration so persisted JSON lines up with the CLI grammar and the cloud wire format: `StatVirtualization` (`strict` / `relaxed` / `off`), `HostPermissions` (`private` / `mirror`), `SecurityProfile` (`default` / `restricted`), `PortProtocol` (`tcp` / `udp`), `SandboxLogLevel` (`error` / `warn` / `info` / `debug` / `trace`), `LogSource` (`stdout` / `stderr` / `output` / `system`), and `CloudSandboxStatus` (snake case). Others keep their Rust variant names on the wire: `RootfsSource` is externally tagged (`{ "Oci": ... }`), `DiskImageFormat` is `"Qcow2" | "Raw" | "Vmdk"`, `PullPolicy` is `"IfMissing" | "Always" | "Never"`, and `RlimitResource` keeps PascalCase variants. Do not assume a lowercase rule across the board.

**`NetworkSpec` is partly opaque by design.** Its common, backend-visible fields (such as `enabled`, `ports`, `max_connections`, and `trust_host_cas`) are typed directly, but the rich local-engine subdocuments (`interface`, `policy`, `dns`, `tls`, `secrets`) are carried as `serde_json::Value`. That lets the shared contract round-trip those documents without depending on the local networking engine crate.

**`VolumeMount::Named.create` is transient.** It is provisioning metadata used at sandbox-creation time and is intentionally skipped when a sandbox config is serialized or persisted. Restarting a sandbox mounts the already-created volume, so the field is absent from the persisted shape.

## Generating the TypeScript bindings

The TypeScript package is generated from this crate; this crate is the source of truth and the bindings are never hand-edited. Generation lives behind the optional `ts` feature, which pulls in `ts-rs`, and the `microsandbox-types-generate` binary requires it.

Regenerate the checked-in bindings:

```bash
cargo run -p microsandbox-types --features ts --bin microsandbox-types-generate
```

Verify they are current; this exits non-zero and names the stale target when the checked-in TypeScript differs from a fresh render:

```bash
cargo run -p microsandbox-types --features ts --bin microsandbox-types-generate -- --check
```

The renderer in [`lib/typescript.rs`](lib/typescript.rs) writes [`../typescript/src/index.ts`](../typescript/src/index.ts), prefixes it with `// @generated by microsandbox-types. Do not edit by hand.`, and configures `ts-rs` to map large integers to `number`.

## Tests

```bash
cargo test -p microsandbox-types
```

The suite covers the validation rules, serde round-trips for the domain and cloud types, and an assertion that the checked-in TypeScript bindings match freshly generated output.
