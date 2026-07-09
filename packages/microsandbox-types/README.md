# microsandbox types

Shared task and wire contract types for microsandbox.

These packages define the backend-neutral shapes that describe what a sandbox should be: its rootfs source, resources, mounts, patches, network, lifecycle, and the cloud HTTP request/response bodies that carry those specs over the wire. Everything that has to agree on a sandbox's shape (the Rust SDK, the CLI, the cloud API, and the TypeScript front end) depends on these contracts instead of redefining them.

This is a contract layer, not a runtime. It does not create, start, or talk to sandboxes. It only models the data those operations exchange.

## Layout

```text
packages/microsandbox-types/
├── rust/
└── typescript/
```

- `rust/` publishes as `microsandbox-types` (crate name `microsandbox_types`). It is the source of truth for every shared type.
- `typescript/` publishes as `@microsandbox/types`. Its `src/cloud.ts` (entry) and `src/domain.ts` are generated from the Rust types, never hand-edited; only the cloud contract and the domain types it references are emitted.

## Source Of Truth

The Rust crate owns the definitions. The TypeScript bindings are derived from them with [`ts-rs`](https://github.com/Aleph-Alpha/ts-rs) behind the crate's `ts` feature, so the two stay byte-for-byte aligned.

```text
rust/lib/*.rs  ──(ts-rs)──▶  typescript/src/{cloud,domain}.ts
```

To regenerate the bindings after changing a Rust type:

```bash
cargo run -p microsandbox-types --features ts --bin microsandbox-types-generate
```

CI runs the same generator with `--check` and fails when the checked-in bindings drift:

```bash
cargo run -p microsandbox-types --features ts --bin microsandbox-types-generate -- --check
```

## What Lives Here

- Sandbox specs: `SandboxSpec`, `SandboxResources`, `SandboxRuntimeOptions`, rootfs sources, mounts, patches, init, lifecycle policy.
- Networking intent: `NetworkSpec`, published ports, protocols.
- Volumes and snapshots: `VolumeSpec`, `SnapshotSpec`, and their kinds.
- Exec and logging: `Rlimit`, `RlimitResource`, `LogSource`, `SandboxLogLevel`.
- Cloud wire contracts: `CloudCreateSandboxRequest`, `CloudSandbox`, paginated/message/error bodies.
- Validation helpers: sandbox-name and hostname rules shared across SDK, CLI, and cloud.

Backend-private materialized state (registry credentials, local cache paths, DB rows, resolved manifest digests, process handles) deliberately stays out of these packages. See each language's README for details.
