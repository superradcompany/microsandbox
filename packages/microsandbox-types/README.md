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
- `typescript/` publishes as `@microsandbox/types`. Its `src/index.ts` is generated from the Rust types, never hand-edited.

## Source Of Truth

The Rust crate owns the definitions. Both the TypeScript (`typescript/src/index.ts`) and Go (`../go/types_gen.go`) bindings are derived from the `#[typeshare]`-annotated Rust types with [typeshare](https://github.com/1Password/typeshare) — one codegen for both languages.

```text
rust/lib/*.rs  ──(typeshare)──▶  typescript/src/index.ts + ../go/types_gen.go
```

To regenerate the bindings after changing a Rust type (requires `cargo install typeshare-cli`):

```bash
just gen
```

Only the `#[typeshare]`-annotated `SandboxSpec` sub-types are emitted, so the bindings cover the sandbox spec building blocks. The cloud wire DTOs and the top-level container specs (`SandboxSpec`, `NetworkSpec`, `VolumeSpec`, …) live in the Rust crate but are intentionally out of scope for the generated bindings. CI regenerates and `git diff --exit-code`s the output, failing when the checked-in bindings drift.

## What Lives Here

- Sandbox specs: `SandboxSpec`, `SandboxResources`, `SandboxRuntimeOptions`, rootfs sources, mounts, patches, init, lifecycle policy.
- Networking intent: `NetworkSpec`, published ports, protocols.
- Volumes and snapshots: `VolumeSpec`, `SnapshotSpec`, and their kinds.
- Exec and logging: `Rlimit`, `RlimitResource`, `LogSource`, `SandboxLogLevel`.
- Cloud wire contracts: `CloudCreateSandboxRequest`, `CloudSandbox`, paginated/message/error bodies.
- Validation helpers: sandbox-name and hostname rules shared across SDK, CLI, and cloud.

Backend-private materialized state (registry credentials, local cache paths, DB rows, resolved manifest digests, process handles) deliberately stays out of these packages. See each language's README for details.
