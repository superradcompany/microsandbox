# microsandbox-types

Shared task and wire contract types for microsandbox.

This crate is the source of truth for the backend-neutral shapes that describe a sandbox and the cloud HTTP bodies that carry them. The Rust SDK, the CLI, and the cloud backend all import these types so they agree on one definition instead of duplicating wire shapes. The generated `@microsandbox/types` TypeScript package is derived from this crate.

It is a leaf dependency by design. It pulls in `serde`, `serde_json`, `chrono`, `sha2`, and `thiserror`, and nothing from the local VM machinery (no runtime, image, network, or database crates). That keeps it cheap enough for front-end generation, cloud API models, and SDK wrappers to all depend on.

## What This Crate Owns

The crate models durable user and wire intent: what the user wants to exist, not how a backend fulfills it.

- **Sandbox spec** (`domain` module): `SandboxSpec`, `SandboxResources`, `SandboxRuntimeOptions`, `EnvVar`, `SandboxPolicy`.
- **Rootfs sources**: `RootfsSource` (bind, OCI, disk image), `OciRootfsSource`, `DiskImageFormat`, `PullPolicy`.
- **Mounts and patches**: `VolumeMount`, `MountOptions`, `StatVirtualization`, `HostPermissions`, `Patch`, `SecurityProfile`.
- **Volumes and snapshots**: `VolumeSpec`, `VolumeKind`, `NamedVolumeCreate`, `NamedVolumeMode`, `SnapshotSpec`, `SnapshotDestination`.
- **Networking**: `NetworkSpec`, `PublishedPortSpec`, `PortProtocol`.
- **Exec and logs**: `Rlimit`, `RlimitResource`, `SandboxLogLevel`, `LogSource`, `HandoffInit`.
- **Cloud wire contracts** (`cloud` module): `CloudCreateSandboxRequest`, `CloudSandbox`, `CloudSandboxStatus`, `CloudPaginated`, `CloudMessageResponse`, `CloudErrorBody`, `CloudErrorDetails`.
- **Validation** (`validation` module): `validate_sandbox_name`, `validate_hostname`, `hostname_from_sandbox_name`, and the `MAX_SANDBOX_NAME_BYTES` / `MAX_HOSTNAME_BYTES` limits.

Backend-private materialized state stays out: registry credentials, local CA paths, replace flags, pull-discovered manifest digests, snapshot upper paths, process handles, and DB rows belong to the SDK and backends, not the contract.

## Usage

```toml
[dependencies]
microsandbox-types = "0.6.4"
```

```rust
use microsandbox_types::{RootfsSource, SandboxResources, SandboxSpec};

let spec = SandboxSpec {
    name: "worker".into(),
    image: RootfsSource::oci("python"),
    resources: SandboxResources { vcpus: 2, memory_mib: 1024, disk_size_mib: None },
    ..Default::default()
};
```

The Rust SDK re-exports the contract types it accepts, so most SDK users get these through `microsandbox::*` and do not depend on this crate directly.

## Serialization Notes

- `SandboxSpec`, `SandboxResources`, `SandboxRuntimeOptions`, `NetworkSpec`, and `MountOptions` use `#[serde(default)]`, so partial JSON fills missing fields from static defaults.
- Lowercase-on-the-wire enums (`StatVirtualization`, `HostPermissions`, `SecurityProfile`, `SandboxLogLevel`, `LogSource`, `PortProtocol`) match the CLI grammar and the TypeScript string unions.
- `VolumeMount` has hand-written `Serialize`/`Deserialize`. It tags variants with a `type` field and accepts a legacy top-level `readonly` flag, folding it into `MountOptions` on read.
- Static defaults only. Nothing here reads process-global or profile config; the SDK and backends apply environment defaults before execution.

## Binding Generation

[typeshare](https://github.com/1Password/typeshare) is the sole codegen for both the Go (`../go/types_gen.go`) and TypeScript (`../typescript/src/index.ts`) bindings. It reads the `#[typeshare]`-annotated types directly from this crate's source, so no crate feature has to be enabled to generate — the `typeshare` feature only governs whether the attribute resolves when the crate itself is compiled.

```bash
# Regenerate both the Go and TypeScript bindings (requires `cargo install typeshare-cli`).
just gen
```

Only the `#[typeshare]`-annotated `SandboxSpec` sub-types are emitted; the cloud wire DTOs and the top-level container specs (`SandboxSpec`, `NetworkSpec`, `VolumeSpec`, …) are intentionally out of scope for the shared bindings.

An integration test (`checked_in_bindings_match_generated_output`) regenerates the TypeScript bindings and fails when `typescript/src/index.ts` drifts. It is skipped when the `typeshare` CLI is not on `PATH`; the CI `just gen` check installs the CLI and enforces staleness there.

## Testing

```bash
cargo test -p microsandbox-types
```
