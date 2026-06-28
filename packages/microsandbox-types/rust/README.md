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
microsandbox-types = "0.6.1"
```

```rust
use microsandbox_types::{RootfsSource, SandboxResources, SandboxSpec};

let spec = SandboxSpec {
    name: "worker".into(),
    image: RootfsSource::oci("python"),
    resources: SandboxResources { cpus: 2, memory_mib: 1024 },
    ..Default::default()
};
```

The Rust SDK re-exports the contract types it accepts, so most SDK users get these through `microsandbox::*` and do not depend on this crate directly.

## Serialization Notes

- `SandboxSpec`, `SandboxResources`, `SandboxRuntimeOptions`, `NetworkSpec`, and `MountOptions` use `#[serde(default)]`, so partial JSON fills missing fields from static defaults.
- Lowercase-on-the-wire enums (`StatVirtualization`, `HostPermissions`, `SecurityProfile`, `SandboxLogLevel`, `LogSource`, `PortProtocol`) match the CLI grammar and the TypeScript string unions.
- `VolumeMount` has hand-written `Serialize`/`Deserialize`. It tags variants with a `type` field and accepts a legacy top-level `readonly` flag, folding it into `MountOptions` on read.
- Static defaults only. Nothing here reads process-global or profile config; the SDK and backends apply environment defaults before execution.

## TypeScript Generation

The `ts` feature derives `ts_rs::TS` on every exported type and builds the `microsandbox-types-generate` binary, which writes `../typescript/src/index.ts`.

```bash
# Regenerate the checked-in bindings.
cargo run -p microsandbox-types --features ts --bin microsandbox-types-generate

# Verify they are current (used in CI; exits non-zero when stale).
cargo run -p microsandbox-types --features ts --bin microsandbox-types-generate -- --check
```

A unit test (`checked_in_bindings_match_generated_output`) also fails when `typescript/src/index.ts` drifts from the generator output, so `cargo test --features ts` catches stale bindings too.

## Testing

```bash
cargo test -p microsandbox-types
cargo test -p microsandbox-types --features ts
```
