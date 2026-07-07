# @microsandbox/types

Shared task and wire contract types for microsandbox, as TypeScript.

This package is the type-only mirror of the `microsandbox-types` Rust crate. It gives TypeScript consumers (the Node SDK, the cloud front end, and anything talking to the cloud API) the exact sandbox spec and cloud wire shapes the rest of microsandbox uses, so a `SandboxSpec` or `CloudCreateSandboxRequest` means the same thing on both sides of the wire.

It contains no runtime code. Every export is a type or interface; importing it adds nothing to your bundle.

## Generated, Not Hand-Written

`src/index.ts` is generated from the Rust crate with [`ts-rs`](https://github.com/Aleph-Alpha/ts-rs) and carries a `// @generated` header. Do not edit it. To change a shape, edit the Rust type and regenerate from the repo root:

```bash
cargo run -p microsandbox-types --features ts --bin microsandbox-types-generate
```

## Install

```bash
npm install @microsandbox/types
```

## Usage

Import the shapes you need with `import type`:

```ts
import type {
  SandboxSpec,
  RootfsSource,
  CloudCreateSandboxRequest,
} from "@microsandbox/types";

const image: RootfsSource = { Oci: { reference: "python", upper_size_mib: null } };

const req: CloudCreateSandboxRequest = {
  name: "worker",
  image: "python",
  vcpus: 2,
  memory_mib: 1024,
  env: {},
  ephemeral: true,
};
```

## Generated Shape Notes

The bindings follow `ts-rs` conventions, which mirror the Rust serde representation:

- Rust enums become tagged unions or string literals. `RootfsSource` is `{ "Bind": string } | { "Oci": OciRootfsSource } | { "DiskImage": {...} }`; lowercase enums like `StatVirtualization` are `"strict" | "relaxed" | "off"`.
- `VolumeMount` is internally tagged with a `type` field (`"Bind" | "Named" | "Tmpfs" | "DiskImage"`).
- Optional Rust fields are `T | null`; fields skipped when absent are `?:` optional.
- `serde_json::Value` is rendered as the `JsonValue` alias for the network subdocuments (`policy`, `dns`, `tls`, `secrets`, `interface`).

## Build And Typecheck

```bash
npm run build       # tsc -> dist/
npm run typecheck   # tsc --noEmit
```
