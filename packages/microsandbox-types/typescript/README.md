# @microsandbox/types

Shared task and wire contract types for microsandbox, as TypeScript.

This package is the type-only mirror of the cloud contract in the `microsandbox-types` Rust crate. It gives TypeScript consumers (the cloud front end and anything talking to the cloud API) the exact cloud wire shapes microsandbox uses, so a `CloudSandboxSpec` means the same thing on both sides of the wire. Only the domain types the cloud contract references are generated; the broader SDK/domain surface is not.

It contains no runtime code. Every export is a type; importing it adds nothing to your bundle.

## Generated, Not Hand-Written

Two files are generated from the Rust crate with [`ts-rs`](https://github.com/Aleph-Alpha/ts-rs), each carrying a `// @generated` header. Do not edit them:

- `src/cloud.ts` — the package entry: the cloud wire twins (`CloudSandboxSpec`, `CloudVolumeMount`, `CloudSecretsConfig`, …), which import and re-export their domain deps from `./domain`.
- `src/domain.ts` — only the domain types the cloud twins transitively reference (`EnvVar`, `Rlimit`, `NetworkPolicy`, …).

To change a shape, edit the Rust type and regenerate from the repo root:

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
import type { CloudSandboxSpec, CloudRootfsSource } from "@microsandbox/types";

const image: CloudRootfsSource = { type: "oci", reference: "python" };

function createSandbox(spec: CloudSandboxSpec) {
  // POST spec to the cloud API
}
```

## Generated Shape Notes

The bindings follow `ts-rs` conventions, which mirror the Rust serde representation:

- Cloud enums are internally tagged with a `type` field: `CloudRootfsSource` is `{ type: "bind"; … } | { type: "oci"; reference: string } | { type: "disk_image"; … }`, and `CloudVolumeMount` / `CloudHostPattern` / `CloudViolationAction` follow the same shape.
- Lowercase domain enums like `StatVirtualization` are string-literal unions (`"strict" | "relaxed" | "off"`).
- Optional Rust fields are `T | null`; fields skipped when absent are `?:` optional.
- The domain types the cloud references (`EnvVar`, `Rlimit`, `NetworkPolicy`, …) live in `domain.ts` and are re-exported from the package entry, so a single import from `@microsandbox/types` sees the whole cloud contract.

## Build And Typecheck

```bash
npm run build       # tsc -> dist/
npm run typecheck   # tsc --noEmit
```
