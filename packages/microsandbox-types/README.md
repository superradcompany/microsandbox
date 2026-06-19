# microsandbox-types

Shared task and wire contract types for microsandbox.

This directory holds one logical type library published in two languages. It is the single, agreed-upon vocabulary that microsandbox components use to talk about sandboxes: the durable description of a sandbox task and the HTTP shapes exchanged with the cloud backend. These are contracts, not machinery. Nothing here builds, schedules, or runs a sandbox; the types only describe what a sandbox is and what the wire looks like.

## Layout

```text
microsandbox-types/
|-- rust/        # `microsandbox-types` crate    -> the source of truth
`-- typescript/  # `@microsandbox/types` package  -> generated from the crate
```

The two packages are kept structurally identical by generation, not by hand: the Rust crate defines the types, and the TypeScript declarations are produced from them. See [`rust/README.md`](rust/README.md) and [`typescript/README.md`](typescript/README.md) for the details specific to each consumer.

## When to use these

Reach for these packages when you are building something that sits alongside microsandbox and needs to speak its language: an SDK, a runtime integration, a cloud client, or a contribution to microsandbox itself. They give you the exact field names, shapes, and serialization that the rest of the system expects.

If your goal is simply to create or run sandboxes, you do not need these packages directly. Use the microsandbox SDK or CLI, which build on top of these contracts and give you the higher-level, ergonomic surface.

## One source of truth

The Rust crate is authoritative. The TypeScript package is generated from it with [`ts-rs`](https://crates.io/crates/ts-rs) (behind the crate's optional `ts` feature), so the two never drift apart by accident and the generated bindings are never edited by hand.

Regenerate the TypeScript bindings whenever the Rust types change:

```bash
cargo run -p microsandbox-types --features ts --bin microsandbox-types-generate
```

CI checks that the committed bindings are current. Run the same check locally before pushing; it exits non-zero and names the stale file if the checked-in TypeScript differs from a fresh render:

```bash
cargo run -p microsandbox-types --features ts --bin microsandbox-types-generate -- --check
```
