# AGENTS.md

These instructions are only for agents contributing changes to this repository.
Do not apply them to other repositories or to general agent behavior outside this contribution workflow.

## Scope

- Follow these guidelines when editing code, docs, tests, examples, CI, or release files for microsandbox.
- Prefer repository conventions over generic agent habits. When unsure, inspect nearby files and match their style.
- Do not create branches, commit, push, tag, publish, or open pull requests unless the human explicitly asks.
- Check `git status --short --branch` before making changes. Do not overwrite or revert user work unless explicitly asked.

## Project Map

- `sdk/rust` is the public Rust SDK crate.
- `crates/cli` contains the `msb` CLI.
- `crates/runtime` contains VM runtime integration.
- `crates/filesystem`, `crates/image`, `crates/network`, `crates/db`, `crates/migration`, `crates/metrics`, `crates/metrics-collector`, `crates/protocol`, and `crates/utils` are shared internal crates.
- `packages/agent-client` and `packages/microsandbox-types` are the shared agent-protocol client and wire-contract type packages, each with Rust and TypeScript implementations.
- `crates/agentd` is the in-guest agent. It is a workspace member; the musl guest binary that ships in releases is built separately.
- `sdk/python`, `sdk/node-ts`, and `sdk/go` contain the language SDKs and native bindings.
- `docs/` contains the documentation site. Keep docs in sync with user-facing behavior.
- `examples/` contains runnable examples. Add new example projects only when requested or clearly required by the contribution.
- `mcp/` and `skills/` are submodules related to agent integrations.
- `vendor/libkrunfw` is a submodule for the kernel firmware library.

Repository layout:

```text
.
|-- AGENTS.md
|-- Cargo.lock
|-- Cargo.toml
|-- DEVELOPMENT.md
|-- Dockerfile.agentd
|-- justfile
|-- msb-entitlements.plist
|-- assets/
|-- crates/
|   |-- agentd/
|   |-- cli/
|   |-- db/
|   |-- filesystem/
|   |-- image/
|   |-- metrics/
|   |-- metrics-collector/
|   |-- migration/
|   |-- network/
|   |-- protocol/
|   |-- runtime/
|   |-- test-init/
|   |-- test-macros/
|   |-- test-utils/
|   `-- utils/
|-- docs/
|   |-- changelog/
|   |-- cli/
|   |-- getting-started/
|   |-- images/
|   |-- networking/
|   |-- observability/
|   |-- recipes/
|   |-- sandboxes/
|   |-- sdk/
|   `-- security/
|-- examples/
|   |-- python/
|   |-- rust/
|   `-- typescript/
|-- mcp/
|   |-- bin/
|   |-- src/
|   `-- package.json
|-- packages/
|   |-- agent-client/
|   `-- microsandbox-types/
|-- packaging/
|   `-- docker/
|-- scripts/
|   `-- smoke/
|-- sdk/
|   |-- go/
|   |-- node-ts/
|   |-- rust/
|   `-- python/
|-- skills/
|   `-- microsandbox/
`-- vendor/
    `-- libkrunfw/
```

## Design Principles

- Before making or continuing a change that may introduce a regression or breaking change, stop and alert the human with the likely impact and affected workflows.
- Keep changes narrowly scoped to the requested behavior. Avoid drive-by refactors, unrelated formatting, or dependency churn.
- Treat sandbox isolation, host filesystem access, networking, and secret handling as security-sensitive. Validate inputs at boundaries and avoid exposing host paths, credentials, or ambient privileges.
- For public APIs, keep the Rust SDK, CLI, Python SDK, Node SDK, Go SDK, docs, and examples consistent when they describe the same capability.
- Prefer explicit errors with useful context over silent fallbacks.

## Rust Layout And Style

- Most Rust crates use `lib/lib.rs` for library code and `bin/main.rs` for binaries. Keep using those paths for new crate entries unless the surrounding crate already does something different.
- When adding a new library or binary target, declare the path explicitly in `Cargo.toml`:

```toml
[lib]
path = "lib/lib.rs"

[[bin]]
name = "example"
path = "bin/main.rs"
```

- Keep crate roots and module roots thin. `lib.rs` and `mod.rs` should declare modules, crate attributes, and exports only. Put implementation in leaf modules such as `sandbox/config.rs`, `policy/types.rs`, or `commands/run.rs`.
- File order should be:
  1. Module docs and crate/file attributes, such as `//! ...` and `#![warn(missing_docs)]`.
  2. `use` imports.
  3. Sectioned items.
- Group imports by origin, separated by blank lines: standard library first, external crates second, then `crate::` and `super::` imports.
- Do not put `use` statements inside sections unless there is a narrow local reason, such as a test module import.
- Use the exact section delimiter shown below. Do not invent alternate Markdown-style, shorter, or decorative section headers.
- Include only sections that contain items. Do not add empty sections just to satisfy the full order.
- Organize Rust files with these section headers, in this order when applicable:

```rust
//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
// Macros
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

//--------------------------------------------------------------------------------------------------
// Re-Exports
//--------------------------------------------------------------------------------------------------
```

- Aggregator files that only expose modules and public items may use `Exports` instead of `Re-Exports` when matching existing files.
- Use qualified section labels only to split large sections into obvious groups, for example `Types: Identifiers`, `Functions: Handlers`, or `Functions: Helpers`.
- Do not create a qualified section for one or two items unless the surrounding file already uses that pattern.
- Put constants and statics under `Constants`.
- Put `struct`, `enum`, `trait`, and `type` definitions under `Types`.
- Put inherent `impl Type` blocks under `Methods`, directly after the related type definitions when practical.
- Put `impl Trait for Type` blocks under `Trait Implementations`.
- Put free functions under `Functions`. If a free function is only used by one public function, place it later in `Functions: Helpers`.
- Put macros under `Macros`, not near the call site.
- Put unit tests under `Tests`, usually as `#[cfg(test)] mod tests`. Keep test-only helpers in the same section.
- Put public re-exports under `Re-Exports`, or `Exports` in root files that use the existing aggregator style.
- Keep items in dependency order inside a section: public surface first, private helpers later.
- Keep docs on public types, fields, methods, functions, and modules. This repo uses `#![warn(missing_docs)]` in public crates, so new public items should explain what they are for.
- Prefer explicit domain types over loosely typed strings, booleans, or tuples when the value crosses an API or subsystem boundary.
- During refactors, conflict resolution, bug fixes, and feature work, call out any expected behavior, API, or data-format changes and wait for direction when the risk is material.
- Use `thiserror` or existing local error patterns for typed errors. Include enough context for callers to understand the failing operation.
- In async code, avoid holding locks across `.await`. Prefer explicit ownership, short critical sections, and existing Tokio patterns in the surrounding module.
- Keep feature-gated code close to the feature it gates and use existing `#[cfg(feature = "...")]` patterns.
- Do not add examples under `examples/` unless requested or clearly required. Prefer tests and docs for small usage coverage.
- Run `cargo fmt` before finalizing Rust changes.

## Development Build Notes

- If you build `msb` to run it locally on macOS, make sure the binary is codesigned with `msb-entitlements.plist`; otherwise VM/runtime failures may be caused by missing entitlements instead of your code change.
- Prefer `just build` or `just build-msb` when producing a runnable local binary. The macOS recipe rebuilds `msb` and runs:

```bash
codesign --entitlements msb-entitlements.plist --force -s - build/msb
```

- If you bypass `just` and call `cargo build` directly, manually codesign the exact `msb` binary you are going to run before testing sandbox startup, protocol, networking, or filesystem behavior.

## Validation

Use focused checks for the files you touched, then broader checks when the change crosses crate, SDK, CLI, or runtime boundaries.

Common Rust checks:

```bash
cargo fmt --all -- --check
cargo clippy --workspace -- -D warnings
cargo test --workspace
cargo build -p microsandbox-cli
```

`agentd` is a workspace member, so the workspace-wide commands above cover it. The musl guest binary that ships in releases is built separately via `just build-agentd`.

Python SDK checks:

```bash
cd sdk/python
uv sync --group dev
uv run maturin develop --release
uv run pytest
uv run ruff check .
```

Node SDK checks:

```bash
cd sdk/node-ts
npm ci
npm run build
npm test
npm run typecheck
```

Go SDK checks:

```bash
cd sdk/go
go test -count=1 .
go test -tags "smoke microsandbox_ffi_path" -count=1 -timeout 2m .
```

Integration tests may require Linux with KVM or macOS Apple Silicon support. If a needed check cannot run in the current environment, say exactly which command was skipped and why.

The full local setup and build loop is documented in `DEVELOPMENT.md`. Use `just setup`, `just build`, and `just install` when you need the full local runtime, `agentd`, or `libkrunfw` artifacts.

## Commits

- Use Conventional Commits for commit titles: `feat`, `fix`, `docs`, `style`, `refactor`, `test`, `chore`, `perf`, `ci`, or `build`.
- Use a scope when it clarifies the affected area, for example `fix(network): ...` or `docs(sdk): ...`.
- Keep the subject imperative, lowercase after the colon, no trailing period, and at most 72 characters.
- Include a commit body for non-trivial changes. Explain what changed and why.
- Use signed commits: `git commit -S`.
- Before committing, inspect the actual diff, including new, modified, and deleted files. Do not write a commit message from filenames or previous commit messages alone.
- If there is nothing to commit, say so rather than creating an empty commit.

Example:

```text
fix(network): wake smoltcp after accepted host connections

Notify the network loop after accepting a published-port connection so
pending guest traffic can make progress without waiting for another timer.
```

## Branches And Pull Requests

- You may make local edits while on `main`, but do not commit directly to `main`. Start from the latest `main` when creating a contribution branch.
- Use short, descriptive, kebab-case branch names. Avoid personal prefixes in shared documentation unless the maintainer asks for one.
- Before opening a PR, compare against the intended base branch and inspect the actual diff:

```bash
git log origin/main..HEAD --oneline
git diff origin/main..HEAD --stat
git diff origin/main..HEAD --name-status
```

- PR titles should follow Conventional Commit style and stay under 72 characters.
- PR descriptions should be plain and accurate:
  - `## TL;DR`: one or two short sentences.
  - `## Description`: a flat bullet list of core changes.
  - `## Test Plan`: concrete commands or observable checks.
- Do not use emojis in PR titles or descriptions.
- If a PR description includes an API example, verify every symbol, path, flag, type, field, and signature against the diff before writing it.

## Version And Release Changes

- Do not bump versions, publish packages, create release tags, or modify release automation unless explicitly asked.
- All released packages share a version. When a version bump is requested, check `Cargo.toml`, `sdk/node-ts/package.json`, `mcp/package.json`, and any other package metadata touched by the release process in `DEVELOPMENT.md`.
- For release or version PRs, summarize the user-visible changes since the previous version bump and run the relevant dry-run publish checks when practical.

## Documentation And Examples

- Update docs when behavior, configuration, CLI flags, SDK APIs, or examples change.
- Keep examples realistic and runnable. Do not invent APIs or flags.
- Prefer editing existing examples over adding new example projects unless the new example is requested or clearly fills a missing user workflow.
- Documentation should describe current behavior, not future plans, unless the page is explicitly about roadmap work.

## Agent Operating Rules

- Use `rg` or `rg --files` for repository searches.
- Read the relevant files before editing. Let existing module boundaries guide the change.
- Make the smallest coherent change that satisfies the request.
- Avoid destructive git commands such as `git reset --hard` and `git checkout --` unless explicitly requested.
- Do not edit generated artifacts, lockfiles, or submodule pointers unless the change requires it.
- If generated files or lockfiles must change, explain why in the final summary.
- Report what changed, what validation ran, and any checks that were skipped.
