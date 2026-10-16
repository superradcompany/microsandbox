# Deny Compatibility & Persistence — Repair Plan (Plan 4 of 5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A persisted bind-mount `deny` policy must never be silently dropped by an older `msb` or by a downgrade, and the Rust domain type must stop breaking source compatibility.

**Architecture:** The deny list is persisted inside `VolumeMount::Bind` in the sandbox `config`/`active_config` records. A marker migration (`m20261012_000001_bind_mount_deny_config`) refuses a downgrade when a non-empty deny list is present. Review found a downgrade path that bypasses the guard, and a domain-type source break. Fix the guard, add a real cross-version regression test, and document the boundary in `COMPATIBILITY.md`.

**Tech Stack:** Rust, `sqlite`/`sea-orm` migrations (`crates/migration`, `crates/db`), `serde_json`.

**Spec / context:**
- Findings: **H6** (`self downgrade --version 0.6.5` bypasses the guard), **M9** (`VolumeMount::Bind` field without `#[non_exhaustive]`), plus G-14 (migration tests use in-memory DBs, no real v0.6.x fixture) and G-06.
- PR-appcypher `3906476056` (add a compatibility-marker migration), PR-toks `4250954769` (the `/mounts` pointer — already fixed in `aecabe8c`).
- Contract targets: bidirectional v0.6.x (v0.6.0 floor); `COMPATIBILITY.md` sections on downgrade and "Expected Evidence" items 3–4; `DOWNGRADE_FLOOR = 0.6.0`.
- **Out of scope:** the read-only path-list / `protect` design in `docs/superpowers/specs/2026-10-12-readonly-path-list-design.md` is a separate, not-yet-approved feature. Do not read, implement, or design around it; treat `deny` as the only pattern-list consumer.

## Global Constraints

- Do not silently add compatibility layers; the guard must **refuse** with a clear error, never migrate data forward.
- `reject_persisted_deny` reads raw JSON (so a later reader cannot drop the policy) and checks both `config` and `active_config`.
- A real released v0.6.x artifact or fixture must back the cross-version claim; same-version round-trips are insufficient.
- Existing persisted relative paths keep legacy startup behavior; do not rewrite them.

## Review Focus

1. `msb self downgrade --version 0.6.5` on a catalog holding a deny-bearing sandbox → must refuse with the deny error, not drop the policy.
2. `msb self downgrade` to any other v0.6.x/v0.7.x → must refuse (must not regress).
3. An older `msb` binary opening a deny-bearing catalog → clean "schema is newer" refusal.
4. External Rust code matching `VolumeMount::Bind { .. }` exhaustively → must not silently break again.
5. An older `msb` reading a persisted bind-deny config → clean refusal, never a silent drop.

---

## File Structure

- `crates/migration/lib/m20261012_000001_bind_mount_deny_config.rs` — `reject_persisted_deny`.
- `crates/db/lib/compat/v0_6_5/config.rs` — the v0.6.5 mount rewrap.
- `crates/db/lib/compat/config.rs` — `config::prepare`.
- `crates/cli/lib/commands/self_cmd.rs` — downgrade orchestration (`:2885-2889`).
- `packages/microsandbox-types/rust/lib/domain.rs` — `VolumeMount` / serde.
- `COMPATIBILITY.md` — contract documentation.

---

### Task 1: Close the v0.6.5 downgrade bypass (H6)

**Files:**
- Modify: `crates/migration/lib/m20261012_000001_bind_mount_deny_config.rs` (`reject_persisted_deny`)
- Optionally modify: `crates/cli/lib/commands/self_cmd.rs` (ordering) or `crates/db/lib/compat/v0_6_5/config.rs`
- Test: `crates/migration/lib/m20261012_000001_bind_mount_deny_config.rs` tests

**Interfaces:**
- Produces: `reject_persisted_deny` inspects **both** the current shape `/mounts[].deny` and the v0.6.5-rewritten shape `/mounts[].bind.deny` before deciding; or the deny guard runs before `config::prepare` rewrites mounts.

**Decision (builder's call):** Make `reject_persisted_deny` shape-tolerant — scan any mount object for a non-empty `deny` value at either nesting. This is robust to future mount rewrites and is the smallest change. (Alternatively, run the guard before `prepare`; if so, prove ordering with the test.)

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn v0_6_5_downgrade_refuses_when_deny_wrapped_in_bind() {
    // Build a DB whose mount is {"mounts":[{"bind":{"host":...,"deny":[".env"]}}]}
    // (the post-prepare shape). Assert down()/preflight refuses.
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p microsandbox-migration v0_6_5_downgrade_refuses`
Expected: FAIL — guard misses the nested shape and proceeds.

- [ ] **Step 3: Implement the shape-tolerant scan**

- [ ] **Step 4: Run the tests**

Run: `cargo test -p microsandbox-migration bind_mount`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/migration/lib/m20261012_000001_bind_mount_deny_config.rs
git commit -m "fix(migration): refuse v0.6.5 downgrade that would drop bind deny policy"
```

---

### Task 2: End-to-end downgrade regression against the CLI path (G-14, G-06)

**Files:**
- Add: `crates/cli/lib/commands/self_cmd/tests.rs` (or extend) — `downgrade_refuses_bind_deny`
- Test: uses a real serialized `SandboxConfig` fixture, not `sqlite::memory` hand-built JSON

**Interfaces:**
- Consumes: the `self downgrade` path at `self_cmd.rs:2885-2889` (`config::prepare` → `Migrator::down`).

- [ ] **Step 1: Write the failing test**

Create a sandbox config row from a real serialized `SandboxConfig` with a bind deny list, then drive `self downgrade --version 0.6.5` and assert the refuse error. Assert the same for `0.6.18` and a `v0.7.x` target.

- [ ] **Step 2: Run to verify the harness**

Run: `cargo test -p microsandbox-cli downgrade_refuses_bind_deny`
Expected: PASS after Task 1; FAIL before.

- [ ] **Step 3: Commit**

```bash
git add crates/cli/lib/commands/self_cmd/tests.rs
git commit -m "test(cli): end-to-end downgrade refusal for bind deny policy"
```

---

### Task 3: Real cross-version fixture for the migration guard (G-14)

**Files:**
- Add: `crates/migration/lib/fixtures/` or `sdk/rust/tests/fixtures/config/` — a captured released v0.6.x DB/config
- Test: a test that opens the fixture and runs the guard

- [ ] **Step 1: Add the fixture**

Commit a small captured v0.6.x sandbox DB (or the config JSON) that predates deny. Document its provenance and version in a `README`.

- [ ] **Step 2: Write the test**

Open the fixture, add a deny-bearing sandbox, run `Migrator::down` to a v0.6.x target, assert refusal; also assert a fresh v0.6.x DB without deny downgrades cleanly.

- [ ] **Step 3: Run**

Run: `cargo test -p microsandbox-migration released_fixture`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add crates/migration/lib/fixtures
git commit -m "test(migration): guard bind deny downgrade against a real v0.6.x fixture"
```

---

### Task 4: Make `VolumeMount` source-compatible going forward (M9)

**Files:**
- Modify: `packages/microsandbox-types/rust/lib/domain.rs` (`VolumeMount`)
- Modify: any in-repo exhaustive matches/constructions
- Test: `cargo build` + a compile test using a helper constructor

**Interfaces:**
- Produces: `#[non_exhaustive]` on `VolumeMount` (and its variants' construction path), plus a `VolumeMount::bind(...)`-style constructor (or `Bind { .. }` builder) so external code has a stable way to construct without struct-literal coupling. Serde stays `#[serde(default)]`.

**Decision (builder's call):** Adding `#[non_exhaustive]` is itself a one-time break for external exhaustive matchers, but prevents a repeat on every future field. Do it, document it in `COMPATIBILITY.md`, and keep serde tolerant.

- [ ] **Step 1: Write the failing test**

A test in `sdk/rust/tests/api_compat.rs` that constructs a bind mount via the new helper (compiles only if the helper exists) and asserts it round-trips through serde with `deny` defaulting empty.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p microsandbox --test api_compat`
Expected: FAIL — helper missing.

- [ ] **Step 3: Add `#[non_exhaustive]` + constructor, update in-repo uses**

- [ ] **Step 4: Run**

Run: `cargo build --workspace`
Run: `cargo test -p microsandbox --test api_compat`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/microsandbox-types/rust/lib/domain.rs sdk/rust/tests/api_compat.rs
git commit -m "refactor(types): non_exhaustive VolumeMount with stable bind constructor"
```

---

### Task 5: Document the compatibility boundary (G-14, H6 docs)

`COMPATIBILITY.md` already exists at the repo root; **modify it — do not create a new file.** It already carries the precedents to copy from.

**Files:**
- Modify: `COMPATIBILITY.md` (existing sections only)

**Sections to extend (existing):**
- **§5 "Launcher-to-Runtime Process Protocol"** (~line 143) — beside the `max_inbound_tcp_connections` capability paragraph (~line 153): add the `bind mount deny lists` launch gate (legacy v0.6.x runtime → upgrade-required, never a silent drop).
- **§6 "Database, Configuration, and Migration History"** (~line 183) — beside the guest-clock marker entry (~line 243): add the `m20261012_000001_bind_mount_deny_config` marker, its downgrade refusal, and the shape-tolerant check for the v0.6.5 rewrapped `bind` form. Add the v0.6.5-specific note near the existing v0.6.5 line (~line 496).
- **§11 "Host Filesystem Metadata"** (~line 349) — the persisted `VolumeMount::Bind.deny` field and the `#[non_exhaustive]` source-compatibility change.

- [ ] **Step 1: Add the entries to the three existing sections**

Follow the surrounding prose style (dense paragraphs, module-path links). Do not create a new top-level section or a new document.

- [ ] **Step 2: Verify the entries match the code and the file is still coherent**

Run: `rg -n "bind mount deny|non_exhaustive|downgrade" COMPATIBILITY.md`
Run: `rg -n "^## " COMPATIBILITY.md`  (confirm no new section was added)

- [ ] **Step 3: Commit**

```bash
git add COMPATIBILITY.md
git commit -m "docs(compatibility): record bind deny launch gate and downgrade guard"
```
