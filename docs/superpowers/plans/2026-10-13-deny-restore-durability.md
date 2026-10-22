# Deny Policy Durability Across Restore — Repair Plan (Plan 2 of 5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A bind-mount `deny` policy must survive snapshot, archive import, restore, and branch, and must be re-applied to restored inodes, aliases, and cached directory entries — never silently dropped or weakened.

**Architecture:** Today the deny list lives only in the live `VolumeMount` config and is re-read when a sandbox starts fresh. Restore can bypass normal lookup by re-interning saved inodes, aliases, and directory-listing snapshots, so the policy is not re-checked. Two changes: (1) capture the deny policy in the external-mounts manifest and refuse a restore that would weaken it; (2) re-filter every restore path (inodes done on Unix already, add directory snapshots + Windows) through the destination deny list.

**Tech Stack:** Rust, `serde_json`, the passthrough `mobility` modules, the SDK snapshot/restore/branch code.

**Spec / context:**
- Findings: **H1** (snapshot/archive/branch don't capture/compare deny), **H2** (restore re-applies to inodes but not aliases/cached dir entries — toks PR comment 2026-10-12), M3/G-10 (restored `DirSnapshot` entries served unfiltered).
- PR-toks: *"can we apply the destination deny policy when restoring inodes, aliases and cached directory entries? these bypass normal lookup during restore. i have local checks and regression tests we can carry over."*
- Unix reference: `crates/filesystem/lib/backends/passthroughfs/unix/mobility.rs::reject_denied_restore_path` (`:702-721`, called `:750`), test `restore_refuses_a_path_the_destination_deny_list_hides`.
- Windows half lives in Plan 1 Task 4; this plan owns the shared manifest, the Unix directory-entry half, and restore-policy validation.
- **Out of scope:** the read-only path-list / `protect` design in `docs/superpowers/specs/2026-10-12-readonly-path-list-design.md` is a separate, not-yet-approved feature. Do not read, implement, or design around it; treat `deny` as the only pattern-list consumer.

## Global Constraints

- Bidirectional v0.6.x compatibility (v0.6.0 floor) both directions; see `COMPATIBILITY.md` and AGENTS.md "Backward Compatibility Review".
- An older `msb` must refuse a newer persisted catalog cleanly; never strand or silently weaken state.
- `deny` is directory-bind-only; a restore that also changes other host-backed options (host path, `readonly`) has the same weakness and should be validated together.
- Deny is host-side only; do not add it to `MSB_DIR_MOUNTS` / bootstrap dir mounts.
- Always fail closed: if a restored path cannot be classified against the destination deny list, refuse the restore.

## Review Focus

1. Restore a sandbox captured with **no** deny into a destination whose config **adds** deny → the denied name must not be reachable via lookup, readdir, aliases, or a retained handle.
2. Branch/fork a deny-bearing source without re-declaring deny → refuse or require re-declaration, never silently proceed.
3. Disk-only restore from an archive (no checkpoint passthrough state) → still enforces the config deny list on the fresh mount.
4. A directory snapshot whose parent path cannot be reconstructed → drop the snapshot, do not serve stale entries.
5. Cross-version: an older `msb` opening a deny-bearing catalog → clean refusal (covered with Plan 4).

---

## File Structure

- `packages/microsandbox-types/rust/lib/snapshot/external_mounts.rs` — manifest extension shape (currently `guest_paths: Vec<String>`).
- `sdk/rust/lib/backend/local/snapshot/create.rs` — `uncaptured_mount_paths` (`:1334`), capture side.
- `sdk/rust/lib/sandbox/external_mounts.rs` — `require_guest_mounts` (`:69-105`), flag comparison (`:306-321`), `authorized_source_mount` (`:423-464`).
- `sdk/rust/lib/sandbox/branch.rs` — external-bind retain (`:406-410`).
- `crates/filesystem/lib/backends/passthroughfs/unix/mobility.rs` — `rebuild` (`:789-799`) directory-snapshot re-filter.
- Docs: `docs/sandboxes/snapshots.mdx`.

---

### Task 1: Capture the deny policy in the external-mounts manifest (H1, capture side)

**Files:**
- Modify: `packages/microsandbox-types/rust/lib/snapshot/external_mounts.rs`
- Modify: `sdk/rust/lib/backend/local/snapshot/create.rs:1334`
- Test: `sdk/rust/lib/backend/local/snapshot/create.rs` unit tests

**Interfaces:**
- Produces: `struct ExternalMountPolicy { guest_path: String, deny: Vec<String> }` (or an additive field on the existing extension), serialized with `#[serde(default)]` so older manifests load as empty. Keep the existing `guest_paths` for backward read compatibility; derive the new field additively.
- Produces: `fn captured_mount_policies(&[VolumeMount]) -> Vec<ExternalMountPolicy>`.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn snapshot_manifest_records_bind_deny_policy() {
    // create side: a spec with a bind mount deny=[".env"] and one without
    // assert captured_mount_policies includes the deny list for the first only
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p microsandbox --lib snapshot_manifest_records_bind_deny_policy`
Expected: FAIL — no such function.

- [ ] **Step 3: Add the manifest field and capture**

Extend the extension additively; populate from `VolumeMount::Bind { deny, .. }` in the capture path. Do not change the digest of mounts that carry no deny (verify `deny: []` produces the same bytes as before).

- [ ] **Step 4: Run the test**

Run: `cargo test -p microsandbox --lib snapshot_manifest_records_bind_deny_policy`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/microsandbox-types/rust/lib/snapshot/external_mounts.rs sdk/rust/lib/backend/local/snapshot/create.rs
git commit -m "feat(snapshot): capture bind-mount deny policy in external mounts manifest"
```

---

### Task 2: Refuse a restore that weakens deny (H1, validate side)

**Files:**
- Modify: `sdk/rust/lib/sandbox/external_mounts.rs` (`require_guest_mounts` `:69-105`, flag comparison `:306-321`)
- Test: `sdk/rust/lib/sandbox/external_mounts.rs` tests

**Interfaces:**
- Consumes: `captured_mount_policies` (Task 1).
- Produces: restore validation that errors with a clear "restore would weaken bind-mount deny policy at <guest_path>; re-declare the deny list" message when the destination mount's deny is a strict subset of the captured one (or absent when captured was non-empty).

**Decision (builder's call):** Require the destination deny list to be **exactly equal** to the captured list; a superset is allowed only if it is a superset (stricter) — never a subset. Missing capture info (legacy manifest) is treated as "unknown", accepted with a warning, never as empty.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn restore_rejects_bind_that_drops_captured_deny() { /* captured [".env"], destination [] -> Err */ }

#[test]
fn restore_accepts_bind_that_preserves_deny() { /* equal lists -> Ok */ }

#[test]
fn restore_accepts_legacy_manifest_without_policy() { /* empty policy -> Ok + warning */ }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p microsandbox --lib restore_rejects_bind_that_drops_captured_deny`
Expected: FAIL — currently succeeds and exposes the path.

- [ ] **Step 3: Implement comparison in `require_guest_mounts`**

Compare captured vs destination per guest path; on weakening return an explicit error. Wire the warning path for legacy manifests.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p microsandbox --lib restore_`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add sdk/rust/lib/sandbox/external_mounts.rs
git commit -m "fix(sandbox): refuse restore that weakens bind-mount deny policy"
```

---

### Task 3: Branch children require deny re-declaration (H1)

**Files:**
- Modify: `sdk/rust/lib/sandbox/branch.rs:406-410`
- Test: `sdk/rust/lib/sandbox/branch.rs` tests

**Interfaces:**
- Consumes: Task 1/2 capture+compare.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn branch_of_deny_bearing_source_requires_redeclaration() {
    // source has deny=[".env"], child supplies plain bind -> Err (or carries deny if inherited)
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p microsandbox --lib branch_of_deny_bearing_source`
Expected: FAIL.

- [ ] **Step 3: Apply the same weakening check to branch external binds**

Reuse the Task 2 validator; if the child does not inherit resources, require the deny list explicitly.

- [ ] **Step 4: Run the test**

Run: `cargo test -p microsandbox --lib branch_`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add sdk/rust/lib/sandbox/branch.rs
git commit -m "fix(sandbox): require deny re-declaration on branch children"
```

---

### Task 4: Re-filter restored directory snapshots on Unix (H2, G-10)

**Files:**
- Modify: `crates/filesystem/lib/backends/passthroughfs/unix/mobility.rs` (`rebuild` `:789-799`)
- Modify: `crates/filesystem/lib/backends/passthroughfs/unix/dir_ops.rs` (`serve_snapshot_entries` consumers)
- Test: `crates/filesystem/lib/backends/passthroughfs/unix/tests/test_deny.rs`

**Interfaces:**
- Consumes: `DirSnapshot { entries }`, `DenyList::matches_basename`/`matches_path`, the directory inode's mount-relative parent path.
- Produces: no public API change.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn restored_directory_snapshot_drops_names_hidden_by_destination_deny() {
    // capture a dir listing without deny; rebuild with deny=[".env"];
    // readdir must not list ".env"
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p microsandbox-filesystem --lib restored_directory_snapshot`
Expected: FAIL — `.env` is listed.

- [ ] **Step 3: Re-filter in `rebuild`**

When rebuilding a `DirHandleState`, drop entries matching the destination deny (using the same dir-only/name-only logic as live readdir). If the parent path cannot be reconstructed, drop the whole snapshot (fail closed) rather than serving stale entries.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p microsandbox-filesystem --lib deny`
Expected: PASS, including prior restore tests.

- [ ] **Step 5: Commit**

```bash
git add crates/filesystem/lib/backends/passthroughfs/unix/mobility.rs crates/filesystem/lib/backends/passthroughfs/unix/dir_ops.rs crates/filesystem/lib/backends/passthroughfs/unix/tests/test_deny.rs
git commit -m "fix(filesystem): refilter restored directory snapshots against deny"
```

---

### Task 5: Strengthen the restore test to a real end-to-end path (G-14)

**Files:**
- Modify: `crates/filesystem/lib/backends/passthroughfs/unix/mobility.rs` test `restore_refuses_a_path_the_destination_deny_list_hides`
- Add: `sdk/rust/tests/` integration test `deny_restore_roundtrip.rs` (or extend an existing snapshot integration test)

- [ ] **Step 1: Write the failing test**

An integration test that creates a sandbox with `deny=[".env"]`, snapshots it, restores/branches it, and asserts (a) the policy round-trips and (b) `.env` is `ENOENT` after restore. Use the existing snapshot integration harness; gate on a live Linux/macOS host.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p microsandbox --test deny_restore_roundtrip`
Expected: FAIL until Tasks 1–4 land.

- [ ] **Step 3: Implement any glue the integration path needs**

Mostly test-only; fix whatever the round-trip reveals.

- [ ] **Step 4: Run the test**

Run: `cargo test -p microsandbox --test deny_restore_roundtrip`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add sdk/rust/tests/deny_restore_roundtrip.rs crates/filesystem/lib/backends/passthroughfs/unix/mobility.rs
git commit -m "test(sandbox): end-to-end deny snapshot restore round-trip"
```

---

### Task 6: Document restore semantics (H1 docs)

**Files:**
- Modify: `docs/sandboxes/snapshots.mdx`
- Modify: `docs/sandboxes/volumes.mdx` (cross-reference)

- [ ] **Step 1: Add the documentation**

State that host-backed bind mounts must be re-supplied on restore, that the `deny` policy is validated against the captured policy and cannot be weakened, and that branch children must re-declare or inherit a deny-bearing mount.

- [ ] **Step 2: Verify links/anchors resolve**

Run: `rg -n "snapshots" docs/sandboxes/volumes.mdx`

- [ ] **Step 3: Commit**

```bash
git add docs/sandboxes/snapshots.mdx docs/sandboxes/volumes.mdx
git commit -m "docs(sandboxes): document deny policy durability across restore"
```
