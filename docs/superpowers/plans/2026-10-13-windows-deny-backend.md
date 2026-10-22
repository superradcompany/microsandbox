# Windows Bind-Mount Deny Backend — Repair Plan (Plan 1 of 5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the Windows passthrough backend compile and make its deny-list enforcement match the Unix backend's guarantees, closing the two security holes found in review.

**Architecture:** The Windows backend (`#[cfg(windows)]`, so never compiled on this Linux dev host) was never verified. It currently does not compile, which means all its deny tests are dead. Fix compilation first, then close two enforcement gaps: unlink error-leak, and alternate-name resolution (8.3 short names + trailing dot/space). Then add deny re-application to Windows restore.

**Tech Stack:** Rust, `winapi`/`windows-sys` bindings, the `ignore`/`globset` deny matcher in `crates/filesystem/lib/backends/passthroughfs/deny.rs`.

**Spec / context:**
- Review register: `bind-mount-deny-option`, base `13d799c5`, review HEAD `aecabe8c`. Findings: **C1 (blocker)**, **H3**, **H4**, **H7**, plus Windows residuals M6 (setattr on replaced path-backed inode), and PR-greptile threads `4248359740`.
- The Unix parity reference is `crates/filesystem/lib/backends/passthroughfs/unix/remove_ops.rs` (`do_unlink`), `unix/mobility.rs` (`reject_denied_restore_path`), and `unix/inode.rs` (`do_lookup`).
- Domain/matcher interfaces are fixed by Plan 3 (`deny-matcher-hardening`); do not change `DenyList`'s public API here except as that plan specifies.
- **Out of scope:** the read-only path-list / `protect` design in `docs/superpowers/specs/2026-10-12-readonly-path-list-design.md` is a separate, not-yet-approved feature. Do not read, implement, or design around it; treat `deny` as the only pattern-list consumer.

**Environment caveat:** This plan REQUIRES a Windows host or `--target x86_64-pc-windows-msvc` toolchain. Every step that says "run the Windows tests" cannot execute on Linux; the executing session must have Windows CI or a Windows runner. If none is available, STOP and escalate rather than marking tasks complete.

## Global Constraints

- Deny is **directory-bind-only**; file binds and non-bind mounts reject `deny` (already enforced elsewhere).
- Name-only deny rules and dir-only (`node_modules/`) rules must both hide the name; a denied name is indistinguishable from an absent one (`ENOENT` on lookup, `EACCES` on mutation) — no error may leak existence or type.
- `.` and `..` are never denied.
- Case-insensitive matching on NTFS is mandatory and must over-match rather than under-match.
- Follow `crates/filesystem/.../windows/` existing conventions; match the Unix backend's fail-closed posture.
- Named residual risk (host-writer TOCTOU in rename) is **accepted** per `neurolabs` reply `3841931084`; do not attempt to close it. Document it, don't fight it.

## Review Focus

Inputs/conditions the tests must pin, most likely to bite first:
1. A denied name that **exists** vs one that **does not exist** → both must yield the same error (`EACCES` on unlink/rename, `ENOENT` on lookup).
2. A denied **directory** reached via its 8.3 short name (`NODE_M~1`) → hidden.
3. A denied name with a **trailing dot or space** (`.env.`, `node_modules `) → hidden or rejected, never resolved.
4. `unlink` of a denied **reparse point** (junction/symlink) → same error as a denied file.
5. Restore of a checkpoint captured with an **empty/weaker** deny list into a mount with a **stronger** one → refuses.

---

## File Structure

- `crates/filesystem/lib/backends/passthroughfs/windows/mod.rs` — component validation, `deny_matches_name`, path reconstruction, name canonicalization.
- `crates/filesystem/lib/backends/passthroughfs/windows/inode.rs` — lookup, `child_path`, `intern_path`.
- `crates/filesystem/lib/backends/passthroughfs/windows/ops.rs` — `unlink`, `rename`, `setattr`.
- `crates/filesystem/lib/backends/passthroughfs/windows/mobility.rs` — restore/rebuild.
- `crates/filesystem/lib/backends/passthroughfs/windows/tests.rs` — Windows-only tests.

---

### Task 1: Fix the compile break (C1 — blocker)

**Files:**
- Modify: `crates/filesystem/lib/backends/passthroughfs/windows/mod.rs:282`
- Test: `cargo check --target x86_64-pc-windows-msvc -p microsandbox-filesystem`

**Interfaces:**
- Uses: `InodeData::path(&self) -> PathBuf` (`windows/inode.rs:64`), `relative_path_string(path: &Path, root: &Path) -> Option<String>` (`windows/mod.rs:324`).

- [ ] **Step 1: Reproduce the failure**

Run: `cargo check --target x86_64-pc-windows-msvc -p microsandbox-filesystem`
Expected: FAIL with `E0308: expected &Path, found &RwLock<PathBuf>` at `windows/mod.rs:282`. (Confirmed independently with a standalone `rustc` probe.)

- [ ] **Step 2: Change `&parent_data.path` to `&parent_data.path()`**

At `windows/mod.rs:282`, replace the field access with the accessor so `&PathBuf` deref-coerces to `&Path`.

- [ ] **Step 3: Verify the Windows target builds**

Run: `cargo check --target x86_64-pc-windows-msvc -p microsandbox-filesystem`
Expected: PASS (no E0308).

- [ ] **Step 4: Compile the Windows test suite**

Run: `cargo test --target x86_64-pc-windows-msvc -p microsandbox-filesystem --no-run`
Expected: builds `windows/tests.rs` (previously never compiled).

- [ ] **Step 5: Commit**

```bash
git add crates/filesystem/lib/backends/passthroughfs/windows/mod.rs
git commit -m "fix(filesystem): compile windows deny backend pass parent path by accessor"
```

---

### Task 2: Unlink must not leak a denied name's existence (H7)

**Files:**
- Modify: `crates/filesystem/lib/backends/passthroughfs/windows/ops.rs` (`unlink`, currently `:151-168`)
- Test: `crates/filesystem/lib/backends/passthroughfs/windows/tests.rs`

**Interfaces:**
- Consumes: `DenyList::has_dir_only_patterns(&self) -> bool`, `fs.deny_matches_name(parent: u64, name: &CStr, is_dir: bool) -> bool`, `fs.safe_metadata(&Path) -> io::Result<Metadata>`.
- Produces: no public API change; `unlink` error contract (below).

**Contract:** `unlink` on a name matching a **name-only** rule returns `EACCES` whether or not the name exists and whether or not it is a reparse point. Only when a **dir-only** rule could apply may metadata be read; if that read fails, treat as a directory and return `EACCES` (fail closed).

- [ ] **Step 1: Write the failing tests**

Add to `windows/tests.rs` (names indicative; match the file's existing helpers):

```rust
#[test]
fn unlink_denied_name_returns_eacces_when_present() { /* deny=.env, create .env, expect EACCES */ }

#[test]
fn unlink_denied_name_returns_eacces_when_absent() { /* deny=.env, do not create, expect EACCES not ENOENT */ }

#[test]
fn unlink_denied_reparse_point_returns_eacces() { /* deny=.env, .env is a junction, expect EACCES not ELOOP */ }

#[test]
fn unlink_dir_only_deny_still_hides_directory() { /* deny=node_modules/, dir present, expect EACCES */ }

#[test]
fn unlink_allowed_file_succeeds() { /* no matching rule, expect Ok and file gone */ }
```

- [ ] **Step 2: Run them to verify failure**

Run: `cargo test --target x86_64-pc-windows-msvc -p microsandbox-filesystem unlink_denied`
Expected: `..._absent` and `..._reparse_point` FAIL with `ENOENT`/`ELOOP` instead of `EACCES`.

- [ ] **Step 3: Reorder the deny decision in `unlink`**

Check name-only rules first (`deny_matches_name(parent, name, false)`) and return `EACCES` before any metadata read. If `deny.has_dir_only_patterns()`, then `safe_metadata`; treat a stat error as `is_dir = true` and deny, else `deny_matches_name(..., is_dir)` then `EACCES`. Keep the existing `require_writable()` and `child_path()` ordering. Mirror the Unix approach in `unix/remove_ops.rs` (`do_unlink`) but preserve the name-only-first ordering that closes the error oracle.

- [ ] **Step 4: Run the tests**

Run: `cargo test --target x86_64-pc-windows-msvc -p microsandbox-filesystem unlink`
Expected: all PASS, including the pre-existing `deny_*` unlink tests re-enabled by Task 1.

- [ ] **Step 5: Commit**

```bash
git add crates/filesystem/lib/backends/passthroughfs/windows/ops.rs crates/filesystem/lib/backends/passthroughfs/windows/tests.rs
git commit -m "fix(filesystem): stop windows unlink leaking hidden name existence"
```

---

### Task 3: Reject/canonicalize alternate Windows names (H4)

**Files:**
- Modify: `crates/filesystem/lib/backends/passthroughfs/windows/mod.rs` (`validate_component` ~`:338-352`, `deny_matches_name` ~`:264-289`)
- Test: `crates/filesystem/lib/backends/passthroughfs/windows/tests.rs`

**Interfaces:**
- Produces: `fn canonical_component(name: &CStr) -> io::Result<Cow<'_, str>>` (new, `mod.rs`) that maps a guest-supplied component to the on-disk long name, or errors; and a tightened `validate_component`.

**Decision (builder's call):** Reject components with a trailing `.` or space (`EINVAL`) — Win32 strips them, so they are never the intended target. For 8.3 short names, resolve the requested component to its long name before the deny decision (`GetLongPathNameW` on the child path, or `FindFirstFileW`'s `cFileName`), then match the long name. If resolution cannot be done cheaply, fall back to denying any component containing a `~` followed by digits (over-match, fail closed).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn lookup_denied_name_via_trailing_dot_is_hidden() { /* deny=.env, lookup ".env." -> EINVAL or ENOENT, never exposes */ }

#[test]
fn lookup_denied_name_via_trailing_space_is_hidden() { /* deny=.env, lookup ".env " */ }

#[test]
fn lookup_denied_long_name_via_short_alias_is_hidden() { /* deny=node_modules/, lookup "NODE_M~1" -> ENOENT */ }

#[test]
fn create_denied_name_via_trailing_dot_is_rejected() { /* deny=.env, create ".env." -> EINVAL/EACCES */ }
```

Gate the 8.3 test on volumes with short-name generation enabled (skip/`#[ignore]` when `NtfsDisable8dot3NameCreation` is set for the volume); note the gate in the test.

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --target x86_64-pc-windows-msvc -p microsandbox-filesystem alias`
Expected: FAIL — the alias resolves onto the denied entry.

- [ ] **Step 3: Implement `validate_component` rejection and canonicalization**

Reject empty/`.`/`..`/containing `/`\\`:`/reserved (existing) plus trailing `.` or space. Add `canonical_component` and call it in `deny_matches_name`/`child_path` before matching, so name-only and dir-only decisions use the canonical name. Keep failing closed: resolution error → deny.

- [ ] **Step 4: Run the tests**

Run: `cargo test --target x86_64-pc-windows-msvc -p microsandbox-filesystem alias`
Run: `cargo test --target x86_64-pc-windows-msvc -p microsandbox-filesystem deny`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/filesystem/lib/backends/passthroughfs/windows/mod.rs crates/filesystem/lib/backends/passthroughfs/windows/tests.rs
git commit -m "fix(filesystem): close windows alternate-name deny bypasses"
```

---

### Task 4: Re-apply deny on Windows restore (H3)

**Files:**
- Modify: `crates/filesystem/lib/backends/passthroughfs/windows/mobility.rs` (`rebuild` ~`:868`, `restore_aliases`)
- Test: `crates/filesystem/lib/backends/passthroughfs/windows/tests.rs`

**Interfaces:**
- Consumes: `DenyList::is_empty() -> bool`, `DenyList::matches_path`/`matches_basename`.
- Reference: `unix/mobility.rs::reject_denied_restore_path` (`:702-721`), called at `:750`.
- Depends on: Plan 2 (`deny-restore-durability`) for the directory-entry re-filter; implement the inode/alias half here so behavior matches Unix, and coordinate the shared manifest shape there.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn windows_restore_refuses_path_hidden_by_destination_deny() { /* capture empty deny, rebuild with stronger deny, expect error */ }

#[test]
fn windows_restore_reapplies_deny_to_aliases() { /* saved alias path now denied -> not interned */ }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --target x86_64-pc-windows-msvc -p microsandbox-filesystem windows_restore`
Expected: FAIL — restore succeeds and re-interns the now-denied path.

- [ ] **Step 3: Add the deny re-check**

In `rebuild`, after reopening each saved component/inode and before insertion, call a Windows analogue of `reject_denied_restore_path` (fstat the reopened object for its type, then `deny.matches_path`), failing closed. Apply the same check in `restore_aliases` before inserting into `by_path`.

- [ ] **Step 4: Run the tests**

Run: `cargo test --target x86_64-pc-windows-msvc -p microsandbox-filesystem windows_restore`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/filesystem/lib/backends/passthroughfs/windows/mobility.rs crates/filesystem/lib/backends/passthroughfs/windows/tests.rs
git commit -m "fix(filesystem): reapply deny on windows restore"
```

---

### Task 5: Windows residuals — setattr on replaced inode; lookup/opendir coherence (M6, PR-g `4248359740`)

**Files:**
- Modify: `crates/filesystem/lib/backends/passthroughfs/windows/ops.rs` (`setattr`), `windows/inode.rs` (`do_lookup`, `intern_path`)
- Test: `crates/filesystem/lib/backends/passthroughfs/windows/tests.rs`

**Interfaces:**
- Consumes: existing `deny_matches_name`; `InodeData::retained`/`metadata_identity`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn setattr_on_replaced_dir_only_denied_path_is_refused() { /* lookup allowed file, replace with denied-name dir, setattr -> EACCES/ENOENT */ }

#[test]
fn opendir_after_replacement_dir_does_not_expose_contents() { /* replacement dir under dir-only deny -> opendir denied */ }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test --target x86_64-pc-windows-msvc -p microsandbox-filesystem setattr_on_replaced`
Expected: FAIL — attributes of the hidden directory are mutated.

- [ ] **Step 3: Gate the inode-scoped path**

For path-backed inodes whose `retained` handle is `None`, re-run the dir-only deny check against the live path before mutating host attributes (setattr mtime/atime/attrs), and before `opendir` trusts the live path. Reuse `deny_matches_name(parent, canonical_name, live_is_dir)`. Keep name-only and dir-only coherence with Task 3.

- [ ] **Step 4: Run the tests**

Run: `cargo test --target x86_64-pc-windows-msvc -p microsandbox-filesystem`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/filesystem/lib/backends/passthroughfs/windows/ops.rs crates/filesystem/lib/backends/passthroughfs/windows/inode.rs crates/filesystem/lib/backends/passthroughfs/windows/tests.rs
git commit -m "fix(filesystem): gate windows inode-scoped ops on live path deny"
```

---

### Task 6: CI platform guardrails

**Files:**
- Modify: `.github/workflows/*` (the workflow that builds the workspace) and/or `justfile`
- Test: `cargo check --target x86_64-pc-windows-msvc -p microsandbox-filesystem`

- [ ] **Step 1: Add a Windows cross-check job**

Add a job that runs `cargo check --target x86_64-pc-windows-msvc -p microsandbox-filesystem` and `cargo check --target aarch64-apple-darwin -p microsandbox-filesystem` so a cfg-gated backend can never silently stop compiling again (root cause of C1).

- [ ] **Step 2: Verify locally (Linux-runnable part)**

Run: `cargo check --target x86_64-pc-windows-msvc -p microsandbox-filesystem`
Expected: PASS (requires the windows target installed).

- [ ] **Step 3: Commit**

```bash
git add .github/workflows justfile
git commit -m "ci: compile windows and macos filesystem backend targets"
```
