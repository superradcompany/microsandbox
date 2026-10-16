# Deny Matcher Hardening — Repair Plan (Plan 3 of 5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The shared deny matcher must reject patterns it cannot enforce, must not be silently inert, must honor a documented case-folding guarantee, and must fail closed at every boundary.

**Architecture:** `DenyList` (`crates/filesystem/lib/backends/passthroughfs/deny.rs`) compiles gitignore-style patterns via the `ignore` crate. Review found patterns that compile to nothing (silent no-ops), an ASCII-only case fold that under-matches on NTFS/APFS, an orphaned case-probe file, and a backend boundary that trusts SDK/runtime validation. Harden the matcher and the shared validator, keep every caller fail-closed.

**Tech Stack:** Rust, `ignore`/`globset`, `packages/microsandbox-types/rust/lib/validation.rs` (shared validators used by Rust/Go/runtime).

**Spec / context:**
- Findings: **H5** (Unicode case fold), **M1** (inert patterns: `foo//`, `./secret`, `//secret`, bare `!`), **M7** (case-probe file leak), **M10** (f2fs/overlayfs assumed case-sensitive), **M2** (backend boundary doesn't enforce writable-path rule), `.`/`..` contract drift, `do_link` hardcode, `name_as_path` fail-open.
- PR-appcypher `3906476026` (invalid pattern must error), `3906476067` (case sensitivity), `3906476079` (`unwrap_or(false)`); PR-toks `3933341505` (RO case guarantee), `3933341632` (parallel temp-dir test panic); PR-greptile `4248102036`.
- Scope every change to the `deny` path only. Do not introduce a generic "path-pattern list" abstraction or move deny policy (negation/allowlist rules, the writable-path invariant) into shared code; there is no second consumer today.
- Windows-dependent tasks require the Windows target; the Unix/matcher tasks run on Linux/macOS.
- **Out of scope:** the read-only path-list / `protect` design in `docs/superpowers/specs/2026-10-12-readonly-path-list-design.md` is a separate, not-yet-approved feature. Do not read, implement, or design around it; treat `deny` as the only pattern-list consumer.

## Global Constraints

- `validate_deny_pattern` / `reject_writable_path_patterns` / `validate_deny_list` are the single source of truth; Rust SDK, Go native, runtime, and (indirectly) Python/Node/CLI all use them.
- Wire hazards (`,`, `:`, `\n`, `\0`), empty, and surrounding whitespace are already rejected — do not loosen.
- A pattern the matcher accepts must be one the matcher enforces. If it cannot be enforced, construction must error.
- Fail closed on any resolution/type failure; never fail open.
- Case handling: NTFS always case-insensitive (over-match); macOS/read-only Linux uses a probe or a known-case-sensitive allowlist; unknown → over-match (case-insensitive).

## Review Focus

1. `deny=foo//`, `deny=./secret`, `deny=//secret`, `deny=!`, `deny=a/./b` → must be rejected at validation (or proven equivalent), never accepted-and-inert.
2. A non-ASCII pattern (`café`) on a case-insensitive mount → must either fold `CAFÉ` or be rejected at config time; never silently under-match.
3. A writable mount reaching `DenyList::new`/`PassthroughFsBuilder` directly with a path pattern → must be refused, not silently allowed.
4. `.` / `..` in any operation → never denied and never breaks a path walk.
5. Case-probe write/remove failure → no artifact left in the user's host directory.

---

## File Structure

- `crates/filesystem/lib/backends/passthroughfs/deny.rs` — matcher build, case probe, `matches_*`.
- `crates/filesystem/lib/backends/shared/platform.rs` — platform path/type helpers.
- `packages/microsandbox-types/rust/lib/validation.rs` — shared validators.
- `crates/filesystem/lib/backends/passthroughfs/unix/create_ops.rs` — `do_link`.
- `crates/filesystem/lib/backends/passthroughfs/unix/mod.rs` — builder boundary, `.`/`..` guard.
- `crates/filesystem/lib/backends/passthroughfs/windows/mod.rs` — `.`/`..` guard (keep in sync).
- Tests: `unix/tests/test_deny.rs`, `test_deny_macos.rs`, `test_deny_perf.rs`, `windows/tests.rs`, `validation.rs` unit tests.

---

### Task 1: Reject non-canonical/inert patterns (M1)

**Files:**
- Modify: `packages/microsandbox-types/rust/lib/validation.rs` (`validate_deny_pattern`)
- Modify: `crates/filesystem/lib/backends/passthroughfs/deny.rs` (`DenyList::build` — defence in depth)
- Test: both files' unit tests

**Interfaces:**
- Produces: `validate_deny_pattern` additionally rejects: a leading `./`; a leading `//`; repeated interior `//`; a pattern that is only `!` (negation with no rule); a pattern equal to `.`/`..`; a leading `/` followed by another `/`. Each with a distinct, actionable message.
- Produces: `DenyList::build` returns `Err` for the same set (never silently compiles to an empty matcher).

**Decision (builder's call):** Reject rather than normalize — a user who typed `./secret` should get an error telling them to write `secret` or `sub/secret`, not silent reinterpretation. `**/name` stays valid.

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn rejects_non_canonical_patterns() {
    for bad in ["./secret", "//secret", "a//b", "!", ".", "..", "foo//"] {
        assert!(validate_deny_pattern(bad).is_err(), "{bad:?}");
    }
    for ok in [".env", "sub/.env", "**/env.secret", "node_modules/", "\\#x", "!keep.txt"] {
        validate_deny_pattern(ok).unwrap();
    }
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p microsandbox-types rejects_non_canonical_patterns`
Expected: FAIL for the inert set.

- [ ] **Step 3: Implement the checks**

Add the rejections to `validate_deny_pattern`; mirror in `DenyList::build` so a direct constructor cannot produce a silent no-op (this closes the PR-appcypher `3906476026` concern generally).

- [ ] **Step 4: Run the tests**

Run: `cargo test -p microsandbox-types deny`
Run: `cargo test -p microsandbox-filesystem --lib deny`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add packages/microsandbox-types/rust/lib/validation.rs crates/filesystem/lib/backends/passthroughfs/deny.rs
git commit -m "fix(filesystem): reject deny patterns that would compile inert"
```

---

### Task 2: Documented and enforced case-folding guarantee (H5, M10, PR-toks)

**Files:**
- Modify: `crates/filesystem/lib/backends/passthroughfs/deny.rs` (`build`, `mount_is_case_insensitive`, `ro_fs_is_case_sensitive`)
- Modify: `packages/microsandbox-types/rust/lib/validation.rs` (config-time rejection for non-ASCII on case-insensitive mounts, if that route is chosen)
- Test: `deny.rs` unit tests; `test_deny_macos.rs`

**Interfaces:**
- Produces (chosen route): **reject non-ASCII deny patterns when the mount is case-insensitive**, with the message: `deny pattern {p:?} contains non-ASCII characters, which cannot be matched case-insensitively on this filesystem; use an ASCII pattern or a case-sensitive mount`. This is enforceable and honest.

**Decision (builder's call):** The alternative — Unicode-aware folding — requires either a `globset` Unicode mode that the crate does not expose, or pre-folding both sides and losing glob semantics. Prefer the enforced guarantee. If the executor can implement true Unicode folding cheaply, they may; the tests below define the required behavior either way (match or config error, never silent under-match).

- [ ] **Step 1: Write the failing tests**

```rust
#[test]
fn non_ascii_pattern_on_case_insensitive_mount_is_rejected_or_folds() {
    // build(["café"], true): either Err, or matches_basename(b"CAFE\u{301}") == true
}
#[test]
fn ascii_folding_still_works() { /* build([".ENV"], true) matches ".env" */ }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p microsandbox-filesystem --lib non_ascii_pattern`
Expected: FAIL (currently accepts and under-matches).

- [ ] **Step 3: Implement the chosen route**

If rejecting: add the ASCII check in the case-insensitive build path (or validation when the mount is known case-insensitive). If folding: implement and keep the test green.

- [ ] **Step 4: Narrow the f2fs/overlayfs allowlist (M10)**

Remove `f2fs`/`overlayfs` from `ro_fs_is_case_sensitive` unless per-directory casefold presence is verified; unknown → case-insensitive (over-match).

- [ ] **Step 5: Run the tests and commit**

Run: `cargo test -p microsandbox-filesystem --lib deny`
```bash
git add crates/filesystem/lib/backends/passthroughfs/deny.rs packages/microsandbox-types/rust/lib/validation.rs
git commit -m "fix(filesystem): enforce documented deny case-folding guarantee"
```

---

### Task 3: Fail-closed case probe and cleanup (M7)

**Files:**
- Modify: `crates/filesystem/lib/backends/passthroughfs/deny.rs` (`probe` write/remove ~`:293-306`)
- Test: `deny.rs` unit tests

**Interfaces:**
- Produces: a `struct ProbeFile { path: PathBuf }` with `impl Drop` that removes the file, used for the case probe so any early `?` return still cleans up; probe write failure → treat as case-insensitive (over-match), not error.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn case_probe_leaves_no_artifact_on_write_failure() {
    // force write/remove failure (read-only dir) and assert the directory is unchanged
}
```

- [ ] **Step 2: Run to verify failure / reasoning**

Run: `cargo test -p microsandbox-filesystem --lib case_probe`

- [ ] **Step 3: Implement the RAII probe guard**

- [ ] **Step 4: Run the tests**

Run: `cargo test -p microsandbox-filesystem --lib deny`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/filesystem/lib/backends/passthroughfs/deny.rs
git commit -m "fix(filesystem): clean up deny case-probe file on failure"
```

---

### Task 4: Enforce the writable-path-pattern rule at the backend boundary (M2)

**Files:**
- Modify: `crates/filesystem/lib/backends/passthroughfs/unix/mod.rs` (`PassthroughFs::new`/builder)
- Modify: `crates/filesystem/lib/backends/passthroughfs/unix/builder.rs` (`:144-148`)
- Test: `unix/tests/test_deny.rs`

**Interfaces:**
- Produces: `PassthroughFsBuilder`/`PassthroughFs::new` reject a path pattern when `readonly == false`, calling `microsandbox_types::reject_writable_path_patterns`.

**Decision (builder's call):** Refuse at construction (defense in depth), matching the SDK/runtime rule; do not leave enforcement solely to callers.

- [ ] **Step 1: Write the failing test**

```rust
#[test]
fn builder_rejects_path_pattern_on_writable_mount() {
    // build with deny=["sub/.env"], readonly=false -> Err
    // readonly=true -> Ok
}
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p microsandbox-filesystem --lib builder_rejects_path_pattern`
Expected: FAIL.

- [ ] **Step 3: Add validation in the builder/new path**

- [ ] **Step 4: Run the tests**

Run: `cargo test -p microsandbox-filesystem --lib deny`
Expected: PASS. (Note: `test_deny_path_pattern_rename_onto_denied_path_is_rejected` currently constructs a writable mount with a path pattern — update it to the new invariant.)

- [ ] **Step 5: Commit**

```bash
git add crates/filesystem/lib/backends/passthroughfs/unix/mod.rs crates/filesystem/lib/backends/passthroughfs/unix/builder.rs crates/filesystem/lib/backends/passthroughfs/unix/tests/test_deny.rs
git commit -m "fix(filesystem): enforce writable-mount path-pattern rule at backend"
```

---

### Task 5: Structural `.`/`..` guard in the matcher; `do_link` type; `name_as_path` fail-closed

**Files:**
- Modify: `crates/filesystem/lib/backends/passthroughfs/deny.rs` (`matches_basename`/`matches_path`/`matches_relative`)
- Modify: `crates/filesystem/lib/backends/passthroughfs/unix/create_ops.rs` (`do_link` `:463`)
- Test: `deny.rs` unit tests; `unix/tests/test_deny.rs`

**Interfaces:**
- Produces: `DenyList` itself exempts `.`/`..` (so backends need not duplicate the guard); `do_link` passes the source inode's real type instead of `false`; non-Unix `name_as_path` returns a fail-closed sentinel (deny) on invalid UTF-8 rather than `""`.

- [ ] **Step 1: Write the failing tests**

```rust
#[test] fn matcher_never_matches_dot_or_dotdot() { /* deny=["*"], matched(".",_)=false, matched("..",_)=false */ }
#[test] fn do_link_denies_dir_only_rule_using_source_type() { /* EACCES when source is dir */ }
```

- [ ] **Step 2: Run to verify failure**

Run: `cargo test -p microsandbox-filesystem --lib matcher_never_matches_dot`
Expected: FAIL.

- [ ] **Step 3: Implement**

Add the structural guard in the matcher; derive `is_dir` in `do_link` from the source inode; make `name_as_path` deny on invalid UTF-8.

- [ ] **Step 4: Run the tests**

Run: `cargo test -p microsandbox-filesystem --lib deny`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/filesystem/lib/backends/passthroughfs/deny.rs crates/filesystem/lib/backends/passthroughfs/unix/create_ops.rs
git commit -m "fix(filesystem): matcher-level dot guard, link type, fail-closed decode"
```

---

### Task 6: Matcher test-quality and coverage (G-07, G-14, G-15)

**Files:**
- Modify: `unix/tests/test_deny.rs`, `test_deny_macos.rs`, `test_deny_perf.rs`, `windows/tests.rs`, `validation.rs`
- Add: `sdk/rust/tests/fixtures/deny/patterns.json` (shared cross-SDK fixture)

- [ ] **Step 1: Strengthen weak tests**
  - `test_decide_rename_deny_proceeds_and_retries_on_stale_source`: add the `Deny` branch and the exchange-destination `Retry` branch.
  - `test_deny_symlink_to_denied_target_does_not_expose_target`: actually traverse the symlink, then assert `ENOENT`.
  - `test_deny_dir_only_readdir_keeps_same_named_file`: assert both a directory and a same-named **file**.
- [ ] **Step 2: Add the missing matcher tests**
  - Non-canonical patterns (Task 1), Unicode case (Task 2), anchor/component-boundary (`dir/secret` vs `x/dir/secret`, `/foo` vs `/foobar`), `matches_path(b"")`, `readdirplus` omission.
- [ ] **Step 3: Add the shared fixture**

Create `sdk/rust/tests/fixtures/deny/patterns.json` mapping `{ "pattern", "readonly", "expect": "accept"|"reject" }`; add one consumer test per SDK (Rust, Python, Node, Go, CLI) that loads it and asserts the same disposition.

- [ ] **Step 4: Run all deny suites**

Run: `cargo test -p microsandbox-filesystem --lib deny`
Run: `cargo test -p microsandbox-types`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add crates/filesystem sdk/rust/tests/fixtures/deny
git commit -m "test(filesystem): close matcher coverage gaps and add shared pattern fixture"
```
