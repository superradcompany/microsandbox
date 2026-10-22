# Deny SDK Parity & Documentation — Repair Plan (Plan 5 of 5)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Every SDK and the CLI expose and validate the bind-mount `deny` feature identically, and the documentation is complete, consistent, and styled like the rest of the docs.

**Architecture:** The shared validator (`packages/microsandbox-types/rust/lib/validation.rs`) is the source of truth, consumed by Rust/Go native/runtime; Python/Node/CLI route through the Rust builder. Review found Python validating only part of the rules at its own boundary, a Python positional-compatibility break, SDK reference pages using forbidden tables, and a bundle of documentation gaps.

**Tech Stack:** Rust, Python (pyo3), Node (`napi-rs`), Go (`cgo` FFI), Mintlify `.mdx` docs.

**Spec / context:**
- Findings: **M3** (Python boundary defers rules, two exception classes), **M4** (Python `MountConfig` positional shift — PR-toks `3933341750`), **M5** (SDK reference tables forbidden — PR-greptile `4255924750`), **M11** (documentation bundle), N5 (Python `apply_mount` drops deny on owned/named).
- PR-greptile `4255924750`; PR-toks `3933341750`.
- Constraints: AGENTS.md SDK-reference rules — *"Do not use tables in SDK references"*; individual method/property headings with visible signatures; examples in collapsed `<Accordion title="Example">`; no redundant overview prose; keep docs in sync with behavior.
- Plan 3 owns the shared validator changes; this plan consumes them.
- **Out of scope:** the read-only path-list / `protect` design in `docs/superpowers/specs/2026-10-12-readonly-path-list-design.md` is a separate, not-yet-approved feature. Do not read, implement, or design around it; treat `deny` as the only pattern-list consumer.

## Global Constraints

- Naming is `deny` (Rust/Python/Node/CLI), `Deny` (Go); defaults: Python `None`, Go `nil`, Node optional, Rust `Vec::new()`.
- Validation rules must be identical at every SDK boundary: empty, `,`, `:`, `\n`, `\0`, leading `#` (reject; `\#` escaped OK), surrounding whitespace, non-bind mounts, file binds, path-pattern-on-writable, cloud create.
- Do not invent APIs; mirror the reference introductions in `docs/sdk/*/volumes.mdx`.
- CLI: `deny=a,ro` parses as deny `a` + `ro`; `deny=a,b` errors. Keep this explicit.

## Review Focus

1. A Python user passing `deny=["a,b"]`, `["#x"]`, `[" .env"]`, or `[""]` → rejected at `MountConfig._to_dict` with a consistent error class, not deferred to create.
2. An existing Python caller constructing `MountConfig` **positionally** → unchanged field order.
3. The Go/Python reference pages → `Deny`/`deny` documented under property headings, no new tables.
4. A cloud user setting `deny` → learns at config time it is local-only.
5. `msb install --mount-dir` docs match `msb run`.

---

## File Structure

- Python: `sdk/python/microsandbox/types.py`, `sdk/python/microsandbox/_microsandbox.pyi`, `sdk/python/src/helpers.rs`, `sdk/python/src/volume.rs`, `sdk/python/tests/test_mount_policies.py`
- Node: `sdk/node-ts/native/mount_builder.rs`, `native/index.d.ts`, `src/internal/napi.ts`, `tests/unit/builders.test.ts`
- Go: `sdk/go/options.go`, `sdk/go/native/src/lib.rs`, tests
- Docs: `docs/sandboxes/volumes.mdx`, `docs/security/filesystem.mdx`, `docs/cli/sandbox-commands.mdx`, `docs/cli/configuration.mdx`, `docs/sdk/{rust,python,go,typescript}/volumes.mdx`

---

### Task 1: Fix Python positional compatibility (M4, PR-toks `3933341750`)

**Files:**
- Modify: `sdk/python/microsandbox/types.py` (`MountConfig` dataclass, `deny` currently at `:706` between `override_gid` and `owned_kind`)
- Test: `sdk/python/tests/test_mount_policies.py`

**Interfaces:**
- Produces: `deny` appended **after** the last existing field so positional construction is unchanged; or `MountConfig` made keyword-only (`kw_only=True`) with a documented minor break. Prefer appending.

- [ ] **Step 1: Write the failing test**

```python
def test_mountconfig_positional_order_unchanged():
    m = MountConfig(MountKind.BIND, "/host", "/guest", ...)  # full positional incl. disk/format/fstype
    assert m.disk is None and m.deny is None
```

- [ ] **Step 2: Run to verify failure**

Run: `cd sdk/python && uv run pytest tests/test_mount_policies.py::test_mountconfig_positional_order_unchanged -v`
Expected: FAIL.

- [ ] **Step 3: Move `deny` after the existing fields**

- [ ] **Step 4: Run**

Run: `cd sdk/python && uv run pytest tests/test_mount_policies.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add sdk/python/microsandbox/types.py sdk/python/tests/test_mount_policies.py
git commit -m "fix(python): append deny field to preserve MountConfig positional compat"
```

---

### Task 2: Python boundary validation parity (M3)

**Files:**
- Modify: `sdk/python/microsandbox/types.py` (`MountConfig._to_dict` ~`:872-875`; delegate to the shared rules)
- Modify: `sdk/python/src/helpers.rs` (`apply_mount` — reject `deny` on owned/named branches, N5)
- Test: `sdk/python/tests/test_mount_policies.py`

**Interfaces:**
- Produces: `_to_dict` rejects empty/`,`/`:`/`\n`/`\0`/leading-`#`/surrounding-whitespace/writable-path with the same error class as the non-bind rule; remove the duplicated `_reject_writable_path_patterns` and call the shared validator (or mirror it exactly and document why).

- [ ] **Step 1: Write the failing tests**

```python
def test_mountconfig_rejects_wire_separators(): ...
def test_mountconfig_rejects_leading_hash(): ...
def test_mountconfig_rejects_surrounding_whitespace(): ...
def test_mountconfig_rejects_empty_pattern(): ...
def test_apply_mount_rejects_deny_on_owned_and_named(): ...
```

- [ ] **Step 2: Run to verify failure**

Run: `cd sdk/python && uv run pytest tests/test_mount_policies.py -v -k "rejects or owned"`
Expected: FAIL for the deferred rules.

- [ ] **Step 3: Implement the boundary checks**

- [ ] **Step 4: Run**

Run: `cd sdk/python && uv run pytest tests/test_mount_policies.py -v`
Run: `cd sdk/python && uv run ruff check .`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add sdk/python/microsandbox/types.py sdk/python/src/helpers.rs sdk/python/tests/test_mount_policies.py
git commit -m "fix(python): validate full deny rule set at MountConfig boundary"
```

---

### Task 3: Node and Go boundary test parity (M3 coverage)

**Files:**
- Modify: `sdk/node-ts/tests/unit/builders.test.ts`
- Modify: `sdk/go/options_test.go`, `sdk/go/sandbox_options_test.go`

- [ ] **Step 1: Add the tests**

Node: reject empty, whitespace, leading `#`, path-on-writable. Go: reject leading `#`, deny on a file bind.
- [ ] **Step 2: Run**

Run: `cd sdk/node-ts && npm test`
Run: `cd sdk/go && go test ./...`
Expected: PASS.
- [ ] **Step 3: Commit**

```bash
git add sdk/node-ts/tests/unit/builders.test.ts sdk/go/options_test.go sdk/go/sandbox_options_test.go
git commit -m "test(node,go): cover deny boundary validation rules"
```

---

### Task 4: SDK reference tables → property headings (M5, PR-greptile `4255924750`)

**Files:**
- Modify: `docs/sdk/go/volumes.mdx` (`Deny` at `:976`)
- Modify: `docs/sdk/python/volumes.mdx` (`deny` row at `:835`; add the missing `bind()` Parameters entry, N1)
- Modify: `sdk/node-ts/native/index.d.ts` / `mount_builder.rs` doc comment (template `:483` wording)

**Interfaces:**
- Produces: `deny` documented under a `### Deny` / property heading with its visible signature, type, description, and constraints (directory binds only; path patterns require read-only; rejected on cloud/file binds) — no table rows. Preserve anchors `#mountoptions` / `#mountconfig`.

- [ ] **Step 1: Convert the entries**

Follow the neighboring method-heading style (e.g. Rust `nodev()`/`fstype()` sections). Keep returned-field tables untouched.
- [ ] **Step 2: Verify**

Run: `rg -n "deny|Deny" docs/sdk/go/volumes.mdx docs/sdk/python/volumes.mdx`
- [ ] **Step 3: Commit**

```bash
git add docs/sdk/go/volumes.mdx docs/sdk/python/volumes.mdx sdk/node-ts/native/index.d.ts sdk/node-ts/native/mount_builder.rs
git commit -m "docs(sdk): document deny under property headings, not tables"
```

---

### Task 5: Documentation completeness bundle (M11, N1)

**Files:**
- Modify: `docs/sandboxes/volumes.mdx`, `docs/security/filesystem.mdx`, `docs/cli/sandbox-commands.mdx`, `docs/cli/configuration.mdx`, `docs/sdk/*/volumes.mdx`

- [ ] **Step 1: Apply the fixes**
  - Cloud rejection of a non-empty deny list → add a `Local-only` note (all SDK pages + volumes page).
  - YAML/config-file `deny` (string option list `:186`, object-mount fields `:218`) → document.
  - `msb install --mount-dir` table → mirror the `msb run` row (`deny`).
  - `docs/sandboxes/volumes.mdx:484` → fix the `` `: ` `` code-span typo and say the colon separates `DEST` from options.
  - `docs/security/filesystem.mdx:45` → convert em dashes to brackets/parentheses (commit `d86d6fba` policy) and trim the 190-word bullet, linking to `/sandboxes/volumes` (dedupe).
  - Hard-link advice (`:486`) → drop the misleading `ro`/name-only recommendation; give the allowlist/not-mounting guidance.
  - Document `.`/`..` never-deny and component-boundary semantics.
  - Node `.d.ts` doc comment → "directory bind mounts only".
- [ ] **Step 2: Verify style against neighbors**

Run: `rg -n "Accordion|msb-param|—" docs/sdk/rust/volumes.mdx docs/security/filesystem.mdx`
- [ ] **Step 3: Commit**

```bash
git add docs
git commit -m "docs: complete and align bind-mount deny documentation"
```

---

### Task 6: CLI help and inspect parity tests (G-14)

**Files:**
- Modify: `crates/cli/lib/commands/common.rs` tests; add an `msb inspect` assertion
- Test: `crates/cli/lib/commands/self_cmd/tests.rs` or `common.rs` tests

- [ ] **Step 1: Add the tests**
  - `-v`/`--mount-dir` help mentions `deny`.
  - `deny=a,ro` → deny `a` + `ro`; `deny=a,b` → error.
  - `msb inspect` on a deny-bearing mount renders `[deny=a, b]`.
- [ ] **Step 2: Run**

Run: `cargo test -p microsandbox-cli deny`
Expected: PASS.
- [ ] **Step 3: Commit**

```bash
git add crates/cli/lib/commands
git commit -m "test(cli): pin deny option parsing and inspect rendering"
```
