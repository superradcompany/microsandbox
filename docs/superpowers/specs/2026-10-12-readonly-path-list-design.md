# Read-only path list for bind mounts

Date: 2026-10-12
Status: approved design, pending plan

## Intent

Expose a host directory to an in-guest agent — notably a `.git` directory, so the
agent can read history and use normal git operations — while guaranteeing the
agent cannot plant a payload at a path that executes or reconfigures later git
activity (`.git/hooks/*`, `.git/config`, `.git/config.worktree`, `.git/info/*`,
`.gitmodules`). The mount must stay writable overall: git legitimately writes
`.git/index`, `.git/refs`, `.git/objects`, `.git/logs` during commits. Only
selected paths are made read-only, and they stay **visible** (unlike the
existing `deny` list, which hides them).

This is the dual of `deny`: `deny` = hide + block writes; the new list =
keep visible, block writes only.

## Goals

- A gitignore-style pattern list that write-protects matching paths on an
  otherwise writable bind mount.
- A **hard guarantee** against in-guest bypass, not best-effort matching.
- Reuse of the existing deny machinery wherever the semantics allow.
- Full parity across Rust/Python/Node/Go SDKs, CLI, and docs.

## Non-goals

- Protecting paths on non-bind mounts (owned/named/disk/tmpfs). Same scope as
  `deny`: directory binds only.
- Hiding content (that is `deny`'s job; the two coexist).
- Protecting against a hostile **host** writer. Like `deny`, the threat model is
  the in-guest agent; a host process racing the mount is out of scope.
- Serving as a substitute for a fully read-only mount.

## Anti-goals (what would make this a failure even if it works)

- A path pattern that a guest can defeat by renaming an ancestor directory.
- Any write path (create, rename, hardlink, truncate, setattr, xattr) that can
  still land content at a protected path.
- Silent over/under-blocking: a writable path that the user believed protected,
  or a broad operation refused with no explanation.

## Constraints and decisions

### Decided by the human

- **Path patterns are required.** Protection must scope to `.git/hooks/`,
  `.git/config`, etc., not over-broad name-only matching. This forces ancestor
  closure.
- **Hard guarantee.** Bypasses must be closed, not documented away.
- **Globs allowed only in the final component.** Every ancestor component of a
  path pattern must be a literal name. This keeps ancestor closure decidable
  and exact.
- **No `!` negation** in the read-only list. Negation makes "does this subtree
  still contain a protected path" non-monotonic and is not needed for the use
  case.

### Builder's calls (checkable)

- **Name.** User-facing option `protect=<pattern>` (CLI), `.protect([...])`
  (SDK builder), `VolumeMount::Bind { readonly_paths: Vec<String>, .. }`
  (domain). Chosen for symmetry with `deny` and to avoid colliding with the
  existing `readonly`/`ro` boolean flag.
- **Shared matcher.** Factor the pattern-building core (gitignore build,
  case-sensitivity probe, `needs_path_reconstruction` / `has_dir_only_patterns`
  flags, `matches_basename`/`matches_path`/`matches_relative`) out of
  `DenyList` into an internal pattern matcher. `DenyList` and the new
  `ReadOnlyList` become thin wrappers; `ReadOnlyList` adds ancestor closure.
- **No-op on read-only mounts.** A `protect` list on a read-only mount is
  accepted and changes nothing, because the whole mount is already protected.
  No special error.

## Pattern language

Identical gitignore parsing to `deny`, with these restrictions enforced by
validation:

- Components before the final one must be literals (no `*`, `?`, `[`, `**`).
- The final component may contain globs and may end in `/` (directory-only).
- No leading `!`.
- Wire-safe: no `,`, `:`, newline, NUL, and no leading/trailing whitespace
  (reuse `validate_deny_pattern`).

Examples:

| Pattern | Meaning |
|---|---|
| `.git/hooks/` | directory `.git/hooks` is read-only (and its subtree) |
| `.git/hooks/*` | every entry directly under `.git/hooks` is read-only |
| `.git/config` | that file is read-only |
| `.git/config.worktree` | that file is read-only |
| `.git/info/` | directory read-only |
| `.gitmodules` | name-only; matches anywhere under the mount |

## Enforcement design

### Matching

- Full mount-relative path matching, with the same case-sensitivity handling as
  `deny` (git `core.ignorecase` probe on writable mounts; filesystem-type
  inference on read-only mounts; Windows always case-insensitive). The probe is
  reused unchanged.
- **Subtree rule.** An entry is protected if it matches, or if any ancestor
  directory matches a pattern (gitignore semantics): a matched directory
  protects its whole subtree, whether or not the pattern is `/`-suffixed. So
  `.git/hooks` and `.git/hooks/` both protect `.git/hooks/pre-commit`; the
  trailing slash only distinguishes a directory from a same-named file. Use the
  ignore crate's `matched_path_or_any_parents` for the create/open/`lookup`-
  adjacent checks to get "inside a protected directory" for free. This matches
  how `deny` already behaves (a hidden directory hides its contents).
- **Precedence.** If a path matches both `deny` and `protect`, `deny` wins:
  the entry is hidden (ENOENT) and never observed as read-only.

### Ancestor closure (the new invariant)

Precompute, at matcher build time, the set of proper literal ancestor
directories of every pattern path (for `.git/hooks/` that is `{.git}`; for
`.git/config` also `{.git}`), as component vectors relative to the mount root.

Rule: a directory entry whose mount-relative path is in the ancestor set cannot
be **renamed, removed, or replaced** (including as a `RENAME_EXCHANGE`
endpoint). This closes `mv .git x` → write → `mv x .git`. Direct matches
already cover `mv .git/hooks x` and `rmdir .git/hooks` via the ordinary name
check.

### Entry points

Treat a `protect` match as `EACCES`; the existing read-only flag continues to
return `EROFS`. Sites to cover, mirroring `deny` plus the inode-scoped sites
`deny` deliberately skips (because it hides) and `protect` must add (because it
does not):

Name-taking mutations (same sites as `deny`):

- `do_create`, `do_mkdir`, `do_mknod`, `do_symlink`, `do_link` (destination),
  and `do_link` source (block a hardlink **from** a protected inode).
- `do_unlink`, `do_rmdir`, `do_rename` — both source and destination, plus the
  ancestor-closure rule in `decide_rename_deny`.

Inode-scoped mutations (new relative to `deny`):

- `do_open` when the flags mutate (`O_WRONLY`/`O_RDWR`/`O_TRUNC`); `do_write`;
  `do_fallocate`; `do_copyfilerange`.
- `do_setattr` when the request mutates (truncate/size, mode, owner, times).
- `do_setxattr`, `do_removexattr`.
- `do_setupmapping` (DAX write mapping).

These inode-scoped checks need the inode's mount-relative path, which the
inode table already exposes for `deny` path reconstruction (and Windows caches
per inode). The cost is only paid on mounts that configure a non-empty
`protect` list.

### Aliases, symlinks, and path availability

The hard guarantee forces these rules:

- **All aliases.** An inode can have several mount-relative names (hardlinks).
  The inode table tracks all of them (`inode_table.rs` `InodeData::aliases`).
  An inode-scoped mutation is protected if **any** alias path matches, so a
  host-created hardlink to a protected file under a non-protected name cannot
  be written through. `deny` documents the opposite limitation precisely
  because it only checks the looked-up name; `protect` closes it.
- **Symlink targets.** The guest kernel resolves symlinks to their target inode
  before the backend sees the open, so an open-for-write through a symlink
  resolves to the protected inode and is caught by the alias check above. The
  symlink's own name is irrelevant.
- **Fail closed.** If a mount-relative path for the inode cannot be
  established, the mutating operation is refused with `EACCES`. This is the
  hard-guarantee direction and is nearly free in practice: an inode outside the
  namespace has no writable path to reach in the first place. `protect` uses
  `EACCES`; the whole-mount `readonly` flag keeps returning `EROFS`.
- **Out of scope.** A hostile host process racing the mount between check and
  syscall remains out of scope (same as `deny`); the guarantee is against the
  in-guest agent.

### Windows

Mirror the same checks in `windows/ops.rs`, `windows/create_ops.rs`,
`windows/inode.rs`, `windows/dir_ops.rs`, using `deny_matches_name` /
`deny_matches_path` equivalents; Windows matches case-insensitively.

## Validation

New `validate_readonly_list(patterns: &[String]) -> TypesResult<()>` in
`packages/microsandbox-types/rust/lib/validation.rs`:

- Reuse `validate_deny_pattern` per pattern.
- Reject negations.
- Reject globs (or any non-literal component) before the final component.
- Bind-only (same as `deny`'s `.deny()`/`deny=` restriction).

## API and transport surface

- Domain: `VolumeMount::Bind.readonly_paths` (new, default empty).
- CLI: `protect=<pattern>` repeatable in `--mount-dir` / `-v` option blocks;
  reuses `sandbox_config.rs` rule-token parsing (`deny@destination` pattern).
- Rust SDK: `MountBuilder::protect(...)`, `VolumeMount::Bind` construction and
  validation.
- Python: `Mount`/`Volume` `protect` field; `types.py` validation.
- Node: `mount_builder.rs` `protect`, `native/index.d.ts`.
- Go: native `lib.rs` mount parsing.
- Docs: `docs/sandboxes/volumes.mdx` and the four SDK volume references.

## Compatibility and migration

`VolumeMount` tolerates unknown fields, so an older binary reading a
`readonly_paths` field would silently ignore it and expose the protected paths
to writes — the same class of failure the `deny` migration guard
(`m20261012_000001_bind_mount_deny_config.rs`) addresses. Required:

- A new schema-free migration marker so older binaries refuse an ahead
  database.
- A downgrade preflight that scans raw JSON (`/spec/mounts`) for a non-empty
  `readonly_paths` and refuses, mirroring `reject_persisted_deny`.
- Bidirectional SDK/`msb` compatibility review per `AGENTS.md`: the new field
  must be optional on the wire and in persisted config, and older SDKs must be
  handled with a clear unsupported-feature error when they cannot express it.

**Decided (human): mirror `deny`.** The binary migration marker plus downgrade
preflight is sufficient; no SDK-side admission check is added. This keeps the
compatibility work runtime-only, consistent with the `deny` change. The
known older-SDK/older-`msb` silent-drop of `readonly_paths` inherits the same
accepted posture as `deny` and is not repaired here.

## What is left to the builder

- Exact shared-matcher refactor shape (rename vs newtype vs trait).
- Naming of the domain field if `readonly_paths` proves awkward in a given SDK.
- Whether `do_write`/`do_fallocate` checks are redundant given `do_open`
  gating open-for-write (keep them as defense in depth unless a cost reason
  says otherwise).
- Error message wording for `protect` refusals.
- Test matrix: matcher unit tests (closure, final-component globs, rejected
  negations/ancestor globs, dir-only), unix + windows enforcement tests
  (ancestor rename, hardlink, rename-dest-onto-protected, create-inside-
  protected, open-for-write, setattr, xattr, dax), SDK/CLI validation tests,
  migration downgrade tests, and path-base regression tests per `AGENTS.md`.
