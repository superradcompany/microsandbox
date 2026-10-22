# Bind-mount deny-list remediation — plan index

Source review: branch `bind-mount-deny-option`, base `13d799c5`, review HEAD `aecabe8c`.
PR #1448 (`superradcompany/microsandbox`, head `neurolabs:bind-mount-deny-option`).
Full register (round 1 + round 2 + PR threads) is in the session summary; this index maps it to plans.

## Out of scope

`docs/superpowers/specs/2026-10-12-readonly-path-list-design.md` (the read-only path-list / `protect` feature) is a separate, not-yet-approved design. These plans must not read, implement, or design around it. Treat `deny` as the only pattern-list feature; do not build generic abstractions for a second list.

## Plans and recommended order

| # | Plan | Scope | Requires |
|---|------|-------|----------|
| 1 | [windows-deny-backend](2026-10-13-windows-deny-backend.md) | C1 blocker, H3, H4, H7, Windows residuals, CI platform guard | Windows/`--target x86_64-pc-windows-msvc` toolchain |
| 2 | [deny-restore-durability](2026-10-13-deny-restore-durability.md) | H1, H2, G-10, restore docs | Plan 3's matcher changes ideally first |
| 3 | [deny-matcher-hardening](2026-10-13-deny-matcher-hardening.md) | H5, M1, M2, M7, M10, `.`/`..`, do_link, coverage | none (do first if on Linux/macOS) |
| 4 | [deny-compat-persistence](2026-10-13-deny-compat-persistence.md) | H6, M9, cross-version fixtures, COMPATIBILITY.md | none |
| 5 | [deny-sdk-parity-docs](2026-10-13-deny-sdk-parity-docs.md) | M3, M4, M5, M11, N1/N5 | Plan 3 for the shared validator |

**Suggested first session:** Plan 1 Task 1 (the compile break). It is cheap and unblocks all Windows evidence; everything else can run in parallel with a Windows runner.

**Runs without a Windows host:** Plans 2, 3, 4, 5, plus Plan 1 Tasks 1–4 only insofar as they use the cross-target check.

## Finding → plan map

- **C1** Windows compile → Plan 1 T1
- **H1** snapshot/archive/branch deny capture → Plan 2 T1–T3, T6
- **H2** restore aliases + cached dir entries → Plan 2 T4 (+ Plan 1 T4)
- **H3** Windows restore deny → Plan 1 T4
- **H4** Windows alternate names (8.3, trailing dot/space) → Plan 1 T3
- **H5** Unicode case fold → Plan 3 T2
- **H6** v0.6.5 downgrade bypass → Plan 4 T1–T2
- **H7** Windows unlink error oracle → Plan 1 T2
- **M1** inert patterns → Plan 3 T1
- **M2** backend writable-path rule → Plan 3 T4
- **M3** Python boundary validation → Plan 5 T2–T3
- **M4** Python positional compat → Plan 5 T1
- **M5** SDK reference tables → Plan 5 T4
- **M7** case-probe leak → Plan 3 T3
- **M9** `VolumeMount` non_exhaustive → Plan 4 T4
- **M10** f2fs/overlayfs case → Plan 3 T2
- **M11** docs bundle → Plan 5 T5
- **M6** setattr/do_link/dir-only oracle → Plan 1 T5, Plan 3 T5
- **G-07/G-14/G-15** test-quality/coverage → Plan 3 T6, Plan 2 T5, Plan 5 T6
- **PR-greptile** rename/exchange/EBUSY family → already fixed (`2ce9b8b5`,`efc9b568`,`d1925492`,`9d07613e`,`a54849fb`,`8a6a5e41`); residual documented, distinct-file edit in Plan 1 T5
- **PR-toks** case-folding order + `/mounts` pointer → already fixed in `aecabe8c`
- **PR-appcypher** (invalid-pattern error, trim, file-bind, migration, case, `unwrap`, macOS unsafe, path-on-writable) → already fixed; macOS compile re-check lives in Plan 1 T6

## Already fixed in `aecabe8c` (do not re-fix)

Leading-`#` rejection; migration pointer `/mounts`; case-insensitive ordering; `validate_volume_mount` deny validation; Python `create()` doc; whitespace/trim; file-bind deny; rename-deny helper extraction; symlink wording. Round-2 reviewers verified each.

## Conventions for executors

- Every plan references the review register and the relevant PR thread ids; keep them in commit bodies where useful for traceability.
- Commit identity used on this branch: `Ole Langbehn (agentic) <ole.langbehn@inoio.de>`; signed commits preferred (no signing key available in the review sandbox).
- Run `cargo fmt --all`, the focused tests named in each task, and `cargo clippy --workspace -- -D warnings` before finishing a Rust task.
