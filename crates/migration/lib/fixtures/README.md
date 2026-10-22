# Released v0.6.x configuration fixtures

These fixtures back the cross-version claim of the bind-mount hide_path downgrade guard
(`crates/migration/lib/m20261012_000001_bind_mount_hide_path_config.rs`). Same-version
in-memory round trips cannot prove that a real released persisted format reaches
the guard, so the guard test opens a fixture captured from a released line.

## `config-0.6.0.json`

- **Format:** released v0.6.0 `SandboxSpec` serialization (the shape stored in the
  `sandbox.config` / `sandbox.active_config` columns).
- **Provenance:** the repository's existing released-format artifact, first
  committed by `7a5798404fe29483444c193dd3f75d8132677c03`
  ("chore(release): prepare v0.7.0 for main (#1542)") at
  `sdk/rust/lib/db/fixtures/config-0.6.0.json`, and present verbatim at tag
  `v0.7.0` (peeled commit `a427b4365765cb633df3267e0cf3d118c25f1843`). Byte-for-byte
  copy of `git show v0.7.0:sdk/rust/lib/db/fixtures/config-0.6.0.json`;
  SHA-256 `ff11b6a72a144db6ec04005f531fc2553baa6e016e3269759ec781c41882fb77`.
- **Shape verification:** the fields match the v0.6.0 released types in
  `packages/microsandbox-types/rust/lib/domain.rs` at tag `v0.6.0` (peeled commit
  `efaab0ec14e57b93e385244cbbd831950618a028`): `resources.cpus`/`memory_mib`
  without `max_cpus`, `image.Oci`, `pull_policy: "IfMissing"`, and no
  `deployment_profile`. It carries no `hide_path` field anywhere.
- **Limitation:** this is the released **format**, not a runtime-captured SQLite
  database image. No released v0.6.x tag in this repository contains a captured
  sandbox database or serialized sandbox config; the tags ship code and docs only,
  and network capture is unavailable in this environment. The fixture is therefore
  the strongest local released-format artifact, shape-verified against the v0.6.0
  tag source rather than derived from the `crates/db/lib/compat/v0_6_5/` rewrap
  code.

The guard test asserts that this hide-path-free released configuration downgrades
cleanly across the marker, and that the same released configuration extended with
a bind `hide_path` list refuses the downgrade.
