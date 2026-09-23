# Configuration compatibility fixture

`v0.6.16.json` is the full example copied verbatim from `docs/configuration.mdx`
in released tag `v0.6.16` (commit `93c14431b387d4666c7c9ca6599bb2fafdc01782`).
It exercises the actual documented unversioned format from that release.
It is not evidence of running an older binary against a newer schema.

Backend fixture tests inject temporary user and managed file paths into the real loader.
There is no test-only empty-policy stub. Use a missing temporary managed file for
an unmanaged fixture, or write a policy to exercise enforcement and load failures.
Layering tests can also construct `ConfigLayers` from explicit patches.
Production and integration-test builds use the platform's managed path.
Integration tests that construct a backend should run on a dedicated test host
whose policy is controlled by the test environment.

Backend unit tests use `LocalBackend::builder().config_path(...)` with a temporary
file and the test-only `managed_config_path(...)` setter, so neither the user's
config nor the machine's policy affects them. Only tests exercising
environment-based selection or runtime paths should use the shared `lock_env()`.
