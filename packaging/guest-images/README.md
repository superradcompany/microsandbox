# Guest images

Base images we publish for use as the *guest* rootfs inside microsandbox VMs. Each one ships a real init binary so `--init auto` (or an explicit `--init <path>`) works out of the box.

| Image | Base | Init | Primary tag |
|-------|------|------|-------------|
| `debian-systemd` | `debian:bookworm` | systemd | `:12`, `:bookworm` |
| `ubuntu-systemd` | `ubuntu:24.04` | systemd | `:24.04`, `:noble` |
| `fedora-systemd` | `fedora:40` | systemd | `:40` |
| `alpine-openrc` | `alpine:3.20` | OpenRC + BusyBox init | `:3.20` |

All images are published to `ghcr.io/superradcompany/<name>:<tag>` for both `linux/amd64` and `linux/arm64` by the `Guest Images` workflow.

## Tags

Each image carries three kinds of tags:

- **Primary** (`:<distro-version>`, e.g. `debian-systemd:12`): the canonical pin most callers use. Mutable: rebuilt weekly to pick up upstream security patches.
- **Distro alias** (`:<codename>`, e.g. `debian-systemd:bookworm`): mirror of the primary, friendlier for humans.
- **Latest** (`:latest`): the newest supported distro version. Mutable.
- **Dated** (`:<distro-version>-YYYY-MM-DD`, e.g. `debian-systemd:12-2026-05-12`): immutable digest pin for reproducible builds.

For reproducible CI, prefer a dated tag or pin by digest (`@sha256:…`).

## Rebuild cadence

Two triggers:

- Weekly cron (Monday 06:00 UTC), to pick up upstream base-image updates without us having to do anything.
- Manual via the `Guest Images` workflow's `workflow_dispatch`.

The same Dockerfiles are used for both. Each rebuild is gated by a smoke test that runs the produced image and verifies an init binary exists at one of the paths `--init auto` checks.

## Adding a new image

1. Add a directory `packaging/guest-images/<name>/` with `Dockerfile` and `README.md`.
2. Add an entry to the `matrix` block in `.github/workflows/guest-images.yml`.
3. Open a PR. The smoke test runs on every PR build.
