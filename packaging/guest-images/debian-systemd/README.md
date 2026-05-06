# `debian-systemd`

Debian with systemd installed and ready for microsandbox's `--init auto` handoff.

## Use

```bash
msb run ghcr.io/superradcompany/debian-systemd:12 \
  --memory 1G --cpus 2 \
  --init auto \
  -- bash
```

## What's inside

`debian:bookworm` plus:

- `systemd`: the init binary at `/lib/systemd/systemd`.
- `systemd-sysv`: provides the `/sbin/init` symlink so `--init auto` finds it on the first probe.
- `dbus`: most systemd-aware services need it.
- `ca-certificates`: TLS works out of the box.

apt lists are cleaned to keep the image small.

## Tags

| Tag | Description |
|-----|-------------|
| `:12`, `:bookworm` | Debian 12, mutable, rebuilt weekly |
| `:12-YYYY-MM-DD` | Immutable date pin |
| `:latest` | Alias for `:bookworm` |

For reproducible builds, pin to a dated tag or a digest (`@sha256:…`).
