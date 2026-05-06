# `fedora-systemd`

Fedora with systemd installed and ready for microsandbox's `--init auto` handoff.

## Use

```bash
msb run ghcr.io/superradcompany/fedora-systemd:40 \
  --memory 1G --cpus 2 \
  --init auto \
  -- bash
```

## What's inside

`fedora:40` (which already ships systemd) plus:

- `dbus`: required by most systemd-aware services.
- `ca-certificates`: TLS works out of the box.
- `dnf upgrade`: latest security fixes layered on top of the base.

dnf cache is cleared after install.

## Tags

| Tag | Description |
|-----|-------------|
| `:40` | Fedora 40, mutable, rebuilt weekly |
| `:40-YYYY-MM-DD` | Immutable date pin |
| `:latest` | Alias for `:40` |

For reproducible builds, pin to a dated tag or a digest (`@sha256:…`).
