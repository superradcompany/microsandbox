# `ubuntu-systemd`

Ubuntu with systemd installed and ready for microsandbox's `--init auto` handoff.

## Use

```bash
msb run ghcr.io/superradcompany/ubuntu-systemd:24.04 \
  --memory 1G --cpus 2 \
  --init auto \
  -- bash
```

## What's inside

`ubuntu:24.04` plus:

- `systemd`: the init binary at `/lib/systemd/systemd`.
- `systemd-sysv`: provides `/sbin/init` so `--init auto` finds it.
- `dbus`: most systemd-aware services need it.
- `ca-certificates`: TLS works out of the box.

apt lists are cleaned to keep the image small.

## Tags

| Tag | Description |
|-----|-------------|
| `:24.04`, `:noble` | Ubuntu 24.04 LTS, mutable, rebuilt weekly |
| `:24.04-YYYY-MM-DD` | Immutable date pin |
| `:latest` | Alias for `:24.04` |

For reproducible builds, pin to a dated tag or a digest (`@sha256:…`).
