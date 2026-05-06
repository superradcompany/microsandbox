# `alpine-openrc`

Alpine with OpenRC and BusyBox init. This is the *non-systemd* path: same handoff mechanic, smaller footprint, faster shutdown.

## Use

```bash
msb run ghcr.io/superradcompany/alpine-openrc:3.20 \
  --memory 256M --cpus 2 \
  --init /sbin/init \
  -- sh
```

`/sbin/init` is BusyBox init, which reads `/etc/inittab` and hands off to OpenRC for runlevels. `--init auto` also works since `/sbin/init` is the first path it probes.

## What's inside

`alpine:3.20` plus:

- `openrc`: provides `rc-service`, `rc-update`, runlevel management.
- `busybox-openrc`: BusyBox-compatible OpenRC init scripts.
- `dbus`: optional, but most "real service" workloads expect it.
- `ca-certificates`: TLS works out of the box.

apk cache is not retained.

## Tags

| Tag | Description |
|-----|-------------|
| `:3.20` | Alpine 3.20, mutable, rebuilt weekly |
| `:3.20-YYYY-MM-DD` | Immutable date pin |
| `:latest` | Alias for `:3.20` |

For reproducible builds, pin to a dated tag or a digest (`@sha256:…`).

## Why ship this alongside systemd images

Two reasons:

1. **Memory budget.** OpenRC's resident set is in the single-digit MiB; systemd is ~50 MiB idle. If your workload doesn't need systemd specifically, you can run far smaller sandboxes.
2. **Reference for "any init works".** microsandbox's `--init` handoff is just `execve(2)`; it isn't tied to systemd. Shipping an OpenRC image alongside the systemd ones makes that visible in the catalog, not just claimed in the docs.
