# Running nested VM snapshot qualification

`nested-snapshot.py` runs an inner Linux VM through full snapshot restore, two
forks, a second snapshot generation, and archive export/import. It checks the
inner workload's memory identity, monotonic timer and counter, and disk readback
records for ten seconds after each operation. The source must keep progressing.
The outer sandbox uses a managed root disk, so this also exercises Microsandbox's
disk capture and restore integration.

This is a manual hardware qualification test. Run the positive matrix with the production
candidate on Linux x86-64, Windows x86-64, or Apple Silicon macOS with nesting support.
No admission bypass is required. Linux ARM64 and Windows ARM64 nesting are unsupported;
startup must reject an enabled nesting setting on those platforms.
`NESTED_EXPECT_UNSUPPORTED=1` remains available to check older runtimes that admit nested
execution but reject full snapshots and forks while the source keeps running.

## Fixture

Use the matching libkrun `tests/nested-restore/os/build.sh` on Linux of the guest
architecture. Its parent root contains QEMU, an inner kernel, initramfs and ext4
disk. Add `/bin/sh` pointing to `busybox`, a `/root` directory, and these files:

```text
# /etc/passwd
root:x:0:0:root:/root:/bin/sh
# /etc/group
root:x:0:
```

Package that parent root as an OCI image for the same architecture, with
`PATH=/bin:/usr/bin` and `/bin/sh` as its default command. For example, copy the
parent contents into a scratch Docker image and export it with `docker save`.
Load the archive with `msb image load -i nested-image.tar`. A plain directory image
cannot provide the managed root disk required by this test.

The outer firmware must include KVM support. Use a matching inner Linux kernel
with the devices and filesystem support listed in libkrun's fixture README.

## Run

Use a disposable home and an absolute path to the candidate binary. On macOS,
codesign that exact binary with `msb-entitlements.plist` before running it.

```sh
export MSB_HOME=/tmp/nested-snapshot-home
export MSB_PATH=/absolute/path/to/msb
export NESTED_IMAGE=nested-restore-test:latest
export NESTED_RESULTS=/tmp/nested-snapshot-results
# Set MSB_LIBKRUNFW_PATH if using a local firmware build.
python3 scripts/smoke/cli/nested-snapshot.py
```

`NESTED_ARCH` can override the host architecture when needed.
`NESTED_KERNEL_ARGS` appends arguments to the inner Linux kernel. For example,
`NESTED_KERNEL_ARGS=hpet=disable` avoided an early boot delay in the standalone
GCloud N4D AMD fixture. The managed-disk CLI matrix also passed with default
kernel arguments on that host. Record overrides as a separate profile: they do
not qualify the default HPET path or change production defaults. The result records the
architecture and effective kernel arguments alongside the workload identity.

Results contain
numbered command outputs and a `result.json` only after all checks pass. The
script stops its uniquely named sandboxes in a `finally` block. Keep the home
until evidence has been inspected, then remove it through normal cleanup.

This does not qualify cross-host migration, networking, external mounts, or
hardware platforms on which the matrix has not run. The qualified platform policy is enforced by libkrun.

2026-10-14: the complete CLI matrix passed on AMD Linux and AMD Windows Server
2025 with default guest kernel arguments. Intel Linux also passed with an
optimized diagnostic build. Its unoptimized build had hit the 30-second control
deadline during second-generation capture; isolated recapture succeeded, and
the optimized full matrix passed without increasing that deadline.

Intel Windows Server 2025 on Azure also passed the complete matrix with an
optimized diagnostic build after creating `/dev` in the Windows bootstrap
filesystem. This lets the kernel mount devtmpfs before starting the agent,
avoiding a pre-main abort when the initial console is late. Normal startup and
a forced missing-console case each passed eight starts with nesting alternating
on and off; the missing-console case failed all eight starts before the fix.

On the Windows test host, invoke the runner directly through SSH. PowerShell
`Start-Process` placed it in a job that disallowed process breakaway, causing
sandbox creation to fail with `Access is denied` even when nesting was disabled.
A minimal child-process probe reproduced that job restriction independently of
Microsandbox. Direct SSH invocation passed the complete matrix.

### Busy inner CPUs

Set `NESTED_BUSY=1` when running the Python lifecycle test with the updated
libkrun full-OS fixture. Both inner workers must keep advancing across restore;
missing worker records, resets and stalls fail the same observation window as
the disk/timer workload. Provision enough host CPUs for all live sandbox copies.

2026-10-15: the rebased CLI candidate passed the full managed-disk matrix on
Apple M5 Pro macOS, including archive export/import. Intel and AMD Windows also
passed the full matrix with both busy inner workers using the precise PIT timer
implementation. All six sandbox copies remained live until cleanup; worker
counters, disk records, timer progress, and workload identity were checked.

For cross-frequency restore validation, set `NESTED_CHECK_CLOCK_RATE=1` to compare
the inner Linux monotonic clock against host elapsed time. Use
`NESTED_SOURCE_MSB_PATH` to select an isolated source executable, and
`NESTED_SOURCE_ENV` (a JSON object) for source-only environment settings. These
apply only to the initial `run`; restore and fork commands use `MSB_PATH` and the
normal environment. This allows a source-clock fixture to request a non-native
hypervisor rate without changing the destination runtime or rewriting snapshots.
The libkrun `tests/nested-restore/clock-source` fixture documents setup and limits.
