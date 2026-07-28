# Microsandbox OCI Runtime Contribution Report

## Overview

This patch adds an experimental runc-compatible runtime named `microsandbox-runtime`. It adapts
Microsandbox's existing libkrun microVM and `agentd` process APIs to the OCI lifecycle expected by
Docker and containerd.

The patch demonstrates that basic Docker workloads can run through Microsandbox, but it is not yet
a complete OCI implementation. In particular, pause/resume, hooks, cgroups, security policies, and
complete Docker networking are still missing. This report describes the implementation, its current
limits, and the decisions that need maintainer agreement before the runtime becomes supported.

## Changes in this patch

| Area | Files | Reason |
| --- | --- | --- |
| OCI model | `crates/runtime/lib/oci/*` | Parse bundles, persist state, and validate lifecycle transitions independently of the CLI. |
| Runtime executable | `crates/oci-runtime/*` | Provide runc-style commands, console handling, error logging, feature reporting, and init monitoring. |
| Guest PTY/processes | `crates/agentd/lib/init.rs`, `session.rs` | Support `/dev/ptmx`, controlling terminals, bare commands through `PATH`, and numeric OCI users. |
| Firmware discovery | `sdk/rust/lib/config/mod.rs` | Find ABI-compatible system installations such as `/usr/lib/libkrunfw.so.5`. |
| Sandbox startup | `sdk/rust/lib/runtime/spawn.rs` | Preserve detached startup stderr and include it in caller-facing errors. |
| stdin handling | `sdk/rust/lib/sandbox/exec.rs`, `backend/cloud.rs` | Send EOF for null/fixed stdin so non-interactive processes do not hang. |

The OCI bundle is parsed with `oci-spec`. The patch does not introduce another VM engine;
Microsandbox remains responsible for launching and managing libkrun-backed microVMs.

## Architecture

The current implementation is a standalone OCI runtime CLI, not a Microsandbox-specific
containerd shim:

```text
Docker
  -> containerd
  -> containerd-shim-runc-v2
  -> microsandbox-runtime
  -> Microsandbox SDK/runtime
  -> libkrun VMM on the host
  -> guest Linux
  -> agentd
  -> OCI process
```

The host runs Docker, containerd, the OCI runtime, the init monitor, `msb`, and libkrun. The guest
is the Linux environment inside the microVM and contains `agentd` and the OCI processes.

### Responsibilities

| Component | Responsibility |
| --- | --- |
| Docker/containerd | Create the OCI bundle, invoke lifecycle commands, attach I/O, and consume exit state. |
| `microsandbox-runtime` | Translate OCI commands and configuration into Microsandbox operations. |
| OCI state store | Preserve state between separate CLI invocations. |
| Host init monitor | Wait between `create` and `start`, provide a host PID, bridge I/O, and observe init exit. |
| Microsandbox/libkrun | Create and own the microVM. |
| `agentd` | Spawn, signal, and observe processes inside the guest. |

The monitor and `agentd` solve different problems. The monitor is a host process used to satisfy
Docker/containerd's process model. `agentd` is inside the VM because host processes cannot directly
manage guest PIDs through host `/proc`.

## Why the implementation is split across two crates

`crates/runtime/lib/oci` contains reusable OCI data and state logic:

```text
bundle.rs       bundle/config.json loading and validation
state.rs        OCI state plus Microsandbox extension state
store.rs        filesystem-backed runtime state
lifecycle.rs    operation and state-transition validation
engine.rs       engine request/response types
error.rs        typed OCI errors
```

`crates/oci-runtime` contains the executable integration:

```text
lib/lib.rs      OCI-to-Microsandbox operations
bin/main.rs     command dispatch
bin/cli.rs      global options
bin/commands.rs lifecycle arguments
bin/console.rs  console socket and PTY handling
bin/features.rs runtime capability response
bin/logging.rs  caller-facing error logs
bin/monitor.rs  host init monitor
```

This keeps Clap and Docker/containerd CLI conventions out of the reusable runtime crate. A future
containerd shim could reuse the bundle, state, and transition types without invoking this CLI.

## OCI mapping

| OCI concept | Current mapping |
| --- | --- |
| Bundle | Caller-owned directory containing `config.json` and the referenced rootfs. |
| Container ID | Maps to a Microsandbox name derived by `sandbox_name_for_container`. |
| Runtime `--root` | Host directory containing one state directory per container. |
| Rootfs | Used as the Microsandbox sandbox root filesystem source. |
| Init/exec process | Guest process started through the Microsandbox protocol and `agentd`. |
| Host PID | PID of the host init monitor recorded for Docker/containerd. |
| Guest PID | PID reported by `agentd` and stored as extension state. |
| Console socket | Host socket used to transfer the OCI PTY file descriptor. |
| MicroVM | Currently one microVM per OCI container. |

The runtime must not delete the OCI bundle because Docker/containerd owns it. `delete` removes the
Microsandbox sandbox and runtime-owned state only.

## Lifecycle implementation

| Command | Current behavior |
| --- | --- |
| `create` | Parse the bundle, create durable `created` state, create a detached microVM, start the host monitor, and write the requested pid file. |
| `start` | Notify the waiting monitor, start the OCI init process through `agentd`, and mark the state `running`. |
| `run` | Perform `create` followed by `start`. |
| `exec` | Load `--process` JSON and start an additional guest process; console and non-console paths are supported. |
| `kill` | Publish a monitor control request; the owning monitor forwards the signal to the guest init session. `--all` is unsupported. |
| `state` | Reconcile and print OCI-compatible persisted state. |
| `delete` | Stop/remove the sandbox when allowed and remove runtime-owned state. |
| `pause` / `resume` | Parsed for compatibility but return explicit not-implemented errors. |

The default state root is `/run/microsandbox-runtime`:

```text
/run/microsandbox-runtime/<container-id>/
  state.json
  start.request
  signal.request
  monitor.log
```

The expected state flow is:

```text
absent -> created -> running -> stopped -> absent
```

## Supporting fixes discovered during Docker integration

### Guest command and PTY execution

OCI images commonly specify bare commands such as `bash` or `sleep`. Guest PTY spawning now uses a
conventional default `PATH`, preserves OCI environment overrides, creates a controlling terminal,
and reports normal spawn errors. Guest initialization creates `/dev/ptmx -> pts/ptmx` after mounting
devpts so interactive applications can allocate terminals.

### Null stdin must produce EOF

`agentd` starts non-TTY processes with a stdin pipe. Previously `StdinMode::Null` sent no protocol
message, leaving that pipe open. Programs such as `cat` or Python reading from stdin waited forever.

The shared stdin policy is now:

```text
Null        -> send an empty ExecStdin frame (EOF)
Pipe        -> send nothing initially and keep stdin open
Bytes(data) -> send data followed by an empty EOF frame
```

Both local and cloud backends use the same helper.

### Detached startup errors

Detached startup uses a dedicated pipe on file descriptor 98 for `{"pid": ...}` startup JSON.
Previously the child's stderr was discarded, so containerd received only a generic failure.

The SDK now writes detached startup stderr to:

```text
<sandbox>/logs/startup.stderr.log
```

If startup times out or exits before valid JSON, the final 8 KiB is included in the runtime error
that containerd reports to Docker.

### libkrunfw discovery

Linux discovery now considers:

```text
libkrunfw.so.<exact-version>
libkrunfw.so.<supported-ABI>
libkrunfw.so
```

It also checks `/usr/lib` and `/usr/local/lib`. This allows a distribution package to provide an
ABI-compatible `libkrunfw.so.5` without requiring `MSB_LIBKRUNFW_PATH`.

### Network namespace isolation

Docker configures networking in the network namespace of the PID returned by the OCI runtime. The
runtime returns the host monitor PID, so leaving that monitor in the host namespace caused Docker
to encounter the host's existing `docker0` route while assigning `172.17.0.x`.

When the OCI bundle requests a network namespace, the monitor calls `unshare(CLONE_NEWNET)` before
it starts. Docker can then attach its veth to the monitor namespace without conflicting with the
host route table. The VMM does not join that namespace; it keeps the normal Microsandbox-managed
userspace virtio-net path.

This removes the route conflict and preserves outbound Microsandbox networking, but it is not full
Docker bridge integration. Docker's veth is not connected to the guest virtio-net backend, so
published ports, user-defined networks, aliases, static addresses, and container-to-container
networking remain incomplete.

### Signal ownership and exit status

Agent relay session IDs belong to the client connection that created them. The host monitor owns
the init process session, so a later `kill` CLI invocation cannot safely send directly to that
session through a new relay connection.

The `kill` command therefore writes `signal.request` into the container state directory and waits
for an acknowledgement. The monitor reads the request, forwards the signal through its existing
connection, and removes the file after delivery. This keeps the monitor alive until it receives the
guest exit event. `agentd` maps signal termination to shell-style status codes, including `143` for
SIGTERM and `137` for SIGKILL, which Docker then reports accurately.

## Comparison with existing runtimes

| Runtime | Model | Relevance to this patch |
| --- | --- | --- |
| runc | Short-lived OCI CLI using host namespaces/cgroups | Defines the command and state behavior being imitated. |
| crun | C OCI CLI with strong systemd/cgroup support | Demonstrates the compatibility flags and host integration mature runtimes support. |
| youki | Rust CLI over reusable container libraries | Supports the decision to separate command parsing from reusable OCI state logic. |
| runsc | runc-compatible CLI backed by a longer-lived sandbox | Shows how an OCI facade can sit in front of a different isolation engine. |
| Kata | containerd shim plus in-guest `kata-agent`, often one VM per pod | Closest reference for a VM runtime and guest agent, but significantly broader than this patch. |

Microsandbox `agentd` is similar to `kata-agent` only in placement and basic process responsibility.
It does not currently create multiple independently managed guest containers with separate rootfs,
mount, and lifecycle state.

## OCI runtime versus containerd shim

A shim is a long-lived host process between containerd and a task implementation. It owns task I/O,
wait/exit behavior, events, and recovery. It does not run inside the VM and does not replace the
guest agent.

| Concern | Current implementation | Native Microsandbox shim |
| --- | --- | --- |
| Entry point | `containerd-shim-runc-v2` invokes `microsandbox-runtime` commands | `containerd-shim-microsandbox-v2` implements TaskService directly |
| Lifetime | Short CLI calls plus one monitor per container | Long-lived process for a task or sandbox |
| State | Files and monitor coordination | Shim-owned task state plus recovery metadata |
| I/O and exits | Host monitor | Shim task streams and events |
| VM sharing | One VM per OCI container | Could choose one VM per container or pod |
| Guest control | `agentd` | `agentd` or an expanded guest API is still required |

The existing runc-v2 shim does not understand Microsandbox. It works only because this runtime
implements the runc-style command surface it expects.

## Current gaps

- OCI hooks are not executed.
- Cgroups and resource updates are not implemented.
- Capabilities, seccomp, AppArmor, SELinux, and complete namespace semantics are not applied.
- `pause`, `resume`, `kill --all`, `update`, and checkpoint/restore are unsupported.
- Command-style and detached `exec` behavior is incomplete.
- Non-TTY attached stdin (`docker run -i` without `-t`) needs explicit OCI file-descriptor support.
- Docker bridge networking and published ports are incomplete.
- State/shim restart recovery has not been tested.
- OCI runtime-tools and containerd conformance suites have not been added.

Every accepted OCI field should eventually be implemented or rejected explicitly. Parsing a flag
without applying its semantics must not be presented as security or OCI compliance.

## Decisions requested from maintainers

1. Should we ship `microsandbox-runtime` as an official binary now, or keep it experimental while
   OCI support is still incomplete?
2. When Docker/containerd pass flags we do not fully support yet, should we accept them for
   compatibility or fail with a clear error?
3. Which namespaces, cgroups, hooks, mounts, and security controls are required for the first
   accepted OCI milestone?
4. Is the per-container monitor an acceptable intermediate host PID, and should networking be
   adapted into the existing userspace virtio-net backend?
5. Should pause freeze guest processes, suspend the VM, or combine both mechanisms?
6. Is one OCI container per VM the intended long-term policy?
7. Is a native containerd shim in scope for this project?
8. What test threshold is required before the runtime is no longer experimental?

## Kubernetes requires a separate decision

This patch does not add Kubernetes support. It only adds the first OCI/Docker layer. If
Kubernetes is wanted later, we should choose one of these paths:

### A. Stop at OCI/Docker

Only finish `microsandbox-runtime` as a Docker/containerd OCI runtime.

This means:

- `docker run` and basic OCI commands are the target.
- Kubernetes is not promised.
- We do not need to support CRI, CNI, pod volumes, or Kubernetes conformance in this patch.

### B. Add a one-container-per-VM shim

Build a real `containerd-shim-microsandbox-v2`.

This means containerd would talk directly to a Microsandbox shim instead of using
`containerd-shim-runc-v2` plus `microsandbox-runtime`.

The model would still be:

```text
one container = one Microsandbox VM
```

This gives better containerd events, wait handling, and recovery. But Kubernetes pods with sidecars
would become multiple VMs, so we would need to decide if that cost and behavior are acceptable.

### C. Build a Kata-style VM-per-pod runtime

Build something closer to Kata Containers.

The model would be:

```text
one Kubernetes pod = one Microsandbox VM
many containers can run inside that VM
```

This would require much more work. `agentd` would need to manage multiple containers inside the VM,
not just start processes. It would need container IDs, separate root filesystems, mounts, process
state, networking, volumes, resources, and recovery.

So this patch should not be described as Kubernetes support. Kubernetes should be a separate
maintainer decision, with its own design and testing plan.

## Validation completed

```text
OCI runtime library tests:       17 passed
OCI runtime binary tests:         3 passed
Rust SDK library tests:         362 passed
Snapshot integration tests:      19 passed with writable MSB_HOME
Focused agentd session tests:     14 passed
Workspace and agentd formatting: passed
Affected-crate and agentd Clippy: passed with warnings denied
Guest agent, msb, and runtime builds: passed
Runtime version/features probe:  passed
```

The complete `agentd` run previously passed 102 tests. Two unrelated TCP tests failed in a
restricted test environment because socket creation returned `EPERM`. Docker tests were completed
on Linux with KVM, including create/start, attached output, TTY, exec, SIGTERM exit status, removal,
DNS, and outbound TCP. Reviewers should repeat them on their host configuration.

## Build and install

Prerequisites include Rust, the normal Microsandbox native dependencies, `/dev/kvm`, libkrun,
ABI-compatible libkrunfw, and Docker Engine.

```bash
just setup
just build

just build-msb
cargo build -p microsandbox-oci-runtime
sudo install -m 0755 build/msb /usr/local/bin/msb
sudo install -m 0755 target/debug/microsandbox-runtime /usr/local/bin/microsandbox-runtime
```

Add the runtime while preserving the other keys in `/etc/docker/daemon.json`:

```json
{
  "runtimes": {
    "microsandbox-runtime": {
      "path": "/usr/local/bin/microsandbox-runtime"
    }
  }
}
```

Validate and restart Docker:

```bash
sudo dockerd --validate --config-file /etc/docker/daemon.json
sudo systemctl restart docker
docker info --format '{{json .Runtimes}}'
```

## Reviewer test commands

Runtime probe:

```bash
microsandbox-runtime --version
microsandbox-runtime features
```

Separate `create` and `start`:

```bash
docker rm -f msb-created 2>/dev/null || true
docker create --name msb-created --runtime microsandbox-runtime hello-world:latest
docker inspect -f '{{.State.Status}}' msb-created
docker start -a msb-created
docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' msb-created
docker rm msb-created
```

Basic run and null-stdin EOF:

```bash
docker run --rm --runtime microsandbox-runtime hello-world:latest
docker run --rm --runtime microsandbox-runtime alpine:latest cat
docker run --rm --runtime microsandbox-runtime python:3.12
```

TTY:

```bash
docker run --rm --runtime microsandbox-runtime -it ubuntu:latest /bin/bash
```

Outbound DNS/TCP, which does not prove Docker bridge or published-port support:

```bash
docker run --rm --runtime microsandbox-runtime python:3.12 \
  python -c "import socket; print(socket.getaddrinfo('example.com',80)[0][4][0]); s=socket.create_connection(('1.1.1.1',53),timeout=3); print('tcp_ok'); s.close()"
```

Detached lifecycle, exec, signal, and delete:

```bash
docker rm -f msb-sleep 2>/dev/null || true
docker run -d --name msb-sleep --runtime microsandbox-runtime ubuntu:latest sleep 300
docker inspect -f '{{.State.Status}} {{.State.Pid}}' msb-sleep
docker exec msb-sleep /bin/sh -c 'echo EXEC_OK; id; pwd'
docker kill --signal TERM msb-sleep
docker wait msb-sleep
docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' msb-sleep
docker rm msb-sleep
```

The expected wait and inspect exit code after SIGTERM is `143`.

Known unsupported pause behavior:

```bash
docker run -d --name msb-pause --runtime microsandbox-runtime ubuntu:latest sleep 300
docker pause msb-pause
docker rm -f msb-pause
```

`docker pause` is currently expected to report that pause is not implemented.
