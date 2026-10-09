# Microsandbox OCI Runtime Contribution Report

## Overview

### Compatibility and limitations

`runmsb` accepts Docker/containerd OCI configuration without a blanket rejection
of cgroups, resources, namespaces, security settings, hooks, or mounts. These
fields remain implementation work where their semantics are not yet supported.
The existing bundle validation still rejects malformed configurations, and
unsupported commands and CLI operations return explicit errors.

Acceptance does not mean enforcement. Do not rely on seccomp,
AppArmor/SELinux, cgroup limits, or full namespace isolation in
this experimental runtime. VM isolation does not replace those requested
controls. Full Docker bridge networking and complete mount
flags/ownership semantics also remain incomplete.
Feature reporting does not advertise unimplemented controls or mount flags.

### Guest process security

OCI `process.noNewPrivileges` and the bounding, effective, permitted,
inheritable, and ambient capability sets are forwarded to agentd. They apply
to container init and `docker exec`, with both pipes and terminals. Agentd
validates capability names and set relationships before spawning. In the child,
it drops bounding capabilities before changing user, applies the final sets
after user and resource-limit setup, and sets no-new-privileges before exec.
Setup failures abort execution instead of running an unrestricted workload.
Agentd itself retains the privileges needed to manage the VM.

`--cap-drop ALL` supplies empty sets, including an empty bounding set so root
cannot regain those capabilities through ordinary exec. A missing capability
configuration is different: it retains the existing sandbox behavior. The
Microsandbox restricted profile still removes mount-administration privileges;
per-command settings do not override that policy. Linux's ordinary capability
transition rules still apply when executing setuid or file-capability binaries.

These additions target matching current `runmsb`, `msb`, and embedded agentd
builds. Rebuild the guest agent, embed it into `msb`, install both host binaries,
and recreate containers. There is no compatibility implementation for these
new settings on older builds; an old agent can ignore the added request fields.
Do not use mixed builds to rely on these protections. Existing compatibility
code for unrelated SDK/runtime operations is unchanged.

After installing matching builds, check both init and exec:

```bash
docker run --rm --runtime runmsb --security-opt no-new-privileges \
  alpine grep NoNewPrivs /proc/self/status
docker run --rm --runtime runmsb --cap-drop ALL \
  alpine grep '^Cap' /proc/self/status
docker run -d --name msb-security-check --runtime runmsb \
  --cap-drop ALL --security-opt no-new-privileges alpine sleep 300
docker exec msb-security-check sh -c 'grep -E "^(Cap|NoNewPrivs)" /proc/self/status'
docker stop msb-security-check
docker rm msb-security-check
```

Expect `NoNewPrivs: 1` and zero values for all five `Cap*` sets. Run the
exec check with `docker exec -t` as well to exercise the terminal path.

### Bind mounts

OCI bind mounts select `HostPermissions::Mirror`: ordinary guest permission bits
for regular files and directories propagate to the host. For example, a file
created with mode `0644` is host-readable instead of being stored as `0600`.
Guest chmod can also change permissions of existing files on the shared mount.
The backend keeps owner access, does not mirror setuid/setgid bits, and retains
guest ownership metadata separately; this does not map file ownership to the
Docker client user. Read-only mounts remain read-only. A guest-created `0600`
file remains private on the host. The normal SDK default remains `Private`.

### Read-only root filesystem

`docker run --read-only --runtime runmsb ...` maps OCI `root.readonly` to a
read-only guest root. Ordinary writes, file creation, and directory creation on
that root fail. Explicit writable bind mounts, named volumes, and tmpfs mounts
remain writable; the root restriction is not applied recursively to them.

Docker may already mount the host rootfs read-only before invoking the runtime.
The VMM therefore exports that directory through a read-only virtiofs backend
and boots the agent from the existing bootstrap filesystem. The agent assembles
an overlay with a read-only lower and a 64 MiB tmpfs upper used only for boot
setup: mountpoints, runtime files, and guest configuration. Before reporting
ready or starting workloads, it remounts the root overlay read-only. This does
not require writing to Docker's rootfs or making the host mount writable.

Docker also supplies `/etc/hosts`, `/etc/hostname`, and `/etc/resolv.conf` as
separate mounts. When those files are read-only, the agent preserves their
contents instead of trying to regenerate them during initialization. It does
not remount them writable or replace them. Only an `EROFS` rejection for an
existing regular file is accepted; missing files, permission errors, and other
write failures still abort initialization. Writable network files retain the
existing Microsandbox-generated configuration.

The implementation is in `lib/sandbox.rs`, SDK `runtime/spawn.rs`, runtime
`runner/vm.rs`, and guest `readonly_root.rs`/`init.rs`. Rebuild the musl guest
agent and embed it when rebuilding `msb`; rebuilding `runmsb` alone is not enough.
The SDK checks the selected `msb` capability, and a distinct required bootstrap
variant makes older agents reject the mode. There is no writable fallback.
Normal writable roots keep their existing boot path.

This implements filesystem write protection, not complete security-policy
enforcement. In particular, a guest process explicitly granted mount
privileges must not be treated as unable to remount guest filesystems. The host
rootfs export itself remains read-only.

After installing the rebuilt binaries, these commands should print
`ROOT_IS_READONLY` and `TMPFS_OK`, respectively:

```bash
docker run --rm --runtime runmsb --read-only alpine sh -ec \
  'if touch /root-write; then exit 1; fi; echo ROOT_IS_READONLY'
docker run --rm --runtime runmsb --read-only --tmpfs /scratch alpine sh -ec \
  'echo TMPFS_OK > /scratch/result; cat /scratch/result'
```

### Runtime compatibility

Compatibility-only CLI switches remain accepted: `--systemd-cgroup`,
`--cgroup-manager`, `--rootless`, `--no-pivot`, and `--no-new-keyring`. They do not
claim implementation of cgroups, rootless execution, or host namespace controls.
Zero `--preserve-fds` remains accepted; nonzero counts and `--pidfd-socket` request
unimplemented descriptor handling and are rejected. Exec overrides not applied
by the implementation are rejected, even alongside `--process`.

Lifecycle mutations use per-container host file locks. State queries no longer
write stale snapshots over pause/resume transitions. Delete reconciles VMM death,
force delete uses bounded host-side termination, and signal zero only probes the
VMM without writing a signal request. Exec must not restart a stopped VM. Its
supervisor intentionally retains workload I/O until workload exit; redirecting
non-terminal stdout/stderr to `/dev/null` would lose Docker exec output.

This patch adds an experimental runc-compatible runtime named `runmsb`. It adapts
Microsandbox's existing libkrun microVM and `agentd` process APIs to the OCI lifecycle expected by
Docker and containerd.

The patch demonstrates that basic Docker workloads can run through Microsandbox, but it is not yet
a complete OCI implementation. In particular, hooks, cgroups, security policies, and
complete Docker networking are still missing. This report describes the implementation, its current
limits, and the decisions that need maintainer agreement before the runtime becomes supported.

## Changes in this patch

| Area | Files | Reason |
| --- | --- | --- |
| OCI model | `crates/runtime/lib/oci/*` | Parse bundles, persist state, and validate lifecycle transitions independently of the CLI. |
| Runtime executable | `crates/oci-runtime/*` | Provide runc-style commands, console handling, error logging, feature reporting, and VMM-supervised init startup. |
| Guest PTY/processes | `crates/agentd/lib/init.rs`, `session.rs` | Support `/dev/ptmx`, controlling terminals, bare commands through `PATH`, and numeric OCI users. |
| Firmware discovery | `sdk/rust/lib/config/mod.rs` | Preserve explicit `libkrunfw` overrides and packaged Microsandbox layouts. |
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
  -> runmsb
  -> Microsandbox SDK/runtime
  -> libkrun VMM on the host
  -> guest Linux
  -> agentd
  -> OCI process
```

The host runs Docker, containerd, the OCI runtime, `msb`, and libkrun. The guest is the Linux
environment inside the microVM and contains `agentd` and the OCI processes.

### Responsibilities

| Component | Responsibility |
| --- | --- |
| Docker/containerd | Create the OCI bundle, invoke lifecycle commands, attach I/O, and consume exit state. |
| `runmsb` | Translate OCI commands and configuration into Microsandbox operations. |
| OCI state store | Preserve state between separate CLI invocations. |
| Microsandbox/libkrun | Create and own the microVM; the VMM process is the host PID Docker/containerd watches. |
| `agentd` | Spawn, signal, and observe processes inside the guest. |

`agentd` is inside the VM because host processes cannot directly manage guest PIDs through host
`/proc`. The host-side process Docker/containerd watches is the persistent Microsandbox VMM process,
not a separate stand-in monitor.

## Why the implementation is split across two crates

`crates/runtime/lib/oci` contains reusable OCI data and state logic:

```text
bundle.rs       bundle/config.json loading and validation
state.rs        OCI state plus Microsandbox extension state
store.rs        filesystem-backed runtime state
lifecycle.rs    operation and state-transition validation
error.rs        typed OCI errors
```

`crates/oci-runtime` contains the executable integration:

```text
lib/lib.rs      thin module root and public re-exports
lib/runtime.rs  OCI-to-Microsandbox lifecycle operations
lib/sandbox.rs  Microsandbox construction and host PID discovery
lib/process.rs  guest process execution, signals, and pid files
lib/console.rs  runtime-side host/guest console bridge
lib/requests.rs VMM start, signal, session, and exit handoff files
lib/options.rs  public lifecycle option types
bin/main.rs     command dispatch
bin/cli.rs      global options
bin/commands.rs lifecycle arguments
bin/console.rs  console socket and PTY handling
bin/features.rs runtime capability response
bin/logging.rs  caller-facing error logs
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
| Host PID | PID of the persistent Microsandbox VMM process recorded for Docker/containerd. |
| Guest PID | PID reported by `agentd` and stored as extension state. |
| Console socket | Host socket used to transfer the PTY master to containerd; the slave is inherited directly by the VMM on fixed FD 100. |
| MicroVM | Currently one microVM per OCI container. |

The runtime must not delete the OCI bundle because Docker/containerd owns it. `delete` removes the
Microsandbox sandbox and runtime-owned state only.

## Lifecycle implementation

| Command | Current behavior |
| --- | --- |
| `create` | Parse the bundle, create durable `created` state, create a detached microVM in OCI startup-gated mode, and write the VMM pid file. |
| `start` | Publish the VMM start gate, wait for the VMM to create the `agentd` exec session, and mark the state `running`. |
| `run` | Perform `create` and `start`, wait for the guest init process and VMM to stop, then return the init process exit code. |
| `exec` | Load `--process` JSON and start an additional guest process; console and non-console paths are supported. |
| `kill` | Signal the guest init session through `agentd` when it exists; killing a created-but-not-started container stops the VMM instead of queuing stale work. `--all` is unsupported. |
| `state` | Reconcile and print OCI-compatible persisted state. |
| `delete` | Stop/remove the sandbox when allowed and remove runtime-owned state. |
| `pause` / `resume` | Suspend and resume the resident VM using Microsandbox's host control endpoint. Save OCI state after the VMM confirms the transition. |

The default state root is `/run/runmsb`:

```text
/run/runmsb/<container-id>/
  state.json
  start.request
  init.session
  init.session.exit
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

The SDK still resolves `libkrunfw` from explicit Microsandbox-controlled sources:

```text
MSB_LIBKRUNFW_PATH
SDK-provided packaged path
config.paths.libkrunfw
paths next to the resolved msb binary
{home}/lib
```

For Linux layouts next to `msb` or under `{home}/lib`, discovery considers:

```text
libkrunfw.so.<exact-version>
libkrunfw.so.<supported-ABI>
libkrunfw.so
```

It intentionally does not search global system library directories such as `/usr/lib` or
`/usr/local/lib`. That keeps this patch from silently binding `runmsb` to a host libkrunfw build
that was not shipped or selected by Microsandbox. Developers can still set `MSB_LIBKRUNFW_PATH`
when they need to test a system package explicitly.

### Network namespace isolation

Docker configures networking in the network namespace of the PID returned by the OCI runtime. The
runtime now returns the VMM PID, so Docker attaches networking to the process that owns the
Microsandbox userspace virtio-net backend.

When the OCI bundle requests a new network namespace without a path, the VMM process calls
`unshare(CLONE_NEWNET)` before libkrun starts. When the request includes a namespace path, the SDK
opens that namespace before spawning and the child calls `setns(..., CLONE_NEWNET)` before exec.
Opening or joining a requested namespace must succeed; there is no fallback to host networking.
Without an OCI network namespace entry, the child inherits the launcher's network namespace.

Docker can attach its veth to the VMM namespace without conflicting with the host route table.
The guest still uses the normal Microsandbox-managed userspace virtio-net path, but that backend
runs inside the requested OCI network namespace. In particular, an existing namespace must not
be ignored: doing so lets a `--network none` container use the launcher's host routes.
Joined namespaces retain automatic guest address selection from their routes. Only newly created
namespaces use an explicit guest address pool while waiting for Docker to attach networking.

For an OCI cold boot, packet processing waits until `start.request`. At that
point the VMM checks its host namespace for an active, non-loopback interface
with an IP address. If there is none, the userspace network stays inactive:
the guest cannot obtain even a synthetic TCP connection from that backend.
Guest loopback remains available. This covers both an empty joined namespace
and a fresh namespace to which Docker has not attached a network interface.
The check happens once; attaching a network later with `docker network connect`
does not activate a container that started without networking.

This removes the route conflict and preserves outbound Microsandbox networking, but it is not full
Docker bridge integration. Docker's veth is not connected to the guest virtio-net backend, so
published ports, user-defined networks, aliases, static addresses, and container-to-container
networking remain incomplete.

### Signal ownership and exit status

The VMM owns the startup command lifecycle. After `runmsb start` publishes `start.request`, the VMM
asks `agentd` to start the OCI init process and writes the accepted session ID to `init.session`.
Later `runmsb kill` uses that session ID to send the requested signal through `agentd`. The VMM
sets its own exit code from the startup command result before shutting the guest down, so
containerd can observe the tracked host PID exit with the workload status.

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
| Entry point | `containerd-shim-runc-v2` invokes `runmsb` commands | `containerd-shim-microsandbox-v2` implements TaskService directly |
| Lifetime | Short CLI calls plus one VMM process per container | Long-lived process for a task or sandbox |
| State | Files plus VMM-owned startup handoff | Shim-owned task state plus recovery metadata |
| I/O and exits | VMM startup command stream | Shim task streams and events |
| VM sharing | One VM per OCI container | Could choose one VM per container or pod |
| Guest control | `agentd` | `agentd` or an expanded guest API is still required |

The existing runc-v2 shim does not understand Microsandbox. It works only because this runtime
implements the runc-style command surface it expects.

## Current gaps

- OCI hooks are not executed.
- Cgroups and resource updates are not implemented. In particular, Docker's
  `--pids-limit` is accepted but not enforced: a test with a limit of 16 still
  started 24 child processes. A guest workload cgroup needs to count and limit
  guest processes; limiting host VMM threads is not equivalent.
- Seccomp, AppArmor, SELinux, and complete namespace semantics are not applied.
  Capability sets and no-new-privileges now have guest child-process enforcement;
  they do not implement the remaining security controls.
- The OCI hostname is not forwarded to the sandbox. Docker's `--hostname`
  is ignored, and the generated guest hostname can contain a 64-character
  label. Python's default HTTP server can fail with `UnicodeError: label too
  long` when resolving it. Forward and validate the requested hostname and
  keep generated fallback labels within the 63-character DNS label limit.
- `kill --all`, `update`, and checkpoint/restore are unsupported.
- Pause/resume suspends the whole VM while retaining its RAM and host PID. It uses the
  existing Microsandbox pause implementation, not a new OCI cgroup freezer. State queries
  reconcile suspension through host control without connecting to the suspended guest.
  Force deletion of a paused container kills the VM through the host SDK.
  The guest kernel must advertise clock-only resume support. Older firmware can
  boot containers but rejects pause/resume; use firmware built from the matching
  Microsandbox vendor revision and recreate the VM after upgrading it.
- Command-style `exec` is incomplete; process-file and detached `exec` are supported.
- Non-TTY stdin is inherited on descriptor 101, separate from the VMM console.
  The startup supervisor forwards input after `ExecStarted` and sends EOF only
  after the inherited input reaches EOF. Install matching `runmsb` and `msb`
  builds when changing this descriptor contract.
- Docker bridge networking and published ports are incomplete. Container-name
  resolution on user-defined networks fails. Published-port access also fails
  with a working guest HTTP server, so fixing the hostname alone will not fix
  ingress. Outbound DNS/TCP success does not establish Docker network support.
- State/shim restart recovery has not been tested.
- OCI runtime-tools and containerd conformance suites have not been added.
- Start, signal, session, and exit handoff still use polled files; a future VMM control API should
  replace them with direct requests over the persistent control channel.
- The OCI-specific VMM supervisor path is enabled only by the `oci-runtime` feature. Normal
  Microsandbox builds retain the standard detached-startup behavior and do not expose the OCI
  start, signal, session, exit, console, or network-namespace handoff.

Every accepted OCI field should eventually be implemented or rejected explicitly. Parsing a flag
without applying its semantics must not be presented as security or OCI compliance.

## Docker follow-up checklist

1. **Rerun the complete Docker suite: completed on 2026-10-02.** The run against
   the installed build from commit `297c05fe` had 41 passing checks and five
   then-known gaps: no-new-privileges, capability dropping, PID limits, user-defined
   network DNS, and published ports. Additional checks passed for interactive
   stdin, read-only root with writable tmpfs, and read-only root with a writable
   bind mount. These results are not OCI conformance or security certification;
   rerun the suite after subsequent changes.
2. **Block external connections with `--network none`: fixed and tested.**
   Keep this isolation check in the regression suite. This does not imply that
   all Docker networking features are implemented.
3. **Support read-only rootfs: implemented and Docker-tested.** Containers
   start with `--read-only`, root writes fail, and explicitly writable bind
   mounts and tmpfs remain writable. Docker's read-only network files are
   preserved, including supplied `--add-host` entries.
4. **Finish Docker networking: implementation still required.** Add published
   ports (`-p`), container-to-container communication, and container-name and
   alias resolution on user-defined networks. Test host-to-container published
   ports, peer connectivity, name resolution, and isolation between networks.
   Working outbound connections alone do not demonstrate these features.

## Decisions requested from maintainers

1. Should we ship `runmsb` as an official binary now, or keep it experimental while
   OCI support is still incomplete?
2. When Docker/containerd pass flags we do not fully support yet, should we accept them for
   compatibility or fail with a clear error?
3. Which namespaces, cgroups, hooks, mounts, and security controls are required for the first
   accepted OCI milestone?
4. Is the VMM-as-host-PID model acceptable, and should networking continue through the existing
   userspace virtio-net backend?
5. Is resident whole-VM pause the desired long-term Docker pause behavior?
6. Is one OCI container per VM the intended long-term policy?
7. Is a native containerd shim in scope for this project?
8. What test threshold is required before the runtime is no longer experimental?

## Kubernetes requires a separate decision

This patch does not add Kubernetes support. It only adds the first OCI/Docker layer. If
Kubernetes is wanted later, we should choose one of these paths:

### A. Stop at OCI/Docker

Only finish `runmsb` as a Docker/containerd OCI runtime.

This means:

- `docker run` and basic OCI commands are the target.
- Kubernetes is not promised.
- We do not need to support CRI, CNI, pod volumes, or Kubernetes conformance in this patch.

### B. Add a one-container-per-VM shim

Build a real `containerd-shim-microsandbox-v2`.

This means containerd would talk directly to a Microsandbox shim instead of using
`containerd-shim-runc-v2` plus `runmsb`.

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
a Microsandbox-provided libkrunfw path or `MSB_LIBKRUNFW_PATH`, and Docker Engine.

`runmsb` is feature-gated because it is still experimental. Its `runmsb` feature enables the
matching `oci-runtime` support in the Rust SDK and runtime crate. The separately installed `msb`
binary must be built with the same support.

```bash
just setup
just build

cargo build -p microsandbox-cli --features oci-runtime --bin msb
cargo build -p runmsb --features runmsb --bin runmsb
sudo install -m 0755 target/debug/msb /usr/local/bin/msb
sudo install -m 0755 target/debug/runmsb /usr/local/bin/runmsb
```

Add the runtime while preserving the other keys in `/etc/docker/daemon.json`:

```json
{
  "runtimes": {
    "runmsb": {
      "path": "/usr/local/bin/runmsb"
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
runmsb --version
runmsb features
```

Separate `create` and `start`:

```bash
docker rm -f msb-created 2>/dev/null || true
docker create --name msb-created --runtime runmsb hello-world:latest
docker inspect -f '{{.State.Status}}' msb-created
docker start -a msb-created
docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' msb-created
docker rm msb-created
```

Basic run and null-stdin EOF:

```bash
docker run --rm --runtime runmsb hello-world:latest
docker run --rm --runtime runmsb alpine:latest cat
docker run --rm --runtime runmsb python:3.12
```

TTY:

```bash
docker run --rm --runtime runmsb -it ubuntu:latest /bin/bash
```

Outbound DNS/TCP, which does not prove Docker bridge or published-port support:

```bash
docker run --rm --runtime runmsb python:3.12 \
  python -c "import socket; print(socket.getaddrinfo('example.com',80)[0][4][0]); s=socket.create_connection(('1.1.1.1',53),timeout=3); print('tcp_ok'); s.close()"
```

No-network isolation (pull the image before applying the test timeout):

```bash
docker pull alpine:latest
timeout 30 docker run --rm --runtime runmsb --network none alpine:latest \
  sh -c 'if nc -z -w 2 1.1.1.1 53; then echo EGRESS_LEAK; exit 1; else echo ISOLATED_EGRESS_OK; fi'
```

Expect `ISOLATED_EGRESS_OK` and exit zero. Also run the outbound test above
without `--network none` to check that ordinary networking still works.

Detached lifecycle, exec, signal, and delete:

```bash
docker rm -f msb-sleep 2>/dev/null || true
docker run -d --name msb-sleep --runtime runmsb ubuntu:latest sleep 300
docker inspect -f '{{.State.Status}} {{.State.Pid}}' msb-sleep
docker exec msb-sleep /bin/sh -c 'echo EXEC_OK; id; pwd'
docker kill --signal TERM msb-sleep
docker wait msb-sleep
docker inspect -f '{{.State.Status}} {{.State.ExitCode}}' msb-sleep
docker rm msb-sleep
```

The expected wait and inspect exit code after SIGTERM is `143`.

Pause and resume the same VM:

```bash
docker run -d --name msb-pause --runtime runmsb ubuntu:latest sleep 300
docker pause msb-pause
docker inspect -f '{{.State.Paused}} {{.State.Pid}}' msb-pause
docker unpause msb-pause
docker inspect -f '{{.State.Paused}} {{.State.Pid}}' msb-pause
docker exec msb-pause /bin/sh -c 'echo RESUMED'
docker pause msb-pause
docker rm -f msb-pause
```

The first inspection should show `true`, the second `false`, with the same host PID.
Exec should print `RESUMED`. The final removal checks cleanup while the VM is paused.
