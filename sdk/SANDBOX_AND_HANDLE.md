# `Sandbox` and `SandboxHandle`: responsibilities and API surface

Status: proposal

This document defines what `Sandbox` and `SandboxHandle` each represent, which
methods belong on which type, how that compares with the Rust SDK today, and a
non-breaking path to get there. The Rust SDK is the reference; the Python,
Node, Go, and Ruby SDKs wrap it through native bindings, so fixing the surface
in Rust first lets the wrappers follow.

## Summary

- Keep two types. They model different things: a **reference** to a sandbox
  and a **live session** with a running sandbox.
- The split is currently hard to see because roughly 30 methods exist on both
  types, and most of those duplicates share an identical implementation.
- Rule: **if a method needs the live guest connection or the VM process this
  object owns, it belongs on `Sandbox`. Everything else belongs on
  `SandboxHandle`.**
- Add `Sandbox::handle()` so nothing becomes unreachable, deprecate the
  duplicates on `Sandbox`, and fix the Python `name` / `id` properties.

## What the two types are

### `SandboxHandle`: a reference

Defined in `sdk/rust/lib/sandbox/handle.rs`. A handle is a cheap, point-in-time
record built from a local DB row or a cloud API response:

- It holds a backend, a name, and backend-private state. No agent connection,
  no process ownership.
- Its state is explicitly a snapshot: `status_snapshot()`,
  `last_failure_message_snapshot()`, and `refresh()` which returns a new handle.
- Because it holds no resources, `Sandbox::list()` can return a page of handles
  for free, and a handle can refer to a sandbox in any state (stopped, running,
  paused).

### `Sandbox`: a live session

Defined in `sdk/rust/lib/sandbox/mod.rs`. A `Sandbox` means "this sandbox is
running and you can talk to it":

- Locally it holds an `AgentClient` connection to the guest (`client()`,
  `client_arc()`).
- In attached mode it owns the VM process. Per `owns_lifecycle()`, dropping it
  or calling `stop` terminates the sandbox; `detach()` disarms that safety net.
- On cloud there is no eager client (the agent WebSocket is opened lazily per
  operation, see `sandbox/cloud.rs`), but the meaning is the same: a `Sandbox`
  is something you can exec against.

### Why not a single type

Merging the two would mean:

1. Every `Sandbox` carries an optional client, and every `exec`, `shell`,
   `attach`, and `fs` call needs a runtime "not connected" error path.
2. Ownership and drop semantics become ambiguous. Today, dropping a handle from
   `list()` never affects a VM, while dropping an attached `Sandbox` does. With
   one type, the same value could mean either depending on how it was obtained.

Both are currently ruled out by the type system. That is the value the split
provides, and the API surface should make it obvious rather than obscure it.

## Proposed API surface

### On both (read-only identity)

`name`, `id`, `backend_kind`, `config`, `local()`, `cloud()`

These must be synchronous and have the same shape on both types in every SDK,
so code that accepts either type works without `isinstance` checks.

### `Sandbox` only (live session)

| Group | Methods |
|---|---|
| Execution | `exec*`, `exec_default*`, `shell*`, `attach*`, `attach_shell` |
| Guest I/O | `fs`, `ssh`, `client`, `client_arc`, `logger` |
| Agent round-trips | `ping`, `touch` |
| Live status | `status` (distinct from the handle's `status_snapshot`) |
| Owned process | `owns_lifecycle`, `detach`, `wait`, `stop_and_wait`, `stop`, `kill` |
| Post-restore info | `restore_warnings` |
| Escape hatch | `handle()` (new) |

`stop` and `kill` intentionally stay on both types. `sb.stop()` is the most
common lifecycle call, and for an attached sandbox it is tied to the process
this object owns. All other lifecycle operations go through `sb.handle()`.

### `SandboxHandle` only (control plane, works in any state)

| Group | Methods |
|---|---|
| State and metadata | `status_snapshot`, `refresh`, `created_at`, `updated_at`, `last_failure_message_snapshot`, `config_json`, `active_config`, `active_config_json` |
| Transition to a live session | `start`, `start_detached`, `connect`, `connect_with_timeout`, `connect_or_start`, `connect_or_start_detached` |
| Signal-based lifecycle | `stop`, `kill`, `request_stop`, `request_kill`, `request_drain`, `drain`, `stop_with_timeout`, `kill_with_timeout`, `restart`, `restart_with`, `destroy`, `destroy_with`, `remove`, `wait_for_status`, `wait_until_stopped` |
| Host-side operations | `pause`, `resume`, `pause_state`, `pause_with_guest_flush`, `snapshot`, `branch`, `branch_many`, `modify`, `compact` |
| Observability | `logs`, `log_stream`, `follow_logs`, `metrics`, `metrics_stream` |

### Static, on the `Sandbox` type

`builder`, `create`, `create_detached`, `create_with_pull_progress`,
`create_detached_with_pull_progress`, `get`, `list`, `list_with`, `restore`,
`restore_ref`

## Comparison with the Rust SDK today

Method inventory taken from every `impl Sandbox` and `impl SandboxHandle` block
under `sdk/rust/lib/sandbox/`.

### Already aligned

| Area | Rust today |
|---|---|
| Execution and guest I/O (`exec*`, `shell*`, `attach*`, `fs`, `ssh`, `client`, `logger`) | `Sandbox` only |
| Owned process (`owns_lifecycle`, `detach`, `wait`, `stop_and_wait`) | `Sandbox` only |
| Transition to a live session (`start`, `connect`, `connect_or_start`) | `SandboxHandle` only |
| Snapshot metadata (`status_snapshot`, `refresh`, `created_at`, `updated_at`, `config_json`, `active_config`) | `SandboxHandle` only |
| `snapshot` | `SandboxHandle` only |
| Statics (`builder`, `create*`, `get`, `list`, `restore`) | `Sandbox` |
| Identity (`name`, `id`, `backend_kind`, `config`, `local`, `cloud`) | Both, synchronous |

### Differences

| Methods | Rust today | Proposed |
|---|---|---|
| `restart`, `restart_with`, `destroy`, `destroy_with`, `request_stop`, `request_kill`, `request_drain`, `stop_with_timeout`, `kill_with_timeout`, `wait_for_status`, `wait_until_stopped` | Both | Handle only |
| `pause`, `resume`, `pause_state`, `pause_with_guest_flush`, `branch`, `branch_many` | Both, identical implementations | Handle only |
| `modify`, `compact`, `logs`, `log_stream`, `follow_logs`, `metrics` | Both | Handle only |
| `ping`, `touch` | Both (handle connects on demand) | `Sandbox` only |
| `stop`, `kill` | Both | Both (deliberate) |
| `drain` | `Sandbox` only; handle has only `request_drain` | Handle |
| `metrics_stream` | `Sandbox` only | Handle, alongside `metrics` |
| `last_failure_message`, `remove_persisted` | `Sandbox` only | Handle (`remove` already lives there) |
| `status` vs `status_snapshot` | Live on `Sandbox`, snapshot on handle | Keep both; they mean different things |
| `Sandbox -> SandboxHandle` accessor | Does not exist | Add `Sandbox::handle()` |
| Static `Sandbox::start(name)` / `Sandbox::remove(name)` | Exist | Drop `remove`; keep `start` only if the saved DB lookup is measurable |

The duplicated methods are pure delegation. For example, `Sandbox::pause` in
`sandbox/pause.rs` and `SandboxHandle::pause` in the same file both call
`lifecycle(self.name(), self.identity(), backend, ControlRequest::Pause)`, and
the same pattern holds for `resume`, `pause_state`, `pause_with_guest_flush`,
`branch`, and `branch_many`. When the same operation does the same thing on
both types, the distinction between them stops communicating anything.

`ping` and `touch` are the weakest case for consolidation: a handle-level
`ping` is a reasonable "check reachability without keeping a connection." They
are listed as `Sandbox` only for consistency with the rule, and can stay on
both if that use case matters.

## Python SDK inconsistency

In `sdk/python/src/sandbox.rs`, `Sandbox.name` and `Sandbox.id` are
`#[getter]`s that return a Future (`future_into_py`). The stub in
`sdk/python/microsandbox/_microsandbox.pyi` declares them as
`async def name(self) -> str` and `async def id(self) -> str` (methods), while
`SandboxHandle.name` and `SandboxHandle.id` are plain synchronous string
properties (`sdk/python/src/sandbox_handle.rs`).

Result: the same attribute has three shapes, and code typed as
`SandboxHandle | Sandbox` breaks:

```python
await Sandbox.start(sb.name())
# TypeError: '_asyncio.Future' object is not callable
```

Names and ids are immutable for the lifetime of the object, so both should be
cached at construction and exposed as synchronous properties on `Sandbox`,
matching `SandboxHandle` and the Rust SDK. `owns_lifecycle` has the same
awaitable-property shape and should be reviewed at the same time.

## Rollout

Removing methods from `Sandbox` is breaking across five SDKs, so stage it:

1. **Now (non-breaking)**
   - Add `Sandbox::handle()` in Rust and expose it in every SDK.
   - Add `SandboxHandle::drain` and `SandboxHandle::metrics_stream`, and move
     `last_failure_message` / `remove_persisted` equivalents onto the handle.
   - Fix Python `Sandbox.name` / `Sandbox.id` to synchronous properties and
     update the `.pyi` stub.
   - Add a short "Handle vs Sandbox" section at the top of the SDK docs:
     a handle is a reference, a `Sandbox` is a live session, and
     `handle.connect()` / `handle.start()` move between them.
2. **Next minor**: mark the duplicated `Sandbox` methods listed above as
   deprecated, pointing to `sb.handle().<method>()`.
3. **Next major**: remove the deprecated methods.

## Out of scope

Renaming `Sandbox` (for example to `SandboxSession`) would make the model more
explicit, but it is a breaking change in every SDK for a naming win. Revisit
only if confusion persists after the documentation and surface changes above.
