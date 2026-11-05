# Exec input and output: draft specification

Status: agreed direction updated 20 October 2026. Implementation is authorized and in progress; this specification describes the target behavior, not a completed implementation.

## Problem and implementation status

Issue #1793 reports host memory growth when an application retains an execution stream without consuming output. Before #1832, stdout and stderr were forwarded into an unbounded SDK queue. The original buffering work also exposed a shared-connection stall: forwarding blocked stdin could stop the connection reader before it reached output acknowledgements.

#1832 was reverted from main in #1875; #1839 restores the buffering work. Its earlier focused repair used a separate connection-wide input allowance. The current local implementation replaces that with per-execution stdin routing and removes the SDK transport reservation ledger, relay-input handshake, and transport acknowledgements. Existing non-execution transport and snapshot safeguards remain.

The earlier benchmark and investigation documents remain historical reference material. Changes are local and uncommitted; validation checkpoints are recorded below.

## Agreed design

- Keep finite, separate per-execution input and output allowances. These bound outstanding data, not lifetime transfer totals or bytes per second.
- Remove the extra SDK input staging queue. Writes wait for capacity rather than copying data into another SDK-owned queue.
- Keep one SDK receiving buffer per execution for unread stdout and stderr. They share the output allowance but retain their identities.
- Use a sandbox-wide execution cap to bound aggregate execution buffering. Do not add an SDK connection cap in this change: connections also serve non-execution operations. Preserve existing connection safeguards.
- Avoid redundant intermediate queues and independent shared byte budgets for execution data. Reserve downstream storage before accepting data and retain ownership through forwarding. Do not release one stage's capacity merely to wait for another stage's budget.
- Keep processing control messages while one execution's stdin delivery is blocked. Use the same shared connection; do not introduce a second vsock channel or user-accessible control socket.
- Retain bounded socket/virtual-transport storage and necessary in-flight framing/writes. Removing redundant buffers does not mean zero buffering or zero internal bounds.
- Preserve data and ordering. Never silently truncate, drop, or resend execution data to recover capacity.

## Limits and configuration

| Setting | Agreed value or scope |
| --- | --- |
| Default input allowance | 64 KiB per execution |
| Default output allowance | 1 MiB combined stdout/stderr per execution |
| Stdin chunk payload | Default 16 KiB; configurable globally and per sandbox |
| Output chunk payload | Default 4 KiB; configurable globally and per sandbox |
| Active executions | Default 128 per sandbox, configurable globally and per sandbox through every SDK |
| Pending acknowledgement state | At most one unsent cumulative update per execution, per direction, per sending endpoint |
| Other eligible control messages | One queue of at most 16 pending messages per outgoing connection; at most 4 KiB encoded per message |
| New SDK connection cap | None in this change |
| Additional execution shared-byte budget | Target removal after consolidated accounting and progress guarantees are validated |

The byte defaults and chunk size are starting points to benchmark, not proven performance optima. Allowances are finite and positive in this design; an unlimited setting would invalidate the aggregate bound and is not part of the agreed target. Released older SDKs retain their historical behavior through an explicit legacy path; they are outside the new buffering guarantee. Unreleased #1839 configuration changes use the finite policy described here.

Global `[exec]` settings are `max_executions`, `input_limit`, `output_limit`, `stdin_chunk_size` and `output_chunk_size`. All five support per-sandbox SDK overrides. Resolve built-in defaults, then global configuration, then explicit sandbox overrides. Exact public language-specific signatures remain to be checked against existing configuration conventions. Keep Rust, Python, Node and Go SDKs consistent; CLI and SSH executions count toward the same sandbox total where they use the execution service.

The runtime owns the authoritative count across SDK connections. Admit atomically before process spawn; reject a new execution at capacity with a clear typed execution-limit error rather than silently queueing it. A sandbox SDK override changes the sandbox's effective policy, not just that client's counter. Persist the resolved setting with sandbox configuration. Live policy changes are outside this change. Hosted services may impose an upper bound and must reject overrides that exceed it.

Validate positive, representable limits before allocating or spawning. Do not treat zero as unlimited. Values fit unsigned 32-bit fields; chunk sizes must fit their allowances and the protocol frame ceiling. Operators choose resource ceilings; raising execution limits can also exhaust the guest blocking-thread pool for PTY readers. SDK-side checks improve errors but never replace runtime enforcement.

At defaults, 128 executions represent 136 MiB of combined input/output allowances, not upfront allocation and not a whole-process memory ceiling. OS pipes, socket buffers, framing, control state, processes, caller-owned input and application-retained results are additional. Metadata must be accounted for so tiny messages cannot defeat memory bounds. A configurable execution cap alone is not a fixed byte ceiling if allowance values can also grow.

An execution retains its admission slot after process exit until all retained output is acknowledged as consumed or the stream is closed and cleaned up. Process exit alone must not free the slot while output remains retained. Release the slot exactly once, including cancellation, failure and disconnect cleanup.

## Input flow

```text
Application write
    |
SDK waits for execution allowance
(no extra SDK input queue)
    |
Shared connection -> runtime per-execution pending stdin
(covered by the same execution allowance)
    |
Guest per-execution stdin storage -> stdin delivery task
    |
OS stdin pipe -> command
```

Successful write submission does not mean the command read the data. The guest returns input allowance only after writing bytes into the command's stdin pipe. The pipe's OS capacity is separate from this allowance. The guest delivery task can await pipe capacity without blocking the shared message reader.

Every permitted chunk must fit storage already accounted for; a receiver must never await a blocked child pipe while reading the next shared-connection message. Where a forwarding write can stall, the reservation must cover retained data until it completes. Pending stdin at the runtime and guest shares the same per-execution allowance: it is returned only after guest pipe delivery. No additional connection-wide stdin budget or transport acknowledgement is needed. Existing non-execution transport and snapshot credit remain separate.

Chunking is independent from allowance. Use chunks no larger than remaining allowance and protocol payload bounds. Preserve byte order and EOF after all successfully submitted bytes. Cancellation may leave a submitted prefix; document this behavior. Specify concurrent-write ordering before implementation. The application must send input and consume output concurrently when the command does both; transport flow control cannot fix application-level circular waits.

## Output flow

```text
Command -> guest OS stdout/stderr pipes
    |
Agent reads/sends only while output allowance is available
    |
Shared transport -> runtime forwards -> SDK output buffer
    |
Application consumes output -> cumulative output acknowledgement
```

The output allowance spans sent-but-unconsumed data in transit and in the SDK buffer; it is not a fresh allowance at every stage. Receiving output into the SDK buffer does not replenish it. Application consumption does. Once allowance runs out, the guest reader pauses; full guest pipes eventually block blocking command writes. Nonblocking writes may return EAGAIN. Other executions and controls must continue progressing.

Avoid a second SDK output staging queue. Preserve stdout/stderr order within each stream and the terminal event ordering after accepted output. Collecting all output still consumes application memory proportional to the result size.

## Acknowledgements and control sending

Rename `core.exec.stdin.credit` to `core.exec.stdin.ack` and `core.exec.output.credit` to `core.exec.output.ack` consistently across wire names, types, schemas, handlers and documentation. Retain one combined output acknowledgement rather than separate stdout/stderr allowances.

An acknowledgement identifies an execution through the existing correlation envelope and reports a cumulative `consumed` counter. Input counts bytes delivered to the stdin pipe. Output counts released output allowance units: payload bytes plus any specified per-chunk metadata charge. Decide and document that charge consistently at both ends; do not imply it measures only payload if overhead is charged. Counters are monotonic and cannot exceed sent/accounted data. Duplicate totals grant no capacity, and backwards or unsent totals are protocol errors. No per-message acknowledgement ID, retry timer or retransmission is introduced. Define integer rollover and execution-ID lifetime rules before finalizing the wire contract.

The sender knows remaining allowance from its local sent and acknowledged counters. Acknowledgements report freed capacity, not a notification that the sender hit its limit. An exhausted write waits; capacity is returned only at the declared consumption boundary.

Each sending endpoint has one control sender:

```text
Latest acknowledgement totals per execution/direction --+
                                                       +-> same connection
One bounded queue for other eligible controls ---------+
```

Replace an unsent acknowledgement with a newer cumulative total instead of enqueueing every update. Output acknowledgement senders run in their own task and yield once before reading the latest counter, allowing nearby consumption updates to coalesce without a timer or minimum batch size. Do not emit an acknowledgement in response to an acknowledgement. Acknowledgement snapshots being serialized remain bounded in addition to pending state.

The other-control queue has 16 pending messages, each at most 4 KiB encoded. An in-progress serialized control message is additional bounded storage. Validate eligible schemas against this ceiling; do not silently reclassify arbitrary requests, large payloads or terminal events as exempt control traffic. Cancellation is an intended eligible operation. Specify the complete allowlist before implementation.

Data cannot consume control reservations. Both endpoints continue reading independently of stalled data delivery; give controls regular sending opportunities between data chunks without starving ordinary data. A single spare queue slot by itself does not prove progress, and priority cannot overtake bytes already on an ordered socket.

Enforce bounded outgoing state and incoming validation in SDK, runtime and guest, not only in the runtime. Local queue saturation waits or fails clearly if the connection closes; do not silently discard controls. Bound pending producers as well as queue contents: a bounded channel must not hide an unbounded collection of spawned tasks/messages waiting to enqueue. Control-flood CPU protection and scheduling fairness remain implementation review items.

## Policy advertisement and proposed API

Advertise the effective policy only in the client-facing `Ready` handshake. All executions in the sandbox use it; no per-command overrides or repeated policy in execution acceptance. `Ready` advertises policy, not reserved capacity for future commands. Runtime admission establishes capacity independently for each execution. The SDK waits for `ExecStarted` before sending stdin, and initializes independent counters per execution.

The runtime owns the policy resolved at sandbox creation. SDKs use the returned policy when creating or attaching, not just locally requested values. Propagate the relevant authoritative settings to the guest through trusted initialization before accepting execution. Do not blindly forward client policy fields. Runtime and guest independently validate incoming chunk sizes and allowances; the SDK validates output. Chunk sizes are enforced maximum payload sizes, not just sender preferences. Validate against framing and allowance bounds, including output overhead.

Live policy changes and per-command overrides are out of scope. A future override feature would need runtime validation and execution acceptance reporting effective settings, with defaults distinguished from hard ceilings. No such fields are introduced now.

```toml
[exec]
max_executions = 128
input_limit = 65536
output_limit = 1048576
stdin_chunk_size = 16384
output_chunk_size = 4096
```

These Rust-like types specify the intended surface; final serialization/capability handling must preserve supported older-peer workflows. `Option` means inherit, never unlimited. Existing envelope correlation identifies each execution.

```rust
pub struct ExecConfigOverride {
    pub max_executions: Option<u32>,
    pub input_limit: Option<u32>,
    pub output_limit: Option<u32>,
    pub stdin_chunk_size: Option<u32>,
    pub output_chunk_size: Option<u32>,
}

pub struct ExecLimits {
    pub max_executions: u32,
    pub input_limit: u32,
    pub output_limit: u32,
    pub stdin_chunk_size: u32,
    pub output_chunk_size: u32,
}

pub struct Ready {
    // Existing fields retained.
    pub exec_limits: Option<ExecLimits>, // absent on older peers
}

pub struct ExecRequest {
    pub cmd: String,
    pub args: Vec<String>,
    pub env: Vec<String>,
    pub cwd: Option<String>,
    pub user: Option<String>,
    pub tty: bool,
    pub rows: u16,
    pub cols: u16,
    pub rlimits: Vec<ExecRlimit>,
}

pub struct ExecRlimit {
    pub resource: String,
    pub soft: u64,
    pub hard: u64,
}

pub struct ExecStarted {
    pub pid: u32,
}

pub struct ExecStdin { pub data: Vec<u8> }
pub struct ExecStdout { pub data: Vec<u8> }
pub struct ExecStderr { pub data: Vec<u8> }

// core.exec.stdin.ack: guest -> SDK, cumulative bytes delivered to stdin pipe.
pub struct ExecStdinAck { pub consumed: u64 }
// core.exec.output.ack: SDK -> guest, cumulative released output allowance units.
pub struct ExecOutputAck { pub consumed: u64 }
```

Control bounds are internal constants, not caller-controlled configuration. Keep existing data/EOF framing and use existing execution identities, subject to capability negotiation. No additional per-command handshake round trip is required beyond existing execution acceptance.

## Violations, lifecycle and compatibility

A custom/faulty sender can exceed allowance even if our SDK does not. Receivers enforce counters and sizes. Never silently drop a chunk and wait for a resend. The agreed SDK violation scope is to close the offending SDK connection and fail its active execution streams with an explicit protocol error; other SDK connections and the sandbox remain running. Keep routing/ownership isolation so one bad client cannot cause a shared guest channel failure. Guest-side violations and oversized/malformed controls need equally explicit handling without attributing one client's fault to unrelated clients.

Define cleanup on disconnect, cancellation, timeout, reader drop, EOF/error and process exit. Wake blocked senders and release reservations exactly once. Cleanup must not depend indefinitely on the application draining output. Do not recycle correlation identities while stale acknowledgements could apply. Snapshot/restore must reconstruct or invalidate allowance/counter state coherently; finalize this before shipping.

Approved compatibility decision: released older SDKs retain legacy execution behavior through an explicit compatibility path. The new flow-control memory guarantee applies only to peers supporting the policy. New SDKs must continue existing workflows with released older runtimes and running guests without forced restarts; older SDKs must continue supported workflows with newer runtimes. Do not silently claim an explicitly requested cap/allowance was enforced by an incapable peer. Finalize capability negotiation, unsupported-policy behavior and protocol generation after checking what has shipped and COMPATIBILITY.md. The new finite policy and message renaming are compatibility-sensitive; this spec does not authorize silent wire breaks or an invented downgrade path.

## Validation and remaining decisions

Preserve the historical [benchmark](EXEC_IO_BENCHMARK.md), [stall investigation](EXEC_IO_STALL_INVESTIGATION.md) and [transport experiment](/Users/toks/.codex/worktrees/exec-transport-admission/benchmark-archive-20261015/EXEC_TRANSPORT_ADMISSION.md). Their original conclusions and prototype slot counts are historical evidence, not the new target policy. The target differs from today's focused #1839 repair; review both the resulting diff from main and the removal of redundant mechanisms.

Use repeatable Linux/KVM trials on temporary infrastructure with the same images/builds; compare pre-#1832 behavior, the current repair and the redesign. Measure throughput, completion/write latency, control latency, CPU and peak host/guest memory across local and simulated-network latency. Cover fast/slow readers, large and tiny writes, full-duplex commands and concurrent executions. Validate 128 as a default rather than treating it as performance evidence.

Required acceptance evidence includes: saturated stdin cannot block output acknowledgements; controls progress without data allowance; complete ordered byte delivery; ordered EOF/exit; duplicate/backwards/unsent ack handling; oversending disconnect isolation; bounded pending controls/tasks; atomic cap admission across multiple SDK connections; failed-start and cleanup slot release; retained completed-output accounting; all SDK configuration precedence; authoritative Ready policy on create/attach; no stdin before acceptance; runtime/guest initialization agreement; hostile chunk sizes; compatibility with released peers. A stalled application must not force unrelated executions to stall.

Still to finalize before shipping: exact API/schema names and range bounds; metadata accounting; language-specific configuration signatures;  allowed control message schemas and scheduling; guest-fault handling; snapshot/restore; negotiated compatibility behavior; measurable performance acceptance thresholds. Keep #1839 draft until the combined implementation and release validation are ready. No further default tuning or unrelated transport changes are implied by this spec update.


## Implementation checkpoint

Local work on the #1839 worktree now includes the shared policy and Ready advertisement, trusted bootstrap propagation, direct SDK stdin sending, acknowledgement wire names, configurable guest chunk sizes, guest admission checks, and retained completion until output is acknowledged. Released-peer compatibility remains a distinct path. Background startup output is acknowledged when discarded.

Validation checkpoint (2026-10-18): Rust SDK unit tests pass (1,312), runtime unit tests pass (466), Python passes (294, five fixture-dependent skips), Node unit tests pass (381, one skip), and Go tests pass. Linux/KVM guest tests pass (218, two privileged memlock tests ignored) and protocol tests pass (85). The nine focused live execution/stdin cases pass, covering retained output admission, legacy behavior, connection-isolated protocol violations, and full-duplex delivery. The general live run passes 95 of 119 cases; 24 require separately prepared fixtures. The dedicated managed-job harness passes all ten Rust cases and both CLI smoke scripts; the snapshot harness passes all six cases (including delay/error/cancel variants). Final focused execution tests pass 9/9 after the managed-job fix. At that checkpoint, ten historical runtime/control/catalog tests were pending: Debian 12 lacked GLIBC_2.38/2.39 for two released-runtime probes, and eight needed historical fixtures. The Ubuntu follow-up below completes those cases. Logs are saved in `/tmp/msb-exec-policy-validation-20261018.tar.gz`. The temporary VM was deleted after collecting evidence.

Cloud creation now carries policy through API validation, persisted driver specs, and runtime launch. Operators enable `orchestrator.exec_policy` after upgrading workers; it supplies defaults and ceilings. Fields omitted from SDK options and global settings inherit the operator policy; the service resolves and validates the complete policy before provisioning. Customers can lower values but requests above any ceiling fail before persistence. The SDK checks service support before sending explicit settings. The cloud patch is in `/Users/toks/.codex/worktrees/exec-policy-cloud` and was checked against these local Microsandbox sources; its dependency must be pinned to the eventual Microsandbox commit before shipping. No cloud deployment has been performed.

Runtime-owned managed jobs now acknowledge output after capture and send stdin in advertised chunks under the guest allowance. They must not bypass the flow-control contract merely because their caller is the runtime rather than an SDK.

Disk-only restores use current global execution settings and SDK overrides. No execution-policy extension is written to snapshot manifests. Full-memory restores instead preserve the complete guest policy from captured memory and advertise the captured Ready unchanged. Global defaults yield to captured values; explicit SDK execution settings must match them or fail with a clear error directing callers to remove the settings or use disk-only restore. A legacy snapshot without an execution policy rejects any explicit execution settings. WorkloadThaw and WorkloadThawed carry no execution policy. Host configuration for a memory restore is aligned with captured Ready, including the legacy path when no execution policy was advertised. Managed requirements and cloud ceilings still apply. No public per-restore override API is added.

Follow-up validation on Ubuntu 24.04/KVM: all ten previously pending historical runtime/control/catalog cases pass using released v0.5.0, v0.6.9, and v0.6.18 fixtures (v0.6.4/v0.6.9 for binary-replacement probes). All six snapshot harness cases, four execution-policy acceptance tests, and eight agent restore tests pass. SDK unit coverage is 1,313 passing with 16 opt-in cases ignored; runtime restore checks passed for the previous thaw-policy design. The cloud policy ceiling test includes sparse snapshot inheritance and rejection above the ceiling. An extra JSON replacement run against v0.6.4 fails because its runtime remains alive after stop; v0.6.9 passes. This older stop path is unchanged by this work and remains a compatibility caveat, not a clean result. Evidence is saved in `/tmp/msb-compat-evidence.tar.gz` and `/tmp/msb-sparse-restore-test.log`; the sparse memory-restore inheritance check describes the superseded thaw-policy design. Changes remain local and uncommitted.


Validation checkpoint (2026-10-20): removed the extra relay-input handshake, SDK reservation ledger, and shared stdin budget in favor of per-execution routing. The saturation regression fails with the old shared forwarding and passes with the new route; it also checks tiny writes and ordered EOF. Runtime tests pass (468), Rust SDK tests pass (1,318), agent-client and protocol tests pass, and all four live Linux/KVM execution-policy cases pass after the review fixes, including the 8 MiB duplex transfer. Claude's final focused review found no outstanding correctness issues. Library Clippy and formatting pass; all-targets Clippy still flags three pre-existing test-module layout warnings. Evidence: `/tmp/msb-routing-linux-evidence-20261020.tar.gz`.

Execution configuration resolution keeps the caller's `ExecConfigPatch` separate from snapshot inspection state. The normal configuration merge produces the single `SandboxConfig.exec`; no execution patches or caller provenance are stored on `SandboxConfig`. Cloud creation sends the sparse request to the service separately. Reusing a concrete config makes its populated execution settings explicit. CPU and memory requests also remain sparse until snapshot inspection. Captured geometry stays in restore state and is applied alongside exec policy in the final configuration merge. `restore_overrides` is removed; reused concrete configs supply populated resource values explicitly.

## Scope decision (2026-10-21): fixed limits, no configuration surface

The configurable execution policy described above is cut from this change. The limits keep their agreed values (128 executions, 64 KiB input, 1 MiB output, 16 KiB stdin chunks, 4 KiB output chunks) but become built-in constants rather than user configuration:

- Removed: the `[exec]` global settings, per-sandbox SDK overrides in all four SDKs (`ExecConfigPatch`/`ExecPolicyPatch` and bindings), persistence of resolved policy on `SandboxConfig`, cloud `orchestrator.exec_policy` with operator ceilings and the service capability handshake, and the snapshot explicit-settings mismatch errors. The companion cloud patch worktree (`exec-policy-cloud`) is shelved.
- Kept: the complete flow-control mechanism (per-execution routing, cumulative input/output acknowledgements), the runtime-owned atomic admission cap with its typed at-capacity error, trusted bootstrap propagation of the policy to the guest, the `Ready.exec_limits` advertisement that clients obey (so constants can change between releases without lockstep upgrades), the legacy path for released peers, and memory restores preserving the captured guest policy. Launching a memory snapshot that captured a policy still requires the `exec_limits` runtime capability; cold boots do not.
- Restore semantics simplify to: memory restore uses whatever the captured Ready advertises; disk-only restore boots fresh with the current built-in defaults. With no explicit settings to conflict, the mismatch-error matrix is gone.

Configurability can be reintroduced later purely additively: the guest would advertise a configured value instead of a constant, and no wire format, SDK logic, or compatibility behavior changes.

### Why acknowledgements instead of a stream per execution

The agent transport is a virtio-console ring buffer (`console=hvc0`, `agent_transport=dual-port-v1`) shared by every SDK client and operation type; there are no per-stream OS sockets to provide flow control. Per-execution streams would require a new guest device and transport with its own bootstrap, compatibility, and snapshot/restore story (the ring-buffer transport is reconstructed on thaw; open per-exec connections would not survive a memory restore), and dynamic virtio-console ports cannot be added after boot. Credit-based acknowledgements over the shared connection are also the established pattern in this codebase: bulk transfers already use `BulkCredit` windows on the same transport.

### Rename (2026-10-21)

With the configuration surface gone, "policy" no longer describes the type: it holds fixed limits. Renamed across the code, wire payloads, and docs before any release: `ExecPolicy` is now `ExecLimits`, `Ready.exec_policy` is `Ready.exec_limits`, the bootstrap field and the launch capability are `exec_limits`, and the live test fixture variable is `MSB_EXPECTED_EXEC_LIMITS`. Generation 10 is unreleased, so the wire rename has no compatibility cost. Historical checkpoint notes above keep the old spelling they were recorded with; saved validation harness scripts that set the old fixture variable need the new name on the next run.

### Output chunk size raised to 16 KiB (2026-10-21)

The 4 KiB value codified agentd's historical read-buffer size, but the new accounting made small chunks more expensive: a 256-byte charge and one accounting step per chunk put 6.25% of the output window into overhead. 16 KiB cuts the per-window message count and overhead charge by four. Interactive output is unaffected because chunk size caps a read; partial output still flushes immediately. Legacy sessions keep the historical 4 KiB read size. To be confirmed in the pending Linux/KVM validation run.
