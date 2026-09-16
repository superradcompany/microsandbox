# Agent and Control Protocol Versioning

Microsandbox has two independently versioned protocols. The agent protocol connects host SDKs to `agentd` inside a VM. The control protocol connects host SDKs to the host runtime for resource changes and secret updates. Sharing a framed client does not merge these protocols, their generations, or their authority.

```text
SDK / CLI
   +-- AgentClient = Client<AgentProtocol>
   |       -> agent socket / pipe -> relay -> guest agentd
   |
   +-- ControlConnection
           +-- legacy JSON adapter --------> host runtime
           +-- ControlClient
                 = Client<ControlProtocol> -> host runtime
```

The release SDK retains its optimized Rust agent implementation for bulk records and Unix shared arenas. The generic public agent client and framed control client use the shared router. This preserves the release branch's existing bulk SDK APIs during the extraction. Agent correlations are retired after use because the release relay rejects reused IDs; control IDs may be reused after terminal completion.

`Client<P>` owns transport I/O, correlation IDs, routing, and local stream ownership. Each protocol supplies setup, outbound metadata, and envelope decoding. Sandbox execution, filesystem services, resource policy, and process lifecycle remain in the SDK/runtime. Public source APIs may change; that does not authorize dropping a supported wire format or historical SDK/runtime workflow.

## The shared outer frame

Both framed protocols use the existing byte layout:

```text
[length: u32 BE][id: u32 BE][flags: u8][envelope bytes]
       |<---------- length counts these bytes --------->|

standard envelope: CBOR { v: u8, t: text, p: bytes }
                                             |
                                  separately encoded payload
```

The four-byte length prefix is excluded from `length`; the ID and flags occupy five bytes. The ordinary frame limit is 4,194,304 bytes after the prefix. The relay routes agent frames using IDs and flags without decoding the envelope, so a payload version cannot hide an incompatible header change.

Native messages encode a payload using their protocol's codec. Encoded messages preserve supplied payload bytes. Raw subscriptions bypass envelope decoding, and exact packet writes preserve caller bytes without allocating an ID or installing a subscription. These escape hatches retain the caller's responsibility for compatible message names, flags, generations, and payloads; they are not evidence that an old peer supports a new operation. Use the original frame when forwarding unknown fields instead of decoding and rebuilding it.

The TypeScript agent codec preserves its existing `cbor-x` encoding, including tagged byte-array payloads. The control codec uses the stricter control record rules below. Extracting the shared engine must not normalize existing agent bytes to the control codec's output.

## Agent generations and existing wire behavior

A running VM keeps its guest agent until that runtime exits. Upgrading the host does not replace an already-running `agentd`, so newer clients retain the supported older relay handshakes and wire forms.

The agent relay supplies an ID-range prologue and the original `core.ready` frame. Current relays supply `[id_min, id_max]`; the supported pre-0.5 path supplies `[id_offset]` followed by the ready frame. `AgentProtocol` recognizes that prologue and retains the ready frame, including unknown fields. No control hello or JSON probe is sent to an agent endpoint.

There are two related values to preserve:

| Value | Current relay path | Supported legacy path |
|---|---|---|
| Known-operation availability gate | Minimum of host generation and ready-frame generation | Minimum of generation 1 and ready-frame generation |
| Generation emitted in native/encoded envelopes | Host's existing `PROTOCOL_VERSION` | Generation 1 |

The current path historically emits the host generation even when its availability gate is lower. The extraction preserves that behavior. Do not rewrite every outgoing agent `v` to the negotiated minimum under the assumption that this would be a neutral cleanup. The Rust agent constant remains 9 and the standalone TypeScript client retains its existing generation 5; adding framed host control does not bump either value or imply that both client packages expose every agent operation.

Known message types have an introduction generation in `MessageType::min_protocol_version()`. `AgentProtocol::prepare` checks availability before admitting native or encoded sends. An unsupported known operation returns the shared client's unsupported-operation category without sending it or closing unrelated streams. Dynamic names and raw bytes remain available to callers who deliberately own their protocol interpretation.

Rust callers inspect `client.ready().negotiated_version`, `client.ready().supports(message_type)`, `client.ready().wire_format`, and `client.ready().ready_bytes()`. Callers retaining only a generation can use `AgentProtocol::ensure_version_compat_for`. TypeScript exposes the corresponding `client.ready.negotiatedVersion`, `supports(wireName)`, `wireFormat`, and `readyBytes`. The package READMEs contain the complete previous-to-current API mappings; the active shared client does not return the old agent-specific unsupported-operation fields.

Generation labels must be checked against actual historical agents. The current introduction map gates filesystem operations at generation 2. The retained v0.5.0 live evidence shows a generation-1 agent that accepts the tested raw filesystem stat operation while the checked path refuses it. That discrepancy remains an unresolved compatibility case; neither the introduction table nor a successful exec test proves every historical filesystem workflow works. Releases before v0.6.0 are outside this change's compatibility target.

### Bootstrap and shutdown

`core.bootstrap` is a one-shot startup frame sent before the ordinary `core.ready` exchange. It configures a newly launched VM with the agent bundled by the selected build. The guest validates its minimum generation and accepts newer bootstrap generations under the existing optional-field rules. This is distinct from connecting a new SDK to an already-running old VM, and it does not prove compatibility of the host SDK/runtime launch JSON or shared database.

Graceful shutdown is an existing uncorrelated agent operation. The SDK preserves its zero ID, shutdown flag, selected wire generation, and empty-unit payload through an explicit packet write, awaited before closing the client. It must not use the generic `send` API, which requires a live owned stream ID. A runtime process exiting is insufficient shutdown evidence: PID fallback can exit without the guest sync needed to preserve recent root-disk writes. The [SDK packet regression test](../../sdk/rust/lib/backend/local/sandbox/shutdown_tests.rs) checks the actual current and legacy packets; live SDK stop/restart tests separately check persistence without manual sync.

## Framed control on the existing endpoint

The host runtime keeps its existing `control.sock` or Windows pipe name, resolved through the existing IPC helper. It chooses the parser once per accepted connection:

```text
first byte
   +-- 0x00 -> framed control hello -> welcome -> persistent operations
   +-- other -> existing JSON request -> JSON response -> close
```

The inspected byte is retained. Opening framed messages are limited to 4,096 bytes, so the hello's four-byte length prefix starts with zero. Malformed input never switches parsers. Empty existence probes close without becoming application requests. This dispatch rule adds no agent or guest route for host-only control operations.

Control uses its own `CONTROL_GENERATION`, initially 1. The opening `control.hello`, `control.welcome`, and handshake `control.error` envelopes use generation 1 and ID zero. Hello has flags zero; welcome and errors have terminal flags. Application requests use nonzero IDs, flags zero, and the selected control generation; replies use the same ID and terminal flags.

Hello identifies `msb.control`, offers a generation range, and supplies maximum frame size and in-flight limits. The current server selects generation 1 when it lies in the offered range and takes the smaller limits. The client rejects a welcome outside its offer before sending an operation. Future implementations select the highest common supported generation while preserving this opening format. The framed control client has the full nonzero u32 ID space and performs no agent relay range exchange.

Control records use unsigned integers of their declared widths, text keys, and independently encoded payloads. Generated encoders emit definite containers, shortest integers, and the declared field order. Checked decoders accept other map orders and unknown optional fields, but reject duplicate record keys, missing required fields, invalid types, out-of-range integers, and trailing input. Optional fields are omitted rather than encoded as null. Raw paths retain original bytes and unknown fields without imposing checked-record interpretation.

Memory wire values remain `u64` in Rust and `bigint` in checked TypeScript results, including small observations. The JSON adapter preserves integer tokens before converting them; `JSON.parse` followed by a bigint conversion would already have lost precision. Rust SDK-compatible input helpers retain the existing `Mebibytes` conversion semantics; callers needing the complete wire input range construct `SetMemoryTarget { total_mib }` directly. This protocol does not redefine shared size helpers or the runtime's resource conversion algorithms.

Resource replies distinguish accepted targets from current observations, without promising convergence. Secret batches execute sequentially, stop at the first operational failure, and retain earlier successful entries. `applied_count` and `failed_index` describe that progress; they do not imply rollback. `effect: "none"` is used only for an operation known not to have mutated its relevant state. Loss of a reply after dispatch leaves the overall outcome unknown. No client reconnect or error string authorizes replay.

### Discovery and legacy JSON obligations

`ControlClient` is explicitly framed and never probes JSON. `ControlConnection` is the compatibility entry point. Its automatic setup sends the existing read-only JSON `capabilities` request and accepts framed control only after an explicit `control_protocols` advertisement containing `cbor`. It then opens a fresh connection for hello/welcome. Valid legacy capabilities without the additive field select JSON. Malformed replies, arbitrary negative replies, EOF, timeouts, and refused handshakes are errors, not evidence for a fallback. The known pre-capability-error allowlist is empty.

The SDK backend shares one session setup among concurrent callers, reuses the framed connection, and opens fresh per-operation connections for JSON. JSON mode selection is reusable only with verified runtime identity continuity. A standalone connector without that verification rediscovers on subsequent JSON connections. Runtime replacement or transport failure invalidates the session; a later caller may establish a new one, but an admitted request is never moved or replayed onto it.

Legacy JSON keeps its operation names, one-request/response behavior, whitespace and EOF handling, and absence of a default request-line size cap. The 64 KiB discovery-response limit is not a new general JSON operation limit. Ordinary compatibility requests retain the actual JSON reply, including errors and unknown fields; checked helpers may interpret it. They do not fabricate a framed ID or CBOR envelope.

Retiring JSON operations requires a separate supported-version decision. Even after such a decision, supported CBOR SDKs may still need the read-only JSON discovery response. Keep that bootstrap until a separately compatible discovery migration is available. Likewise, new SDKs still need their JSON adapter for supported old runtimes. Neither retirement requires renaming the endpoint.

## Evolution rules

1. **One version number** (the generation), agreed once at the handshake.
2. **The binary frame header never changes shape.** A negotiated generation may add a body format selected by an exclusive flag, but old peers are never sent that format.
3. **New fields are always optional**, so old and new can ignore or default what they don't know.
4. **New kinds of message and body format are only ever added, never removed or redefined**, and each records the generation it arrived in.
5. **The host checks the agreed version before sending** anything new, so unsupported features
   fail cleanly and alone.
6. **The newer side speaks the older format.** The old runtime is never asked to learn anything.

## Sources and verification

| Contract | Authoritative source or check |
|---|---|
| Agent constants, flags, wire names, introduction map | [message.rs](lib/message.rs) |
| Outer frame encoding | [codec.rs](lib/codec.rs) |
| Agent relay setup, send gates, ready metadata | [Rust agent protocol](../../packages/agent-client/rust/lib/protocol.rs), [TypeScript agent protocol](../../packages/agent-client/typescript/src/protocol.ts) |
| Control records and handshake | [control module](lib/control/mod.rs), [wire decoder](lib/wire.rs) |
| Shared-socket dispatch and host handlers | [server.rs](../runtime/lib/control/server.rs), [handler.rs](../runtime/lib/control/handler.rs) |
| Automatic discovery and JSON adaptation | [Rust connection](../../packages/control-client/rust/lib/connection.rs), [TypeScript connection](../../packages/control-client/typescript/src/connection.ts) |
| Backend ownership and process identity | [control registry](../../sdk/rust/lib/backend/local/control/registry.rs), [identity checks](../../sdk/rust/lib/backend/local/control/identity.rs) |
| Source migration and low-level examples | [Rust agent README](../../packages/agent-client/rust/README.md), [TypeScript agent README](../../packages/agent-client/typescript/README.md), [Rust control README](../../packages/control-client/rust/README.md), [TypeScript control README](../../packages/control-client/typescript/README.md) |

The [schema snapshot test](tests/schema_snapshot.rs) freezes the agent generation, frame constants, flag bits, and message introduction inventory. Its append-only check protects prior message names and introduction generations. These snapshots do not describe every payload field or freeze every serialized payload; do not cite them as complete serialization compatibility evidence.

The [control contract tests](tests/control_contract.rs) generate the 26 [generation-1 fixtures](../../packages/protocol-fixtures/control-v1.json) and compare exact bytes. Rust and TypeScript consume that corpus, including pinned unknown payload and envelope fields whose original frames survive raw forwarding. They also test strict records, maximum-width memory values, partial secret progress, and secret-safe diagnostics. The [legacy JSON tests](tests/legacy_json_contract.rs) use pinned historical source contracts from v0.6.4 through v0.6.18, and the [agent fixtures](../../packages/protocol-fixtures/agent-ts-v5/fixtures.json) preserve the previous TypeScript encoder. Source fixtures complement actual released artifacts; they do not substitute for them.

Focused checks, from the repository root:

```sh
cargo test -p microsandbox-protocol --locked --test schema_snapshot --test control_contract --test legacy_json_contract
cargo test -p microsandbox-protocol-client -p microsandbox-agent-client -p microsandbox-control-client --all-features --locked
npm --prefix packages run build
npm --prefix packages run typecheck
npm --prefix packages test
```

The stable wire header and ordinary control body are:

```
[ length ][ id ][ flags ][ body ]  <- fixed binary header, read first, never changes shape
body = CBOR { v, t, p }            <- ordinary control envelope
              p = CBOR { ... }     <- payload for that message type
```

Generation 9 adds attempt-scoped workload freeze/thaw for full checkpoint capture and activation. Hosts reject those operations against generation-8 agents before sending. Generation 8's released bulk-transfer contract remains unchanged; the discarded, unreleased freeze/thaw assignment to generation 8 has no compatibility shim.

The unreleased generation-9 handshake includes complete-frame transport boundaries and `core.workload.transport.credit`. The bundled host and guest use the optional Ready capability `workload_transport_barrier_version: 2`; an absent or unsupported value refuses full capture/pause before mutation. The superseded development contract `1` charged stdin against command capacity and is refused on full restore, not translated. This internal contract does not change SDK framing or add a socket. Older SDK requests still use their negotiated generation; their payloads are not reinterpreted to implement the barrier.

The host gates ordinary input, finishes any admitted frame, and sends its cumulative control/data wire-byte and frame positions through a bounded private lifecycle queue. The existing `bulk_*` fields count logical data: raw bulk, stdin, inline filesystem/TCP payloads, and ordered EOF, regardless of physical port. Command metadata uses separate `control_*` capacity. The guest retains accepted input independently of blocked consumers, freezes workloads, and parks output at complete frames. Frozen reports the dedicated bulk output cut and absolute input grants; combined transport orders its output on the primary stream instead. Continue releases source-owned queued input only after Thawed. Restore carries the existing cumulative counters and retained input debt forward instead of granting a fresh window. Unrelated admitted metadata may bypass credit-blocked data, but per-correlation and client-disconnect ordering are retained. Incomplete boundaries time out without authorizing capture. These required fields finalize unreleased generation 9 in place; superseded development full snapshots are refused, not translated.

Generation 8 adds one negotiated data-body alternative without changing the header:

```
flags = FLAG_BULK                  <- exclusive; no lifecycle flag may be combined with it
body = [ kind ][ flow ][ 0 ][ offset ][ opaque payload ]
       u8     u8     u16   u64 BE    1..negotiated maximum bytes
```

Filesystem reads/writes and TCP streams first negotiate this format through CBOR control messages. A host connected to a generation-7 or older runtime never offers raw bulk and continues using the CBOR data messages. The relay validates the universal length and exclusive flag shape, routes on the unchanged correlation ID, and does not interpret bulk kind, flow, offsets, credits, or payload.

The optional `dual-port-v1` transport profile is orthogonal to this schema. On the internal `agent-bulk` port only, each unchanged generation-8 frame is prefixed by a 128-bit client incarnation. The relay strips that prefix before forwarding the frame to an SDK. Fixed `MSBL` range-lifecycle records on the ordered control port establish the current incarnation and acknowledge its disconnect before control IDs are reused; they are decoded only after the host and guest bind `dual-port-v1`, are not `MessageType` values, and therefore do not alter the generation-8 schema. Once a transport profile ships, its framing is immutable even though it has a separate capability gate.

- **`v`** is the generation, echoed onto each message. Same number negotiated at the handshake;
  not a per-message version. Don't gate behavior by reading it per message.
- **`MessageType::min_protocol_version()`** (`lib/message.rs`) is the per-type label: the
  generation that introduced the type. It has no wildcard arm, so adding a `MessageType` won't
  compile until you assign its generation (and bump `PROTOCOL_VERSION` to match). Core and exec
  types are generation 1 (the pre-0.5 legacy runtime handles them); the `Fs*` types are generation
  2, because filesystem streaming did not exist in the legacy protocol.
- **The send gate** lives on the host client (`packages/agent-client/rust/lib/client.rs`). At
  handshake the client computes `negotiated_version = min(our PROTOCOL_VERSION, the generation the
sandbox echoed in its ready frame)`. Every typed send checks `min_protocol_version()` against it
  and rejects too-old sandboxes with `AgentClientError::UnsupportedOperation`. The error's message
  advises restarting the sandbox, which re-provisions agentd at the current version (agentd is a
  host build artifact, not baked into the sandbox image). The name is direction-neutral so the same
  error can later cover the reverse skew (a newer runtime feature an older SDK can't use). Callers
  that can't gate by sending (the SSH/SFTP layer, the filesystem fail-fast) consult
  `AgentClient::supports(MessageType)` or `AgentClient::ensure_version_compat(MessageType)`, the single predicate
  over the same mechanism, instead of inspecting the protocol generation directly.
- **Both directions share one primitive:** `MessageType::is_available_at(peer_generation)`. The guest
  can gate a guest-initiated message the same way, because it already receives each peer's generation
  on every message (the `v` field). The send-site enforcement on the guest lands with the first
  feature that needs it — reverse port forwarding, where the guest opens a channel to the host — since
  no guest-initiated message type is above generation 1 yet.
- **Codec vs. gate.** `AgentProtocol` (Current / LegacyV1) selects the wire _codec_ (the container
  format). `negotiated_version` drives the _capability gate_. These are the two consumers of the
  one generation number.
- **The binary header** `[length][id][flags]` is immutable. The relay routes on `id`/`flags` without parsing the body, and it bridges a host and guest that may be different generations, so changing the header would force the relay to translate.
- **`flags`** is a 1-byte field (4 of 8 bits used) carrying either lifecycle hints or the exclusive generation-8 raw-body discriminator. New bits are append-only, must define whether combination is legal, and must be withheld from peers below their capability generation.
- **Generation-8 raw bulk is an additive, gated body format.** `FLAG_BULK` is never combined with lifecycle flags; opening offers and acceptance messages establish the permitted operation kind, flow mask, record limit, and initial absolute credits before any raw record may appear.
- **A real format break** (kind 3) now means changing the immutable header or changing an existing body's interpretation. That requires forking the codec per `AgentProtocol` generation and carrying the old one until a support horizon (see `TODO(upgrade-0.6)`).

### Tests that keep this honest

- **Schema snapshot test** (`crates/protocol/tests/schema_snapshot.rs`): generate the current
  protocol surface (the `PROTOCOL_VERSION`, the frame constants and flag bits, and every
  `MessageType` with its introducing generation, iterated via `MessageType::ALL`) as deterministic
  JSON and diff it against the checked-in `crates/protocol/schema/gen-<PROTOCOL_VERSION>.json`. Fail
  on mismatch. Re-bless an intended change with
  `UPDATE_PROTOCOL_SCHEMA=1 cargo test -p microsandbox-protocol --test schema_snapshot`; the
  generator only ever writes the current generation's file, so prior-generation files stay frozen,
  and a generation bump shows up as a reviewable diff.
- **Unit tests** (`message.rs`, `client.rs`): an unknown extra field decodes via `serde(default)` in
  both directions; a too-new message type is rejected on send with the typed `UnsupportedOperation`
  error; the negotiated generation is the lower of the two sides; every type is sendable to a current
  peer; wire strings are unique and round-trip.
- **Future:** a golden-bytes interop corpus (canonical encoded samples of each payload, asserted to
  decode under current code) and an append-only gate (a new `gen-N.json` may only add message types
  versus `gen-(N-1).json`) once a second generation exists to compare against.
