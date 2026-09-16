# TypeScript control client

`ControlClient` is `Client<ControlProtocol>` over the shared framed engine. It sends a bounded `control.hello` directly, negotiates generation and limits, and exposes the original welcome frame. Use it when the peer is known to support framed control. It does not probe JSON or downgrade after failure.

The root entry is browser-safe and accepts a caller-owned byte transport or reconnectable connector. The `/node` entry accepts an existing Unix socket or Windows named-pipe path without renaming it.

```ts
import { GetMemoryState, MiB, SetMemoryTarget, typedMessage } from "@microsandbox/control-client";
import { connectFramedControl } from "@microsandbox/control-client/node";

async function inspectAndResize(path: string) {
  const client = await connectFramedControl(path, { setupTimeoutMs: 10_000 });
  try {
    const response = await client.request(typedMessage("control.memory.state", {}));
    console.log(response.type, response.raw.body);
    const before = await client.requestTyped(new GetMemoryState());
    const accepted = await client.requestTyped(new SetMemoryTarget(MiB(2048)));
    console.log(before.target_mib, accepted.target_mib); // bigint, even for small values
  } finally {
    await client.close();
  }
}
```

Checked helpers cover capabilities, memory state/target, CPU state/target, and ordered secret updates. They validate replies and retain the actual response on `ControlClientError`. Generic message requests return peer error frames directly. A target reply reports acceptance and observation; it does not establish guest convergence. Secret batches stop at the first failure and retain earlier completed changes.

Use `connectControl` for automatic discovery on the same endpoint. It sends the existing read-only JSON capabilities request, closes that exchange, and opens a fresh framed connection only after an affirmative CBOR advertisement. Setup has one total deadline across both connections. Malformed discovery, timeout, EOF without a reply, or a failed welcome never trigger fallback or replay.

```text
connectControl(path)
    |
    +-- JSON capabilities --> valid legacy reply --> fresh JSON exchange per operation
    |
    +-- JSON capabilities --> advertises CBOR -----> fresh hello/welcome --> shared framed client
```

```ts
import { GetMemoryState, MiB, SetMemoryTarget, typedMessage } from "@microsandbox/control-client";
import { connectControl } from "@microsandbox/control-client/node";

async function compatibleResize(path: string) {
  const connection = await connectControl(path);
  try {
    const reply = await connection.request(typedMessage("control.memory.state", {}));
    if (reply.kind === "cbor") console.log(reply.frame.raw.body);
    else console.log(reply.reply.raw, reply.reply.value.get("memory"));
    const before = await connection.requestTyped(new GetMemoryState());
    const accepted = await connection.requestTyped(new SetMemoryTarget(MiB(2048)));
    return { before, accepted };
  } finally {
    await connection.close();
  }
}
```

`ControlConnection.connectConnector` accepts a repeatable caller connector from the browser-safe root. The connection exposes the read-only `capabilities` discovery snapshot, `mode`, `clone()`, `isClosed()`, `close()`, `request()`, and `requestTyped()`. `framed()` returns the complete generic surface in CBOR mode and fails locally with `unsupported_mode` in JSON mode. Encoded messages likewise fail locally in JSON mode; the adapter translates only known, validated native operations.

`JsonReply` contains the original response line, including its delimiter and whitespace, and a lossless `Map` of fields. `JsonNumber.token` retains each original numeric token; checked memory observations become `bigint` without passing through a JavaScript number. Ordinary requests return `ok:false` replies. Checked helpers raise `legacy_remote` with the original reply and unknown batch progress. Neither arbitrary diagnostic strings nor legacy errors are converted into structured CBOR errors.

For explicit legacy access, construction is inert and performs no discovery:

```ts
import { GetCpuState } from "@microsandbox/control-client";
import { jsonControl } from "@microsandbox/control-client/node";

async function inspectLegacy(path: string) {
  const client = jsonControl(path);
  try {
    return await client.requestTyped(new GetCpuState());
  } finally {
    await client.close();
  }
}
```

The equivalent root API is `JsonControlClient.fromConnector(connector, options?)`. Ordinary legacy request and response lines keep their existing size contract; only automatic discovery replies have a 64 KiB limit. Preparing a secret batch snapshots its entries without imposing the framed 4 MiB ceiling on JSON. JavaScript strings remain subject to garbage collection; explicit buffer clearing is not a guarantee that all copies have been erased.

A standalone automatic JSON connection rediscovers before each fresh operation because an endpoint path cannot establish process identity. `ControlConnection.connectVerifiedConnector` permits discovery reuse when the caller supplies a `VerifiedControlConnector`: `connect` must verify every connected peer against the saved OS process birth identity, and `verifySession` must check the active run and process before each operation. Both receive a deadline and cancellation context. Runtime replacement raises `runtime_changed` before mutation admission and closes the shared handle. This extension point does not implement an SDK database or OS identity verifier by itself.

`MiB`, `GiB`, `KiB`, `TiB`, and `Mebibytes` are exported from `@microsandbox/types/size`. Their arithmetic matches the SDK helpers. `SetMemoryTarget` validates integer precision and range before converting to the wire quantity; it also accepts `bigint` for full-width values.

All generic operations remain available:

| Need | Method |
|---|---|
| Native or encoded payload | `request(typedMessage(...))`, `request(encodedMessage(...))` |
| Exact opaque envelope | `requestRaw(flags, body)` |
| Message or raw subscription | `openStream(...)`, `openStreamRaw(...)` |
| Owned sender and receiver | `stream.split()` |
| Follow-up using an owned ID | `sendOnStream(id, ...)`, `sendRaw(id, ...)` |
| Exact packet without a subscription | `writeUnchecked(bytes)` |
| Optional checked unary operation | `requestTyped(request)` |
| Shared connection ownership | `clone()`, `close()` |

```ts
import { ControlClient, encodedMessage, type ByteTransport } from "@microsandbox/control-client";

async function inspectExtension(transport: ByteTransport, payload: Uint8Array) {
  const client = await ControlClient.connectTransport(transport);
  try {
    const reply = await client.request(encodedMessage("extension.inspect", payload));
    return { name: reply.type, payload: reply.payload, original: reply.raw };
  } finally {
    await client.close();
  }
}
```

The default control request deadline is 30 seconds. Expiry abandons the local wait; it does not cancel remote work or retry it. `ClientError.delivery` distinguishes requests that were not admitted from unknown outcomes. Complete idle connections do not expire automatically. Explicit close closes every clone; JavaScript finalization is only best-effort cleanup.

From `packages`, run `npm run build`, `npm run typecheck`, and `npm test`. Live validation is deliberately opt-in: set `MSB_CONTROL_TEST_SOCKET` to a disposable framed runtime's socket and run `npm test -w @microsandbox/control-client`. Add `MSB_CONTROL_TEST_MODE=cbor` to run automatic discovery as well. The package serializes test files because live files mutate and restore the same VM's targets. A skipped live test is not platform or runtime compatibility evidence.

For a historical JSON-only runtime, set `MSB_CONTROL_TEST_MODE=json` and run only the compatibility live file with `npm exec -w @microsandbox/control-client -- vitest run tests/compatibility-live.test.ts`. It checks automatic and explicit JSON access, concurrent reads, full-width result types, and accepted memory/CPU targets, then restores the original targets. These running-runtime tests do not establish SDK launch compatibility.

The additional secret test requires `MSB_CONTROL_TEST_SECRET` naming a dummy fixture initially set to `before` and allowed for `example.invalid`. It exercises partial completion, malformed batches, and legacy JSON failures, then restores those fixture values.
