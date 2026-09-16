# @microsandbox/protocol-client

A protocol-neutral framed client for TypeScript. `Client<P>` owns one byte transport, correlation IDs, bounded queues, a serialized writer, and response routing. `P` owns setup, its envelope codec, and message gates. Agent and control operations stay in their protocol packages; sandbox lifecycle stays in the SDK.

```text
                 Client<P>
          /          |           \
 native payload   encoded      raw frame / exact packet
          \          |           /
          protocol codec + shared router
                       |
                ByteTransport
```

## Implementing a protocol

An external package can implement setup and metadata using only public declarations. This example protocol reads one ready byte and uses the shared CBOR envelope. Its server must implement that same handshake.

```ts
import {
  Client, CborEnvelopeCodec, readExactly,
  type Protocol, type ByteTransport, type EstablishContext, type Established, type SendMetadata,
} from "@microsandbox/protocol-client";

class ExampleProtocol implements Protocol<number> {
  async establish(transport: ByteTransport, context: EstablishContext): Promise<Established<number>> {
    const ready = (await readExactly(transport, 1, context.signal))[0]!;
    return {
      transport, ready, codec: new CborEnvelopeCodec(), limits: context.limits,
      ids: { start: 1, endExclusive: 2 ** 32 },
    };
  }
  prepare(ready: number, _wireName: string): SendMetadata {
    return { generation: ready, flags: 0 };
  }
}

async function connect(transport: ByteTransport) {
  return Client.connectTransport(transport, new ExampleProtocol(), { setupTimeoutMs: 10_000 });
}
```

`ByteTransport.read(maxBytes)` returns between one and `maxBytes` ordered bytes, or `null` for clean EOF. The engine makes one read at a time and independently serializes writes. `close()` must wake both directions. Passing a transport transfers ownership, including when setup fails. `Connector.connect(context)` supplies repeatable dialing with a deadline and abort signal; it does no discovery itself. `LocalConnector` and `NodeTransport` live at `@microsandbox/protocol-client/node`. Browser-safe `WebSocketConnector` and `WebSocketTransport` are root exports.

`EnvelopeCodec.encodePayload()` supports protocol-specific native encoders. `encode()` wraps supplied payload bytes; `decode()` returns an inspectable `InboundFrame` retaining its `raw` frame. The standard codec uses `{ v, t, p }`, with `p` an actual CBOR byte string, strict unsigned integers, and open message names. Raw subscriptions never invoke that codec.

## Public access levels

| API | Input and result |
| --- | --- |
| `request(typedMessage(name, value))` | Native payload; first `InboundFrame` reply |
| `request(encodedMessage(name, bytes))` | Pre-encoded application payload; first message reply |
| `requestTyped(request)` | Optional checked request and result decoder; requires terminal reply |
| `openStream(message)` | Owned native stream through terminal |
| `requestRaw(flags, body)` / `openStreamRaw(flags, body)` | Opaque envelope bodies and raw replies |
| `sendOnStream(id, message)` / `sendRaw(id, flags, body)` | Explicit ID owned by this connection |
| `writeUnchecked(bytes)` | Exact transport bytes without framing or semantic checks |
| `stream.split()` | Separate owned sender and single receiver |
| `client.ready` / `clone()` / `close()` | Protocol metadata and shared connection lifetime |

Checked helpers are optional; neither native messages nor raw responses are narrowed to a generated message enum. Application errors remain distinct from `ClientError`. Unknown message names, payload bytes, and envelope fields remain inspectable.

## Limits, ownership, and cancellation

Default engine limits are 4 MiB per frame, 1024 in-flight exchanges, 256 queued writes, 1024 queued responses per exchange, and 8 MiB of combined engine-owned packet buffering. Protocol setup can select tighter limits. Counts exclude caller-owned inputs, returned frames, and operating-system or browser socket buffers. Native transports read in paused mode; the WebSocket adapter separately caps its input queue and closes on overflow.

A setup deadline covers dialing and protocol establishment. Optional request deadlines cover writer admission and local response waiting; incomplete-frame deadlines start only when a frame begins. Idle connections have no implicit incomplete-frame deadline. `AbortSignal` cancels local waiting. `delivery: "not_sent"` means an attempt never entered the writer; `"unknown"` means it may have reached the peer. The engine never retries an admitted operation.

Closing a stream only stops local delivery. Nonterminal abandoned exchanges retain their IDs until terminal; stale split senders remain invalid after ID reuse. A receive timeout leaves future frames available. Shared `client.close()` wakes every handle and closes the transport. Close explicitly in `finally`: JavaScript finalization is best-effort, while explicit close is deterministic.

## Development

From `packages`, run `npm ci`, `npm run build`, `npm run typecheck`, and `npm test`. Tests exercise an externally defined protocol, full-width IDs, byte preservation, routing, cancellation and admission, ownership, backpressure, transport truncation, WebSocket bounds, and public README examples. Live runtime and historical SDK compatibility tests are additional release requirements.

To check package exports independently of workspace resolution, install locally packed client packages into a separate consumer directory, then run `node protocol-fixtures/check-packed-protocol-consumer.mjs /path/to/consumer` from `packages`. The consumer lockfile must identify the protocol-client tarball and integrity, and the installed package must not be a workspace symlink. This compiles and executes a custom connector, non-CBOR envelope codec, native/encoded/raw/checked calls, full-width IDs, split streams, explicit sends, and exact packet writes against the installed declarations.

The command prints a retained output directory. With the packed agent and control packages also installed in that consumer, pass that output directory to `node protocol-fixtures/check-browser-package-roots.mjs /path/to/consumer/protocol-consumer-output`. This bundles all three root exports for the browser, rejects Node builtin imports, and executes the same protocol consumer without Node globals. It verifies browser package loading; actual browser/WebSocket integration remains a separate check.

Protocols choose whether completed correlation IDs may be reused. Agent connections retire IDs for the lifetime of the connection, matching the relay; control connections may reuse an ID after its terminal response. Exhaustion is a local error and does not reconnect or replay a request.
