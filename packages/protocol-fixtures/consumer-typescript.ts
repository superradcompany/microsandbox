import {
  Client, ClientError, InboundFrame, encodeFrame, encodedMessage, readExactly,
  readRawFrame, typedMessage, type ByteTransport, type ConnectContext, type Connector,
  type EnvelopeCodec, type EstablishContext, type Established, type Protocol,
  type RawFrame, type Request, type SendMetadata,
} from "@microsandbox/protocol-client";

// This file is compiled and executed outside the workspace, against installed tarballs.
// Its deliberately non-CBOR envelope ensures an external protocol owns the codec.
const text = new TextEncoder();
const utf8 = new TextDecoder();
function assert(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}
function equal(actual: Uint8Array, expected: Uint8Array): void {
  assert(actual.length === expected.length && actual.every((value, i) => value === expected[i]), "bytes changed");
}

class MemoryTransport implements ByteTransport {
  peer!: MemoryTransport;
  private chunks: Uint8Array[] = [];
  private ended = false;
  private wake?: () => void;

  async read(maxBytes: number): Promise<Uint8Array | null> {
    while (!this.chunks.length && !this.ended) await new Promise<void>(resolve => { this.wake = resolve; });
    const chunk = this.chunks[0];
    if (!chunk) return null;
    const bytes = chunk.subarray(0, maxBytes);
    if (bytes.length === chunk.length) this.chunks.shift();
    else this.chunks[0] = chunk.subarray(bytes.length);
    return bytes;
  }
  async write(bytes: Uint8Array): Promise<void> {
    if (this.ended || this.peer.ended) throw new ClientError("closed");
    this.peer.chunks.push(Uint8Array.from(bytes));
    this.peer.wake?.(); this.peer.wake = undefined;
  }
  async close(): Promise<void> {
    this.ended = true; this.peer.ended = true;
    this.wake?.(); this.peer.wake?.();
  }
}

class ExternalCodec implements EnvelopeCodec {
  encodePayload(value: unknown): Uint8Array { return text.encode(JSON.stringify(value)); }
  encode(generation: number, name: string, payload: Uint8Array): Uint8Array {
    const bytes = text.encode(name);
    assert(bytes.length <= 255, "fixture name too long");
    return new Uint8Array([generation, bytes.length, ...bytes, ...payload]);
  }
  decode(frame: RawFrame): InboundFrame {
    const [generation, length] = frame.body;
    assert(generation !== undefined && length !== undefined && frame.body.length >= length + 2, "invalid custom envelope");
    return new InboundFrame(frame.id, frame.flags, generation, utf8.decode(frame.body.subarray(2, length + 2)), frame.body.subarray(length + 2), frame);
  }
}

class ExternalProtocol implements Protocol<number> {
  async establish(transport: ByteTransport, context: EstablishContext): Promise<Established<number>> {
    const ready = (await readExactly(transport, 1, context.signal))[0]!;
    return { transport, ready, codec: new ExternalCodec(), limits: context.limits, ids: { start: 0xfffffffe, endExclusive: 2 ** 32 } };
  }
  prepare(ready: number, _name: string): SendMetadata { return { generation: ready, flags: 2 }; }
}

class ExternalConnector implements Connector {
  calls = 0;
  constructor(private readonly transport: ByteTransport) {}
  async connect(context: ConnectContext): Promise<ByteTransport> {
    assert(!context.signal.aborted && Number.isFinite(context.deadlineMs), "missing setup context");
    this.calls++;
    return this.transport;
  }
}

class CheckedNumber implements Request<number> {
  message() { return encodedMessage("custom.checked", text.encode("17")); }
  decode(frame: InboundFrame): number {
    assert(frame.type === "custom.checked" && frame.isTerminal(), "wrong checked reply");
    return JSON.parse(utf8.decode(frame.payload)) as number;
  }
}

async function main(): Promise<void> {
  const transport = new MemoryTransport(), server = new MemoryTransport();
  transport.peer = server; server.peer = transport;
  const connector = new ExternalConnector(transport);
  await server.write(new Uint8Array([7]));
  const client = await Client.connectConnector(connector, new ExternalProtocol());
  const read = async () => {
    const item = await readRawFrame(server);
    assert(item, "unexpected server EOF");
    item.release(); return item.frame;
  };
  const echo = async () => {
    const frame = await read();
    await server.write(encodeFrame({ ...frame, flags: 1 }));
    return frame;
  };
  try {
    assert(connector.calls === 1 && client.ready === 7, "external setup failed");
    const native = client.request(typedMessage("custom.native", { count: 9 }));
    const nativeBytes = await echo();
    const decoded = await native;
    assert(decoded.protocolVersion === 7 && JSON.parse(utf8.decode(decoded.payload)).count === 9, "custom native codec failed");
    equal(decoded.raw.body, nativeBytes.body);

    const opaqueBytes = new Uint8Array([0xff, 0, 0x9f]);
    const opaque = client.request(encodedMessage("custom.unknown", opaqueBytes));
    const encoded = await echo();
    assert(encoded.id === 0xffffffff, "full u32 ID space unavailable");
    equal((await opaque).payload, opaqueBytes);

    const raw = client.requestRaw(0xd6, opaqueBytes);
    const rawRequest = await echo();
    assert(rawRequest.flags === 0xd6, "raw flags changed");
    equal(rawRequest.body, opaqueBytes); equal((await raw).body, opaqueBytes);

    const checked = client.requestTyped(new CheckedNumber());
    await echo(); assert(await checked === 17, "external checked request failed");

    const stream = await client.openStream(typedMessage("custom.stream", {}));
    const opening = await read();
    const { sender, receiver } = stream.split();
    await sender.send(encodedMessage("custom.chunk", opaqueBytes));
    assert((await read()).id === opening.id, "split sender lost its ID");
    await client.sendOnStream(sender.id, typedMessage("custom.chunk", { next: true }));
    assert((await read()).id === opening.id, "explicit native send lost its ID");
    await server.write(encodeFrame({ ...opening, flags: 1 }));
    assert((await receiver.next())?.isTerminal() && await receiver.next() === null, "terminal native ownership failed");
    sender.close(); receiver.close();

    const rawStream = await client.openStreamRaw(2, opaqueBytes);
    const rawOpening = await read();
    const parts = rawStream.split();
    await client.sendRaw(parts.sender.id, 0xa0, opaqueBytes);
    const followup = await read();
    assert(followup.id === rawOpening.id && followup.flags === 0xa0, "raw explicit send changed metadata");
    await server.write(encodeFrame({ ...rawOpening, flags: 1 }));
    equal((await parts.receiver.next())!.body, opaqueBytes);
    assert(await parts.receiver.next() === null, "raw terminal delivered twice");
    parts.sender.close(); parts.receiver.close();

    const packet = new Uint8Array([0xde, 0xad, 0, 0xbe]);
    await client.writeUnchecked(packet); equal(await readExactly(server, packet.length), packet);
    const sibling = client.clone(); await client.close();
    try { await sibling.requestRaw(0, opaqueBytes); throw new Error("closed clone admitted a request"); }
    catch (error) { assert(error instanceof ClientError && error.delivery === "not_sent", "closed clone lost error metadata"); }
    console.log("Packed external protocol consumer passed: custom connector/codec, full-width IDs, native/encoded/raw/checked calls, split streams, explicit sends, exact packets and shared close.");
  } finally { await client.close(); await server.close(); }
}

let timeout: ReturnType<typeof setTimeout>;
try {
  await Promise.race([main(), new Promise<never>((_, reject) => { timeout = setTimeout(() => reject(new Error("consumer deadline")), 10_000); })]);
} finally { clearTimeout(timeout!); }
