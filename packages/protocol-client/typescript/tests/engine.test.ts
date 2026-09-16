import { describe, expect, it } from "vitest";
import {
  Client, CborEnvelopeCodec, ClientError, defaultLimits, encodeEnvelope, encodeFrame, encodedMessage,
  readExactly, readRawFrame, typedMessage, type ByteTransport, type EstablishContext, type Established,
  type Protocol, type RawFrame, type SendMetadata,
} from "../src/index.js";

class MemoryTransport implements ByteTransport {
  private chunks: Uint8Array[] = [];
  private ended = false;
  private notify?: () => void;
  peer!: MemoryTransport;
  writes = 0;
  closed = false;
  async read(maxBytes: number): Promise<Uint8Array | null> {
    while (this.chunks.length === 0 && !this.ended) await new Promise<void>(resolve => { this.notify = resolve; });
    const chunk = this.chunks[0];
    if (!chunk) return null;
    const bytes = chunk.subarray(0, maxBytes);
    if (bytes.length === chunk.length) this.chunks.shift();
    else this.chunks[0] = chunk.subarray(bytes.length);
    return bytes;
  }
  async write(bytes: Uint8Array): Promise<void> {
    if (this.closed || this.peer.ended) throw new ClientError("closed");
    this.writes++;
    this.peer.chunks.push(Uint8Array.from(bytes));
    this.peer.notify?.(); this.peer.notify = undefined;
  }
  async close(): Promise<void> {
    this.closed = true; this.ended = true; this.peer.ended = true;
    this.notify?.(); this.peer.notify?.();
  }
}

class ExternalProtocol implements Protocol<number> {
  async establish(transport: ByteTransport, context: EstablishContext): Promise<Established<number>> {
    const ready = (await readExactly(transport, 1))[0]!;
    return { transport, ready, codec: new CborEnvelopeCodec(), ids: { start: 1, endExclusive: 2 ** 32 }, limits: context.limits };
  }
  prepare(ready: number, name: string): SendMetadata {
    if (name === "future.gated" && ready < 2) throw new ClientError("unsupported_operation");
    return { generation: ready, flags: 2 };
  }
}

function transports() {
  const client = new MemoryTransport(), server = new MemoryTransport();
  client.peer = server; server.peer = client;
  return { client, server };
}
async function pair(ids = { start: 1, endExclusive: 2 }, limits = defaultLimits()) {
  const io = transports();
  const client = await Client.fromEstablished(new ExternalProtocol(), { transport: io.client, codec: new CborEnvelopeCodec(), ids, ready: 1, limits });
  return { client, server: io.server, transport: io.client };
}
async function read(server: ByteTransport): Promise<RawFrame> {
  const value = await readRawFrame(server);
  if (!value) throw new Error("unexpected server EOF");
  value.release(); return value.frame;
}
const body = (type: string, value: Uint8Array) => encodeEnvelope({ v: 1, t: type, p: value });
const tick = () => new Promise<void>(resolve => setTimeout(resolve, 0));

describe("public generic framed engine", () => {
  it("establishes an external protocol and preserves native, encoded and unknown bytes", async () => {
    const io = transports();
    await io.server.write(new Uint8Array([1]));
    const client = await Client.connectTransport(io.client, new ExternalProtocol());
    expect(client.ready).toBe(1);
    const call = client.request(typedMessage("future.native", { n: 7 }));
    const request = await read(io.server);
    await io.server.write(encodeFrame({ ...request, flags: 1 }));
    expect((await call).decodePayload()).toEqual({ n: 7 });
    const opaque = client.request(encodedMessage("future.unknown", new Uint8Array([0xff, 0, 1])));
    const next = await read(io.server);
    await io.server.write(encodeFrame({ ...next, flags: 1 }));
    const response = await opaque;
    expect(response.payload).toEqual(new Uint8Array([0xff, 0, 1]));
    expect(response.raw.body).toEqual(next.body);
    await client.close();
  });

  it("routes reordered fragmented replies including u32::MAX", async () => {
    const { client, server } = await pair({ start: 0xffffffe0, endExclusive: 2 ** 32 });
    const calls = Array.from({ length: 32 }, (_, n) => client.requestRaw(0, new Uint8Array([0xff, n])));
    const requests: RawFrame[] = [];
    for (let n = 0; n < 32; n++) requests.push(await read(server));
    expect(requests.at(-1)?.id).toBe(0xffffffff);
    for (const request of requests.reverse()) {
      for (const byte of encodeFrame({ ...request, flags: 1 })) await server.write(new Uint8Array([byte]));
    }
    expect((await Promise.all(calls)).map(frame => frame.body[1])).toEqual(Array.from({ length: 32 }, (_, n) => n));
    await client.close();
  });

  it("retains split leases, delivers terminal once, and rejects stale senders after ID reuse", async () => {
    const { client, server } = await pair();
    const stream = await client.openStreamRaw(0, new Uint8Array([1]));
    const { sender, receiver } = stream.split();
    expect(() => stream.id).toThrow("split");
    await read(server);
    await sender.send(0, new Uint8Array([2]));
    expect((await read(server)).body[0]).toBe(2);
    await server.write(encodeFrame({ id: 1, flags: 1, body: new Uint8Array([3]) }));
    expect((await receiver.next())?.body[0]).toBe(3);
    expect(await receiver.next()).toBeNull();
    await tick();
    const next = await client.openStreamRaw(0, new Uint8Array([4]));
    await read(server);
    await expect(sender.send(0, new Uint8Array([5]))).rejects.toMatchObject({ code: "stream_closed", delivery: "not_sent" });
    sender.close(); receiver.close(); next.close(); await client.close();
  });

  it("keeps a nonterminal unary reply draining until terminal", async () => {
    const { client, server } = await pair();
    const call = client.requestRaw(0, new Uint8Array([1]));
    await read(server);
    await server.write(encodeFrame({ id: 1, flags: 0, body: new Uint8Array([2]) }));
    expect((await call).body[0]).toBe(2);
    await expect(client.requestRaw(0, new Uint8Array([3]))).rejects.toMatchObject({ code: "ids_exhausted" });
    await server.write(encodeFrame({ id: 1, flags: 1, body: new Uint8Array() }));
    await tick();
    const next = await client.openStreamRaw(0, new Uint8Array([4]));
    expect((await read(server)).body[0]).toBe(4);
    next.close(); await client.close();
  });

  it("aborts only local waiting after admission and never replays", async () => {
    const { client, server, transport } = await pair();
    const abort = new AbortController();
    const call = client.requestRaw(0, new Uint8Array([1]), { signal: abort.signal });
    const failed = expect(call).rejects.toMatchObject({ code: "cancelled", delivery: "unknown" });
    await read(server); abort.abort(); await failed;
    expect(transport.writes).toBe(1);
    await expect(client.requestRaw(0, new Uint8Array([2]))).rejects.toMatchObject({ code: "ids_exhausted" });
    await client.close();
  });


  it.each(["abort", "timeout"] as const)("finishes a partial packet after %s and drains before ID reuse", async mode => {
    const { client, server, transport } = await pair();
    let unblock!: () => void;
    const blocked = new Promise<void>(resolve => { unblock = resolve; });
    const original = transport.write.bind(transport);
    const packets: Uint8Array[] = [];
    transport.write = async bytes => {
      packets.push(Uint8Array.from(bytes));
      if (packets.length === 1) {
        // Expose a real prefix to the peer and withhold the remainder until the
        // request waiter has canceled. Closing only that waiter must not truncate it.
        await original(bytes.subarray(0, 3));
        await blocked;
        await original(bytes.subarray(3));
      } else await original(bytes);
    };
    try {
      const abort = new AbortController();
      const body = new Uint8Array(64).fill(0x31);
      const expected = encodeFrame({ id: 1, flags: 0, body });
      const call = client.requestRaw(0, body, {
        signal: abort.signal,
        ...(mode === "timeout" ? { requestTimeoutMs: 20 } : {}),
      });
      const failed = expect(call).rejects.toMatchObject({
        code: mode === "abort" ? "cancelled" : "timeout", delivery: "unknown",
      });
      const prefix = await readExactly(server, 3);
      if (mode === "abort") abort.abort();
      await failed;
      expect(client.isClosed()).toBe(false);
      await expect(client.sendRaw(1, 0, new Uint8Array([9]))).rejects.toMatchObject({ code: "stream_closed" });
      await expect(client.requestRaw(0, new Uint8Array([2]))).rejects.toMatchObject({ code: "ids_exhausted" });

      unblock();
      const remainder = await readExactly(server, expected.length - prefix.length);
      expect(new Uint8Array([...prefix, ...remainder])).toEqual(expected);
      await expect(client.requestRaw(0, new Uint8Array([2]))).rejects.toMatchObject({ code: "ids_exhausted" });
      await server.write(encodeFrame({ id: 1, flags: 0, body: new Uint8Array([0x71]) }));
      await server.write(encodeFrame({ id: 1, flags: 1, body: new Uint8Array([0x72]) }));
      await tick();

      const following = client.requestRaw(0, new Uint8Array([0x22]));
      const request = await read(server);
      expect(request.id).toBe(1);
      expect(request.body).toEqual(new Uint8Array([0x22]));
      await server.write(encodeFrame({ id: 1, flags: 1, body: new Uint8Array([0x44]) }));
      expect((await following).body).toEqual(new Uint8Array([0x44]));
      // Two logical writes prove the canceled request was neither replayed nor
      // replaced by an implicit EOF/signal frame when its waiter disappeared.
      expect(packets).toEqual([expected, encodeFrame(request)]);
    } finally {
      unblock();
      await client.close();
    }
  });

  it("rejects pre-aborted requests without writes or leased IDs", async () => {
    const { client, server, transport } = await pair();
    const abort = new AbortController(); abort.abort();
    await expect(client.requestRaw(0, new Uint8Array([1]), { signal: abort.signal })).rejects.toMatchObject({ code: "cancelled", delivery: "not_sent" });
    expect(transport.writes).toBe(0);
    const next = await client.openStreamRaw(0, new Uint8Array([2]));
    expect((await read(server)).id).toBe(1);
    next.close(); await client.close();
  });

  it("does not consume a future frame when one receive times out", async () => {
    const { client, server } = await pair();
    const stream = await client.openStreamRaw(0, new Uint8Array([1]));
    await read(server);
    await expect(stream.next(5)).rejects.toMatchObject({ code: "timeout" });
    await server.write(encodeFrame({ id: 1, flags: 1, body: new Uint8Array([9]) }));
    expect((await stream.next())?.body[0]).toBe(9);
    stream.close(); await client.close();
  });

  it("wakes pending receives on stream close and preserves the connection", async () => {
    const { client, server } = await pair();
    const stream = await client.openStreamRaw(0, new Uint8Array([1]));
    await read(server);
    const pending = stream.next(); stream.close(); expect(await pending).toBeNull();
    expect(client.isClosed()).toBe(false);
    await expect(client.sendRaw(1, 0, new Uint8Array())).rejects.toMatchObject({ code: "stream_closed" });
    await client.close();
  });

  it("rejects transport loss before terminal and distinguishes a partial prefix", async () => {
    for (const prefix of [new Uint8Array(), new Uint8Array([0, 0])]) {
      const { client, server } = await pair();
      const stream = await client.openStreamRaw(0, new Uint8Array([1]));
      await read(server);
      if (prefix.length) await server.write(prefix);
      await server.close();
      await expect(stream.next()).rejects.toMatchObject({ code: prefix.length ? "truncated_frame" : "peer_closed", delivery: "unknown" });
      stream.close(); await client.close();
    }
  });

  it("applies gates before writes and preserves exact packet access", async () => {
    const { client, server, transport } = await pair();
    await expect(client.request(typedMessage("future.gated", {}))).rejects.toMatchObject({ code: "unsupported_operation", delivery: "not_sent" });
    expect(transport.writes).toBe(0);
    await client.writeUnchecked(new Uint8Array([4, 3, 2, 1]));
    expect(await readExactly(server, 4)).toEqual(new Uint8Array([4, 3, 2, 1]));
    await client.close();
  });

  it("checked helpers require terminal responses without narrowing ordinary messages", async () => {
    const { client, server } = await pair();
    const request = { message: () => encodedMessage("future.checked", new Uint8Array([0xa0])), decode: () => 7 };
    const call = client.requestTyped(request);
    const failed = expect(call).rejects.toMatchObject({ code: "invalid_data", delivery: "unknown" });
    await read(server);
    await server.write(encodeFrame({ id: 1, flags: 0, body: body("future.checked.result", new Uint8Array([7])) }));
    await failed;
    await expect(client.requestTyped(request)).rejects.toMatchObject({ code: "ids_exhausted" });
    await client.close();
  });

  it("times out before writer admission without using the pending ID or sending later", async () => {
    const { client, server, transport } = await pair({ start: 1, endExclusive: 3 }, defaultLimits({ queuedWrites: 1 }));
    let unblock!: () => void;
    const blocked = new Promise<void>(resolve => { unblock = resolve; });
    const original = transport.write.bind(transport);
    let entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    transport.write = async bytes => { entered(); await blocked; await original(bytes); };
    const first = client.openStreamRaw(0, new Uint8Array([1]));
    await started;
    await expect(client.requestRaw(0, new Uint8Array([2]), { requestTimeoutMs: 5 }))
      .rejects.toMatchObject({ code: "timeout", delivery: "not_sent" });
    unblock();
    const stream = await first;
    expect((await read(server)).id).toBe(1);
    const next = await client.openStreamRaw(0, new Uint8Array([3]));
    expect((await read(server)).id).toBe(2);
    expect(transport.writes).toBe(2);
    stream.close(); next.close(); await client.close();
  });

  it("reserves the packet byte budget before admission and keeps queued writes owned", async () => {
    const { client, server, transport } = await pair({ start: 1, endExclusive: 4 }, defaultLimits({ maxFrameSize: 32, bufferedBytes: 36 }));
    let unblock!: () => void;
    const blocked = new Promise<void>(resolve => { unblock = resolve; });
    const original = transport.write.bind(transport);
    let entered!: () => void;
    const started = new Promise<void>(resolve => { entered = resolve; });
    transport.write = async bytes => { entered(); await blocked; await original(bytes); };
    const input = new Uint8Array(27).fill(7);
    const first = client.openStreamRaw(0, input);
    await started;
    input.fill(9);
    await expect(client.requestRaw(0, new Uint8Array([2]), { requestTimeoutMs: 5 }))
      .rejects.toMatchObject({ code: "timeout", delivery: "not_sent" });
    unblock();
    const stream = await first;
    expect((await read(server)).body).toEqual(new Uint8Array(27).fill(7));
    expect(transport.writes).toBe(1);
    stream.close(); await client.close();
  });

  it("backpressures a slow receiver and resumes other IDs after local disposal", async () => {
    const { client, server } = await pair({ start: 1, endExclusive: 3 }, defaultLimits({ queuedResponses: 1 }));
    const slow = await client.openStreamRaw(0, new Uint8Array([1]));
    const fast = await client.openStreamRaw(0, new Uint8Array([2]));
    await read(server); await read(server);
    await server.write(encodeFrame({ id: slow.id, flags: 0, body: new Uint8Array([11]) }));
    await server.write(encodeFrame({ id: slow.id, flags: 1, body: new Uint8Array([12]) }));
    await server.write(encodeFrame({ id: fast.id, flags: 1, body: new Uint8Array([21]) }));
    await expect(fast.next(5)).rejects.toMatchObject({ code: "timeout" });
    slow.close();
    expect((await fast.next(1000))?.body[0]).toBe(21);
    expect(client.isClosed()).toBe(false);
    fast.close(); await client.close();
  });

  it("shared close interrupts a reader blocked on a terminal queue", async () => {
    const { client, server } = await pair(undefined, defaultLimits({ queuedResponses: 1 }));
    const clone = client.clone();
    const stream = await client.openStreamRaw(0, new Uint8Array([1]));
    await read(server);
    await server.write(encodeFrame({ id: stream.id, flags: 0, body: new Uint8Array([1]) }));
    await server.write(encodeFrame({ id: stream.id, flags: 1, body: new Uint8Array([2]) }));
    await tick();
    await clone.close();
    expect(client.isClosed()).toBe(true);
    await expect(client.requestRaw(0, new Uint8Array())).rejects.toMatchObject({ code: "closed", delivery: "not_sent" });
    expect(await server.read(1)).toBeNull();
    stream.close(); await client.close();
  });

  it("closes transports on invalid setup, pre-aborted setup, and a late dial result", async () => {
    for (const options of [{ limits: { maxFrameSize: 0 } }, { signal: AbortSignal.abort() }]) {
      const io = transports();
      await expect(Client.connectTransport(io.client, new ExternalProtocol(), options)).rejects.toBeInstanceOf(ClientError);
      expect(io.client.closed).toBe(true);
    }
    const invalid = transports();
    await expect(Client.fromEstablished(new ExternalProtocol(), {
      transport: invalid.client, codec: new CborEnvelopeCodec(), ids: { start: 0, endExclusive: 1 }, ready: 1, limits: defaultLimits(),
    })).rejects.toMatchObject({ code: "invalid_options" });
    expect(invalid.client.closed).toBe(true);
    const io = transports();
    let dial!: (value: ByteTransport) => void;
    const call = Client.connectConnector({ connect: () => new Promise(resolve => { dial = resolve; }) }, new ExternalProtocol(), { setupTimeoutMs: 5 });
    await expect(call).rejects.toMatchObject({ code: "timeout", delivery: "not_sent" });
    dial(io.client);
    await tick();
    expect(io.client.closed).toBe(true);
  });

  it("bounds the whole setup attempt and incomplete frames while leaving idle connections alive", async () => {
    const io = transports();
    await expect(Client.connectTransport(io.client, new ExternalProtocol(), { setupTimeoutMs: 5 }))
      .rejects.toMatchObject({ code: "timeout", delivery: "not_sent" });
    expect(io.client.closed).toBe(true);
    const { client, server } = await pair(undefined, defaultLimits({ incompleteFrameTimeoutMs: 10 }));
    const stream = await client.openStreamRaw(0, new Uint8Array());
    await read(server);
    await expect(stream.next(20)).rejects.toMatchObject({ code: "timeout" });
    expect(client.isClosed()).toBe(false);
    await server.write(new Uint8Array([0]));
    await expect(stream.next(1000)).rejects.toMatchObject({ code: "timeout", delivery: "unknown" });
    expect(client.isClosed()).toBe(true);
    stream.close(); await client.close();
  });

  it("reports native decoding errors without narrowing independent raw subscriptions", async () => {
    const { client, server } = await pair({ start: 1, endExclusive: 3 });
    const native = await client.openStream(typedMessage("example.request", {}));
    const raw = await client.openStreamRaw(0, new Uint8Array([0xff]));
    await read(server); await read(server);
    await server.write(encodeFrame({ id: native.id, flags: 1, body: new Uint8Array([0xff]) }));
    await server.write(encodeFrame({ id: raw.id, flags: 1, body: new Uint8Array([0xff]) }));
    await expect(native.next()).rejects.toMatchObject({ code: "invalid_data", delivery: "unknown" });
    expect((await raw.next())?.body).toEqual(new Uint8Array([0xff]));
    native.close(); raw.close(); await client.close();
  });
});
