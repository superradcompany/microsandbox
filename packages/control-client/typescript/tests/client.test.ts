import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { afterEach, expect, it } from "vitest";
import {
  ClientError, decodeEnvelope, encodeEnvelope, encodeFrame, encodeRecord, readRawFrame,
  type ByteTransport, type RawFrame,
} from "@microsandbox/protocol-client";
import { ControlClient, GetCapabilities, GetMemoryState, decodeHello, encodedMessage, typedMessage } from "../src/index.js";
import { connectFramedControl } from "../src/node.js";

const cleanup: Array<() => Promise<void>> = [];
afterEach(async () => { while (cleanup.length) await cleanup.pop()!(); });

async function server(handler: (transport: ByteTransport) => Promise<void>): Promise<string> {
  const directory = await mkdtemp(path.join(os.tmpdir(), "msb-ctl-ts-"));
  const endpoint = process.platform === "win32" ? `\\\\.\\pipe\\msb-control-test-${path.basename(directory)}` : path.join(directory, "control.sock");
  const sockets = new Set<net.Socket>(), failures: unknown[] = [];
  const listener = net.createServer(socket => {
    sockets.add(socket); socket.on("error", () => {}); socket.once("close", () => sockets.delete(socket));
    const transport: ByteTransport = {
      async read(maxBytes) {
        for (;;) {
          const size = Math.min(maxBytes, socket.readableLength);
          if (size) return socket.read(size) as Uint8Array;
          if (socket.readableEnded || socket.destroyed) return null;
          await new Promise<void>(resolve => {
            const wake = () => { for (const name of ["readable", "end", "close", "error"]) socket.removeListener(name, wake); resolve(); };
            for (const name of ["readable", "end", "close", "error"]) socket.once(name, wake);
          });
        }
      },
      async write(bytes) { await new Promise<void>((resolve, reject) => socket.write(bytes, error => error ? reject(error) : resolve())); },
      async close() { socket.destroy(); },
    };
    void handler(transport).catch(error => { failures.push(error); socket.destroy(); });
  });
  await new Promise<void>((resolve, reject) => { listener.once("error", reject); listener.listen(endpoint, resolve); });
  cleanup.push(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>(resolve => listener.close(() => resolve()));
    await rm(directory, { recursive: true, force: true });
    expect(failures).toEqual([]);
  });
  return endpoint;
}

const packet = (id: number, type: string, payload: unknown, flags = 1, generation = 1) => encodeFrame({ id, flags, body: encodeEnvelope({ v: generation, t: type, p: encodeRecord(payload) }) });
const welcome = { protocol: "msb.control", generation: 1, max_frame_size: 4096, max_in_flight: 4 };
async function opening(transport: ByteTransport): Promise<void> {
  const raw = (await readRawFrame(transport))!.frame;
  expect([raw.id, raw.flags]).toEqual([0, 0]);
  const envelope = decodeEnvelope(raw.body);
  expect([envelope.v, envelope.t]).toEqual([1, "control.hello"]);
  expect(decodeHello(envelope.p)).toMatchObject({ max_in_flight: 64, protocol: "msb.control" });
}

it("sends a direct hello, preserves fragmented welcome bytes, and multiplexes one connection", async () => {
  const endpoint = await server(async transport => {
    await opening(transport);
    const bytes = packet(0, "control.welcome", { ...welcome, extension: true });
    for (const byte of bytes) await transport.write(new Uint8Array([byte]));
    const first = (await readRawFrame(transport))!.frame, second = (await readRawFrame(transport))!.frame;
    expect(first.id).not.toBe(second.id);
    await transport.write(packet(second.id, "control.memory.state", { boot_mib: 1, target_mib: 2, current_mib: 3, max_mib: 0xffffffffffffffffn }));
    await transport.write(packet(first.id, "control.capabilities.result", { cpu_resize: true, memory_resize: true, secrets_update: false }));
  });
  const client = await connectFramedControl(endpoint);
  cleanup.push(() => client.close());
  expect(client.ready.frame.decodePayload()).toMatchObject({ extension: true });
  expect(client.ready.welcome).toEqual(welcome);
  const [caps, memory] = await Promise.all([client.requestTyped(new GetCapabilities()), client.requestTyped(new GetMemoryState())]);
  expect(caps.cpu_resize).toBe(true); expect(memory.max_mib).toBe(0xffffffffffffffffn);
  await client.clone().close(); expect(client.isClosed()).toBe(true);
});

it("rejects invalid or over-offer welcomes and never sends application bytes afterward", async () => {
  const cases = [
    packet(1, "control.welcome", welcome), packet(0, "control.welcome", welcome, 0),
    packet(0, "control.welcome", welcome, 1, 2), packet(0, "wrong", welcome),
    ...[{ protocol: "wrong" }, { generation: 2 }, { max_frame_size: 4095 }, { max_in_flight: 65 }, { max_in_flight: 0 }].map(overrides => packet(0, "control.welcome", { ...welcome, ...overrides })),
  ];
  for (const bytes of cases) {
    let afterHello = false;
    const endpoint = await server(async transport => { await opening(transport); await transport.write(bytes); afterHello = (await transport.read(1)) !== null; });
    await expect(connectFramedControl(endpoint)).rejects.toMatchObject({ code: "invalid_data", delivery: "not_sent" });
    expect(afterHello).toBe(false);
  }
});

it("bounds the opening allocation from its prefix and preserves explicit refusal", async () => {
  for (const [bytes, code] of [
    [new Uint8Array([0x7f, 0xff, 0xff, 0xff]), "invalid_data"],
    [packet(0, "control.error", { code: "unsupported_generation", message: "upgrade", effect: "none" }), "unsupported_operation"],
  ] as const) {
    const endpoint = await server(async transport => { await opening(transport); await transport.write(bytes); });
    await expect(connectFramedControl(endpoint, { setupTimeoutMs: 500 })).rejects.toMatchObject({ code, delivery: "not_sent" });
  }
});

it("keeps native unknown replies, opaque payloads, raw IDs and exact packet writes available", async () => {
  const rawReply: RawFrame = { id: 1, flags: 1, body: new Uint8Array([0xff, 0, 7]) };
  const endpoint = await server(async transport => {
    await opening(transport); await transport.write(packet(0, "control.welcome", welcome));
    const native = (await readRawFrame(transport))!.frame;
    expect(decodeEnvelope(native.body)).toMatchObject({ t: "extension", p: new Uint8Array([0xff]) });
    await transport.write(encodeFrame({ id: native.id, flags: 1, body: encodeRecord({ v: 1, t: "future", p: new Uint8Array([0xff]), extra: 7 }) }));
    const start = (await readRawFrame(transport))!.frame;
    expect(start.body).toEqual(new Uint8Array([0xff, 1]));
    const followup = (await readRawFrame(transport))!.frame;
    expect(followup).toEqual({ id: start.id, flags: 7, body: new Uint8Array([0xff, 2]) });
    expect((await readRawFrame(transport))!.frame).toEqual({ id: 123, flags: 8, body: new Uint8Array([0xff, 3]) });
    await transport.write(encodeFrame({ ...rawReply, id: start.id }));
  });
  const client = await connectFramedControl(endpoint); cleanup.push(() => client.close());
  await expect(client.request(typedMessage("control.hello", {}))).rejects.toMatchObject({ code: "unsupported_operation", delivery: "not_sent" });
  const response = await client.request(encodedMessage("extension", new Uint8Array([0xff])));
  expect(response.type).toBe("future"); expect(response.payload).toEqual(new Uint8Array([0xff]));
  const stream = await client.openStreamRaw(0, new Uint8Array([0xff, 1]));
  const { sender, receiver } = stream.split();
  await client.sendRaw(sender.id, 7, new Uint8Array([0xff, 2]));
  await client.writeUnchecked(encodeFrame({ id: 123, flags: 8, body: new Uint8Array([0xff, 3]) }));
  expect((await receiver.next())!.body).toEqual(rawReply.body);
  receiver.close(); sender.close();
});

it("uses one setup deadline and closes a transport whose welcome never arrives", async () => {
  let closed = false, writes = 0;
  const transport: ByteTransport = {
    async read() { return await new Promise<null>(() => {}); },
    async write() { writes++; }, async close() { closed = true; },
  };
  await expect(ControlClient.connectTransport(transport, { setupTimeoutMs: 20 })).rejects.toMatchObject({ code: "timeout", delivery: "not_sent" });
  expect(writes).toBe(1); expect(closed).toBe(true);
  await expect(ControlClient.connectTransport(transport, { limits: { maxFrameSize: 128 } })).rejects.toBeInstanceOf(ClientError);
  expect(writes).toBe(1);
});
