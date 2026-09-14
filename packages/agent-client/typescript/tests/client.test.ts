import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createHash } from "node:crypto";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { decode, encode } from "cbor-x";
import { afterEach, describe, expect, it } from "vitest";

import { connectUnix } from "../src/node.js";
import { encodedMessage, typedMessage } from "../src/message.js";
import { TransportPacket, type RawFrame } from "../src/packet.js";

const PROTOCOL_VERSION = 5;
const FLAG_TERMINAL = 1;

type Envelope = {
  v: number;
  t: string;
  p: Uint8Array;
};

const cleanup: Array<() => Promise<void>> = [];

afterEach(async () => {
  while (cleanup.length > 0) {
    await cleanup.pop()?.();
  }
});

describe("AgentClient over a local relay", () => {
  it("rejects relay id ranges with no usable ids", async () => {
    const relay = await startRelay(async (socket) => {
      // Rejection happens at the range, before the client reads a ready frame.
      // Sending more bytes races the expected disconnect on Windows pipes.
      const range = Buffer.alloc(8);
      range.writeUInt32BE(1, 4);
      await write(socket, range);
    });

    await expect(connectUnix(relay.path)).rejects.toThrow(
      "invalid client configuration",
    );
  });

  it("performs handshake and completes a typed request", async () => {
    const relay = await startRelay(async (socket) => {
      await writeHandshake(socket, 1, 1024);
      const request = await readFrame(socket);
      const envelope = decode(request.body) as Envelope;
      expect(envelope.t).toBe("core.fs.request");
      expect(decode(envelope.p)).toEqual({ op: { ping: true } });

      await writeFrame(socket, {
        id: request.id,
        flags: FLAG_TERMINAL,
        body: encodeEnvelope("core.fs.response", { ok: true }),
      });
    });

    const client = await connectUnix(relay.path);
    const response = await client.request(
      typedMessage("core.fs.request", { op: { ping: true } }),
    );

    expect(response.type).toBe("core.fs.response");
    expect(response.decodePayload()).toEqual({ ok: true });
    await client.close();
  });

  it("does not reuse a correlation id after its request completes", async () => {
    const relay = await startRelay(async (socket) => {
      await writeHandshake(socket, 1, 3);
      for (const expectedId of [1, 2]) {
        const request = await readFrame(socket);
        expect(request.id).toBe(expectedId);
        await writeFrame(socket, {
          id: request.id,
          flags: FLAG_TERMINAL,
          body: encodeEnvelope("core.fs.response", { ok: true }),
        });
      }
      // Keep the transport open so exhaustion, rather than EOF, is observed.
      await new Promise<void>(resolve => socket.once("end", resolve));
    });

    const client = await connectUnix(relay.path);
    const request = typedMessage("core.fs.request", { op: { ping: true } });
    await expect(client.request(request)).resolves.toBeDefined();
    await expect(client.request(request)).resolves.toBeDefined();
    await expect(client.request(request)).rejects.toThrow(
      "correlation ID range exhausted",
    );
    await client.close();
  });

  it("routes stream frames and allows follow-up sends", async () => {
    const relay = await startRelay(async (socket) => {
      await writeHandshake(socket, 10, 1024);
      const open = await readFrame(socket);
      const openEnvelope = decode(open.body) as Envelope;
      expect(open.id).toBe(10);
      expect(openEnvelope.t).toBe("core.exec.request");

      await writeFrame(socket, {
        id: open.id,
        flags: 0,
        body: encodeEnvelope("core.exec.started", { pid: 42 }),
      });

      const stdin = await readFrame(socket);
      const stdinEnvelope = decode(stdin.body) as Envelope;
      expect(stdin.id).toBe(open.id);
      expect(stdinEnvelope.t).toBe("core.exec.stdin");
      expect(decode(stdinEnvelope.p)).toEqual({
        data: Uint8Array.from([104, 105]),
      });

      await writeFrame(socket, {
        id: open.id,
        flags: FLAG_TERMINAL,
        body: encodeEnvelope("core.exec.exited", { code: 0 }),
      });
    });

    const client = await connectUnix(relay.path);
    const stream = await client.openStream(
      typedMessage("core.exec.request", { cmd: "cat" }),
    );

    const started = await stream.next();
    expect(started?.type).toBe("core.exec.started");

    await stream.send(
      typedMessage("core.exec.stdin", { data: Uint8Array.from([104, 105]) }),
    );

    const exited = await stream.next();
    expect(exited?.type).toBe("core.exec.exited");
    expect(exited?.decodePayload()).toEqual({ code: 0 });
    expect(await stream.next()).toBeNull();
    await client.close();
  });

  it("does not lose a frame after a timed out stream read", async () => {
    const relay = await startRelay(async (socket) => {
      await writeHandshake(socket, 10, 1024);
      const open = await readFrame(socket);
      await new Promise((resolve) => setTimeout(resolve, 50));
      await writeFrame(socket, {
        id: open.id,
        flags: 0,
        body: encodeEnvelope("core.exec.started", { pid: 7 }),
      });
    });

    const client = await connectUnix(relay.path);
    const stream = await client.openStream(
      typedMessage("core.exec.request", { cmd: "sleep" }),
    );

    await expect(stream.next(5)).rejects.toThrow("timed out");
    const frame = await stream.next(1_000);
    expect(frame?.type).toBe("core.exec.started");
    expect(frame?.decodePayload()).toEqual({ pid: 7 });
    await client.close();
  });

  it("wakes stream reads after local stream close", async () => {
    const relay = await startRelay(async (socket) => {
      await writeHandshake(socket, 10, 1024);
      await readFrame(socket);
      await new Promise((resolve) => setTimeout(resolve, 100));
    });

    const client = await connectUnix(relay.path);
    const stream = await client.openStream(
      typedMessage("core.exec.request", { cmd: "cat" }),
    );
    const next = stream.next();
    await stream.close();
    await expect(next).resolves.toBeNull();
    await expect(stream.next()).resolves.toBeNull();
    await client.close();
  });

  it("rejects EOF in the middle of a response frame", async () => {
    const relay = await startRelay(async (socket) => {
      await writeHandshake(socket, 10, 1024);
      await readFrame(socket);
      const len = Buffer.alloc(4);
      len.writeUInt32BE(64, 0);
      await write(socket, len);
      socket.end();
    });

    const client = await connectUnix(relay.path);
    await expect(
      client.request(typedMessage("core.fs.request", { op: { ping: true } })),
    ).rejects.toThrow("transport closed inside a frame");
    await client.close();
  });

  it("surfaces core.error frames as ordinary terminal responses", async () => {
    const relay = await startRelay(async (socket) => {
      await writeHandshake(socket, 100, 200);
      const request = await readFrame(socket);
      await writeFrame(socket, {
        id: request.id,
        flags: FLAG_TERMINAL,
        body: encodeEnvelope("core.error", {
          kind: "invalid_payload",
          message: "decode payload for core.fs.request: bad cbor",
          offending_type: "core.fs.request",
        }),
      });
    });

    const client = await connectUnix(relay.path);
    const response = await client.request(
      typedMessage("core.fs.request", { malformed: true }),
    );

    expect(response.type).toBe("core.error");
    expect(response.decodePayload()).toEqual({
      kind: "invalid_payload",
      message: "decode payload for core.fs.request: bad cbor",
      offending_type: "core.fs.request",
    });
    await client.close();
  });

  it("preserves byte fixtures generated by the pinned predecessor encoder", async () => {
    const base = new URL("../../../protocol-fixtures/agent-ts-v5/", import.meta.url);
    const fixture = JSON.parse(await readFile(new URL("fixtures.json", base), "utf8")) as {
      sourceSha256: string; cases: Array<{ name: string; type: string; flags: number; envelopeHex: string }>;
    };
    const source = await readFile(new URL("message.ts", base));
    expect(createHash("sha256").update(source).digest("hex")).toBe(fixture.sourceSha256);
    const messages = [
      typedMessage("core.exec.request", { cmd: "cat", args: [] }),
      typedMessage("core.exec.stdin", { data: new Uint8Array([104, 105]) }),
      encodedMessage("core.exec.stdin", new Uint8Array([0xff, 0, 0x18, 0x20])),
      encodedMessage("core.fs.request", Uint8Array.from(Buffer.from("a1626f70a16470696e67f5", "hex"))),
      typedMessage("core.shutdown", {}),
    ];
    const relay = await startRelay(async socket => {
      await writeHandshake(socket, 1, 1024);
      for (const expected of fixture.cases) {
        const frame = await readFrame(socket);
        expect(frame.flags, expected.name).toBe(expected.flags);
        expect(Buffer.from(frame.body).toString("hex"), expected.name).toBe(expected.envelopeHex);
        await writeFrame(socket, { ...frame, flags: 1 });
      }
    });
    const client = await connectUnix(relay.path);
    for (const message of messages) expect((await client.request(message)).type).toBe(message.type);
    await client.close();
  });

  it("supports legacy pre-0.5 relay prologues and gates newer operations before sending", async () => {
    for (const offset of [0, 0x40000000]) {
      const relay = await startRelay(async socket => {
        const prefix = Buffer.alloc(4);
        prefix.writeUInt32BE(offset);
        await write(socket, prefix);
        await writeFrame(socket, { id: 0, flags: 0, body: encode({ v: 1, t: "core.ready", p: encode({ boot_time_ns: 1 }) }) });
        const request = await readFrame(socket);
        expect(request.id).toBe(offset + 1);
        expect(request.flags).toBe(2);
        expect(decode(request.body)).toMatchObject({ v: 1, t: "core.exec.request" });
        await writeFrame(socket, { id: request.id, flags: 1, body: encode({ v: 1, t: "core.exec.exited", p: encode({ code: 0 }) }) });
      });
      const client = await connectUnix(relay.path);
      expect(client.ready.wireFormat).toBe("legacy_v1");
      expect(client.ready.negotiatedVersion).toBe(1);
      expect(client.ready.agentVersion).toBe("");
      await expect(client.request(typedMessage("core.fs.request", {})))
        .rejects.toMatchObject({ code: "unsupported_operation", delivery: "not_sent" });
      expect((await client.request(typedMessage("core.exec.request", { cmd: "true" }))).decodePayload()).toEqual({ code: 0 });
      await client.close();
    }
  });

  it("keeps current envelopes at generation five when negotiating a lower feature generation", async () => {
    const relay = await startRelay(async socket => {
      await writeHandshake(socket, 10, 100, 1);
      const request = await readFrame(socket);
      expect(decode(request.body)).toMatchObject({ v: 5, t: "core.exec.request" });
      await writeFrame(socket, { ...request, flags: 1 });
    });
    const client = await connectUnix(relay.path);
    expect(client.ready.wireFormat).toBe("current");
    expect(client.ready.negotiatedVersion).toBe(1);
    await expect(client.request(typedMessage("core.tcp.connect", {}))).rejects.toMatchObject({ code: "unsupported_operation" });
    await client.request(typedMessage("core.exec.request", { cmd: "true" }));
    await client.close();
  });

  it("offers raw streams, exact packet writes, and explicit ID sends through the same client", async () => {
    const relay = await startRelay(async socket => {
      await writeHandshake(socket, 10, 100);
      const request = await readFrame(socket);
      expect(request.body).toEqual(new Uint8Array([0xff, 1]));
      const followup = await readFrame(socket);
      expect(followup).toMatchObject({ id: request.id, flags: 7, body: new Uint8Array([0xff, 2]) });
      const packet = await readFrame(socket);
      expect(packet).toMatchObject({ id: 99, flags: 8, body: new Uint8Array([0xff, 3]) });
      await writeFrame(socket, { id: request.id, flags: 1, body: new Uint8Array([0xff, 4]) });
    });
    const client = await connectUnix(relay.path);
    const stream = await client.openStreamRaw(0, new Uint8Array([0xff, 1]));
    await client.sendRaw(stream.id, 7, new Uint8Array([0xff, 2]));
    await client.writeUnchecked(TransportPacket.fromFrame({ id: 99, flags: 8, body: new Uint8Array([0xff, 3]) }));
    expect((await stream.next())?.body).toEqual(new Uint8Array([0xff, 4]));
    expect(await stream.next()).toBeNull();
    stream.close(); await client.close();
  });

  it("retains unknown message names and complete envelopes on native responses", async () => {
    const reply = Uint8Array.from(encode({ v: 5, t: "extension.unknown", p: new Uint8Array([0xff, 0, 1]), future: { n: 7 } }));
    const relay = await startRelay(async socket => {
      await writeHandshake(socket, 10, 100);
      const request = await readFrame(socket);
      expect(request.flags).toBe(0);
      await writeFrame(socket, { id: request.id, flags: 1, body: reply });
    });
    const client = await connectUnix(relay.path);
    const frame = await client.request(encodedMessage("extension.unknown", new Uint8Array([0xff])));
    expect(frame.type).toBe("extension.unknown");
    expect(Array.from(frame.raw.body)).toEqual(Array.from(reply));
    expect(frame.payload).toEqual(new Uint8Array([0xff, 0, 1]));
    await client.close();
  });
});

async function startRelay(
  handler: (socket: net.Socket) => Promise<void>,
): Promise<{ path: string }> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "msb-agent-client-"));
  // Node uses named pipes for local IPC on Windows.
  const sockPath = process.platform === "win32"
    ? `\\\\.\\pipe\\msb-agent-test-${path.basename(dir)}`
    : path.join(dir, "agent.sock");
  const sockets = new Set<net.Socket>();
  const failures: unknown[] = [];
  const server = net.createServer((socket) => {
    sockets.add(socket);
    socket.on("error", () => {});
    socket.once("close", () => sockets.delete(socket));
    handler(socket)
      .catch((error: unknown) => { failures.push(error); socket.destroy(); })
      .finally(() => socket.end());
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(sockPath, resolve);
  });

  cleanup.push(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
    expect(failures).toEqual([]);
  });

  return { path: sockPath };
}

async function writeHandshake(
  socket: net.Socket,
  idMin: number,
  idMax: number,
  generation = PROTOCOL_VERSION,
): Promise<void> {
  const range = Buffer.alloc(8);
  range.writeUInt32BE(idMin, 0);
  range.writeUInt32BE(idMax, 4);
  await write(socket, range);
  await writeFrame(socket, {
    id: 0,
    flags: 0,
    body: encode({ v: generation, t: "core.ready", p: encode({
      boot_time_ns: 1,
      init_time_ns: 2,
      ready_time_ns: 3,
      agent_version: "test",
    }) }),
  });
}

async function readFrame(socket: net.Socket): Promise<RawFrame> {
  const len = await readExact(socket, 4);
  const frameLength = len.readUInt32BE(0);
  const rest = await readExact(socket, frameLength);
  const packet = new Uint8Array(4 + frameLength);
  packet.set(len, 0);
  packet.set(rest, 4);
  return TransportPacket.fromBytes(packet).rawFrame();
}

async function writeFrame(socket: net.Socket, frame: RawFrame): Promise<void> {
  await write(socket, Buffer.from(TransportPacket.fromFrame(frame).bytes));
}

function encodeEnvelope(type: string, payload: unknown): Uint8Array {
  return encode({
    v: PROTOCOL_VERSION,
    t: type,
    p: encode(payload),
  });
}

async function readExact(socket: net.Socket, length: number): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let received = 0;

  while (received < length) {
    const chunk = socket.read(length - received) as Buffer | null;
    if (chunk !== null) {
      chunks.push(chunk);
      received += chunk.byteLength;
      continue;
    }

    await new Promise<void>((resolve, reject) => {
      const cleanup = () => {
        socket.removeListener("readable", ready);
        socket.removeListener("error", fail);
        socket.removeListener("end", ended);
      };
      const ready = () => { cleanup(); resolve(); };
      const fail = (error: Error) => { cleanup(); reject(error); };
      const ended = () => fail(new Error("socket ended"));
      socket.once("readable", ready);
      socket.once("error", fail);
      socket.once("end", ended);
    });
  }

  return Buffer.concat(chunks, length);
}

async function write(socket: net.Socket, bytes: Buffer): Promise<void> {
  await new Promise<void>((resolve, reject) => {
    socket.write(bytes, (error) => {
      if (error) reject(error);
      else resolve();
    });
  });
}
