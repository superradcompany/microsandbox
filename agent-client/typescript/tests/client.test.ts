import { mkdtemp, rm } from "node:fs/promises";
import net from "node:net";
import os from "node:os";
import path from "node:path";

import { decode, encode } from "cbor-x";
import { afterEach, describe, expect, it } from "vitest";

import { connectUnix } from "../src/node.js";
import { typedMessage } from "../src/message.js";
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

describe("AgentClient over a Unix socket relay", () => {
  it("rejects relay id ranges with no usable ids", async () => {
    const relay = await startRelay(async (socket) => {
      await writeHandshake(socket, 0, 1);
    });

    await expect(connectUnix(relay.path)).rejects.toThrow(
      "no usable nonzero ids",
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
    ).rejects.toThrow("transport closed before enough bytes");
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
});

async function startRelay(
  handler: (socket: net.Socket) => Promise<void>,
): Promise<{ path: string }> {
  const dir = await mkdtemp(path.join(os.tmpdir(), "msb-agent-client-"));
  const sockPath = path.join(dir, "agent.sock");
  const server = net.createServer((socket) => {
    handler(socket)
      .catch((error) => socket.destroy(error))
      .finally(() => socket.end());
  });

  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen(sockPath, resolve);
  });

  cleanup.push(async () => {
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await rm(dir, { recursive: true, force: true });
  });

  return { path: sockPath };
}

async function writeHandshake(
  socket: net.Socket,
  idMin: number,
  idMax: number,
): Promise<void> {
  const range = Buffer.alloc(8);
  range.writeUInt32BE(idMin, 0);
  range.writeUInt32BE(idMax, 4);
  await write(socket, range);
  await writeFrame(socket, {
    id: 0,
    flags: 0,
    body: encodeEnvelope("core.ready", {
      boot_time_ns: 1,
      init_time_ns: 2,
      ready_time_ns: 3,
      agent_version: "test",
    }),
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
      socket.once("readable", resolve);
      socket.once("error", reject);
      socket.once("end", () => reject(new Error("socket ended")));
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
