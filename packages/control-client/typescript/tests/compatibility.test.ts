import { inspect } from "node:util";
import { expect, it } from "vitest";
import {
  ClientError, decodeEnvelope, encodeEnvelope, encodeFrame, encodeRecord,
  type ByteTransport, type ConnectContext, type Connector,
} from "@microsandbox/protocol-client";
import {
  ControlClientError, ControlConnection, GetCapabilities, GetCpuState, GetMemoryState,
  JsonControlClient, JsonNumber, JsonReply, MiB, SetCpuTarget, SetMemoryTarget, UpdateSecrets,
  encodedMessage, typedMessage, type VerifiedControlConnector,
} from "../src/index.js";

const bytes = (text: string) => new TextEncoder().encode(text);
const text = (bytes: Uint8Array) => new TextDecoder().decode(bytes);
const caps = { cpu_resize: true, memory_resize: true, secrets_update: true };
const legacyCaps = JSON.stringify({ ok: true, capabilities: caps }) + "\n";
const cborCaps = JSON.stringify({ ok: true, capabilities: caps, control_protocols: ["json", "cbor"] }) + "\n";
const cborOnlyCaps = JSON.stringify({ ok: true, capabilities: caps, control_protocols: ["cbor"] }) + "\n";
const memory = '{"ok":true,"memory":{"boot_mib":1,"target_mib":9007199254740993,"current_mib":0,"max_mib":18446744073709551615}}\n';
const cpu = '{"ok":true,"cpu":{"possible":4,"requested_online":2,"actual_online":1,"enforced":1}}\n';
const packet = (id: number, type: string, payload: unknown) => encodeFrame({ id, flags: 1, body: encodeEnvelope({ v: 1, t: type, p: encodeRecord(payload) }) });

class Transport implements ByteTransport {
  closed = false;
  writes = 0;
  private chunks: Uint8Array[] = [];
  private wake?: () => void;
  constructor(private readonly handle: (bytes: Uint8Array, transport: Transport) => void | Promise<void>) {}
  feed(chunk: Uint8Array): void { this.chunks.push(chunk); this.wake?.(); }
  async read(max: number): Promise<Uint8Array | null> {
    while (!this.chunks.length) {
      if (this.closed) return null;
      await new Promise<void>(resolve => { this.wake = resolve; });
      this.wake = undefined;
    }
    const chunk = this.chunks.shift()!, part = chunk.slice(0, max);
    if (chunk.length > max) this.chunks.unshift(chunk.subarray(max));
    return part;
  }
  async write(bytes: Uint8Array): Promise<void> {
    if (this.closed) throw new Error("fixture is closed");
    this.writes++;
    await this.handle(bytes, this);
  }
  async close(): Promise<void> { this.closed = true; this.wake?.(); }
}

class Dialer implements Connector {
  readonly transports: Transport[] = [];
  constructor(readonly make: (index: number) => Transport) {}
  async connect(_context: ConnectContext): Promise<ByteTransport> {
    const transport = this.make(this.transports.length);
    this.transports.push(transport);
    return transport;
  }
}

function jsonDialer(replies: readonly string[], onWrite?: (line: string) => void): Dialer {
  return new Dialer(index => new Transport(async (data, transport) => {
    onWrite?.(text(data));
    transport.feed(bytes(replies[index]!));
    await transport.close();
  }));
}
function framed(): Transport {
  return new Transport((data, transport) => {
    const id = new DataView(data.buffer, data.byteOffset).getUint32(4);
    const envelope = decodeEnvelope(data.subarray(9));
    if (envelope.t === "control.hello") {
      transport.feed(packet(0, "control.welcome", { protocol: "msb.control", generation: 1, max_frame_size: 4096, max_in_flight: 4 }));
    } else transport.feed(packet(id, "control.capabilities.result", caps));
  });
}

it("retains original JSON, unknown numeric tokens, strings, and prototype-like keys", () => {
  const raw = bytes(' \t{"ok":true,"future":9007199254740993000,"huge":1e9999,"__proto__":{"v":1},"escape":"𝄞\\n"} \r\n');
  const reply = new JsonReply(raw);
  expect(reply.raw).toEqual(raw);
  expect((reply.value.get("future") as JsonNumber).token).toBe("9007199254740993000");
  expect((reply.value.get("huge") as JsonNumber).token).toBe("1e9999");
  expect(reply.value.get("__proto__")).toBeInstanceOf(Map);
  expect(reply.value.get("escape")).toBe("𝄞\n");
  expect(inspect(reply)).not.toContain("9007199254740993000");
  expect(new GetMemoryState().decodeJson(new JsonReply(bytes(memory)))).toEqual({ boot_mib: 1n, target_mib: 9007199254740993n, current_mib: 0n, max_mib: 0xffffffffffffffffn });
});

it("rejects duplicate decoded keys at every depth, malformed JSON, invalid UTF-8 and noninteger observations", () => {
  for (const malformed of [
    '{"ok":true,"ok":false}', '{"ok":true,"x":{"a":1,"\\u0061":2}}',
    '{"x":[{"a":1,"a":2}]}', '{"x":01}', '{"x":NaN}', '{"x":1,}', '{"x":"\\ud800"}',
    '{"x":"\\udc00"}', '{"x":1} trailing', "[]", "\ufeff{}", '{"x":' + "[".repeat(130) + "0" + "]".repeat(130) + "}",
  ]) expect(() => new JsonReply(bytes(malformed))).toThrow(ClientError);
  expect(() => new JsonReply(Uint8Array.of(123, 34, 120, 34, 58, 34, 0xff, 34, 125))).toThrow(ClientError);
  for (const token of ["-0", "-1", "1.0", "1e0", "18446744073709551616", '"2"']) {
    const reply = new JsonReply(bytes(memory.replace("9007199254740993", token)));
    expect(() => new GetMemoryState().decodeJson(reply)).toThrow(expect.objectContaining({ code: "invalid_json_response", response: reply }));
  }
});

it("explicit JSON is inert, maps all six operations, and writes full-width integer tokens", async () => {
  const writes: string[] = [];
  const dialer = jsonDialer([legacyCaps, memory, memory, cpu, cpu, '{"ok":true}\n'], line => writes.push(line));
  const client = JsonControlClient.fromConnector(dialer);
  expect(dialer.transports).toHaveLength(0);
  expect(await client.requestTyped(new GetCapabilities())).toEqual(caps);
  expect((await client.requestTyped(new GetMemoryState())).max_mib).toBe(0xffffffffffffffffn);
  await client.requestTyped(new SetMemoryTarget(0xffffffffffffffffn));
  await client.requestTyped(new GetCpuState());
  await client.requestTyped(new SetCpuTarget(2));
  expect(await client.requestTyped(new UpdateSecrets([]))).toEqual({ outcome: "complete", applied_count: 0 });
  expect(writes).toEqual([
    '{"op":"capabilities"}\n', '{"op":"memory_state"}\n',
    '{"op":"memory_target","total_mib":18446744073709551615}\n',
    '{"op":"cpu_state"}\n', '{"op":"cpu_target","online":2}\n', '{"op":"secrets_update","changes":[]}\n',
  ]);
  expect(dialer.transports.every(transport => transport.closed)).toBe(true);
  expect(client.isClosed()).toBe(false);
  await client.clone().close();
  await expect(client.requestTyped(new GetCapabilities())).rejects.toMatchObject({ code: "closed", delivery: "not_sent" });
  expect(dialer.transports).toHaveLength(6);
});

it("ordinary JSON keeps ok:false and checked failures retain unknown batch progress", async () => {
  const raw = '{"ok":false,"error":"dummy-value: arbitrary future diagnostic","extension":18446744073709551616}\n';
  const client = JsonControlClient.fromConnector(jsonDialer([raw, raw]));
  const reply = await client.request(typedMessage("control.secrets.update", { changes: [] }));
  expect(text(reply.raw)).toBe(raw);
  expect(reply).not.toHaveProperty("id");
  const error = await client.requestTyped(new UpdateSecrets([])).catch(error => error);
  expect(error).toMatchObject({ code: "legacy_remote", delivery: "unknown", response: expect.any(JsonReply) });
  expect(error).not.toHaveProperty("applied_count");
  expect(inspect(error)).not.toContain("dummy-value");
  expect(client.isClosed()).toBe(false);
  await client.close();
});

it("encoded, unknown and invalid native JSON operations fail before dialing", async () => {
  const dialer = jsonDialer([]);
  const client = JsonControlClient.fromConnector(dialer);
  for (const message of [encodedMessage("control.capabilities", Uint8Array.of(0xa0)), typedMessage("future.op", {})]) {
    await expect(Promise.resolve().then(() => client.request(message))).rejects.toMatchObject({ code: "unsupported_mode", delivery: "not_sent" });
  }
  await expect(Promise.resolve().then(() => client.request(typedMessage("control.cpu.target", { online: "2" })))).rejects.toMatchObject({ code: "invalid_data" });
  expect(dialer.transports).toHaveLength(0);
});

it("automatic JSON rechecks without identity; verified owners reuse discovery on fresh streams", async () => {
  for (const verified of [false, true]) {
    let checks = 0;
    const writes: string[] = [];
    const dialer = jsonDialer(verified ? [legacyCaps, memory, cpu] : [legacyCaps, legacyCaps, memory, legacyCaps, cpu], line => writes.push(line));
    const verifier: VerifiedControlConnector = { connect: context => dialer.connect(context), async verifySession() { checks++; } };
    const client = verified ? await ControlConnection.connectVerifiedConnector(verifier) : await ControlConnection.connectConnector(dialer);
    expect(client.mode).toBe("json");
    expect(() => client.framed()).toThrow(expect.objectContaining({ code: "unsupported_mode", delivery: "not_sent" }));
    await client.requestTyped(new GetMemoryState());
    expect((await client.request(typedMessage("control.cpu.state", {}))).kind).toBe("json");
    expect(dialer.transports).toHaveLength(verified ? 3 : 5);
    expect(writes.filter(line => line.includes('"capabilities"'))).toHaveLength(verified ? 1 : 3);
    expect(checks).toBe(verified ? 3 : 0);
    await client.close();
  }
});

// Read-only JSON discovery outlives JSON operations under the retirement contract.
it.each([{ name: "json+cbor", reply: cborCaps }, { name: "cbor only", reply: cborOnlyCaps }])("CBOR discovery is once, uses a fresh connection, and keeps the generic low-level API ($name)", async ({ reply }) => {
  const dialer = new Dialer(index => index === 0 ? new Transport((data, transport) => {
    expect(text(data)).toBe('{"op":"capabilities"}\n');
    transport.feed(bytes(reply));
  }) : framed());
  const client = await ControlConnection.connectConnector(dialer);
  expect(client.mode).toBe("cbor");
  expect(dialer.transports[0]!.closed).toBe(true);
  expect(await client.requestTyped(new GetCapabilities())).toEqual(caps);
  expect((await client.request(typedMessage("control.capabilities", {}))).kind).toBe("cbor");
  const raw = await client.framed().requestRaw(0, encodeEnvelope({ v: 1, t: "control.capabilities", p: encodeRecord({}) }));
  expect(decodeEnvelope(raw.body).t).toBe("control.capabilities.result");
  expect(dialer.transports).toHaveLength(2);
  expect(dialer.transports.map(transport => transport.writes)).toEqual([1, 4]);
  await client.clone().close();
  expect(client.isClosed()).toBe(true);
});

it("never guesses legacy support from malformed, negative or unsupported discovery", async () => {
  for (const raw of [
    '{"ok":false,"error":"unknown operation capabilities"}\n',
    '{"ok":true}\n', legacyCaps.replace("true", '"true"'),
    JSON.stringify({ ok: true, capabilities: caps, error: "conflict" }),
    ...[null, [], ["future"], ["json", 1], "json"].map(control_protocols => JSON.stringify({ ok: true, capabilities: caps, control_protocols })),
    '{"ok":true,"ok":true}\n',
  ]) {
    const dialer = jsonDialer([raw]);
    await expect(ControlConnection.connectConnector(dialer)).rejects.toBeInstanceOf(ClientError);
    expect(dialer.transports).toHaveLength(1);
    expect(dialer.transports[0]!.closed).toBe(true);
  }
});

it.each([{ name: "json+cbor", reply: cborCaps }, { name: "cbor only", reply: cborOnlyCaps }])("a failed welcome after positive discovery closes without downgrading ($name)", async ({ reply }) => {
  const dialer = new Dialer(index => new Transport((data, transport) => {
    if (index === 0) {
      expect(text(data)).toBe('{"op":"capabilities"}\n');
      transport.feed(bytes(reply));
    } else {
      expect(decodeEnvelope(data.subarray(9)).t).toBe("control.hello");
      transport.feed(packet(0, "wrong.welcome", {}));
    }
  }));
  await expect(ControlConnection.connectConnector(dialer)).rejects.toMatchObject({ code: "invalid_data", delivery: "not_sent" });
  expect(dialer.transports).toHaveLength(2);
  expect(dialer.transports.map(transport => transport.writes)).toEqual([1, 1]);
  expect(dialer.transports.every(transport => transport.closed)).toBe(true);
});

it("detects changed JSON format and connected peer identity before mutation", async () => {
  const dialer = jsonDialer([legacyCaps, cborCaps]);
  const client = await ControlConnection.connectConnector(dialer);
  await expect(client.requestTyped(new SetMemoryTarget(MiB(512)))).rejects.toMatchObject({ code: "runtime_changed", delivery: "not_sent" });
  expect(client.isClosed()).toBe(true);
  expect(dialer.transports).toHaveLength(2);
  for (const advertised of [legacyCaps, cborCaps]) {
    const peer = jsonDialer([advertised]);
    let dials = 0;
    const verified: VerifiedControlConnector = {
      async connect(context) {
        if (++dials > 1) throw new ControlClientError("runtime_changed");
        return peer.connect(context);
      },
      async verifySession() {},
    };
    if (advertised === cborCaps) await expect(ControlConnection.connectVerifiedConnector(verified)).rejects.toMatchObject({ code: "runtime_changed", delivery: "not_sent" });
    else {
      const connection = await ControlConnection.connectVerifiedConnector(verified);
      await expect(connection.requestTyped(new SetCpuTarget(2))).rejects.toMatchObject({ code: "runtime_changed", delivery: "not_sent" });
      expect(connection.isClosed()).toBe(true);
    }
  }
});

it("lost replies and failed read-only rediscovery have distinct delivery and never replay", async () => {
  for (const automatic of [false, true]) {
    const dialer = new Dialer(index => new Transport(async (_, transport) => {
      if (automatic && index === 0) transport.feed(bytes(legacyCaps));
      else await transport.close();
    }));
    const client = automatic ? await ControlConnection.connectConnector(dialer) : JsonControlClient.fromConnector(dialer);
    await expect(client.requestTyped(new SetCpuTarget(2))).rejects.toMatchObject({ code: "peer_closed", delivery: automatic ? "not_sent" : "unknown" });
    expect(dialer.transports).toHaveLength(automatic ? 2 : 1);
    expect(client.isClosed()).toBe(true);
  }
});

it("verified framed operations recheck the active run before admitting bytes", async () => {
  let checks = 0;
  const dialer = new Dialer(index => index === 0 ? new Transport((_, transport) => transport.feed(bytes(cborCaps))) : framed());
  const connector: VerifiedControlConnector = {
    connect: context => dialer.connect(context),
    async verifySession() { if (++checks === 3) throw new ControlClientError("runtime_changed"); },
  };
  const client = await ControlConnection.connectVerifiedConnector(connector);
  await expect(client.requestTyped(new SetCpuTarget(2))).rejects.toMatchObject({ code: "runtime_changed", delivery: "not_sent" });
  expect(dialer.transports[1]!.writes).toBe(1); // Only hello, never the mutation.
  expect(client.isClosed()).toBe(true);
});

it("shared close cancels a stalled identity recheck before framed admission", async () => {
  let checks = 0, started!: () => void;
  const verifying = new Promise<void>(resolve => { started = resolve; });
  const dialer = new Dialer(index => index === 0 ? new Transport((_, transport) => transport.feed(bytes(cborCaps))) : framed());
  const connector: VerifiedControlConnector = {
    connect: context => dialer.connect(context),
    async verifySession() {
      if (++checks === 3) { started(); await new Promise<void>(() => {}); }
    },
  };
  const client = await ControlConnection.connectVerifiedConnector(connector);
  const request = client.requestTyped(new SetCpuTarget(2)).catch(error => error);
  await verifying; await client.clone().close();
  expect(await request).toMatchObject({ code: "closed", delivery: "not_sent" });
  expect(dialer.transports[1]!.writes).toBe(1);
});

it("zero waits, cancellation, shared close and late dials do not leak or silently reopen", async () => {
  for (const options of [{ requestTimeoutMs: 0 }, { signal: AbortSignal.abort() }]) {
    const dialer = jsonDialer([]), client = JsonControlClient.fromConnector(dialer);
    await expect(client.requestTyped(new SetCpuTarget(2), options)).rejects.toMatchObject({ delivery: "not_sent" });
    expect(dialer.transports).toHaveLength(0);
  }
  let began!: () => void;
  const writing = new Promise<void>(resolve => { began = resolve; });
  const dialer = new Dialer(() => new Transport(() => { began(); }));
  const client = JsonControlClient.fromConnector(dialer);
  const pending = client.requestTyped(new SetCpuTarget(2)).catch(error => error);
  await writing; await client.clone().close();
  expect(await pending).toMatchObject({ code: "closed", delivery: "unknown" });
  expect(dialer.transports[0]!.closed).toBe(true);

  let finish!: (transport: ByteTransport) => void, started!: () => void;
  const dialing = new Promise<void>(resolve => { started = resolve; });
  const late = new Transport(() => {}), cancel = new AbortController();
  const waiting = ControlConnection.connectConnector({ connect() { started(); return new Promise(resolve => { finish = resolve; }); } }, { signal: cancel.signal }).catch(error => error);
  await dialing; cancel.abort();
  expect(await waiting).toMatchObject({ code: "cancelled", delivery: "not_sent" });
  finish(late);
  await new Promise(resolve => setTimeout(resolve, 0));
  expect(late.closed).toBe(true);
});

it("setup has one deadline across discovery and redial", async () => {
  const transports: Transport[] = [];
  let dials = 0;
  const connector: Connector = {
    async connect() {
      const index = dials++;
      await new Promise(resolve => setTimeout(resolve, 30));
      const transport = index === 0 ? new Transport((_, transport) => transport.feed(bytes(cborCaps))) : framed();
      transports.push(transport);
      return transport;
    },
  };
  await expect(ControlConnection.connectConnector(connector, { setupTimeoutMs: 50 })).rejects.toMatchObject({ code: "timeout", delivery: "not_sent" });
  await new Promise(resolve => setTimeout(resolve, 35));
  expect(dials).toBe(2);
  expect(transports.every(transport => transport.closed)).toBe(true);
  expect(transports[1]!.writes).toBe(0);
});

it("discovery is bounded while ordinary legacy secret batches retain their larger size contract", async () => {
  const oversized = '{"ok":true,"capabilities":' + JSON.stringify(caps) + ',"x":"' + "x".repeat(65536) + '"}\n';
  await expect(ControlConnection.connectConnector(jsonDialer([oversized]))).rejects.toMatchObject({ code: "invalid_data", delivery: "not_sent" });
  let length = 0;
  const client = JsonControlClient.fromConnector(jsonDialer(['{"ok":true}\n'], line => { length = line.length; }));
  const changes = [{ change: "rotate" as const, name: "fixture", value: "x".repeat(4 * 1024 * 1024) }];
  const request = new UpdateSecrets(changes);
  changes[0]!.value = "changed-after-preparation";
  expect(await client.requestTyped(request)).toEqual({ outcome: "complete", applied_count: 1 });
  expect(length).toBeGreaterThan(4 * 1024 * 1024);
  expect(() => request.message()).toThrow();
  await client.close();
});

it("nonempty EOF and first-line replies preserve the legacy delimiters", async () => {
  for (const eof of [false, true]) {
    const raw = cpu.trimEnd();
    const dialer = new Dialer(() => new Transport(async (_, transport) => {
      transport.feed(bytes(eof ? raw : raw + "\nignored-after-first-line"));
      if (eof) await transport.close();
    }));
    const client = JsonControlClient.fromConnector(dialer);
    const reply = await client.request(typedMessage("control.cpu.state", {}));
    expect(text(reply.raw)).toBe(eof ? raw : raw + "\n");
    expect(client.isClosed()).toBe(false);
    await client.close();
  }
});
