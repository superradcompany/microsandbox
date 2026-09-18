import {
  Client, InboundFrame, CborEnvelopeCodec, WebSocketConnector, WebSocketTransport,
  encodeFrame, encodedMessage, readExactly, typedMessage,
  type ByteTransport, type EnvelopeCodec, type EstablishContext, type Established,
  type Protocol, type RawFrame, type Request,
} from "@microsandbox/protocol-client";
import { AgentClient, AgentEnvelopeCodec } from "@microsandbox/agent-client";
import {
  ControlConnection, GetCapabilities, GetCpuState, GetMemoryState,
  JsonControlClient, MiB, SetCpuTarget, SetMemoryTarget,
} from "@microsandbox/control-client";

// Compile this fixture against installed package tarballs, bundle for browsers,
// and serve it beside an authenticated relay to a disposable live VM.
const text = new TextEncoder();
const utf8 = new TextDecoder();
function assert(value: unknown, message: string): asserts value {
  if (!value) throw new Error(message);
}
function equal(actual: Uint8Array, expected: Uint8Array): void {
  assert(actual.length === expected.length && actual.every((v, i) => v === expected[i]), "bytes changed");
}
const observedRejections: { code?: string; delivery?: string }[] = [];
async function rejected(promise: Promise<unknown>, code: string | readonly string[], delivery?: string): Promise<void> {
  try { await promise; }
  catch (error) {
    const failure = error as { code?: string; delivery?: string };
    observedRejections.push({ code: failure.code, delivery: failure.delivery });
    assert(typeof code === "string" ? failure.code === code : code.includes(failure.code ?? ""), `expected ${code}, received ${failure.code}`);
    assert(delivery === undefined || failure.delivery === delivery, `wrong delivery: ${failure.delivery}`);
    return;
  }
  throw new Error(`expected rejection: ${code}`);
}

// This is deliberately not CBOR: a browser consumer owns its protocol codec.
class BrowserCodec implements EnvelopeCodec {
  encodePayload(value: unknown): Uint8Array { return text.encode(JSON.stringify(value)); }
  encode(generation: number, name: string, payload: Uint8Array): Uint8Array {
    const encoded = text.encode(name);
    assert(encoded.length < 256, "fixture name too long");
    return new Uint8Array([generation, encoded.length, ...encoded, ...payload]);
  }
  decode(frame: RawFrame): InboundFrame {
    const version = frame.body[0]!, length = frame.body[1]!;
    assert(frame.body.length >= length + 2, "bad custom envelope");
    return new InboundFrame(frame.id, frame.flags, version, utf8.decode(frame.body.subarray(2, 2 + length)), frame.body.subarray(2 + length), frame);
  }
}
class BrowserProtocol implements Protocol<number> {
  async establish(transport: ByteTransport, context: EstablishContext): Promise<Established<number>> {
    const ready = (await readExactly(transport, 1, context.signal))[0]!;
    return { transport, codec: new BrowserCodec(), ready, limits: context.limits, ids: { start: 0xfffffffe, endExclusive: 2 ** 32 } };
  }
  prepare(ready: number) { return { generation: ready, flags: 2 }; }
}
class CheckedNumber implements Request<number> {
  message() { return encodedMessage("browser.checked", text.encode("17")); }
  decode(frame: InboundFrame): number {
    assert(frame.type === "browser.checked" && frame.isTerminal(), "wrong checked reply");
    return JSON.parse(utf8.decode(frame.payload)) as number;
  }
}

type Case = { name: string; passed: boolean; elapsedMs: number; error?: string };
type Configuration = { baseUrl: string; expectedAgentVersion: string; expectedControlMode: "json" | "cbor" };

export async function runBrowserLive(config: Configuration) {
  const cases: Case[] = [];
  const check = async (name: string, operation: () => Promise<void>) => {
    const start = performance.now();
    try { await operation(); cases.push({ name, passed: true, elapsedMs: performance.now() - start }); }
    catch (error) { cases.push({ name, passed: false, elapsedMs: performance.now() - start, error: String(error) }); }
    document.querySelector("pre")!.textContent = JSON.stringify(cases, null, 2);
  };
  const connector = (path: string) => new WebSocketConnector(`${config.baseUrl}/${path}`);

  await check("native browser globals and exact CBOR bigint", async () => {
    for (const name of ["process", "Buffer", "require"]) assert(!(name in globalThis), `Node global leaked: ${name}`);
    assert(WebSocket.toString().includes("[native code]"), "WebSocket is not native");
    const codec = new CborEnvelopeCodec(), integer = 9007199254740993n;
    const body = codec.encode(1, "browser.bigint", codec.encodePayload({ integer }));
    assert(codec.decode({ id: 1, flags: 1, body }).decodePayload<{ integer: bigint }>().integer === integer, "integer rounded");
  });

  await check("custom protocol, full u32 IDs, native/encoded/raw/checked calls and exact packets", async () => {
    const client = await Client.connectConnector(connector("generic"), new BrowserProtocol());
    try {
      assert(client.ready === 7, "custom handshake lost");
      const opaque = new Uint8Array([0xff, 0, 0x9f]);
      const replies = await Promise.all([
        client.request(typedMessage("browser.native", { value: 9 })),
        client.request(encodedMessage("browser.dynamic", opaque)),
      ]);
      assert(replies[0]!.id === 0xfffffffe && replies[1]!.id === 0xffffffff, "u32 IDs narrowed");
      assert(JSON.parse(utf8.decode(replies[0]!.payload)).value === 9, "native payload changed");
      equal(replies[1]!.payload, opaque);
      equal((await client.requestRaw(0xd6, opaque)).body, opaque);
      assert(await client.requestTyped(new CheckedNumber()) === 17, "checked decode failed");
      const stream = await client.openStreamRaw(2, opaque), { sender, receiver } = stream.split();
      try {
        equal((await receiver.next())!.body, opaque);
        assert(await receiver.next() === null, "terminal frame repeated");
        await rejected(sender.send(0, opaque), "stream_closed", "not_sent");
      } finally { sender.close(); receiver.close(); }
      // The fixture records this unowned packet without replying. It must not
      // reserve an engine ID or rewrite the caller's chosen body and flags.
      await client.writeUnchecked(encodeFrame({ id: 77, flags: 0xa0, body: opaque }));
    } finally { await client.close(); }
  });

  const agent = await AgentClient.connectConnector(connector("agent"));
  try {
    await check("real agent metadata and 24 concurrent encoded requests", async () => {
      assert(agent.ready.agentVersion === config.expectedAgentVersion, "wrong guest agent");
      assert(agent.ready.readyBytes.length > 0, "ready bytes missing");
      const replies = await Promise.all(Array.from({ length: 24 }, () => agent.request(encodedMessage("core.ping", new Uint8Array([0xa0])))));
      assert(new Set(replies.map(frame => frame.id)).size === 24, "concurrent IDs collided");
      for (const frame of replies) assert(frame.type === "core.pong" && frame.isTerminal(), "bad ping response");
    });
    await check("owned execution stream, large explicit-ID stdin, stdout/stderr and stale sender", async () => {
      const stream = await agent.openStream(typedMessage("core.exec.request", { cmd: "/bin/sh", args: ["-c", "read value; printf '%s' \"$value\"; printf browser-stderr >&2"] }));
      const { sender, receiver } = stream.split();
      try {
        assert((await receiver.next(5000))?.type === "core.exec.started", "exec did not start");
        const input = "browser-input:" + "x".repeat(256 * 1024);
        await agent.sendOnStream(sender.id, typedMessage("core.exec.stdin", { data: text.encode(input + "\n") }));
        const stdout: Uint8Array[] = [], stderr: Uint8Array[] = [];
        let code: number | undefined;
        for (;;) {
          const frame = await receiver.next(10000);
          if (!frame) break;
          if (frame.type === "core.exec.stdout") stdout.push(frame.decodePayload<{ data: Uint8Array }>().data);
          else if (frame.type === "core.exec.stderr") stderr.push(frame.decodePayload<{ data: Uint8Array }>().data);
          else if (frame.type === "core.exec.exited") code = frame.decodePayload<{ code: number }>().code;
          else throw new Error(`unexpected exec frame ${frame.type}`);
        }
        assert(stdout.map(bytes => utf8.decode(bytes)).join("") === input, "large stdout changed");
        assert(stderr.map(bytes => utf8.decode(bytes)).join("") === "browser-stderr" && code === 0, "stderr or exit changed");
        await rejected(sender.send(typedMessage("core.exec.stdin", { data: new Uint8Array() })), "stream_closed", "not_sent");
      } finally { sender.close(); receiver.close(); }
    });
    await check("raw exec and exact framed stdin packet", async () => {
      const codec = new AgentEnvelopeCodec();
      const body = (name: string, payload: unknown) => codec.encode(5, name, codec.encodePayload(payload));
      const stream = await agent.openStreamRaw(2, body("core.exec.request", { cmd: "sh", args: ["-c", "read x; printf '%s' \"$x\""] }));
      const { sender, receiver } = stream.split();
      try {
        assert(codec.decode((await receiver.next())!).type === "core.exec.started", "raw exec did not start");
        await agent.writeUnchecked(encodeFrame({ id: sender.id, flags: 0, body: body("core.exec.stdin", { data: text.encode("exact-packet\n") }) }));
        let output = "", code: number | undefined;
        for (;;) {
          const raw = await receiver.next(5000);
          if (!raw) break;
          const frame = codec.decode(raw);
          if (frame.type === "core.exec.stdout") output += utf8.decode(frame.decodePayload<{ data: Uint8Array }>().data);
          if (frame.type === "core.exec.exited") code = frame.decodePayload<{ code: number }>().code;
        }
        assert(output === "exact-packet" && code === 0, "raw execution changed");
      } finally { sender.close(); receiver.close(); }
    });
    await check("receiver timeout leaves later output readable", async () => {
      const stream = await agent.openStream(typedMessage("core.exec.request", { cmd: "sh", args: ["-c", "sleep 0.3; printf late-output"] }));
      try {
        assert((await stream.next())?.type === "core.exec.started", "delayed exec did not start");
        await rejected(stream.next(10), "timeout", "unknown");
        let output = "", code: number | undefined;
        for await (const frame of stream) {
          if (frame.type === "core.exec.stdout") output += utf8.decode(frame.decodePayload<{ data: Uint8Array }>().data);
          if (frame.type === "core.exec.exited") code = frame.decodePayload<{ code: number }>().code;
        }
        assert(output === "late-output" && code === 0, "timeout consumed output");
      } finally { stream.close(); }
    });
    await check("pre-admission cancellation and filesystem request", async () => {
      const signal = AbortSignal.abort();
      await rejected(agent.request(typedMessage("core.fs.request", {}), { signal }), "cancelled", "not_sent");
      const frame = await agent.request(typedMessage("core.fs.request", { op: { Stat: { path: "/etc/os-release", follow_symlink: true } } }));
      assert(frame.decodePayload<{ ok: boolean }>().ok, "cancel broke later filesystem request");
    });
    await check("shared close rejects clone locally", async () => {
      const clone = agent.clone();
      await agent.close();
      await rejected(clone.request(encodedMessage("core.ping", new Uint8Array([0xa0]))), "closed", "not_sent");
    });
  } finally { await agent.close(); }

  await check("automatic control discovery, bigint state, same-target mutations and explicit JSON", async () => {
    const connection = await ControlConnection.connectConnector(connector("control"));
    const json = JsonControlClient.fromConnector(connector("control"));
    try {
      assert(connection.mode === config.expectedControlMode, "wrong control mode");
      const [memory, cpu] = await Promise.all([connection.requestTyped(new GetMemoryState()), connection.requestTyped(new GetCpuState())]);
      assert(typeof memory.target_mib === "bigint", "memory lost bigint");
      assert((await connection.requestTyped(new SetMemoryTarget(MiB(Number(memory.target_mib))))).target_mib === memory.target_mib, "memory target changed");
      assert((await connection.requestTyped(new SetCpuTarget(cpu.requested_online))).requested_online === cpu.requested_online, "CPU target changed");
      const caps = await json.requestTyped(new GetCapabilities());
      assert(caps.cpu_resize && caps.memory_resize, "JSON capabilities missing");
      assert((await json.requestTyped(new GetMemoryState())).target_mib === memory.target_mib, "JSON/CBOR disagree");
      assert((await json.requestTyped(new GetCpuState())).requested_online === cpu.requested_online, "JSON CPU changed");
    } finally { await connection.close(); await json.close(); }
  });
  await check("real WebSocket incoming-byte overflow is bounded", async () => {
    const transport = await WebSocketTransport.connect(`${config.baseUrl}/overflow`, undefined, undefined, { bufferedBytes: 1024 });
    try { await rejected(transport.read(4096), "capacity"); } finally { await transport.close(); }
  });
  await check("real WebSocket text frames are rejected", async () => {
    const transport = await WebSocketTransport.connect(`${config.baseUrl}/text`);
    try { await rejected(transport.read(4096), "invalid_data"); } finally { await transport.close(); }
  });
  await check("setup deadline closes a stalled WebSocket", async () => {
    await rejected(Client.connectConnector(connector("stall"), new BrowserProtocol(), { setupTimeoutMs: 100 }), "timeout", "not_sent");
  });
  await check("peer close racing write drain remains unknown without replay", async () => {
    const client = await Client.connectConnector(connector("drop"), new BrowserProtocol());
    try { await rejected(client.request(typedMessage("browser.drop", {})), ["closed", "peer_closed"], "unknown"); }
    finally { await client.close(); }
  });
  await check("peer EOF after write completion remains unknown without replay", async () => {
    const client = await Client.connectConnector(connector("drop-after-write"), new BrowserProtocol());
    try { await rejected(client.request(typedMessage("browser.drop", {})), "peer_closed", "unknown"); }
    finally { await client.close(); }
  });
  return { userAgent: navigator.userAgent, cases, observedRejections, passed: cases.every(item => item.passed) };
}

(globalThis as unknown as { runBrowserLive: typeof runBrowserLive }).runBrowserLive = runBrowserLive;
