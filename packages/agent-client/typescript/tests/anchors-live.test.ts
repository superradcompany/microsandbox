import { decode, encode } from "cbor-x";
import { expect, it } from "vitest";
import { connectUnix } from "../src/node.js";
import { typedMessage } from "../src/message.js";

const endpoint = process.env.MSB_AGENT_TEST_SOCKET;
const expectedVersion = process.env.MSB_AGENT_TEST_VERSION;
const wire = process.env.MSB_AGENT_ANCHOR_WIRE;

it.skipIf(!endpoint || !wire)("live anchor: metadata and execution stream", async () => {
  const client = await connectUnix(endpoint!);
  try {
    expect(client.ready.agentVersion).toBe(expectedVersion);
    expect(client.ready.wireFormat).toBe(wire);
    expect(client.ready.negotiatedVersion).toBe(Number(process.env.MSB_AGENT_ANCHOR_GENERATION));
    console.info("anchor ready", client.ready);
    // TS's known schema ends at generation five: Ping is a dynamic name,
    // not a checked operation. Exercise its known filesystem gate on gen one.
    if (client.ready.negotiatedVersion === 1) {
      await expect(client.request(typedMessage("core.fs.request", {})))
        .rejects.toMatchObject({ code: "unsupported_operation", delivery: "not_sent" });
    }
    const stream = await client.openStream(typedMessage("core.exec.request", {
      cmd: "/bin/sh", args: ["-c", "read value; printf '%s' \"$value\"; printf 'compat-stderr' >&2"],
    }));
    const { sender, receiver } = stream.split();
    try {
      expect((await receiver.next(5_000))?.type).toBe("core.exec.started");
      await client.sendOnStream(sender.id, typedMessage("core.exec.stdin", { data: new TextEncoder().encode("compat-input\n") }));
      const stdout: number[] = [], stderr: number[] = [];
      let code: number | undefined;
      for (;;) {
        const frame = await receiver.next(5_000);
        if (!frame) break;
        switch (frame.type) {
          case "core.exec.stdout": stdout.push(...frame.decodePayload<{ data: Uint8Array }>().data); break;
          case "core.exec.stderr": stderr.push(...frame.decodePayload<{ data: Uint8Array }>().data); break;
          case "core.exec.exited": code = frame.decodePayload<{ code: number }>().code; break;
          default: throw new Error(`unexpected live exec message: ${frame.type}`);
        }
      }
      expect(new TextDecoder().decode(new Uint8Array(stdout))).toBe("compat-input");
      expect(new TextDecoder().decode(new Uint8Array(stderr))).toBe("compat-stderr");
      expect(code).toBe(0);
      await expect(sender.send(typedMessage("core.exec.stdin", { data: new Uint8Array() }))).rejects.toMatchObject({ code: "stream_closed" });
    } finally { receiver.close(); sender.close(); }
  } finally { await client.close(); }
}, 15_000);


it.skipIf(!endpoint || !wire)("live anchor: historical filesystem workflow", async () => {
  const client = await connectUnix(endpoint!);
  try {
    const response = client.request(typedMessage("core.fs.request", {
      op: { Stat: { path: "/etc/os-release", follow_symlink: true } },
    }));
    // The historical fixture chooses the expectation, not current capability gates.
    if (process.env.MSB_AGENT_ANCHOR_FILESYSTEM === "supported") {
      const frame = await response;
      expect(frame.type).toBe("core.fs.response");
      expect(frame.decodePayload<{ ok: boolean }>().ok).toBe(true);
    } else {
      await expect(response).rejects.toMatchObject({ code: "unsupported_operation", delivery: "not_sent" });
    }
  } finally { await client.close(); }
}, 15_000);


it.skipIf(!endpoint || wire !== "current" || process.env.MSB_AGENT_ANCHOR_GENERATION !== "1")("live anchor: exact generation-one filesystem diagnostic", async () => {
  const client = await connectUnix(endpoint!);
  try {
    // Deliberately use the public raw path to distinguish a client-side gate
    // from the released agent's actual ability to execute the historical form.
    const payload = encode({ op: { Stat: { path: "/etc/os-release", follow_symlink: true } } });
    const response = await client.requestRaw(2, encode({ v: 1, t: "core.fs.request", p: payload }));
    const envelope = decode(response.body) as { v: number; t: string; p: Uint8Array };
    expect(envelope.t).toBe("core.fs.response");
    expect((decode(envelope.p) as { ok: boolean }).ok).toBe(true);
  } finally { await client.close(); }
}, 15_000);
