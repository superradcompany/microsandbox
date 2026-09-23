import { expect, it } from "vitest";
import { connectUnix } from "../src/node.js";
import { encodedMessage, typedMessage } from "../src/message.js";

const endpoint = process.env.MSB_AGENT_TEST_SOCKET;
const expectedVersion = process.env.MSB_AGENT_TEST_VERSION;

it.skipIf(!endpoint || !expectedVersion)("live historical agent: version, owned execution stream, stdin, stderr, filesystem and opaque ping", async () => {
  const client = await connectUnix(endpoint!);
  try {
    expect(client.ready.agentVersion).toBe(expectedVersion);
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
    const fs = await client.request(typedMessage("core.fs.request", { op: { Stat: { path: "/etc/os-release", follow_symlink: true } } }));
    expect(fs.type).toBe("core.fs.response"); expect(fs.decodePayload<{ ok: boolean }>().ok).toBe(true);
    const ping = await client.request(encodedMessage("core.ping", new Uint8Array([0xa0])));
    expect(ping.type).toBe("core.pong"); expect(ping.raw.body.length).toBeGreaterThan(0);
  } finally { await client.close(); }
}, 15_000);
