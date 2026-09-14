import net from "node:net";
import { expect, it } from "vitest";
import { LocalConnector } from "@microsandbox/protocol-client/node";
import { decodeEnvelope, encodeEnvelope, encodeFrame, encodeRecord, type Connector } from "@microsandbox/protocol-client";
import {
  ControlClient, GetCapabilities, GetCpuState, GetMemoryState, SetCpuTarget, SetMemoryTarget,
  UpdateSecrets, typedMessage,
} from "../src/index.js";
import { connectFramedControl } from "../src/node.js";

const endpoint = process.env.MSB_CONTROL_TEST_SOCKET;
const secretName = process.env.MSB_CONTROL_TEST_SECRET;

// Deliberately opt in: this changes targets on a disposable live VM and restores
// them in finally. A skipped run is not evidence that the runtime gate passed.
it.skipIf(!endpoint)("live runtime: JSON and fragmented/native/raw/checked CBOR, concurrent peers and accepted resource targets", async () => {
  const connector = new LocalConnector(endpoint!);
  const fragmented: Connector = {
    async connect(context) {
      const transport = await connector.connect(context);
      return {
        read: (size: number) => transport.read(size), close: () => transport.close(),
        async write(bytes: Uint8Array) {
          for (let at = 0; at < bytes.length; at += 3) await transport.write(bytes.subarray(at, at + 3));
        },
      };
    },
  };
  const client = await ControlClient.connectConnector(fragmented);
  const peers: ControlClient[] = [];
  let memory: Awaited<ReturnType<GetMemoryState["decode"]>> | undefined;
  let cpu: Awaited<ReturnType<GetCpuState["decode"]>> | undefined;
  try {
    const jsonCaps = await legacy(endpoint!, { op: "capabilities" });
    expect(jsonCaps).toMatchObject({ ok: true, control_protocols: ["json", "cbor"] });
    const caps = await client.requestTyped(new GetCapabilities());
    // Release runtimes also expose JSON-only checkpoint and lifecycle features.
    // The capabilities shared with framed control must agree exactly.
    expect(jsonCaps.capabilities).toMatchObject(caps);
    memory = await client.requestTyped(new GetMemoryState());
    cpu = await client.requestTyped(new GetCpuState());
    expect(typeof memory.current_mib).toBe("bigint");
    expect(caps).toMatchObject({ memory_resize: true, cpu_resize: true });

    // Each method must agree on the accepted target, while observations may
    // change asynchronously as the guest processes the request.
    const acceptedMemory = await client.requestTyped(new SetMemoryTarget(memory.max_mib));
    expect(acceptedMemory.target_mib).toBe(memory.max_mib);
    const acceptedCpu = await client.requestTyped(new SetCpuTarget(cpu.possible));
    expect(acceptedCpu.requested_online).toBe(cpu.possible);
    expect(await legacy(endpoint!, { op: "memory_state" })).toMatchObject({ ok: true, memory: { target_mib: Number(memory.max_mib) } });
    expect(await legacy(endpoint!, { op: "cpu_state" })).toMatchObject({ ok: true, cpu: { requested_online: cpu.possible } });

    for (let i = 0; i < 6; i++) peers.push(await connectFramedControl(endpoint!));
    await Promise.all(peers.flatMap(peer => Array.from({ length: 8 }, () => peer.requestTyped(new GetMemoryState()).then(state => expect(state.target_mib).toBe(memory!.max_mib)))));
    const unknown = await client.request(typedMessage("extension.not_registered", { data: true }));
    expect(unknown.type).toBe("control.error");
    expect(unknown.decodePayload()).toMatchObject({ code: "unsupported_operation", effect: "none" });
    const invalid = await client.requestRaw(0, encodeEnvelope({ v: 1, t: "control.memory.target", p: encodeRecord({ total_mib: "wrong" }) }));
    expect(decodeEnvelope(invalid.body).t).toBe("control.error");

    const raw = await client.openStreamRaw(0, encodeEnvelope({ v: 1, t: "control.cpu.state", p: encodeRecord({}) }));
    const { sender, receiver } = raw.split();
    expect(decodeEnvelope((await receiver.next())!.body).t).toBe("control.cpu.state");
    expect(await receiver.next()).toBeNull(); receiver.close(); sender.close();

    // Exact packets bypass subscriptions. Their unregistered terminal replies
    // must not disrupt the next managed exchange on this same connection.
    await client.writeUnchecked(encodeFrame({ id: 0xffffffff, flags: 0, body: encodeEnvelope({ v: 1, t: "control.capabilities", p: encodeRecord({}) }) }));
    expect(await client.requestTyped(new GetCapabilities())).toEqual(caps);
    if (caps.secrets_update) expect(await client.requestTyped(new UpdateSecrets([]))).toEqual({ outcome: "complete", applied_count: 0 });
    else await expect(client.requestTyped(new UpdateSecrets([]))).rejects.toMatchObject({ code: "peer", peerError: { code: "secrets_update_unavailable", effect: "none" } });
    console.log(JSON.stringify({ live: "control", mode: "json+cbor", concurrentReads: 48, maxMemoryMiB: String(memory.max_mib), possibleCpus: cpu.possible }));
  } finally {
    // A fresh cleanup connection also verifies independent redial after earlier
    // activity; never replay a failed mutating request automatically.
    try {
      const restore = await connectFramedControl(endpoint!);
      try {
        if (memory) await restore.requestTyped(new SetMemoryTarget(memory.target_mib));
        if (cpu) await restore.requestTyped(new SetCpuTarget(cpu.requested_online));
      } finally { await restore.close(); }
    } finally { await Promise.all([...peers, client].map(peer => peer.close())); }
  }
}, 30_000);

it.skipIf(!endpoint || !secretName)("live runtime: ordered secret failures preserve progress and legacy JSON error shape", async () => {
  const client = await connectFramedControl(endpoint!);
  try {
    expect((await client.requestTyped(new GetCapabilities())).secrets_update).toBe(true);
    const result = await client.requestTyped(new UpdateSecrets([
      { change: "remove", name: "msb-control-absent-fixture" },
      { change: "rotate", name: secretName!, value: "after-fixture" },
      { change: "set_allowed_hosts", name: secretName!, hosts: [] },
      { change: "rotate", name: secretName!, value: "must-not-be-applied" },
    ]));
    expect(result).toMatchObject({ outcome: "failed", applied_count: 2, failed_index: 2, error: { code: "invalid_secret_hosts", effect: "none" } });
    expect(await client.requestTyped(new UpdateSecrets([]))).toEqual({ outcome: "complete", applied_count: 0 });
    const missing = await client.requestTyped(new UpdateSecrets([{ change: "rotate", name: "msb-control-absent-fixture", value: "dummy" }]));
    expect(missing).toMatchObject({ outcome: "failed", applied_count: 0, failed_index: 0, error: { code: "unknown_secret", effect: "none" } });
    const malformed = await client.request(typedMessage("control.secrets.update", { changes: [
      { change: "rotate", name: secretName!, value: "must-not-dispatch" },
      { change: "set_allowed_hosts", name: secretName!, hosts: [1] },
    ] }));
    expect(malformed.decodePayload()).toMatchObject({ code: "invalid_request", effect: "none" });
    const jsonFailure = await legacy(endpoint!, { op: "secrets_update", changes: [{ change: "set_allowed_hosts", name: secretName!, hosts: [] }] });
    expect(jsonFailure).toMatchObject({ ok: false, error: expect.any(String) });
    expect(jsonFailure).not.toHaveProperty("applied_count");
  } finally {
    try {
      await client.requestTyped(new UpdateSecrets([
        { change: "rotate", name: secretName!, value: "before" },
        { change: "set_allowed_hosts", name: secretName!, hosts: ["example.invalid"] },
      ]));
    } finally { await client.close(); }
  }
}, 30_000);

async function legacy(path: string, request: unknown): Promise<Record<string, unknown>> {
  const socket = net.createConnection(path);
  const chunks: Buffer[] = [];
  try {
    await new Promise<void>((resolve, reject) => {
      socket.once("error", reject); socket.once("connect", resolve);
    });
    socket.write(JSON.stringify(request) + "\n");
    for await (const chunk of socket) {
      chunks.push(chunk as Buffer);
      // JSON replies are newline framed. Windows can report EPIPE at closure,
      // so finish at the complete reply instead of waiting for a clean EOF.
      if (Buffer.concat(chunks).includes(0x0a)) break;
    }
    return JSON.parse(Buffer.concat(chunks).toString("utf8")) as Record<string, unknown>;
  } finally { socket.destroy(); }
}
