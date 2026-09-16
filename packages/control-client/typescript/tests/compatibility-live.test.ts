import { expect, it } from "vitest";
import {
  GetCapabilities, GetCpuState, GetMemoryState, JsonReply, SetCpuTarget, SetMemoryTarget,
  UpdateSecrets, typedMessage, type CpuState, type MemoryState,
} from "../src/index.js";
import { connectControl, jsonControl } from "../src/node.js";

const endpoint = process.env.MSB_CONTROL_TEST_SOCKET;
const mode = process.env.MSB_CONTROL_TEST_MODE;
const secretName = process.env.MSB_CONTROL_TEST_SECRET;

// Opt-in mutation of a disposable VM. Restore accepted resource targets and the
// documented dummy secret; a skipped test is not historical compatibility proof.
it.skipIf(!endpoint || !mode)("live automatic discovery and explicit JSON preserve resource and secret workflows", async () => {
  expect(["json", "cbor"]).toContain(mode);
  const client = await connectControl(endpoint!), json = jsonControl(endpoint!);
  let memory: MemoryState | undefined, cpu: CpuState | undefined;
  try {
    expect(client.mode).toBe(mode);
    const caps = await client.requestTyped(new GetCapabilities());
    expect(await json.requestTyped(new GetCapabilities())).toEqual(caps);
    memory = await client.requestTyped(new GetMemoryState());
    cpu = await client.requestTyped(new GetCpuState());
    expect(typeof memory.current_mib).toBe("bigint");
    expect(caps).toMatchObject({ memory_resize: true, cpu_resize: true });
    expect((await client.requestTyped(new SetMemoryTarget(memory.max_mib))).target_mib).toBe(memory.max_mib);
    expect((await client.requestTyped(new SetCpuTarget(cpu.possible))).requested_online).toBe(cpu.possible);
    const native = await client.request(typedMessage("control.memory.state", {}));
    expect(native.kind).toBe(mode);
    if (native.kind === "json") {
      expect(native.reply).toBeInstanceOf(JsonReply);
      expect(native.reply.value.get("ok")).toBe(true);
      expect(native.reply).not.toHaveProperty("id");
    }
    await Promise.all(Array.from({ length: 8 }, async () => {
      const [automatic, explicit] = await Promise.all([
        client.requestTyped(new GetCpuState()), json.requestTyped(new GetCpuState()),
      ]);
      expect(automatic.requested_online).toBe(cpu!.possible);
      expect(explicit.requested_online).toBe(cpu!.possible);
    }));
    if (caps.secrets_update) expect(await client.requestTyped(new UpdateSecrets([]))).toEqual({ outcome: "complete", applied_count: 0 });
    if (secretName) {
      await expect(json.requestTyped(new UpdateSecrets([
        { change: "remove", name: "msb-control-absent-fixture" },
        { change: "rotate", name: secretName, value: "after-fixture" },
        { change: "set_allowed_hosts", name: secretName, hosts: [] },
        { change: "rotate", name: secretName, value: "must-not-be-applied" },
      ]))).rejects.toMatchObject({ code: "legacy_remote", delivery: "unknown", response: expect.any(JsonReply) });
    }
    console.log(JSON.stringify({ live: "automatic-control", mode: client.mode, pairedCpuReads: 8, maxMemoryMiB: String(memory.max_mib), possibleCpus: cpu.possible }));
  } finally {
    const restore = jsonControl(endpoint!);
    try {
      if (memory) await restore.requestTyped(new SetMemoryTarget(memory.target_mib));
      if (cpu) await restore.requestTyped(new SetCpuTarget(cpu.requested_online));
      if (secretName) await restore.requestTyped(new UpdateSecrets([
        { change: "rotate", name: secretName, value: "before" },
        { change: "set_allowed_hosts", name: secretName, hosts: ["example.invalid"] },
      ]));
    } finally { await Promise.all([restore.close(), json.close(), client.clone().close()]); }
    expect(client.isClosed()).toBe(true);
  }
}, 30_000);
