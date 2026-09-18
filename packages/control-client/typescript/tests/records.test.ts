import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import {
  CborEnvelopeCodec, WireError, decodeEnvelope, decodeFrame, encodeEnvelope, encodeRecord,
} from "@microsandbox/protocol-client";
import {
  ControlClientError, GetCapabilities, GetCpuState, GetMemoryState, SetCpuTarget, SetMemoryTarget,
  UpdateSecrets, MiB, GiB, KiB, decodeCapabilities, decodeControlError, decodeCpuState,
  decodeHello, decodeMemoryState, decodeSecretsResult, decodeSecretsUpdate, decodeWelcome,
} from "../src/index.js";

const fixtures = JSON.parse(readFileSync(new URL("../../../protocol-fixtures/control-v1.json", import.meta.url), "utf8")) as {
  cases: Array<{ name: string; type: string; frame_hex: string; payload_hex: string }>;
};
const decoders: Record<string, (bytes: Uint8Array) => unknown> = {
  "control.hello": decodeHello, "control.welcome": bytes => decodeWelcome(bytes),
  "control.capabilities.result": decodeCapabilities, "control.error": decodeControlError,
  "control.secrets.result": decodeSecretsResult, "control.secrets.update": decodeSecretsUpdate,
};

describe("checked records consume the independently pinned Rust/TS fixtures", () => {
  for (const fixture of fixtures.cases) {
    const raw = decodeFrame(Buffer.from(fixture.frame_hex, "hex"));
    const envelope = decodeEnvelope(raw.body);
    const decode = decoders[envelope.t]
      ?? (raw.flags === 1 ? { "control.memory.state": decodeMemoryState, "control.cpu.state": decodeCpuState }[envelope.t] : undefined);
    if (!decode) continue;
    it(fixture.name, () => {
      const checked = decode(envelope.p);
      // Fixtures with unknown fields are consumed, but checked records need not
      // re-emit extension fields. Exact original bytes remain on the raw frame.
      expect(checked).toBeDefined();
      expect(new CborEnvelopeCodec().decode(raw).raw).toBe(raw);
    });
  }
});

it("retains full-width memory observations as bigint and checks existing SDK units", () => {
  expect(decodeMemoryState(encodeRecord({ boot_mib: 0, target_mib: 2048, current_mib: 9007199254740993n, max_mib: 0xffffffffffffffffn })))
    .toEqual({ boot_mib: 0n, target_mib: 2048n, current_mib: 9007199254740993n, max_mib: 0xffffffffffffffffn });
  expect(new SetMemoryTarget(MiB(2048)).total_mib).toBe(2048n);
  expect(new SetMemoryTarget(GiB(2)).total_mib).toBe(2048n);
  expect(new SetMemoryTarget(0xffffffffffffffffn).total_mib).toBe(0xffffffffffffffffn);
  for (const value of [KiB(1), MiB(-1), MiB(NaN), MiB(Infinity), MiB(2 ** 53), 1n << 64n]) expect(() => new SetMemoryTarget(value)).toThrow(WireError);
  for (const value of [-1, 1.5, 2 ** 32, NaN]) expect(() => new SetCpuTarget(value)).toThrow(WireError);
});

it("checks pinned memory extensions while retaining their exact original frames", () => {
  for (const name of ["memory_state_future_payload_field", "memory_state_future_envelope_field"]) {
    const fixture = fixtures.cases.find(fixture => fixture.name === name);
    expect(fixture, "the future-field case must be pinned").toBeDefined();
    const packet = Buffer.from(fixture!.frame_hex, "hex");
    const raw = decodeFrame(packet);
    const frame = new CborEnvelopeCodec().decode(raw);
    expect(new GetMemoryState().decode(frame)).toEqual({
      boot_mib: 512n, target_mib: 2048n, current_mib: 1024n, max_mib: 4096n,
    });
    expect(Buffer.from(frame.raw.body).toString("hex")).toBe(packet.subarray(9).toString("hex"));
    if (name === "memory_state_future_envelope_field") {
      expect(encodeEnvelope(decodeEnvelope(frame.raw.body))).not.toEqual(frame.raw.body);
    }
  }
});

it("rejects required-field, duplicate-key and integer-type errors without exposing payloads", () => {
  const memory = { boot_mib: 1, target_mib: 2, current_mib: 3, max_mib: 4 };
  for (const value of [-1, 1.5, "2", null, true]) expect(() => decodeMemoryState(encodeRecord({ ...memory, target_mib: value }))).toThrow(WireError);
  expect(() => decodeCpuState(encodeRecord({ possible: 1, requested_online: 2, actual_online: 1, enforced: 1n << 32n }))).toThrow(WireError);
  expect(() => decodeCapabilities(encodeRecord({ cpu_resize: true, memory_resize: 1, secrets_update: false }))).toThrow(WireError);
  const duplicate = Buffer.from("a2617800617801", "hex");
  for (const decode of [decodeMemoryState, decodeControlError, decodeCapabilities, decodeCpuState, decodeHello, decodeSecretsUpdate, decodeSecretsResult]) expect(() => decode(duplicate)).toThrow(WireError);
  expect(() => decodeControlError(encodeRecord({ code: "future", message: "private", effect: "probably" }))).toThrow(WireError);
});

const frame = (type: string, payload: unknown, flags = 1) => new CborEnvelopeCodec().decode({
  id: 7, flags, body: encodeEnvelope({ v: 1, t: type, p: encodeRecord(payload) }),
});

it("native peer errors stay inspectable and checked errors retain unknown codes and actual frames", () => {
  const response = frame("control.error", { code: "future_error", message: "peer diagnostic", effect: "unknown", future: 5 });
  expect(response.decodePayload()).toMatchObject({ code: "future_error", future: 5 });
  try { new GetMemoryState().decode(response); throw new Error("expected rejection"); }
  catch (error) {
    expect(error).toBeInstanceOf(ControlClientError);
    expect(error).toMatchObject({ code: "peer", response, peerError: { code: "future_error", effect: "unknown" } });
    expect(String(error)).not.toContain("peer diagnostic");
  }
  for (const request of [new GetMemoryState(), new GetCpuState(), new GetCapabilities(), new SetMemoryTarget(MiB(8)), new SetCpuTarget(2)]) {
    expect(() => request.decode(frame("future.reply", {}, 1))).toThrow(ControlClientError);
    expect(() => request.decode(frame("control.error", { code: "busy", message: "busy", effect: "none" }, 3))).toThrow(ControlClientError);
  }
});

it("snapshots secret batches and preserves ordered partial progress without inferring rollback", () => {
  const changes = [{ change: "remove" as const, name: "first" }, { change: "remove" as const, name: "second" }];
  const request = new UpdateSecrets(changes);
  changes.splice(0); // Prepared bytes and count still describe the original batch.
  expect(decodeSecretsUpdate(request.message().payload).changes).toHaveLength(2);
  const failed = { outcome: "failed", applied_count: 1, failed_index: 1, error: { code: "unknown_secret", message: "missing", effect: "none" } };
  expect(request.decode(frame("control.secrets.result", failed))).toEqual(failed);
  expect(request.decode(frame("control.secrets.result", { outcome: "complete", applied_count: 2 }))).toEqual({ outcome: "complete", applied_count: 2 });
  for (const payload of [{ ...failed, failed_index: 0 }, { ...failed, applied_count: 2, failed_index: 2 }, { outcome: "complete", applied_count: 1 }]) {
    expect(() => request.decode(frame("control.secrets.result", payload))).toThrow(ControlClientError);
  }
  const nested = encodeRecord({ code: "x", message: "m", effect: "none" });
  // Append duplicate unknown keys inside the nested error, where a permissive
  // decoder would otherwise erase evidence before validation.
  const duplicate = Uint8Array.from([0xa5, ...nested.subarray(1), 0x61, 0x78, 0, 0x61, 0x78, 1]);
  const prefix = encodeRecord({ outcome: "failed", applied_count: 0, failed_index: 0 });
  const payload = Uint8Array.from([0xa4, ...prefix.subarray(1), 0x65, ...new TextEncoder().encode("error"), ...duplicate]);
  expect(() => decodeSecretsResult(payload)).toThrow(WireError);
});
