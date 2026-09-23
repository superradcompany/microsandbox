import { encodedMessage, encodeRecord, WireError, type EncodedMessage, type InboundFrame } from "@microsandbox/protocol-client";
import type { Mebibytes } from "@microsandbox/types/size";
import { ControlClientError } from "./error.js";
import { jsonCapabilities, jsonCpu, jsonMemory, type JsonReply } from "./json-reply.js";
import { snapshotChanges, type CheckedControlRequest, type LegacyControlRequest } from "./legacy-request.js";
import {
  CONTROL_GENERATION, checkedUint, decodeCapabilities, decodeControlError, decodeCpuState,
  decodeMemoryState, decodeSecretsResult,
  type Capabilities, type CpuState, type MemoryState, type SecretChange, type SecretsResult,
} from "./records.js";

function checked<T>(frame: InboundFrame, name: string, decode: (bytes: Uint8Array) => T): T {
  const invalid = () => new ControlClientError("invalid_response", frame);
  if (frame.protocolVersion !== CONTROL_GENERATION || frame.id === 0 || frame.flags !== 1) throw invalid();
  if (frame.type === "control.error") {
    let error;
    try { error = decodeControlError(frame.payload); } catch { throw invalid(); }
    throw new ControlClientError("peer", frame, error);
  }
  if (frame.type !== name) throw invalid();
  try { return decode(frame.payload); } catch { throw invalid(); }
}

/** Optional checked helpers only prepare records and decode replies; no SDK policy. */
export class GetCapabilities implements CheckedControlRequest<Capabilities> {
  message(): EncodedMessage { return encodedMessage("control.capabilities", encodeRecord({})); }
  decode(frame: InboundFrame): Capabilities { return checked(frame, "control.capabilities.result", decodeCapabilities); }
  jsonRequest(): LegacyControlRequest { return { op: "capabilities" }; }
  decodeJson(reply: JsonReply): Capabilities { return reply.checked(value => jsonCapabilities(value.get("capabilities"))); }
}
export class GetMemoryState implements CheckedControlRequest<MemoryState> {
  message(): EncodedMessage { return encodedMessage("control.memory.state", encodeRecord({})); }
  decode(frame: InboundFrame): MemoryState { return checked(frame, "control.memory.state", decodeMemoryState); }
  jsonRequest(): LegacyControlRequest { return { op: "memory_state" }; }
  decodeJson(reply: JsonReply): MemoryState { return reply.checked(value => jsonMemory(value.get("memory"))); }
}
export class SetMemoryTarget implements CheckedControlRequest<MemoryState> {
  readonly total_mib: bigint;
  /** Reuse SDK units; bigint also accepts a full-width wire quantity directly. */
  constructor(size: Mebibytes | bigint) { this.total_mib = checkedUint(size, 64); }
  message(): EncodedMessage { return encodedMessage("control.memory.target", encodeRecord({ total_mib: this.total_mib })); }
  decode(frame: InboundFrame): MemoryState { return checked(frame, "control.memory.state", decodeMemoryState); }
  jsonRequest(): LegacyControlRequest { return { op: "memory_target", total_mib: this.total_mib }; }
  decodeJson(reply: JsonReply): MemoryState { return new GetMemoryState().decodeJson(reply); }
}
export class GetCpuState implements CheckedControlRequest<CpuState> {
  message(): EncodedMessage { return encodedMessage("control.cpu.state", encodeRecord({})); }
  decode(frame: InboundFrame): CpuState { return checked(frame, "control.cpu.state", decodeCpuState); }
  jsonRequest(): LegacyControlRequest { return { op: "cpu_state" }; }
  decodeJson(reply: JsonReply): CpuState { return reply.checked(value => jsonCpu(value.get("cpu"))); }
}
export class SetCpuTarget implements CheckedControlRequest<CpuState> {
  readonly online: number;
  constructor(online: number) { this.online = Number(checkedUint(online, 32)); }
  message(): EncodedMessage { return encodedMessage("control.cpu.target", encodeRecord({ online: this.online })); }
  decode(frame: InboundFrame): CpuState { return checked(frame, "control.cpu.state", decodeCpuState); }
  jsonRequest(): LegacyControlRequest { return { op: "cpu_target", online: this.online }; }
  decodeJson(reply: JsonReply): CpuState { return new GetCpuState().decodeJson(reply); }
}
export class UpdateSecrets implements CheckedControlRequest<SecretsResult> {
  readonly #changes: readonly SecretChange[];
  constructor(changes: readonly SecretChange[]) {
    // Snapshot the prepared batch so caller mutation cannot change the sent
    // entries or invalidate interpretation of partial progress after admission.
    this.#changes = snapshotChanges(changes);
  }
  message(): EncodedMessage { return encodedMessage("control.secrets.update", encodeRecord({ changes: this.#changes })); }
  jsonRequest(): LegacyControlRequest { return { op: "secrets_update", changes: snapshotChanges(this.#changes) }; }
  decodeJson(reply: JsonReply): SecretsResult {
    return reply.checked(() => ({ outcome: "complete", applied_count: this.#changes.length }));
  }
  decode(frame: InboundFrame): SecretsResult {
    return checked(frame, "control.secrets.result", bytes => {
      const result = decodeSecretsResult(bytes);
      if (result.outcome === "complete" ? result.applied_count !== this.#changes.length : result.failed_index >= this.#changes.length) throw new WireError("invalid_record");
      return result;
    });
  }
}
