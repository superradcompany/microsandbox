import { encodedMessage, encodeRecord, WireError, type EncodedMessage, type InboundFrame } from "@microsandbox/protocol-client";
import type { Mebibytes } from "@microsandbox/types/size";
import { ControlClientError } from "./error.js";
import {
  jsonBranch, jsonCapabilities, jsonCheckpoint, jsonCpu, jsonDiskCheckpoint,
  jsonDiskCompaction, jsonMemory, jsonPause, jsonRootDisk, jsonRuntimeCapabilities,
  type JsonReply,
} from "./json-reply.js";
import {
  snapshotChanges, type CheckedControlRequest, type CompatibleControlRequest,
  type ExtendedLegacyControlRequest, type LegacyControlRequest,
} from "./legacy-request.js";
import {
  CONTROL_GENERATION, checkedUint, decodeBranchResult, decodeCapabilities, decodeCheckpointResult,
  decodeControlError, decodeCpuState, decodeDiskCheckpointState, decodeDiskCompactionResult,
  decodeMemoryState, decodePauseState, decodeRootDiskState, decodeRuntimeCapabilities,
  decodeSecretsResult, type BranchCreate, type BranchResult, type Capabilities,
  type CheckpointCreate, type CheckpointResult, type CpuState, type DiskCheckpointCreate,
  type DiskCheckpointState, type DiskCompact, type DiskCompactionResult, type MemoryState,
  type Pause, type PauseState, type RootDiskGrow, type RootDiskState, type RuntimeCapabilities,
  type SecretChange, type SecretsResult,
} from "./records.js";

function checked<T>(frame: InboundFrame, name: string, decode: (bytes: Uint8Array) => T, minimum = 1): T {
  const invalid = () => new ControlClientError("invalid_response", frame);
  if (frame.protocolVersion < minimum || frame.protocolVersion > CONTROL_GENERATION || frame.id === 0 || frame.flags !== 1) throw invalid();
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
export class GetRuntimeCapabilities implements CompatibleControlRequest<RuntimeCapabilities> {
  readonly minGeneration = 2;
  message(): EncodedMessage { return encodedMessage("control.capabilities", encodeRecord({})); }
  decode(frame: InboundFrame): RuntimeCapabilities {
    return checked(frame, "control.capabilities.result", decodeRuntimeCapabilities, 2);
  }
  jsonRequest(): LegacyControlRequest { return { op: "capabilities" }; }
  decodeJson(reply: JsonReply): RuntimeCapabilities {
    return reply.checked(value => jsonRuntimeCapabilities(value.get("capabilities")));
  }
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

abstract class GenerationTwoRequest<T> implements CompatibleControlRequest<T> {
  readonly minGeneration = 2;
  abstract message(): EncodedMessage;
  abstract decode(frame: InboundFrame): T;
  abstract jsonRequest(): ExtendedLegacyControlRequest;
  abstract decodeJson(reply: JsonReply): T;
}

export class CreateCheckpoint extends GenerationTwoRequest<CheckpointResult> {
  readonly value: CheckpointCreate;
  constructor(value: CheckpointCreate) {
    super();
    const intent = value.intent;
    if (intent !== "full_snapshot" && intent !== "park" && intent !== "transparent_transfer") throw new WireError("invalid_record");
    this.value = {
      ...(value.guest_flush === undefined ? {} : { guest_flush: guestFlush(value.guest_flush) }),
      record_integrity: bool(value.record_integrity), checkpoint_id: text(value.checkpoint_id), intent,
    };
  }
  message(): EncodedMessage { return encodedMessage("control.checkpoint.create", encodeRecord(compact(this.value))); }
  decode(frame: InboundFrame): CheckpointResult {
    return checked(frame, "control.checkpoint.result", decodeCheckpointResult, 2);
  }
  jsonRequest(): ExtendedLegacyControlRequest { return { op: "checkpoint_create", ...this.value }; }
  decodeJson(reply: JsonReply): CheckpointResult {
    let checkpoint: CheckpointResult["checkpoint"];
    try { checkpoint = reply.value.has("checkpoint") ? jsonCheckpoint(reply.value.get("checkpoint")) : undefined; }
    catch { throw new ControlClientError("invalid_json_response", reply); }
    const ok = reply.value.get("ok");
    if (checkpoint && (ok === true || ok === false)) {
      const error = reply.value.get("error");
      if (error !== undefined && error !== null && typeof error !== "string") throw new ControlClientError("invalid_json_response", reply);
      return { checkpoint, ...(ok === false ? { recovery_error: typeof error === "string" ? error : "source recovery failed without a runtime diagnostic" } : {}) };
    }
    return reply.checked(() => { throw new ControlClientError("invalid_json_response", reply); });
  }
}

export class CreateDiskCheckpoint extends GenerationTwoRequest<DiskCheckpointState> {
  readonly value: DiskCheckpointCreate;
  constructor(value: DiskCheckpointCreate) {
    super();
    this.value = {
      ...(value.guest_flush === undefined ? {} : { guest_flush: guestFlush(value.guest_flush) }),
      checkpoint_id: text(value.checkpoint_id),
    };
  }
  message(): EncodedMessage { return encodedMessage("control.disk.checkpoint.create", encodeRecord(compact(this.value))); }
  decode(frame: InboundFrame): DiskCheckpointState {
    return checked(
      frame,
      "control.disk.checkpoint.result",
      bytes => decodeDiskCheckpointState(bytes, frame.decodePayload()),
      2,
    );
  }
  jsonRequest(): ExtendedLegacyControlRequest { return { op: "disk_checkpoint_create", ...this.value }; }
  decodeJson(reply: JsonReply): DiskCheckpointState {
    return reply.checked(value => jsonDiskCheckpoint(value.get("disk_checkpoint")));
  }
}

export class CreateBranch extends GenerationTwoRequest<BranchResult> {
  readonly value: BranchCreate;
  constructor(value: BranchCreate) {
    super();
    this.value = {
      ...(value.guest_flush === undefined ? {} : { guest_flush: guestFlush(value.guest_flush) }),
      record_integrity: bool(value.record_integrity), branch_id: text(value.branch_id),
      child_name: text(value.child_name), memory_cache_dir: text(value.memory_cache_dir),
    };
  }
  message(): EncodedMessage { return encodedMessage("control.branch.create", encodeRecord(compact(this.value))); }
  decode(frame: InboundFrame): BranchResult { return checked(frame, "control.branch.result", decodeBranchResult, 2); }
  jsonRequest(): ExtendedLegacyControlRequest { return { op: "branch_create", ...this.value }; }
  decodeJson(reply: JsonReply): BranchResult { return reply.checked(value => jsonBranch(value.get("branch"))); }
}

export class PauseRuntime extends GenerationTwoRequest<PauseState> {
  readonly value: Pause;
  constructor(value: Pause = {}) {
    super();
    this.value = value.guest_flush === undefined ? {} : { guest_flush: guestFlush(value.guest_flush) };
  }
  message(): EncodedMessage { return encodedMessage("control.pause", encodeRecord(compact(this.value))); }
  decode(frame: InboundFrame): PauseState { return checked(frame, "control.pause.state", decodePauseState, 2); }
  jsonRequest(): ExtendedLegacyControlRequest {
    return this.value.guest_flush === undefined
      ? { op: "pause" }
      : { op: "pause_with_guest_flush", guest_flush: this.value.guest_flush };
  }
  decodeJson(reply: JsonReply): PauseState { return reply.checked(value => jsonPause(value.get("pause"))); }
}

export class ResumeRuntime extends GenerationTwoRequest<PauseState> {
  message(): EncodedMessage { return encodedMessage("control.resume", encodeRecord({})); }
  decode(frame: InboundFrame): PauseState { return checked(frame, "control.pause.state", decodePauseState, 2); }
  jsonRequest(): ExtendedLegacyControlRequest { return { op: "resume" }; }
  decodeJson(reply: JsonReply): PauseState { return reply.checked(value => jsonPause(value.get("pause"))); }
}

export class GetPauseState extends GenerationTwoRequest<PauseState> {
  message(): EncodedMessage { return encodedMessage("control.pause.state", encodeRecord({})); }
  decode(frame: InboundFrame): PauseState { return checked(frame, "control.pause.state", decodePauseState, 2); }
  jsonRequest(): ExtendedLegacyControlRequest { return { op: "pause_state" }; }
  decodeJson(reply: JsonReply): PauseState { return reply.checked(value => jsonPause(value.get("pause"))); }
}

export class GrowRootDisk extends GenerationTwoRequest<RootDiskState> {
  readonly value: RootDiskGrow;
  constructor(sizeBytes: number | bigint) { super(); this.value = { size_bytes: checkedUint(sizeBytes, 64) }; }
  message(): EncodedMessage { return encodedMessage("control.root-disk.grow", encodeRecord(this.value)); }
  decode(frame: InboundFrame): RootDiskState { return checked(frame, "control.root-disk.state", decodeRootDiskState, 2); }
  jsonRequest(): ExtendedLegacyControlRequest { return { op: "root_disk_grow", ...this.value }; }
  decodeJson(reply: JsonReply): RootDiskState { return reply.checked(value => jsonRootDisk(value.get("root_disk"))); }
}

export class CompactDisks extends GenerationTwoRequest<DiskCompactionResult> {
  readonly value: DiskCompact;
  constructor(value: Omit<DiskCompact, "layers"> & { layers?: number | bigint }) {
    super();
    const target = value.target;
    const checkedTarget = target.kind === "all" || target.kind === "root"
      ? { kind: target.kind }
      : target.kind === "disk"
        ? { kind: "disk" as const, guest_path: text(target.guest_path) }
        : (() => { throw new WireError("invalid_record"); })();
    this.value = {
      target: checkedTarget, dry_run: bool(value.dry_run),
      ...(value.layers === undefined ? {} : { layers: checkedUint(value.layers, 64) }),
    };
  }
  message(): EncodedMessage { return encodedMessage("control.disk.compact", encodeRecord(compact(this.value))); }
  decode(frame: InboundFrame): DiskCompactionResult {
    return checked(frame, "control.disk.compact.result", decodeDiskCompactionResult, 2);
  }
  jsonRequest(): ExtendedLegacyControlRequest { return { op: "disk_compact", ...this.value }; }
  decodeJson(reply: JsonReply): DiskCompactionResult {
    return reply.checked(value => jsonDiskCompaction(value.get("compaction")));
  }
}

function compact<T extends object>(value: T): T {
  return Object.fromEntries(Object.entries(value).filter(([, field]) => field !== undefined)) as T;
}

function text(value: unknown): string {
  if (typeof value !== "string" || /[\uD800-\uDFFF]/u.test(value)) throw new WireError("invalid_record");
  return value;
}

function bool(value: unknown): boolean {
  if (typeof value !== "boolean") throw new WireError("invalid_record");
  return value;
}

function guestFlush(value: unknown): "auto" | "required" | "skip" {
  if (value !== "auto" && value !== "required" && value !== "skip") throw new WireError("invalid_record");
  return value;
}
