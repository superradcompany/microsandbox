import {
  MAX_FRAME_SIZE, WireError, readArray, readBool, readRecord, readText, readUint, required,
} from "@microsandbox/protocol-client";

export const MIN_CONTROL_GENERATION = 1;
export const CONTROL_GENERATION = 2;
/** Hello and welcome envelopes keep their generation-one bootstrap encoding. */
export const CONTROL_HANDSHAKE_GENERATION = 1;
export const CONTROL_PROTOCOL = "msb.control";
export const MAX_HANDSHAKE_FRAME_SIZE = 4096;
export const DEFAULT_MAX_IN_FLIGHT = 64;
export const DEFAULT_SETUP_TIMEOUT_MS = 10_000;
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;
/** Application messages introduced by framed control generation two. */
export const CONTROL_GENERATION_TWO_MESSAGES = [
  "control.checkpoint.create", "control.checkpoint.result",
  "control.disk.checkpoint.create", "control.disk.checkpoint.result",
  "control.branch.create", "control.branch.result", "control.pause", "control.resume",
  "control.pause.state", "control.root-disk.grow", "control.root-disk.state",
  "control.disk.compact", "control.disk.compact.result",
] as const;

export type ControlHello = {
  protocol: string; min_generation: number; max_generation: number;
  max_frame_size: number; max_in_flight: number;
};
export type ControlWelcome = {
  protocol: string; generation: number; max_frame_size: number; max_in_flight: number;
};
export type Capabilities = { root_disk_grow?: boolean; cpu_resize: boolean; memory_resize: boolean; secrets_update: boolean };
export type RuntimeCapabilities = Capabilities & {
  guest_flush_policy?: boolean; optional_disk_integrity?: boolean; branch_create?: boolean;
  branch_memfd?: boolean; pause_resume?: boolean; disk_compact?: boolean;
  disk_compact_owned?: boolean; checkpoint_create?: boolean; disk_checkpoint_create?: boolean;
};
/** Every memory observation is bigint, including zero and small values. */
export type MemoryState = { boot_mib: bigint; target_mib: bigint; current_mib: bigint; max_mib: bigint };
export type MemoryTarget = { total_mib: bigint };
export type CpuState = { possible: number; requested_online: number; actual_online: number; enforced: number };
export type CpuTarget = { online: number };
export type SecretChange =
  | { change: "rotate"; name: string; value: string }
  | { change: "remove"; name: string }
  | { change: "set_allowed_hosts"; name: string; hosts: readonly string[] };
export type SecretsUpdate = { changes: readonly SecretChange[] };
export type ErrorEffect = "none" | "unknown";
export type ControlError = { code: string; message: string; effect: ErrorEffect };
export type SecretsResult =
  | { outcome: "complete"; applied_count: number }
  | { outcome: "failed"; applied_count: number; failed_index: number; error: ControlError };
export type GuestFlush = "auto" | "required" | "skip";
export type CheckpointCaptureIntent = "full_snapshot" | "park" | "transparent_transfer";
export type CheckpointCreate = {
  guest_flush?: GuestFlush; record_integrity: boolean; checkpoint_id: string;
  intent: CheckpointCaptureIntent;
};
export type CheckpointState = {
  checkpoint_id: string; checkpoint_root: string; path: string; memory_mode: string;
  memory_logical_bytes: bigint; memory_emitted_bytes: bigint;
};
export type CheckpointResult = { checkpoint?: CheckpointState; recovery_error?: string };
export type DiskCheckpointCreate = { guest_flush?: GuestFlush; checkpoint_id: string };
export type DiskCheckpointState = {
  checkpoint_id: string; path: string; disk: unknown; owned_volumes: readonly unknown[];
};
export type BranchCreate = {
  guest_flush?: GuestFlush; record_integrity: boolean; branch_id: string;
  child_name: string; memory_cache_dir: string;
};
export type BranchResult = { path: string };
export type Pause = { guest_flush?: GuestFlush };
export type PauseState = { paused: boolean; recovery_required: boolean; capture_unavailable?: string };
export type RootDiskGrow = { size_bytes: bigint };
export type RootDiskState = {
  filesystem_bytes: bigint; device_bytes: bigint; total_us: bigint; pause_us: bigint; guest_us: bigint;
};
export type DiskCompactionTarget =
  | { kind: "all" }
  | { kind: "root" }
  | { kind: "disk"; guest_path: string };
export type DiskCompact = { target: DiskCompactionTarget; layers?: bigint; dry_run: boolean };
export type DiskCompactionDiskResult = {
  guest_path: string; input_layers: bigint; selected_layers: bigint; output_layers: bigint;
  materialized_bytes: bigint; total_us: bigint;
};
export type DiskCompactionResult = {
  dry_run: boolean; input_layers: bigint; selected_layers: bigint; output_layers: bigint;
  materialized_bytes: bigint; total_us: bigint; pause_us: bigint;
  disks: readonly DiskCompactionDiskResult[];
};

/** Names are a convenience; open native/encoded message names remain supported. */
export const ControlMessageType = {
  Hello: "control.hello", Welcome: "control.welcome", Capabilities: "control.capabilities",
  CapabilitiesResult: "control.capabilities.result", MemoryState: "control.memory.state",
  MemoryTarget: "control.memory.target", CpuState: "control.cpu.state", CpuTarget: "control.cpu.target",
  SecretsUpdate: "control.secrets.update", SecretsResult: "control.secrets.result", Error: "control.error",
  CheckpointCreate: "control.checkpoint.create", CheckpointResult: "control.checkpoint.result",
  DiskCheckpointCreate: "control.disk.checkpoint.create", DiskCheckpointResult: "control.disk.checkpoint.result",
  BranchCreate: "control.branch.create", BranchResult: "control.branch.result",
  Pause: "control.pause", Resume: "control.resume", PauseState: "control.pause.state",
  RootDiskGrow: "control.root-disk.grow", RootDiskState: "control.root-disk.state",
  DiskCompact: "control.disk.compact", DiskCompactResult: "control.disk.compact.result",
} as const;

type Fields = Map<string, Uint8Array>;
const uint = (fields: Fields, name: string, bits: 8 | 32 = 32): number => Number(readUint(required(fields, name), bits));
const text = (fields: Fields, name: string): string => readText(required(fields, name));

/** Validate native quantities before conversion or encoding; never silently round. */
export function checkedUint(value: number | bigint, bits: 8 | 32 | 64): bigint {
  if (typeof value !== "bigint" && (typeof value !== "number" || !Number.isSafeInteger(value))) throw new WireError("invalid_record");
  const integer = BigInt(value);
  if (integer < 0n || integer >= (1n << BigInt(bits))) throw new WireError("invalid_record");
  return integer;
}

function validateLimits(frame: number, inFlight: number): void {
  checkedUint(frame, 32); checkedUint(inFlight, 32);
  if (frame < MAX_HANDSHAKE_FRAME_SIZE || frame > MAX_FRAME_SIZE || inFlight < 1) throw new WireError("invalid_record");
}

export function validateHello(hello: ControlHello): void {
  checkedUint(hello.min_generation, 8); checkedUint(hello.max_generation, 8);
  validateLimits(hello.max_frame_size, hello.max_in_flight);
  if (hello.protocol !== CONTROL_PROTOCOL || hello.min_generation < 1 || hello.min_generation > hello.max_generation) throw new WireError("invalid_record");
}

export function decodeHello(bytes: Uint8Array): ControlHello {
  const fields = readRecord(bytes);
  const hello = {
    protocol: text(fields, "protocol"), min_generation: uint(fields, "min_generation", 8),
    max_generation: uint(fields, "max_generation", 8), max_frame_size: uint(fields, "max_frame_size"),
    max_in_flight: uint(fields, "max_in_flight"),
  };
  validateHello(hello);
  return hello;
}

export function decodeWelcome(bytes: Uint8Array, hello?: ControlHello): ControlWelcome {
  const fields = readRecord(bytes);
  const welcome = {
    protocol: text(fields, "protocol"), generation: uint(fields, "generation", 8),
    max_frame_size: uint(fields, "max_frame_size"), max_in_flight: uint(fields, "max_in_flight"),
  };
  validateLimits(welcome.max_frame_size, welcome.max_in_flight);
  if (welcome.protocol !== CONTROL_PROTOCOL || welcome.generation < 1) throw new WireError("invalid_record");
  if (hello && (welcome.generation < hello.min_generation || welcome.generation > hello.max_generation
      || welcome.max_frame_size > hello.max_frame_size || welcome.max_in_flight > hello.max_in_flight)) throw new WireError("invalid_record");
  return welcome;
}

export function decodeCapabilities(bytes: Uint8Array): Capabilities {
  const fields = readRecord(bytes);
  return { ...(fields.has("root_disk_grow") ? { root_disk_grow: readBool(required(fields, "root_disk_grow")) } : {}), cpu_resize: readBool(required(fields, "cpu_resize")), memory_resize: readBool(required(fields, "memory_resize")), secrets_update: readBool(required(fields, "secrets_update")) };
}
export function decodeRuntimeCapabilities(bytes: Uint8Array): RuntimeCapabilities {
  const fields = readRecord(bytes);
  const optional = (name: string): boolean => fields.has(name) ? readBool(required(fields, name)) : false;
  return {
    root_disk_grow: optional("root_disk_grow"), guest_flush_policy: optional("guest_flush_policy"),
    optional_disk_integrity: optional("optional_disk_integrity"), branch_create: optional("branch_create"),
    branch_memfd: optional("branch_memfd"), pause_resume: optional("pause_resume"),
    disk_compact: optional("disk_compact"), disk_compact_owned: optional("disk_compact_owned"),
    cpu_resize: readBool(required(fields, "cpu_resize")), memory_resize: readBool(required(fields, "memory_resize")),
    secrets_update: readBool(required(fields, "secrets_update")), checkpoint_create: optional("checkpoint_create"),
    disk_checkpoint_create: optional("disk_checkpoint_create"),
  };
}
export function decodeMemoryState(bytes: Uint8Array): MemoryState {
  const fields = readRecord(bytes);
  return {
    boot_mib: readUint(required(fields, "boot_mib"), 64), target_mib: readUint(required(fields, "target_mib"), 64),
    current_mib: readUint(required(fields, "current_mib"), 64), max_mib: readUint(required(fields, "max_mib"), 64),
  };
}
export function decodeCpuState(bytes: Uint8Array): CpuState {
  const fields = readRecord(bytes);
  return { possible: uint(fields, "possible"), requested_online: uint(fields, "requested_online"), actual_online: uint(fields, "actual_online"), enforced: uint(fields, "enforced") };
}
export function decodeControlError(bytes: Uint8Array): ControlError {
  const fields = readRecord(bytes);
  const effect = text(fields, "effect");
  if (effect !== "none" && effect !== "unknown") throw new WireError("invalid_record");
  return { code: text(fields, "code"), message: text(fields, "message"), effect };
}
export function decodeSecretsResult(bytes: Uint8Array): SecretsResult {
  const fields = readRecord(bytes), outcome = text(fields, "outcome"), applied_count = uint(fields, "applied_count");
  if (outcome === "complete") return { outcome, applied_count };
  if (outcome !== "failed") throw new WireError("invalid_record");
  const failed_index = uint(fields, "failed_index");
  if (failed_index !== applied_count) throw new WireError("invalid_record");
  // Check the actual nested record before a library decoder can collapse keys.
  return { outcome, applied_count, failed_index, error: decodeControlError(required(fields, "error")) };
}
export function decodeSecretsUpdate(bytes: Uint8Array): SecretsUpdate {
  const fields = readRecord(bytes);
  const changes = readArray(required(fields, "changes")).map(bytes => {
    const entry = readRecord(bytes), change = text(entry, "change"), name = text(entry, "name");
    switch (change) {
      case "rotate": return { change, name, value: text(entry, "value") };
      case "remove": return { change, name };
      case "set_allowed_hosts": return { change, name, hosts: readArray(required(entry, "hosts")).map(readText) };
      default: throw new WireError("invalid_record");
    }
  });
  return { changes };
}

export function decodeCheckpointResult(bytes: Uint8Array): CheckpointResult {
  const fields = readRecord(bytes);
  const result: CheckpointResult = {};
  if (fields.has("checkpoint")) {
    const checkpoint = readRecord(required(fields, "checkpoint"));
    result.checkpoint = {
      checkpoint_id: text(checkpoint, "checkpoint_id"), checkpoint_root: text(checkpoint, "checkpoint_root"),
      path: text(checkpoint, "path"), memory_mode: text(checkpoint, "memory_mode"),
      memory_logical_bytes: readUint(required(checkpoint, "memory_logical_bytes"), 64),
      memory_emitted_bytes: readUint(required(checkpoint, "memory_emitted_bytes"), 64),
    };
  }
  if (fields.has("recovery_error")) result.recovery_error = text(fields, "recovery_error");
  return result;
}

export function decodeDiskCheckpointState(bytes: Uint8Array, decoded?: unknown): DiskCheckpointState {
  const fields = readRecord(bytes);
  if (decoded === null || typeof decoded !== "object" || Array.isArray(decoded)) throw new WireError("invalid_record");
  const value = decoded as Record<string, unknown>;
  if (!("disk" in value) || (value.owned_volumes !== undefined && !Array.isArray(value.owned_volumes))) {
    throw new WireError("invalid_record");
  }
  return {
    checkpoint_id: text(fields, "checkpoint_id"), path: text(fields, "path"),
    disk: value.disk, owned_volumes: value.owned_volumes ?? [],
  };
}

export function decodeBranchResult(bytes: Uint8Array): BranchResult {
  return { path: text(readRecord(bytes), "path") };
}

export function decodePauseState(bytes: Uint8Array): PauseState {
  const fields = readRecord(bytes);
  return {
    paused: readBool(required(fields, "paused")),
    recovery_required: readBool(required(fields, "recovery_required")),
    ...(fields.has("capture_unavailable") ? { capture_unavailable: text(fields, "capture_unavailable") } : {}),
  };
}

export function decodeRootDiskState(bytes: Uint8Array): RootDiskState {
  const fields = readRecord(bytes);
  return {
    filesystem_bytes: readUint(required(fields, "filesystem_bytes"), 64),
    device_bytes: readUint(required(fields, "device_bytes"), 64), total_us: readUint(required(fields, "total_us"), 64),
    pause_us: readUint(required(fields, "pause_us"), 64), guest_us: readUint(required(fields, "guest_us"), 64),
  };
}

export function decodeDiskCompactionResult(bytes: Uint8Array): DiskCompactionResult {
  const fields = readRecord(bytes);
  const disks = readArray(required(fields, "disks")).map(bytes => {
    const disk = readRecord(bytes);
    return {
      guest_path: text(disk, "guest_path"), input_layers: readUint(required(disk, "input_layers"), 64),
      selected_layers: readUint(required(disk, "selected_layers"), 64),
      output_layers: readUint(required(disk, "output_layers"), 64),
      materialized_bytes: readUint(required(disk, "materialized_bytes"), 64),
      total_us: readUint(required(disk, "total_us"), 64),
    };
  });
  return {
    dry_run: readBool(required(fields, "dry_run")), input_layers: readUint(required(fields, "input_layers"), 64),
    selected_layers: readUint(required(fields, "selected_layers"), 64),
    output_layers: readUint(required(fields, "output_layers"), 64),
    materialized_bytes: readUint(required(fields, "materialized_bytes"), 64),
    total_us: readUint(required(fields, "total_us"), 64), pause_us: readUint(required(fields, "pause_us"), 64), disks,
  };
}
