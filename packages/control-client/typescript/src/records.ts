import {
  MAX_FRAME_SIZE, WireError, readArray, readBool, readRecord, readText, readUint, required,
} from "@microsandbox/protocol-client";

export const CONTROL_GENERATION = 1;
export const CONTROL_PROTOCOL = "msb.control";
export const MAX_HANDSHAKE_FRAME_SIZE = 4096;
export const DEFAULT_MAX_IN_FLIGHT = 64;
export const DEFAULT_SETUP_TIMEOUT_MS = 10_000;
export const DEFAULT_REQUEST_TIMEOUT_MS = 30_000;

export type ControlHello = {
  protocol: string; min_generation: number; max_generation: number;
  max_frame_size: number; max_in_flight: number;
};
export type ControlWelcome = {
  protocol: string; generation: number; max_frame_size: number; max_in_flight: number;
};
export type Capabilities = { root_disk_grow?: boolean; cpu_resize: boolean; memory_resize: boolean; secrets_update: boolean };
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

/** Names are a convenience; open native/encoded message names remain supported. */
export const ControlMessageType = {
  Hello: "control.hello", Welcome: "control.welcome", Capabilities: "control.capabilities",
  CapabilitiesResult: "control.capabilities.result", MemoryState: "control.memory.state",
  MemoryTarget: "control.memory.target", CpuState: "control.cpu.state", CpuTarget: "control.cpu.target",
  SecretsUpdate: "control.secrets.update", SecretsResult: "control.secrets.result", Error: "control.error",
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
