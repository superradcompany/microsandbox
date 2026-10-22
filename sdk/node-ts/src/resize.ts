import {
  modificationPlanFromJson,
  type ResourceResizeStatus,
  type SandboxModificationPlan,
} from "./modify.js";

/** Operation ownership, separate from resource convergence. */
export type ResizeOutcome = "pending" | "applied" | "superseded";

/** Availability of authoritative evidence for the latest operation read. */
export type ResizeObservation = "available" | "unsupported" | "paused" | "unavailable";

/** Accepted or requested capacity. Arbitrary u64 quantities stay lossless. */
export type ResizeTarget =
  | { resource: "cpus"; online: number }
  | { resource: "memory"; totalMib: bigint };

/** Retained operation identity. Caller-supplied status is never proof of completion. */
export interface ResizeOperation {
  id: string;
  runtimeBootId: string;
  generation: bigint;
  requestedTarget: ResizeTarget;
  acceptedTarget: ResizeTarget;
  status: ResourceResizeStatus;
  outcome: ResizeOutcome;
  observation: ResizeObservation;
}

/** A modification's ordinary plan and its exact tracked live requests, if any. */
export interface SandboxModificationResult {
  plan: SandboxModificationPlan;
  /** Null for dry runs, non-live changes and supported changes through older runtimes. */
  resizeOperations: ResizeOperation[] | null;
}

// Only this private native JSON boundary uses decimal strings. Never let JSON.parse
// round a generation or memory target before constructing the public bigint value.
type WireTarget = { resource: "cpus"; online: number } | { resource: "memory"; total_mib: string };
interface WireOperation {
  id: string;
  runtime_boot_id: string;
  generation: string;
  requested_target: WireTarget;
  accepted_target: WireTarget;
  status: ResourceResizeStatus;
  outcome: ResizeOutcome;
  observation: ResizeObservation;
}

const MAX_U64 = (1n << 64n) - 1n;

export function resizeOperationsFromJson(raw: string): ResizeOperation[] {
  const values: WireOperation[] = JSON.parse(raw);
  return values.map(operationFromWire);
}

export function modificationResultFromJson(raw: string): SandboxModificationResult {
  const value = JSON.parse(raw);
  return {
    plan: modificationPlanFromJson(JSON.stringify(value.plan)),
    resizeOperations: value.resize_operations === null
      ? null
      : (value.resize_operations as WireOperation[]).map(operationFromWire),
  };
}

/** Validate and encode before any native dispatch. The Rust waiter revalidates authority. */
export function resizeOperationsToJson(operations: readonly ResizeOperation[]): string {
  if (!Array.isArray(operations) || operations.length === 0 || operations.length > 2) {
    throw new TypeError("expected one or two resize operations");
  }
  return JSON.stringify(operations.map((operation): WireOperation => ({
    id: operation.id,
    runtime_boot_id: operation.runtimeBootId,
    generation: exactU64(operation.generation, "generation").toString(),
    requested_target: targetToWire(operation.requestedTarget),
    accepted_target: targetToWire(operation.acceptedTarget),
    status: operation.status,
    outcome: operation.outcome,
    observation: operation.observation,
  })));
}

function operationFromWire(operation: WireOperation): ResizeOperation {
  return {
    id: operation.id,
    runtimeBootId: operation.runtime_boot_id,
    generation: fromDecimal(operation.generation, "generation"),
    requestedTarget: targetFromWire(operation.requested_target),
    acceptedTarget: targetFromWire(operation.accepted_target),
    status: operation.status,
    outcome: operation.outcome,
    observation: operation.observation,
  };
}

function targetFromWire(target: WireTarget): ResizeTarget {
  return target.resource === "memory"
    ? { resource: "memory", totalMib: fromDecimal(target.total_mib, "totalMib") }
    : { resource: "cpus", online: target.online };
}

function targetToWire(target: ResizeTarget): WireTarget {
  if (target.resource === "memory") {
    return { resource: "memory", total_mib: exactU64(target.totalMib, "totalMib").toString() };
  }
  if (target.resource !== "cpus" || !Number.isInteger(target.online)
      || target.online < 0 || target.online > 0xffffffff) {
    throw new TypeError("CPU resize target must contain an unsigned 32-bit online count");
  }
  return { resource: "cpus", online: target.online };
}

function exactU64(value: bigint, field: string): bigint {
  if (typeof value !== "bigint" || value < 0n || value > MAX_U64) {
    throw new TypeError(`${field} must be an unsigned 64-bit bigint`);
  }
  return value;
}

function fromDecimal(value: string, field: string): bigint {
  if (typeof value !== "string" || !/^(0|[1-9][0-9]*)$/.test(value)) {
    throw new TypeError(`${field} must be an exact decimal string from the native library`);
  }
  return exactU64(BigInt(value), field);
}
