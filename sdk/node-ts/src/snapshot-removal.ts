import type { HeadUpdate } from "./snapshot.js";

/** Facts captured by one exact checkpoint removal under storage ownership. */
export interface CheckpointRemoveResult {
  readonly id: string;
  readonly headUpdate: HeadUpdate | null;
  readonly warnings: readonly string[];
}

/** The complete history removed by one confirmed publication. */
export interface SnapshotRemoveResult {
  readonly group: string;
  readonly removed: readonly string[];
  readonly headUpdate: HeadUpdate;
  readonly warnings: readonly string[];
}

/** @internal Success and committed-recovery errors use the same result projection. */
export function parseGroupRemoval(value: unknown): SnapshotRemoveResult {
  if (!value || typeof value !== "object") throw new TypeError("Invalid group removal result");
  const record = value as Record<string, unknown>;
  if (typeof record.group !== "string" || !Array.isArray(record.removed) ||
      !record.removed.every(id => typeof id === "string") || record.head_update == null) {
    throw new TypeError("Invalid group removal result");
  }
  const checked = parseCheckpointRemoval({ id: "", head_update: record.head_update, warnings: record.warnings });
  return { group: record.group, removed: [...record.removed], headUpdate: checked.headUpdate!, warnings: checked.warnings };
}

/** @internal Parse both successful results and committed-removal recovery errors. */
export function parseCheckpointRemoval(value: unknown): CheckpointRemoveResult {
  if (!value || typeof value !== "object") throw new TypeError("Invalid checkpoint removal result");
  const record = value as Record<string, unknown>;
  const head = record.head_update as Record<string, unknown> | null;
  if (typeof record.id !== "string" || !Array.isArray(record.warnings) ||
      !record.warnings.every((warning) => typeof warning === "string")) {
    throw new TypeError("Invalid checkpoint removal result");
  }
  if (head !== null && (!head || typeof head.group !== "string" ||
      !(head.previous === null || typeof head.previous === "string") ||
      !(head.head === null || typeof head.head === "string") ||
      typeof head.reason !== "string" || typeof head.changed !== "boolean")) {
    throw new TypeError("Invalid checkpoint removal head outcome");
  }
  return { id: record.id, headUpdate: head as HeadUpdate | null, warnings: record.warnings as string[] };
}
