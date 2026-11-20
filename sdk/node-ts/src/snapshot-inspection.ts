/** Source availability at inspection time; it does not certify future capture readiness. */
export type SnapshotSourceStatus = "available" | "missing_sandbox" | "different_catalog";

export interface SnapshotSourceBinding {
  readonly databaseUuid: string;
  readonly sandboxId: number;
  readonly recordedName: string;
  readonly currentName: string | null;
  readonly status: SnapshotSourceStatus;
}

/** One coherent group metadata read. An unbound history has source=null. */
export interface SnapshotGroupInfo {
  readonly name: string;
  readonly path: string;
  readonly head: string | null;
  readonly checkpointCount: number;
  readonly source: SnapshotSourceBinding | null;
}

/** @internal Native absence is explicit; malformed bindings must not become unbound histories. */
export function parseGroupInfo(value: unknown): SnapshotGroupInfo {
  const invalid = () => new TypeError("Invalid native snapshot group inspection");
  if (!value || typeof value !== "object") throw invalid();
  const info = value as Record<string, unknown>;
  if (typeof info.name !== "string" || typeof info.path !== "string" ||
      !(info.head === null || typeof info.head === "string") ||
      !Number.isSafeInteger(info.checkpoint_count) || (info.checkpoint_count as number) < 0) throw invalid();
  let source: SnapshotSourceBinding | null = null;
  if (info.source !== null) {
    if (!info.source || typeof info.source !== "object") throw invalid();
    const binding = info.source as Record<string, unknown>;
    if (typeof binding.database_uuid !== "string" || !Number.isInteger(binding.sandbox_id) ||
        (binding.sandbox_id as number) <= 0 || typeof binding.recorded_name !== "string" ||
        !["available", "missing_sandbox", "different_catalog"].includes(binding.status as string) ||
        !(binding.current_name === null || typeof binding.current_name === "string") ||
        (binding.status === "available") !== (typeof binding.current_name === "string")) throw invalid();
    source = { databaseUuid: binding.database_uuid, sandboxId: binding.sandbox_id as number,
      recordedName: binding.recorded_name, currentName: binding.current_name as string | null,
      status: binding.status as SnapshotSourceStatus };
  }
  return { name: info.name, path: info.path, head: info.head as string | null,
    checkpointCount: info.checkpoint_count as number, source };
}
