import { UnsupportedOperationError } from "./errors.js";
import { withMappedErrors } from "./internal/error-mapping.js";
import { napi } from "./internal/napi.js";

export interface StorageRecoverySelection { diskId: string; candidateId: string }
export interface StorageRecoveryOptions {
  selections?: readonly StorageRecoverySelection[];
  acceptSelectedView?: boolean;
  /** macOS: all legacy VMs across homes are stopped, and no new writers may start during recovery. */
  legacyWritersStopped?: boolean;
}
export interface StorageRecovery { name: string; ready: boolean; originalsRetained: boolean }

/** Shared wrapper for Sandbox.recoverStorage; the native SDK owns all locking and revalidation. */
export async function recoverStorage(name: string, options: StorageRecoveryOptions = {}): Promise<StorageRecovery> {
  if (!napi.Sandbox.recoverStorage) throw new UnsupportedOperationError("storage recovery requires an updated native SDK; upgrade or rebuild it");
  const result = JSON.parse(await withMappedErrors(() => napi.Sandbox.recoverStorage!(name, JSON.stringify({
    selections: (options.selections ?? []).map(item => ({ disk_id: item.diskId, candidate_id: item.candidateId })),
    accept_selected_view: options.acceptSelectedView ?? false,
    legacy_writers_stopped: options.legacyWritersStopped ?? false,
  })))) as { name: string; ready: boolean; originals_retained: boolean };
  return { name: result.name, ready: result.ready, originalsRetained: result.originals_retained };
}
