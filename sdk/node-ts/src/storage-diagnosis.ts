import { UnsupportedOperationError } from "./errors.js";
import { withMappedErrors } from "./internal/error-mapping.js";
import { napi } from "./internal/napi.js";
import type { RuntimeConfig } from "./setup.js";

/** Select named sandboxes or explicitly the complete configured home. */
export type StorageSelection = { names: readonly string[]; allSandboxes?: never } | { allSandboxes: true; names?: never };
export type StorageDiagnosticStatus = "ready" | "eligible" | "maintenance_required" | "recovery_required" | "in_progress" | "unavailable";

/** Disk candidates remain provisional and cannot authorize migration. */
export interface StorageCandidate {
  id: string;
  diskId: string;
  layers: number;
  virtualSize: bigint;
  estimatedBytes: bigint;
}
export interface StorageInspection {
  status: "ready" | "eligible" | "recovery-required" | "in-progress";
  reasons: string[];
  candidates: StorageCandidate[];
  previewAvailable: boolean;
  estimatedBytes: bigint;
}
export interface StorageSandboxDiagnosis {
  name: string;
  status: StorageDiagnosticStatus;
  running: boolean;
  protectionRegistered: boolean;
  guestMounts: Record<string, string>;
  reason: string | null;
  inspection: StorageInspection | null;
}
export interface StorageDiagnosis {
  home: string;
  sandboxes: StorageSandboxDiagnosis[];
  requiredRuntimeCapability: string;
}

/** Inspect storage without backend initialization or catalog/disk changes. SQLite may
 * maintain read-lock WAL sidecars. No runtime is downloaded, started, or stopped. */
export async function diagnoseStorage(selection: StorageSelection, config: RuntimeConfig = {}): Promise<StorageDiagnosis> {
  if ((selection.names !== undefined) === (selection.allSandboxes === true) || selection.names?.length === 0) {
    throw new TypeError("select sandbox names or allSandboxes: true, exclusively");
  }
  if (!napi.diagnoseStorage) {
    throw new UnsupportedOperationError("storage diagnostics require an updated native SDK; upgrade or rebuild the microsandbox native package");
  }
  const json = await withMappedErrors(() => napi.diagnoseStorage!(JSON.stringify({
    home: config.home, msb_path: config.msbPath, libkrunfw_path: config.libkrunfwPath,
  }), JSON.stringify(selection.allSandboxes ? "all" : { named: selection.names })));
  const report = JSON.parse(json) as WireReport;
  return {
    home: report.home,
    requiredRuntimeCapability: report.required_runtime_capability,
    sandboxes: report.sandboxes.map(item => ({
      name: item.name, status: item.status, running: item.running,
      protectionRegistered: item.protection_registered, reason: item.reason,
      guestMounts: item.guest_mounts ?? {},
      inspection: item.inspection === null ? null : {
        status: item.inspection.status, reasons: item.inspection.reasons,
        estimatedBytes: exactBytes(item.inspection.estimated_bytes),
        previewAvailable: item.inspection.preview_available ?? false,
        candidates: item.inspection.candidates.map(candidate => ({
          id: candidate.id, diskId: candidate.disk_id, layers: candidate.layers,
          virtualSize: exactBytes(candidate.virtual_size), estimatedBytes: exactBytes(candidate.estimated_bytes),
        })),
      },
    })),
  };
}

function exactBytes(value: string): bigint {
  if (!/^(0|[1-9][0-9]{0,19})$/.test(value)) {
    throw new RangeError("invalid storage diagnostic byte count");
  }
  const bytes = BigInt(value);
  if (bytes > 2n ** 64n - 1n) throw new RangeError("storage byte count exceeds u64");
  return bytes;
}
interface WireReport {
  home: string;
  required_runtime_capability: string;
  sandboxes: Array<{
    name: string; status: StorageDiagnosticStatus; running: boolean;
    protection_registered: boolean; guest_mounts?: Record<string, string>; reason: string | null;
    inspection: null | { status: StorageInspection["status"]; reasons: string[]; estimated_bytes: string; preview_available?: boolean;
      candidates: Array<{ id: string; disk_id: string; layers: number; virtual_size: string; estimated_bytes: string }> };
  }>;
}
