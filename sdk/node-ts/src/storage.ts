import { withMappedErrors } from "./internal/error-mapping.js";
import { napi } from "./internal/napi.js";
import { UnsupportedOperationError } from "./errors.js";
import type {
  NapiMemoryCacheEntry,
  NapiStorageCategoryUsage,
  NapiStorageItemUsage,
} from "./internal/napi.js";

/** Storage observations use logical bytes, not exclusive physical ownership. */
export interface StorageUsage {
  readonly images: StorageCategoryUsage;
  readonly snapshots: StorageCategoryUsage;
  readonly sandboxes: StorageCategoryUsage;
  readonly volumes: StorageCategoryUsage;
  readonly branchMemory: StorageCategoryUsage;
  readonly snapshotMemory: StorageCategoryUsage;
  readonly notes: readonly string[];
}

/** Unknown values are null. Allocated blocks may include shared CoW extents. */
export interface StorageCategoryUsage {
  readonly count: number | null;
  readonly inUse: number | null;
  readonly logicalBytes: bigint | null;
  readonly allocatedBytes: bigint | null;
  readonly reclaimableLogicalBytes: bigint | null;
  readonly items: readonly StorageItemUsage[];
  readonly notes: readonly string[];
}

export interface StorageItemUsage {
  readonly name: string;
  readonly path: string;
  readonly logicalBytes: bigint | null;
  readonly allocatedBytes: bigint | null;
  readonly inUse: boolean | null;
  readonly reclaimable: boolean | null;
  readonly reasons: readonly string[];
}

export type MemoryCacheKind = NapiMemoryCacheEntry["kind"];
export type MemoryCacheState = NapiMemoryCacheEntry["state"];

export interface MemoryCacheEntry {
  readonly path: string;
  readonly kind: MemoryCacheKind;
  readonly logicalBytes: bigint | null;
  readonly allocatedBytes: bigint | null;
  readonly state: MemoryCacheState;
  readonly error: string | null;
}

/** Per-file failures are retained in entries even if other files were removed. */
export interface MemoryCacheReport {
  readonly dryRun: boolean;
  readonly entries: readonly MemoryCacheEntry[];
  readonly filesRemoved: number;
  readonly logicalBytesRemoved: bigint;
  readonly physicalBytesReclaimed: bigint | null;
  readonly truncated: boolean;
}

export interface StoragePruneOptions {
  /** Inspect eligibility without removing any file. Defaults to false. */
  readonly dryRun?: boolean;
  /** Minimum file age, in whole non-negative seconds. Defaults to zero. */
  readonly olderThanSeconds?: number;
}

export class Storage {
  /**
   * Observe the selected local backend's managed storage without cleanup.
   * Byte fields are exact bigints; unknown measurements are null.
   */
  static async usage(): Promise<StorageUsage> {
    const usage = napi.storageUsage;
    if (!usage) {
      throw missingBinding("Storage.usage()");
    }
    const raw = await withMappedErrors(() => usage());
    return {
      images: categoryFromNapi(raw.images),
      snapshots: categoryFromNapi(raw.snapshots),
      sandboxes: categoryFromNapi(raw.sandboxes),
      volumes: categoryFromNapi(raw.volumes),
      branchMemory: categoryFromNapi(raw.branchMemory),
      snapshotMemory: categoryFromNapi(raw.snapshotMemory),
      notes: raw.notes,
    };
  }

  /**
   * Remove unused published runtime RAM, or preview with dryRun: true.
   * Snapshots, sandbox disks, volumes, images, and stable locks are retained.
   * Per-file failures are reported in entries; inspect them after every run.
   */
  static async prune(opts: StoragePruneOptions = {}): Promise<MemoryCacheReport> {
    if (opts.dryRun !== undefined && typeof opts.dryRun !== "boolean") {
      throw new TypeError("dryRun must be a boolean");
    }
    if (opts.olderThanSeconds !== undefined &&
        (!Number.isSafeInteger(opts.olderThanSeconds) || opts.olderThanSeconds < 0)) {
      throw new RangeError("olderThanSeconds must be a non-negative safe integer");
    }
    const prune = napi.storagePrune;
    if (!prune) {
      throw missingBinding("Storage.prune()");
    }
    const raw = await withMappedErrors(() => prune(opts.dryRun, opts.olderThanSeconds));
    return {
      dryRun: raw.dryRun,
      entries: raw.entries.map((entry) => ({
        path: entry.path,
        kind: entry.kind,
        logicalBytes: entry.logicalBytes ?? null,
        allocatedBytes: entry.allocatedBytes ?? null,
        state: entry.state,
        error: entry.error ?? null,
      })),
      filesRemoved: safeNumber(raw.filesRemoved),
      logicalBytesRemoved: raw.logicalBytesRemoved,
      physicalBytesReclaimed: raw.physicalBytesReclaimed ?? null,
      truncated: raw.truncated,
    };
  }
}

function categoryFromNapi(raw: NapiStorageCategoryUsage): StorageCategoryUsage {
  return {
    count: optionalNumber(raw.count),
    inUse: optionalNumber(raw.inUse),
    logicalBytes: raw.logicalBytes ?? null,
    allocatedBytes: raw.allocatedBytes ?? null,
    reclaimableLogicalBytes: raw.reclaimableLogicalBytes ?? null,
    items: raw.items.map(itemFromNapi),
    notes: raw.notes,
  };
}

function itemFromNapi(raw: NapiStorageItemUsage): StorageItemUsage {
  return {
    name: raw.name,
    path: raw.path,
    logicalBytes: raw.logicalBytes ?? null,
    allocatedBytes: raw.allocatedBytes ?? null,
    inUse: raw.inUse ?? null,
    reclaimable: raw.reclaimable ?? null,
    reasons: raw.reasons,
  };
}

/** @internal Observe a captured native handle without re-resolving the default backend. */
export async function storageUsageFromHandle(
  inner: { storageUsage?: () => Promise<NapiStorageItemUsage> },
  operation: string,
): Promise<StorageItemUsage> {
  const usage = inner.storageUsage;
  if (!usage) {
    throw missingBinding(operation);
  }
  // N-API instance methods require the original receiver, even when extracted for checking.
  return itemFromNapi(await withMappedErrors(() => usage.call(inner)));
}

function optionalNumber(value: number | null | undefined): number | null {
  return value == null ? null : safeNumber(value);
}

function safeNumber(value: number): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError("storage count is outside JavaScript's non-negative safe integer range");
  }
  return value;
}

function missingBinding(operation: string): UnsupportedOperationError {
  return new UnsupportedOperationError(
    `${operation} requires a newer native binding; upgrade or rebuild the microsandbox native package`,
  );
}
