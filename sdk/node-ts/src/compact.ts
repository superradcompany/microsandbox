/** Explicit maintenance of the root and all owned data disks by default. */
export interface DiskCompactionOptions {
  /** Up to this many oldest sealed physical layers per disk, including the base; minimum two. */
  layers?: number;
  /** Only this owned disk's guest mount path; '/' selects the root. Conflicts with rootDiskOnly. */
  disk?: string;
  /** Only the root disk. Conflicts with disk. */
  rootDiskOnly?: boolean;
  dryRun?: boolean;
}

/** Per-disk physical counts; fewer than two selected layers leaves the disk unchanged. */
export interface DiskCompactionDiskResult {
  guestPath: string;
  inputLayers: number;
  selectedLayers: number;
  outputLayers: number;
  materializedBytes: number;
  /** Preparation/materialization time; excludes journal adoption and backend switching. */
  totalUs: number;
}

/** Timings are microseconds; materialized bytes are not reclaimed space. */
export interface DiskCompactionResult {
  dryRun: boolean;
  inputLayers: number;
  selectedLayers: number;
  outputLayers: number;
  materializedBytes: number;
  /** Whole-operation time, including the shared journal/backend adoption phase. */
  totalUs: number;
  pauseUs: number;
  disks: DiskCompactionDiskResult[];
}

export function compactionResultFromJson(json: string): DiskCompactionResult {
  const result = JSON.parse(json);
  return {
    dryRun: result.dry_run,
    inputLayers: result.input_layers,
    selectedLayers: result.selected_layers,
    outputLayers: result.output_layers,
    materializedBytes: result.materialized_bytes,
    totalUs: result.total_us,
    pauseUs: result.pause_us,
    disks: result.disks.map((disk: Record<string, number | string>) => ({
      guestPath: disk.guest_path as string,
      inputLayers: disk.input_layers as number,
      selectedLayers: disk.selected_layers as number,
      outputLayers: disk.output_layers as number,
      materializedBytes: disk.materialized_bytes as number,
      totalUs: disk.total_us as number,
    })),
  };
}
