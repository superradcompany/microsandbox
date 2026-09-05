/** Explicit maintenance; omitted layers selects every sealed backing layer. */
export interface DiskCompactionOptions {
  /** Oldest physical layers, including the base, excluding the writable head. */
  layers?: number;
  dryRun?: boolean;
}

/** Timings are microseconds; materialized bytes are not reclaimed space. */
export interface DiskCompactionResult {
  dryRun: boolean;
  inputLayers: number;
  selectedLayers: number;
  outputLayers: number;
  materializedBytes: number;
  totalUs: number;
  pauseUs: number;
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
  };
}
