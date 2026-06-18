export interface SandboxMetrics {
  readonly cpuPercent: number;
  readonly vcpuTimeNs: number;
  readonly memoryBytes: number;
  readonly memoryAvailableBytes: number | null;
  readonly memoryHostResidentBytes: number | null;
  readonly memoryLimitBytes: number;
  readonly diskReadBytes: number;
  readonly diskWriteBytes: number;
  readonly netRxBytes: number;
  readonly netTxBytes: number;
  readonly upperUsedBytes: number | null;
  readonly upperFreeBytes: number | null;
  readonly upperHostAllocatedBytes: number | null;
  /** Uptime in milliseconds. */
  readonly uptimeMs: number;
  readonly timestamp: Date;
}
