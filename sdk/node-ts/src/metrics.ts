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
  /** Uptime in milliseconds. */
  readonly uptimeMs: number;
  readonly timestamp: Date;
}
