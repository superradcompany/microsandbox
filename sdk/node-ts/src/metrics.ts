export interface SandboxMetrics {
  readonly cpuPercent: number;
  readonly memoryBytes: number;
  readonly memoryLimitBytes: number;
  readonly diskReadBytes: number;
  readonly diskWriteBytes: number;
  readonly netRxBytes: number;
  readonly netTxBytes: number;
  /** Uptime in milliseconds. */
  readonly uptimeMs: number;
  readonly timestamp: Date;
}
