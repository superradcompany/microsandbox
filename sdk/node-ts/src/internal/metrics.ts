import type { SandboxMetrics } from "../metrics.js";
import type { NapiSandboxMetrics } from "./napi.js";

export function metricsFromNapi(raw: NapiSandboxMetrics): SandboxMetrics {
  return {
    cpuPercent: raw.cpuPercent,
    memoryBytes: raw.memoryBytes,
    memoryLimitBytes: raw.memoryLimitBytes,
    diskReadBytes: raw.diskReadBytes,
    diskWriteBytes: raw.diskWriteBytes,
    netRxBytes: raw.netRxBytes,
    netTxBytes: raw.netTxBytes,
    uptimeMs: raw.uptimeMs,
    timestamp: new Date(raw.timestampMs),
  };
}
