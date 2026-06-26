import type { SandboxMetrics } from "../metrics.js";
import type { NapiSandboxMetrics } from "./napi.js";

export function metricsFromNapi(raw: NapiSandboxMetrics): SandboxMetrics {
  return {
    cpuPercent: raw.cpuPercent,
    vcpuTimeNs: raw.vcpuTimeNs,
    memoryBytes: raw.memoryBytes,
    memoryAvailableBytes: raw.memoryAvailableBytes ?? null,
    memoryHostResidentBytes: raw.memoryHostResidentBytes ?? null,
    memoryLimitBytes: raw.memoryLimitBytes,
    diskReadBytes: raw.diskReadBytes,
    diskWriteBytes: raw.diskWriteBytes,
    netRxBytes: raw.netRxBytes,
    netTxBytes: raw.netTxBytes,
    upperUsedBytes: raw.upperUsedBytes ?? null,
    upperFreeBytes: raw.upperFreeBytes ?? null,
    upperHostAllocatedBytes: raw.upperHostAllocatedBytes ?? null,
    uptimeMs: raw.uptimeMs,
    timestamp: new Date(raw.timestampMs),
  };
}
