import { withMappedErrors } from "./internal/error-mapping.js";
import { metricsFromNapi } from "./internal/metrics.js";
import { napi } from "./internal/napi.js";
import type { NapiSandboxMetrics } from "./internal/napi.js";
import type { SandboxMetrics } from "./metrics.js";

/** Snapshot of metrics for every running sandbox, keyed by name. */
export async function allSandboxMetrics(): Promise<Record<string, SandboxMetrics>> {
  const raw = await withMappedErrors(() => napi.allSandboxMetrics());
  const out: Record<string, SandboxMetrics> = {};
  for (const [name, m] of Object.entries(raw)) {
    out[name] = metricsFromNapi(m as NapiSandboxMetrics);
  }
  return out;
}
