import type { SandboxStatus } from "./sandbox-status.js";
import type { NapiSandboxRestartOptions, NapiSandboxDestroyOptions } from "./internal/napi.js";

export interface SandboxStopResult {
  readonly name: string;
  readonly status: SandboxStatus;
  readonly exitCode: number | null;
  readonly signal: number | null;
  readonly observedAt: Date;
  readonly source: string | null;
}

export type RestartOptions = NapiSandboxRestartOptions;
export type DestroyOptions = NapiSandboxDestroyOptions;
