import type { PullProgress } from "./pull-progress.js";

/** Runtime preparation stages, before the sandbox is ready for commands. */
export type StartupPhase = "preparing_snapshot" | "waiting_for_memory_backing" |
  "preparing_memory_backing" | "reusing_memory_backing" | "syncing_memory_backing" | "activating";

/** Best-effort cumulative telemetry. Await the creation result to determine success. */
export type CreationProgress = PullProgress | {
  readonly kind: "startup";
  readonly phase: StartupPhase;
  readonly completedBytes: number;
  readonly totalBytes?: number | null;
};

export interface CreationProgressStream extends AsyncIterable<CreationProgress> {
  recv(): Promise<CreationProgress | null>;
}
