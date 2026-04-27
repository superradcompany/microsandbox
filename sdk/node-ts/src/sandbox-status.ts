export type SandboxStatus = "running" | "stopped" | "crashed" | "draining";

export const SandboxStatuses: readonly SandboxStatus[] = [
  "running",
  "stopped",
  "crashed",
  "draining",
] as const;
