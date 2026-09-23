export type SandboxStatus =
  | "created"
  | "starting"
  | "running"
  | "draining"
  | "paused"
  | "stopped"
  | "crashed";

export const SandboxStatuses: readonly SandboxStatus[] = [
  "created",
  "starting",
  "running",
  "draining",
  "paused",
  "stopped",
  "crashed",
] as const;
