export type LogLevel = "trace" | "debug" | "info" | "warn" | "error";

export const LogLevels: readonly LogLevel[] = [
  "trace",
  "debug",
  "info",
  "warn",
  "error",
] as const;
