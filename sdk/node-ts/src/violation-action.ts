/** Action taken when a secret would be sent to a disallowed host. */
export type ViolationAction = "block" | "block-and-log" | "block-and-terminate";

export const ViolationActions: readonly ViolationAction[] = [
  "block",
  "block-and-log",
  "block-and-terminate",
] as const;
