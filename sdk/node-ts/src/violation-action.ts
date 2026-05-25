/** Action taken when a secret would be sent to a disallowed host. */
export type ViolationAction =
  | "block"
  | "block-and-log"
  | "block-and-terminate"
  | "passthrough";

export const ViolationActions: readonly ViolationAction[] = [
  "block",
  "block-and-log",
  "block-and-terminate",
  "passthrough",
] as const;
