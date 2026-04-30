/** Stdin behavior for `Sandbox.exec` and friends. */
export type StdinMode =
  | { kind: "null" }
  | { kind: "pipe" }
  | { kind: "bytes"; data: Uint8Array };

export const Stdin = {
  /** Connect stdin to `/dev/null`. */
  null: (): StdinMode => ({ kind: "null" }),
  /** Open a writable pipe — caller writes via `ExecHandle.stdin`. */
  pipe: (): StdinMode => ({ kind: "pipe" }),
  /** Send the given bytes (or UTF-8-encoded string) and close stdin. */
  bytes: (data: Uint8Array | string): StdinMode => ({
    kind: "bytes",
    data: typeof data === "string" ? new TextEncoder().encode(data) : data,
  }),
};
