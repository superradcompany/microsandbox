/** Event emitted by `Sandbox.execStream` and friends. */
export type ExecEvent =
  | { kind: "started"; pid: number }
  | { kind: "stdout"; data: Uint8Array }
  | { kind: "stderr"; data: Uint8Array }
  | { kind: "exited"; code: number };

/** Internal: the loose shape produced by the native binding. */
export interface RawExecEvent {
  eventType: "started" | "stdout" | "stderr" | "exited";
  pid?: number;
  data?: Uint8Array;
  code?: number;
}

export function normalizeExecEvent(raw: RawExecEvent): ExecEvent {
  switch (raw.eventType) {
    case "started":
      if (typeof raw.pid !== "number") {
        throw new Error("exec event: missing pid on Started");
      }
      return { kind: "started", pid: raw.pid };
    case "stdout":
      if (!raw.data) throw new Error("exec event: missing data on Stdout");
      return { kind: "stdout", data: raw.data };
    case "stderr":
      if (!raw.data) throw new Error("exec event: missing data on Stderr");
      return { kind: "stderr", data: raw.data };
    case "exited":
      if (typeof raw.code !== "number") {
        throw new Error("exec event: missing code on Exited");
      }
      return { kind: "exited", code: raw.code };
  }
}
