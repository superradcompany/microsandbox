import type { Rlimit, RlimitResource } from "./rlimit.js";
import type { StdinMode } from "./stdin.js";
import type { NapiExecConfig } from "./internal/napi.js";

/** Options consumed by `Sandbox.execWith` / `execStreamWith`. */
export interface ExecOptions {
  args: readonly string[];
  cwd: string | null;
  user: string | null;
  env: ReadonlyArray<readonly [string, string]>;
  timeoutMs: number | null;
  stdin: StdinMode;
  tty: boolean;
  rlimits: readonly Rlimit[];
}

export class ExecOptionsBuilder {
  private _args: string[] = [];
  private _cwd: string | null = null;
  private _user: string | null = null;
  private _env: Array<readonly [string, string]> = [];
  private _timeoutMs: number | null = null;
  private _stdin: StdinMode = { kind: "null" };
  private _tty = false;
  private _rlimits: Rlimit[] = [];

  arg(arg: string): this {
    this._args.push(arg);
    return this;
  }

  args(args: Iterable<string>): this {
    for (const a of args) this._args.push(a);
    return this;
  }

  cwd(cwd: string): this {
    this._cwd = cwd;
    return this;
  }

  user(user: string): this {
    this._user = user;
    return this;
  }

  env(key: string, value: string): this {
    this._env.push([key, value]);
    return this;
  }

  envs(
    vars: Iterable<readonly [string, string]> | Record<string, string>,
  ): this {
    if (Symbol.iterator in vars) {
      for (const [k, v] of vars as Iterable<readonly [string, string]>) {
        this._env.push([k, v]);
      }
    } else {
      for (const [k, v] of Object.entries(vars)) this._env.push([k, v]);
    }
    return this;
  }

  /** Kill the process if it hasn't exited within `ms` milliseconds. */
  timeout(ms: number): this {
    this._timeoutMs = ms;
    return this;
  }

  stdinNull(): this {
    this._stdin = { kind: "null" };
    return this;
  }

  stdinPipe(): this {
    this._stdin = { kind: "pipe" };
    return this;
  }

  stdinBytes(data: Uint8Array | string): this {
    this._stdin = {
      kind: "bytes",
      data: typeof data === "string" ? new TextEncoder().encode(data) : data,
    };
    return this;
  }

  tty(enabled: boolean): this {
    this._tty = enabled;
    return this;
  }

  rlimit(resource: RlimitResource, limit: number): this {
    this._rlimits.push({ resource, soft: limit, hard: limit });
    return this;
  }

  rlimitRange(resource: RlimitResource, soft: number, hard: number): this {
    this._rlimits.push({ resource, soft, hard });
    return this;
  }

  build(): ExecOptions {
    return {
      args: this._args.slice(),
      cwd: this._cwd,
      user: this._user,
      env: this._env.slice(),
      timeoutMs: this._timeoutMs,
      stdin: this._stdin,
      tty: this._tty,
      rlimits: this._rlimits.slice(),
    };
  }
}

/** Internal: render an `ExecOptions` into the binding's flat `NapiExecConfig`. */
export function execOptionsToNapi(
  cmd: string,
  opts: ExecOptions,
): NapiExecConfig {
  let stdin: string | undefined;
  switch (opts.stdin.kind) {
    case "null":
      stdin = "null";
      break;
    case "pipe":
      stdin = "pipe";
      break;
    case "bytes":
      stdin = new TextDecoder("utf-8").decode(opts.stdin.data);
      break;
  }

  const env: Record<string, string> | undefined =
    opts.env.length === 0 ? undefined : Object.fromEntries(opts.env);

  return {
    cmd,
    args: opts.args.length === 0 ? undefined : opts.args.slice(),
    cwd: opts.cwd ?? undefined,
    user: opts.user ?? undefined,
    env,
    timeoutMs: opts.timeoutMs ?? undefined,
    stdin,
    tty: opts.tty || undefined,
  };
}
