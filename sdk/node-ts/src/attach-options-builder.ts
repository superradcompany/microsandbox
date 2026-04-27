import type { Rlimit, RlimitResource } from "./rlimit.js";
import type { NapiAttachConfig } from "./internal/napi.js";

/** Options consumed by `Sandbox.attachWith`. */
export interface AttachOptions {
  args: readonly string[];
  cwd: string | null;
  user: string | null;
  env: ReadonlyArray<readonly [string, string]>;
  detachKeys: string | null;
  rlimits: readonly Rlimit[];
}

export class AttachOptionsBuilder {
  private _args: string[] = [];
  private _cwd: string | null = null;
  private _user: string | null = null;
  private _env: Array<readonly [string, string]> = [];
  private _detachKeys: string | null = null;
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

  /** Detach key sequence (e.g. `"ctrl-]"` or `"ctrl-p,ctrl-q"`). */
  detachKeys(spec: string): this {
    this._detachKeys = spec;
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

  build(): AttachOptions {
    return {
      args: this._args.slice(),
      cwd: this._cwd,
      user: this._user,
      env: this._env.slice(),
      detachKeys: this._detachKeys,
      rlimits: this._rlimits.slice(),
    };
  }
}

/** Internal: render an `AttachOptions` into the binding's flat shape. */
export function attachOptionsToNapi(
  cmd: string,
  opts: AttachOptions,
): NapiAttachConfig {
  return {
    cmd,
    args: opts.args.length === 0 ? undefined : opts.args.slice(),
    cwd: opts.cwd ?? undefined,
    user: opts.user ?? undefined,
    env:
      opts.env.length === 0 ? undefined : Object.fromEntries(opts.env),
    detachKeys: opts.detachKeys ?? undefined,
  };
}
