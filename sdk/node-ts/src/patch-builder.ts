import type { Patch } from "./patch.js";

/** Optional flags for the file-targeting patch kinds. */
export interface PatchFileOptions {
  /** Unix permissions (e.g. `0o644`). */
  mode?: number;
  /** Allow shadowing an existing path. */
  replace?: boolean;
}

/** Optional flags for `copyDir` and `symlink`. */
export interface PatchReplaceOnly {
  replace?: boolean;
}

/** Optional flags for `mkdir`. */
export interface PatchModeOnly {
  mode?: number;
}

export class PatchBuilder {
  private readonly patches: Patch[] = [];

  /** Write text to a file in the guest rootfs. */
  text(path: string, content: string, opts: PatchFileOptions = {}): this {
    this.patches.push({
      kind: "text",
      path,
      content,
      mode: opts.mode,
      replace: opts.replace,
    });
    return this;
  }

  /** Write raw bytes to a file in the guest rootfs. */
  file(
    path: string,
    content: Uint8Array,
    opts: PatchFileOptions = {},
  ): this {
    this.patches.push({
      kind: "file",
      path,
      content,
      mode: opts.mode,
      replace: opts.replace,
    });
    return this;
  }

  /** Copy a host file into the guest rootfs. */
  copyFile(src: string, dst: string, opts: PatchFileOptions = {}): this {
    this.patches.push({
      kind: "copyFile",
      src,
      dst,
      mode: opts.mode,
      replace: opts.replace,
    });
    return this;
  }

  /** Recursively copy a host directory into the guest rootfs. */
  copyDir(src: string, dst: string, opts: PatchReplaceOnly = {}): this {
    this.patches.push({
      kind: "copyDir",
      src,
      dst,
      replace: opts.replace,
    });
    return this;
  }

  /** Create a symlink in the guest rootfs. */
  symlink(target: string, link: string, opts: PatchReplaceOnly = {}): this {
    this.patches.push({
      kind: "symlink",
      target,
      link,
      replace: opts.replace,
    });
    return this;
  }

  /** Create a directory (idempotent). */
  mkdir(path: string, opts: PatchModeOnly = {}): this {
    this.patches.push({ kind: "mkdir", path, mode: opts.mode });
    return this;
  }

  /** Delete a path (idempotent). */
  remove(path: string): this {
    this.patches.push({ kind: "remove", path });
    return this;
  }

  /** Append text to an existing file; copies up from a lower layer if needed. */
  append(path: string, content: string): this {
    this.patches.push({ kind: "append", path, content });
    return this;
  }

  /** @internal */
  build(): Patch[] {
    return this.patches.slice();
  }
}
