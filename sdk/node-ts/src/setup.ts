import { withMappedErrors } from "./internal/error-mapping.js";
import { napi } from "./internal/napi.js";

export class Setup {
  private readonly inner = new napi.Setup();

  /** Override the install root (default: `~/.microsandbox`). */
  baseDir(path: string): this {
    this.inner.baseDir(path);
    return this;
  }

  /** Pin a specific runtime version (default: package's pinned version). */
  version(version: string): this {
    this.inner.version(version);
    return this;
  }

  /** Skip the post-install verification step. */
  skipVerify(enabled: boolean): this {
    this.inner.skipVerify(enabled);
    return this;
  }

  /** Re-download even if the binaries are already present. */
  force(enabled: boolean): this {
    this.inner.force(enabled);
    return this;
  }

  async install(): Promise<void> {
    await withMappedErrors(() => this.inner.install());
  }
}

/** Begin a customizable install. */
export function setup(): Setup {
  return new Setup();
}

/** Download and install msb + libkrunfw under non-empty `$MSB_HOME`,
 * or `~/.microsandbox/` when the override is unset or empty. */
export async function install(): Promise<void> {
  await withMappedErrors(() => napi.install());
}

/** True when the runtime binaries are present and runnable. */
export function isInstalled(): boolean {
  return napi.isInstalled();
}

/**
 * Read the version embedded in an executable without running it.
 * Returns null for older executables without the version section. Invalid
 * executables, malformed version sections and file access failures reject.
 * No firmware, installation, network access or `--version` fallback is needed.
 */
export async function resolveRuntimeVersion(executable: string): Promise<string | null> {
  return (await withMappedErrors(() => napi.resolveRuntimeVersion(executable))) ?? null;
}
