import { mapNapiError, withMappedErrors } from "./internal/error-mapping.js";
import { napi } from "./internal/napi.js";

/** Per-call overrides layered on persisted configuration and the runtime home. */
export interface RuntimeConfig {
  home?: string;
  msbPath?: string;
  libkrunfwPath?: string;
}

/** Source of a resolved executable and firmware pair. */
export type RuntimeOrigin =
  | "environment"
  | "sdk_package"
  | "configuration"
  | "home"
  | "installed";

/** The selected executable, matching firmware library, and resolution source. */
export interface ResolvedRuntime {
  msbPath: string;
  libkrunfwPath: string;
  origin: RuntimeOrigin;
}

/** Explicit acquisition options; ensureRuntime ignores them when a pair resolves. */
export interface InstallOptions {
  source?: "release_download" | "archive" | "directory" | "embedded_archive";
  sourcePath?: string;
  version?: string;
  force?: boolean;
  verify?: boolean;
  expectedArchiveSha256?: string;
}

function configJson(config: RuntimeConfig): string {
  return JSON.stringify({
    home: config.home,
    msb_path: config.msbPath,
    libkrunfw_path: config.libkrunfwPath,
  });
}

function optionsJson(options: InstallOptions): string {
  return JSON.stringify({
    source: options.source,
    source_path: options.sourcePath,
    version: options.version,
    force: options.force,
    verify: options.verify,
    expected_archive_sha256: options.expectedArchiveSha256,
  });
}

function runtimeFromJson(json: string): ResolvedRuntime {
  const result = JSON.parse(json) as {
    msb_path: string;
    libkrunfw_path: string;
    origin: RuntimeOrigin;
  };
  return {
    msbPath: result.msb_path,
    libkrunfwPath: result.libkrunfw_path,
    origin: result.origin,
  };
}

/** Resolve an existing pair without installing host binaries; throws if absent or incomplete. */
export function resolveRuntime(config: RuntimeConfig = {}): ResolvedRuntime {
  try {
    return runtimeFromJson(napi.resolveRuntime(configJson(config)));
  } catch (error) {
    throw mapNapiError(error);
  }
}

/** Whether a complete pair resolves, including explicit overrides and package fallbacks. */
export function isRuntimeInstalled(config: RuntimeConfig = {}): boolean {
  return napi.isRuntimeInstalled(configJson(config));
}

/** Install from the selected source and return the installed pair. */
export async function installRuntime(
  config: RuntimeConfig = {},
  options: InstallOptions = {},
): Promise<ResolvedRuntime> {
  return runtimeFromJson(
    await withMappedErrors(() =>
      napi.installRuntime(configJson(config), optionsJson(options)),
    ),
  );
}

/** Resolve first; install only when absent, propagating incomplete-pair errors. */
export async function ensureRuntime(
  config: RuntimeConfig = {},
  options: InstallOptions = {},
): Promise<ResolvedRuntime> {
  return runtimeFromJson(
    await withMappedErrors(() =>
      napi.ensureRuntime(configJson(config), optionsJson(options)),
    ),
  );
}
