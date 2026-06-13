import { napi } from "./internal/napi.js";

export type DefaultBackend =
  | "local"
  | {
      kind: "cloud";
      url: string;
      apiKey: string;
    }
  | {
      kind: "cloud";
      profile: string;
    };

/** Set the process-wide default backend used by SDK entry points. */
export function setDefaultBackend(backend: DefaultBackend): void {
  const setNative = napi.setDefaultBackend;
  if (!setNative) {
    throw new Error("native setDefaultBackend binding is unavailable");
  }

  if (backend === "local") {
    setNative("local");
    return;
  }

  if ("profile" in backend) {
    setNative("cloud", undefined, undefined, backend.profile);
    return;
  }

  setNative("cloud", backend.url, backend.apiKey);
}

/**
 * Temporarily replace the process-wide default backend while `fn` runs.
 *
 * This restores the previous backend in a `finally` block, but it is not
 * task-local: concurrent work in the same process can observe the temporary
 * backend while the callback is running.
 */
export async function withDefaultBackend<T>(
  backend: DefaultBackend,
  fn: () => Promise<T> | T,
): Promise<T> {
  const pushNative = napi.pushDefaultBackend;
  const popNative = napi.popDefaultBackend;
  if (!pushNative || !popNative) {
    throw new Error("native backend scope bindings are unavailable");
  }

  const token = pushBackend(pushNative, backend);
  try {
    return await fn();
  } finally {
    popNative(token);
  }
}

/** Return the active default backend kind. */
export function defaultBackendKind(): "local" | "cloud" {
  const getNative = napi.defaultBackendKind;
  if (!getNative) {
    throw new Error("native defaultBackendKind binding is unavailable");
  }
  return getNative();
}

function pushBackend(
  pushNative: NonNullable<typeof napi.pushDefaultBackend>,
  backend: DefaultBackend,
): number {
  if (backend === "local") {
    return pushNative("local");
  }

  if ("profile" in backend) {
    return pushNative("cloud", undefined, undefined, backend.profile);
  }

  return pushNative("cloud", backend.url, backend.apiKey);
}
