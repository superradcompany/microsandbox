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

/** Return the active default backend kind. */
export function defaultBackendKind(): "local" | "cloud" {
  const getNative = napi.defaultBackendKind;
  if (!getNative) {
    throw new Error("native defaultBackendKind binding is unavailable");
  }
  return getNative();
}
