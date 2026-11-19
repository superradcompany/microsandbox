import type { NativeBindings } from "./napi.js";
import { createRequire } from "node:module";

const sdkVersion = (createRequire(import.meta.url)("../../package.json") as { version: string }).version;

export type ProviderKind = "local" | "remote";
type Loader = () => NativeBindings;
const loaders = new Map<ProviderKind, Loader>();
const loaded = new Map<ProviderKind, NativeBindings>();
const owners = new WeakMap<object, NativeBindings>();
const initialized = new WeakSet<object>();
let fallback: Loader | undefined;
let initialize: (native: NativeBindings) => void = () => {};
let full: NativeBindings | undefined;
let fullRegistered = false;
let defaultLocal: NativeBindings | undefined;

function validate(native: NativeBindings, version: string, kind: ProviderKind | "full"): NativeBindings {
  const info = JSON.parse(native.providerInfo()) as Record<string, unknown>;
  const supported = kind === "full" ? info.local === true && info.remote === true : info[kind] === true;
  if (info.abi !== 1 || info.version !== version || version !== sdkVersion || !supported) {
    throw new Error(`Incompatible ${kind} microsandbox provider; reinstall matching core and provider versions`);
  }
  return native;
}

/** Internal provider entry point. Registration never replaces a loaded library. */
export function registerProvider(kind: ProviderKind, loader: Loader, version: string): void {
  if (loaders.has(kind) || loaded.has(kind)) {
    throw new Error(`A ${kind} microsandbox provider is already registered`);
  }
  loaders.set(kind, () => validate(loader(), version, kind));
}

/** Full-package entry point; resources still use the same core wrapper classes. */
export function registerFullProvider(loader: Loader, version: string): void {
  if (full || fullRegistered) throw new Error("A full microsandbox provider is already registered");
  fullRegistered = true;
  fallback = () => validate(loader(), version, "full");
}

export function registerFallback(loader: Loader, configure: typeof initialize): void {
  fallback = loader;
  initialize = configure;
}

function prepare(native: NativeBindings): NativeBindings {
  if (!initialized.has(native)) {
    initialize(native);
    // Native constructors own every result's prototype, including results from
    // async operations. This preserves allocation/library identity without a
    // mutable global binding or tagging each individual returned object.
    for (const value of Object.values(native)) {
      if (typeof value === "function" && value.prototype) {
        owners.set(value.prototype, native);
      }
    }
    initialized.add(native);
  }
  return native;
}

export function binding(kind: ProviderKind): NativeBindings {
  const existing = loaded.get(kind);
  if (existing) return existing;
  const loader = loaders.get(kind);
  if (loader) {
    const native = prepare(loader());
    loaded.set(kind, native);
    return native;
  }
  if (!full && fallback) {
    try {
      full = prepare(fallback());
    } catch (error) {
      // A missing full-package loader is expected in core-only installations.
      // Do not disguise malformed binaries or dependency-loading failures.
      if (!(error instanceof Error) || !("code" in error) || error.code !== "MODULE_NOT_FOUND"
          || !error.message.includes("../../native/index.cjs")) throw error;
    }
  }
  if (full) return full;
  throw new Error(`Install and import @microsandbox/${kind} before using ${kind} operations`);
}

/** Select the library for this call; live objects retain their original library. */
export function defaultBinding(): NativeBindings {
  const kind = optionsBinding().configuredProviderKind();
  return kind === "local" ? (defaultLocal ??= binding("local")) : binding("remote");
}

export function nativeOwner(value: object): NativeBindings | undefined {
  let prototype: object | null = value;
  while (prototype) {
    const owner = owners.get(prototype);
    if (owner) return owner;
    prototype = Object.getPrototypeOf(prototype);
  }
  return undefined;
}

export function bindingFor(value: object, adapter?: NativeBindings): NativeBindings {
  // Structural adapters have no native prototype. Native objects always retain
  // their library, even when another provider was registered more recently.
  return nativeOwner(value) ?? adapter ?? binding("local");
}

/** Configuration-only builders may use either provider; resource calls may not. */
export function optionsBinding(): NativeBindings {
  return binding(loaders.has("local") || !loaders.has("remote") ? "local" : "remote");
}

/** Lazy exported constructor, preserving instanceof across provider libraries. */
export function nativeConstructor<K extends keyof NativeBindings>(key: K): NativeBindings[K] {
  return new Proxy(function () {}, {
    construct: (_target, args) => Reflect.construct(optionsBinding()[key] as Function, args),
    get: (_target, property) => {
      if (property === Symbol.hasInstance) {
        return (value: unknown) => {
          if (!value || typeof value !== "object") return false;
          const constructor = nativeOwner(value)?.[key];
          return typeof constructor === "function" && value instanceof constructor;
        };
      }
      return Reflect.get(optionsBinding()[key] as object, property);
    },
  }) as NativeBindings[K];
}
