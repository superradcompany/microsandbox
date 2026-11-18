import { remapKeysToCamel } from "./config.js";
import { deprecate } from "node:util";
import { mapNapiError } from "./error-mapping.js";
import type { NativeBindings } from "./napi.js";
import { nativeOwner } from "./provider.js";

/** Install wrapper conveniences separately on every loaded native provider. */
export function configureNative(napi: NativeBindings): void {
// Native fluent builders. The classes themselves live in the napi-rs
// binding (`native/index.cjs`); the TS layer just re-exports them so
// `import { DnsBuilder } from "microsandbox"` keeps working.

// Attach a JS-side `policy(NetworkPolicy)` method to the native
// `NetworkBuilder.prototype` so callers can pass the plain
// `NetworkPolicy` object produced by `NetworkPolicy.fromProfiles()` /
// `.allowAll()` / `.none()` and the custom-rule
// factories. Native exposes `policyJson(string)`; this shim
// serializes once.
// Wrap a class's prototype method so any thrown error gets remapped
// to a typed `MicrosandboxError` subclass via the prefix the Rust
// binding emits (`[InvalidConfig] ...`). Used on builders whose
// `.build()` can throw a typed validation error.
// eslint-disable-next-line @typescript-eslint/no-explicit-any
function wrapMethodWithErrorMap(cls: any, method: string) {
  const proto = cls.prototype;
  const orig = proto[method];
  if (typeof orig !== "function" || (orig as { __wrapped?: boolean }).__wrapped) {
    return;
  }
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const wrapped = function (this: unknown, ...args: any[]) {
    try {
      const result = orig.apply(this, args);
      if (result && typeof result.then === "function") {
        return result.catch((e: unknown) => {
          throw mapNapiError(e);
        });
      }
      return result;
    } catch (e) {
      throw mapNapiError(e);
    }
  };
  (wrapped as { __wrapped?: boolean }).__wrapped = true;
  proto[method] = wrapped;
}

wrapMethodWithErrorMap(napi.MountBuilder, "build");
wrapMethodWithErrorMap(napi.SandboxBuilder, "create");
wrapMethodWithErrorMap(napi.PatchBuilder, "build");
wrapMethodWithErrorMap(napi.DnsBuilder, "build");
wrapMethodWithErrorMap(napi.SecretBuilder, "build");
wrapMethodWithErrorMap(napi.NetworkBuilder, "secret");
wrapMethodWithErrorMap(napi.SandboxBuilder, "secret");
wrapMethodWithErrorMap(napi.VolumeBuilder, "create");

// `SandboxBuilder.build()` natively returns the JSON-serialized config
// (snake_case). Replace it with a TS-side wrapper that parses and
// key-maps to camelCase so consumers get a plain JS object.
{
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const proto: any = napi.SandboxBuilder.prototype;
  if (!proto.__buildWrapped) {
    const origBuild = proto.build;
    proto.build = async function () {
      let json: string;
      try {
        json = await origBuild.apply(this);
      } catch (e) {
        throw mapNapiError(e);
      }
      const config = remapKeysToCamel(JSON.parse(json));
      // Preserve the deprecated read accessor on built configurations.
      config.network.maxTcpConnections = config.network.maxConnections;
      Object.defineProperty(config.network, "maxConnections", {
        get: () => config.network.maxTcpConnections,
        enumerable: false,
      });
      return config;
    };
    Object.defineProperty(proto, "__buildWrapped", {
      value: true,
      enumerable: false,
      writable: false,
      configurable: false,
    });
  }
}

// Hide native-only helper methods from enumeration so user-facing
// iteration (`Object.keys`, `for...in`) sees only the documented
// surface. The methods still work; they're just not advertised.
function hideMethod(cls: { prototype: Record<string, unknown> }, name: string): void {
  if (Object.prototype.hasOwnProperty.call(cls.prototype, name)) {
    const value = cls.prototype[name];
    Object.defineProperty(cls.prototype, name, {
      value,
      enumerable: false,
      writable: true,
      configurable: true,
    });
  }
}
hideMethod(napi.NetworkBuilder, "buildJson");
hideMethod(napi.NetworkBuilder, "policyJson");
hideMethod(napi.NetworkBuilder, "policyFromBuilder");
hideMethod(napi.RestoreBuilder, "networkPolicyJson");
hideMethod(napi.RestoreBuilder, "networkPolicyFromBuilder");
hideMethod(napi.SandboxBuilder, "execWithBuilder");
hideMethod(napi.SandboxBuilder, "execStreamWithBuilder");
hideMethod(napi.SandboxBuilder, "attachWithBuilder");

// `NetworkBuilder.build()` natively returns a JSON-serialized
// `NetworkConfig` (snake_case from Rust serde). Wrap with parse +
// camelCase remap so callers get a plain JS object.
{
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const proto: any = napi.NetworkBuilder.prototype;
  if (!proto.__buildWrapped) {
    proto.build = function () {
      let json: string;
      try {
        json = this.buildJson();
      } catch (e) {
        throw mapNapiError(e);
      }
      const config = remapKeysToCamel(JSON.parse(json));
      // Preserve the deprecated read accessor on built configurations.
      config.maxTcpConnections = config.maxConnections;
      Object.defineProperty(config, "maxConnections", {
        get: () => config.maxTcpConnections,
        enumerable: false,
      });
      return config;
    };
    Object.defineProperty(proto, "__buildWrapped", {
      value: true,
      enumerable: false,
      writable: false,
      configurable: false,
    });
  }
}

{
  // The TS-side `NetworkPolicy` object uses camelCase struct keys
  // (`defaultEgress`, `defaultIngress`); the Rust struct expects
  // snake_case. The TS-side `Destination` factory produces an
  // *internally* tagged shape (`{kind: "group", group: "public"}`)
  // while the Rust `Destination` enum is *externally* tagged
  // (`{group: "public"}` or just `"any"`). Convert both before
  // serializing.
  const camelToSnake = (k: string): string =>
    k.replace(/[A-Z]/g, (c) => "_" + c.toLowerCase());
  // The Rust enums are `serde(rename_all = "snake_case")`, while TS uses kebab-case.
  const kebabToSnake = (s: string): string => s.replace(/-/g, "_");
  // Detect a TS-side Destination object (carries `kind` discriminator
  // produced by `Destination.any/cidr/domain/domainSuffix/group`) and
  // rewrite it to the Rust externally-tagged form.
  const isDestination = (v: unknown): v is { kind: string } & Record<string, unknown> => {
    if (!v || typeof v !== "object" || Array.isArray(v)) return false;
    const obj = v as Record<string, unknown>;
    if (typeof obj.kind !== "string") return false;
    return ["any", "cidr", "domain", "domainSuffix", "group"].includes(obj.kind);
  };
  const remapDestination = (
    v: { kind: string } & Record<string, unknown>,
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    deep: (x: any) => any,
  ): unknown => {
    const tag = camelToSnake(v.kind);
    if (v.kind === "any") return tag; // unit variant -> bare string
    // The data field name in the TS factory varies by variant: cidr →
    // `cidr`, domain → `domain`, domainSuffix → `suffix`, group → `group`.
    // Map each to its Rust externally-tagged data slot.
    const dataField = v.kind === "domainSuffix" ? "suffix" : v.kind;
    // Only `group` carries an enum string ("link-local" -> "link_local").
    // The other strings must be preserved as-is.
    const value =
      v.kind === "group" && typeof v.group === "string"
        ? kebabToSnake(v.group)
        : deep(v[dataField]);
    return { [tag]: value };
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const remapKeys = (v: any): any => {
    if (Array.isArray(v)) return v.map(remapKeys);
    if (isDestination(v)) return remapDestination(v, remapKeys);
    if (v && typeof v === "object") {
      const out: Record<string, unknown> = {};
      for (const [k, val] of Object.entries(v)) out[camelToSnake(k)] = remapKeys(val);
      return out;
    }
    return v;
  };
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const proto: any = napi.NetworkBuilder.prototype;
  if (!proto.policy) {
    proto.policy = function (p: unknown) {
      // If `p` is a `NetworkPolicyBuilder` instance, route through the
      // dedicated native bridge to skip the JSON round-trip and to
      // surface lazy parse/validation errors at this call site.
      if (p instanceof napi.NetworkPolicyBuilder) {
        this.policyFromBuilder(p);
        return this;
      }
      // Serialize a foreign provider's policy rather than passing its native
      // pointer into this library's class conversion machinery.
      if (p && typeof p === "object" && nativeOwner(p) && "build" in p && typeof p.build === "function") p = p.build();
      this.policyJson(JSON.stringify(remapKeys(p)));
      return this;
    };
  }
  // Restore shares policy conversion, but never exposes the broad NetworkBuilder callback.
  const restoreProto = napi.RestoreBuilder.prototype;
  // Keep old fluent calls working, with Node's standard once-per-process warning.
  restoreProto.forked = deprecate(function (this: import("./napi.js").NapiRestoreBuilder) {
    return this.cowMemory();
  }, "RestoreBuilder.forked() is deprecated; use cowMemory() instead", "MSB_RESTORE_FORKED");
  if (!restoreProto.networkPolicy) {
    restoreProto.networkPolicy = function (p: unknown) {
      if (p instanceof napi.NetworkPolicyBuilder) {
        this.networkPolicyFromBuilder(p);
      } else {
        if (p && typeof p === "object" && nativeOwner(p) && "build" in p && typeof p.build === "function") p = p.build();
        this.networkPolicyJson(JSON.stringify(remapKeys(p)));
      }
      return this;
    };
  }
}

}
