import { Context, LocalContext, RemoteContext, Volumes } from "./context.js";
import { withMappedErrors } from "./internal/error-mapping.js";
import {
  napi,
  type NapiVolume,
  type NapiVolumeBuilderSetters,
} from "./internal/napi.js";
import { VolumeFs } from "./volume-fs.js";

/**
 * Fluent builder for a named volume. Returned by `Volume.builder(name)`.
 *
 * The instance IS the napi-rs `VolumeBuilder` class. The terminal
 * `create()` is wrapped to return a TS `Volume` (so we can keep
 * type-level distinction from the raw napi class).
 */
// See the rationale in `sandbox.ts:SandboxBuilder` — extend a
// setters-only base interface so polymorphic `this` rebinds to
// `VolumeBuilder` through chained calls.
export interface VolumeBuilder extends NapiVolumeBuilderSetters {
  create(): Promise<Volume>;
}

export type VolumeKind = "dir" | "disk";

function volumeKind(value: unknown): VolumeKind {
  // Native inspections serialize Rust variant names. Resource getters use SDK spellings.
  switch (value) {
    case "Directory": case "dir": return "dir";
    case "Disk": case "disk": return "disk";
    default: throw new TypeError(`Unknown volume kind: ${value}`);
  }
}

/** A fresh backend observation; unavailable measurements remain null. */
export interface VolumeInfo {
  id: string; name: string; kind: VolumeKind; isDefault: boolean;
  quotaMib: number | null; usedBytes: number | null; capacityBytes: number | null;
  diskFormat: string | null; diskFstype: string | null;
  labels: ReadonlyArray<readonly [string, string]>; createdAt: Date | null;
}

export class Volume {
  /** @internal */
  readonly inner: NapiVolume;

  /** @internal */
  constructor(inner: NapiVolume) {
    this.inner = inner;
  }

  /** Capture a local destination; never changes ambient routing. */
  static local(): Volumes { return new LocalContext().volumes; }
  /** Capture remote environment credentials now, before creating or looking up a resource. */
  static remote(): Volumes { return RemoteContext.fromEnv().volumes; }
  static ctx(context: Context): Volumes { return context.volumes; }

  get context(): Context { return Context.fromNative(this.inner.context()); }

  /** Begin building a new volume on the configured backend. */
  static builder(name: string): VolumeBuilder {
    return Volume.fromNativeBuilder(new napi.VolumeBuilder(name));
  }

  /** @internal */
  static fromNativeBuilder(nb: InstanceType<typeof napi.VolumeBuilder>): VolumeBuilder {
    const origCreate = nb.create.bind(nb);
    (nb as unknown as { create: () => Promise<Volume> }).create = async () => {
      const inner = await withMappedErrors(() => origCreate());
      return new Volume(inner);
    };
    return nb as unknown as VolumeBuilder;
  }

  /** Look up an existing volume by name. */
  static async get(name: string): Promise<Volume> {
    const raw = await withMappedErrors(() => napi.Volume.get(name));
    return new Volume(raw);
  }

  /** Get the cloud account's always-present default volume. */
  static async getDefault(): Promise<Volume> {
    const raw = await withMappedErrors(() => napi.Volume.getDefault());
    return new Volume(raw);
  }

  /** List all volumes. */
  static async list(): Promise<Volume[]> {
    const infos = await withMappedErrors(() => napi.Volume.list());
    return infos.map((inner) => new Volume(inner));
  }

  /** Delete a volume by name. */
  static async remove(name: string): Promise<void> {
    await withMappedErrors(() => napi.Volume.remove(name));
  }

  /** Stable identity within this resource's retained destination; no I/O. */
  get id(): string { return this.inner.id; }
  get isDefault(): boolean { return this.inner.isDefault; }
  get kind(): VolumeKind { return volumeKind(this.inner.kind); }
  get diskFormat(): string | null { return this.inner.diskFormat ?? null; }
  get diskFstype(): string | null { return this.inner.diskFstype ?? null; }
  get createdAt(): Date | null {
    const timestamp = this.inner.createdAt;
    return typeof timestamp === "number" ? new Date(timestamp) : null;
  }

  /** Fetch mutable metadata together; returned values are one observation. */
  async info(): Promise<VolumeInfo> {
    const value = JSON.parse(await withMappedErrors(() => this.inner.info()));
    return { id: value.id, name: value.name, kind: volumeKind(value.kind), isDefault: value.is_default,
      quotaMib: value.quota_mib, usedBytes: value.used_bytes, capacityBytes: value.capacity_bytes,
      diskFormat: value.disk_format, diskFstype: value.disk_fstype, labels: value.labels,
      createdAt: value.created_at == null ? null : new Date(value.created_at) };
  }

  /** Delete the captured identity, leaving any same-name replacement untouched. */
  async destroy(): Promise<void> {
    await withMappedErrors(() => this.inner.destroy());
  }

  get name(): string {
    return this.inner.name;
  }

  get path(): string {
    return this.inner.path;
  }

  /** Direct filesystem operations through the volume's bound backend. */
  fs(): VolumeFs {
    return new VolumeFs(this.inner.fs());
  }
}
