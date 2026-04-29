import { withMappedErrors } from "./internal/error-mapping.js";
import {
  napi,
  type NapiVolume,
  type NapiVolumeBuilder,
} from "./internal/napi.js";
import { VolumeHandle, volumeInfoToHandle } from "./volume-handle.js";
import { VolumeFs } from "./volume-fs.js";

/**
 * Fluent builder for a named volume. Returned by `Volume.builder(name)`.
 *
 * The instance IS the napi-rs `VolumeBuilder` class. The terminal
 * `create()` is wrapped to return a TS `Volume` (so we can keep
 * type-level distinction from the raw napi class).
 */
export type VolumeBuilder = Omit<NapiVolumeBuilder, "create"> & {
  create(): Promise<Volume>;
};

export class Volume {
  /** @internal */
  readonly inner: NapiVolume;

  /** @internal */
  constructor(inner: NapiVolume) {
    this.inner = inner;
  }

  /** Begin building a new volume. */
  static builder(name: string): VolumeBuilder {
    const nb = new napi.VolumeBuilder(name);
    const origCreate = nb.create.bind(nb);
    (nb as unknown as { create: () => Promise<Volume> }).create = async () => {
      const inner = await withMappedErrors(() => origCreate());
      return new Volume(inner);
    };
    return nb as unknown as VolumeBuilder;
  }

  /** Look up an existing volume by name. */
  static async get(name: string): Promise<VolumeHandle> {
    const raw = await withMappedErrors(() => napi.Volume.get(name));
    return new VolumeHandle(raw);
  }

  /** List all volumes. */
  static async list(): Promise<VolumeHandle[]> {
    const infos = await withMappedErrors(() => napi.Volume.list());
    return infos.map(volumeInfoToHandle);
  }

  /** Delete a volume by name. */
  static async remove(name: string): Promise<void> {
    await withMappedErrors(() => napi.Volume.remove(name));
  }

  get name(): string {
    return this.inner.name;
  }

  get path(): string {
    return this.inner.path;
  }

  /** Host-side filesystem operations on this volume's directory. */
  fs(): VolumeFs {
    return new VolumeFs(this.inner.fs());
  }
}
