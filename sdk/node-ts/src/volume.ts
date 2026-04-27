import { withMappedErrors } from "./internal/error-mapping.js";
import type { NapiVolume } from "./internal/napi.js";
import { napi } from "./internal/napi.js";
import { VolumeBuilder } from "./volume-builder.js";
import { VolumeHandle, volumeInfoToHandle } from "./volume-handle.js";
import { VolumeFs } from "./volume-fs.js";

export class Volume {
  /** @internal */
  readonly inner: NapiVolume;

  /** @internal */
  constructor(inner: NapiVolume) {
    this.inner = inner;
  }

  static builder(name: string): VolumeBuilder {
    return new VolumeBuilder(name);
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
