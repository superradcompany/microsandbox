import { withMappedErrors } from "./internal/error-mapping.js";
import type {
  NapiVolumeHandle,
  NapiVolumeInfo,
} from "./internal/napi.js";
import { VolumeFs } from "./volume-fs.js";

const READ_ONLY_MSG =
  "VolumeHandle is read-only — fetch a live handle via Volume.get(name) for lifecycle methods.";

export class VolumeHandle {
  private readonly inner: NapiVolumeHandle | NapiVolumeInfo;
  readonly name: string;
  readonly quotaMib: number | null;
  readonly usedBytes: number;
  readonly labels: ReadonlyArray<readonly [string, string]>;
  readonly createdAt: Date | null;

  /** @internal */
  constructor(inner: NapiVolumeHandle | NapiVolumeInfo) {
    this.inner = inner;
    this.name = inner.name;
    this.quotaMib =
      typeof inner.quotaMib === "number" ? inner.quotaMib : null;
    this.usedBytes = inner.usedBytes;
    this.labels = Object.entries(inner.labels);
    this.createdAt =
      typeof inner.createdAt === "number" ? new Date(inner.createdAt) : null;
  }

  async remove(): Promise<void> {
    if (typeof (this.inner as NapiVolumeHandle).remove !== "function") {
      throw new Error(READ_ONLY_MSG);
    }
    await withMappedErrors(() => (this.inner as NapiVolumeHandle).remove());
  }

  /** Host-side filesystem operations on this volume's directory. */
  fs(): VolumeFs {
    if (typeof (this.inner as NapiVolumeHandle).fs !== "function") {
      throw new Error(READ_ONLY_MSG);
    }
    return new VolumeFs((this.inner as NapiVolumeHandle).fs());
  }
}

/** @internal */
export function volumeInfoToHandle(info: NapiVolumeInfo): VolumeHandle {
  return new VolumeHandle(info);
}
