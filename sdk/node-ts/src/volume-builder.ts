import type { Mebibytes } from "./size.js";

/** Built volume configuration produced by `VolumeBuilder.build()`. */
export interface VolumeConfig {
  readonly name: string;
  readonly quotaMib: number | null;
  readonly labels: ReadonlyArray<readonly [string, string]>;
}

import { withMappedErrors } from "./internal/error-mapping.js";
import { napi } from "./internal/napi.js";
import { Volume } from "./volume.js";

export class VolumeBuilder {
  private readonly _name: string;
  private _quotaMib: number | null = null;
  private _labels: Array<readonly [string, string]> = [];

  /** @internal use `Volume.builder(name)` */
  constructor(name: string) {
    this._name = name;
  }

  quota(size: Mebibytes | number): this {
    this._quotaMib = Math.max(0, Math.floor(size));
    return this;
  }

  label(key: string, value: string): this {
    this._labels.push([key, value]);
    return this;
  }

  build(): VolumeConfig {
    return {
      name: this._name,
      quotaMib: this._quotaMib,
      labels: this._labels.slice(),
    };
  }

  async create(): Promise<Volume> {
    const cfg = this.build();
    const inner = await withMappedErrors(() =>
      napi.Volume.create({
        name: cfg.name,
        quotaMib: cfg.quotaMib ?? undefined,
        labels:
          cfg.labels.length > 0 ? Object.fromEntries(cfg.labels) : undefined,
      }),
    );
    return new Volume(inner);
  }
}
