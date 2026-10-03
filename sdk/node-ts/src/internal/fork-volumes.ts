import { UnsupportedError } from "../errors.js";
import { napi, type NapiMountBuilder, type NapiSandbox } from "./napi.js";

/** Captured-disk rebindings for a fork, keyed by guest path. */
export type ForkVolumes = Record<string, (mount: NapiMountBuilder) => NapiMountBuilder>;

type ForkVolumesNative = Required<Pick<NapiSandbox, "forkWithVolumes" | "forkManyWithVolumes">>;

/** Configure one mount per guest path. */
export function forkMountBuilders(volumes: ForkVolumes | undefined): NapiMountBuilder[] {
  return Object.entries(volumes ?? {}).map(([guest, configure]) =>
    configure(new napi.MountBuilder(guest)),
  );
}

/** Refuse a fork with volumes when the native library would silently ignore them. */
export function withForkVolumes<T extends Partial<ForkVolumesNative>>(
  inner: T,
): T & ForkVolumesNative {
  if (
    typeof inner.forkWithVolumes !== "function" ||
    typeof inner.forkManyWithVolumes !== "function"
  ) {
    throw new UnsupportedError(
      "Installed native SDK does not support fork volumes; update the microsandbox native library",
    );
  }
  return inner as T & ForkVolumesNative;
}
