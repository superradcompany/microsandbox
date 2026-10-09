import { napi, type NapiMountBuilder } from "./napi.js";

/** Captured-disk rebindings for a fork, keyed by guest path. */
export type ForkVolumes = Record<string, (mount: NapiMountBuilder) => NapiMountBuilder>;

/** Configure one mount per guest path. */
export function forkMountBuilders(volumes: ForkVolumes | undefined): NapiMountBuilder[] {
  return Object.entries(volumes ?? {}).map(([guest, configure]) =>
    configure(new napi.MountBuilder(guest)),
  );
}
