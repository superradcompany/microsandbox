import type { DiskImageFormat } from "./rootfs.js";

/** Discriminator tags for `VolumeMount`. */
export type VolumeMountKind = "bind" | "named" | "tmpfs" | "disk";

export const VolumeMountKinds: readonly VolumeMountKind[] = [
  "bind",
  "named",
  "tmpfs",
  "disk",
] as const;

/** Volume mount specification — see `MountBuilder` for the fluent constructor. */
export type VolumeMount =
  | { kind: "bind"; host: string; guest: string; readonly: boolean }
  | { kind: "named"; name: string; guest: string; readonly: boolean }
  | { kind: "tmpfs"; guest: string; sizeMib: number | null; readonly: boolean }
  | {
      kind: "disk";
      host: string;
      guest: string;
      format: DiskImageFormat;
      fstype: string | null;
      readonly: boolean;
    };
