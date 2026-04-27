import type { DiskImageFormat } from "./rootfs.js";

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
