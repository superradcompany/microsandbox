/** Pre-boot rootfs modification — see `PatchBuilder` for the fluent constructor. */
export type Patch =
  | {
      kind: "text";
      path: string;
      content: string;
      mode?: number;
      replace?: boolean;
    }
  | {
      kind: "file";
      path: string;
      content: Uint8Array;
      mode?: number;
      replace?: boolean;
    }
  | {
      kind: "copyFile";
      src: string;
      dst: string;
      mode?: number;
      replace?: boolean;
    }
  | { kind: "copyDir"; src: string; dst: string; replace?: boolean }
  | { kind: "symlink"; target: string; link: string; replace?: boolean }
  | { kind: "mkdir"; path: string; mode?: number }
  | { kind: "remove"; path: string }
  | { kind: "append"; path: string; content: string };
