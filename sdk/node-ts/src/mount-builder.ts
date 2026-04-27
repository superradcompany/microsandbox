import { InvalidConfigError } from "./errors.js";
import type { VolumeMount } from "./mount.js";
import type { DiskImageFormat } from "./rootfs.js";
import type { Mebibytes } from "./size.js";

type Kind =
  | { tag: "unset" }
  | { tag: "bind"; host: string }
  | { tag: "named"; name: string }
  | { tag: "tmpfs" }
  | { tag: "disk"; host: string };

const FSTYPE_FORBIDDEN = /[,;:=]/;

export class MountBuilder {
  private readonly guest: string;
  private kind: Kind = { tag: "unset" };
  private _readonly = false;
  private sizeMib: number | null = null;
  private diskFormat: DiskImageFormat | null = null;
  private diskFstype: string | null = null;
  private deferredError: Error | null = null;

  /** @internal use `SandboxBuilder.volume(guestPath, m => …)` */
  constructor(guest: string) {
    this.guest = guest;
  }

  bind(host: string): this {
    this.kind = { tag: "bind", host };
    return this;
  }

  named(name: string): this {
    this.kind = { tag: "named", name };
    return this;
  }

  tmpfs(): this {
    this.kind = { tag: "tmpfs" };
    return this;
  }

  /** Mount a host disk image as a virtio-blk device. */
  disk(host: string): this {
    this.kind = { tag: "disk", host };
    return this;
  }

  /** Override the disk image format. Only valid alongside `disk()`. */
  format(format: DiskImageFormat): this {
    this.diskFormat = format;
    return this;
  }

  /** Inner filesystem type for a disk image (e.g. `"ext4"`). */
  fstype(fstype: string): this {
    if (FSTYPE_FORBIDDEN.test(fstype)) {
      this.deferredError ??= new InvalidConfigError(
        `fstype must not contain ',', ';', ':', or '=': ${fstype}`,
      );
      return this;
    }
    this.diskFstype = fstype;
    return this;
  }

  /** Prevent writes to this mount. */
  readonly(): this {
    this._readonly = true;
    return this;
  }

  /** Size limit in MiB (tmpfs only). */
  size(size: Mebibytes | number): this {
    this.sizeMib = Math.max(0, Math.floor(size));
    return this;
  }

  /** @internal */
  build(): VolumeMount {
    if (this.deferredError) throw this.deferredError;

    if (!this.guest.startsWith("/")) {
      throw new InvalidConfigError(
        `guest mount path must be absolute: ${this.guest}`,
      );
    }
    if (this.guest === "/") {
      throw new InvalidConfigError("cannot mount a volume at guest root /");
    }
    if (this.guest.includes(":") || this.guest.includes(";")) {
      throw new InvalidConfigError(
        `guest mount path must not contain ':' or ';': ${this.guest}`,
      );
    }
    if (this.sizeMib !== null && this.kind.tag !== "tmpfs") {
      throw new InvalidConfigError(".size() is only valid for tmpfs mounts");
    }
    if (this.diskFormat !== null && this.kind.tag !== "disk") {
      throw new InvalidConfigError(".format() is only valid for disk image mounts");
    }
    if (this.diskFstype !== null && this.kind.tag !== "disk") {
      throw new InvalidConfigError(".fstype() is only valid for disk image mounts");
    }

    switch (this.kind.tag) {
      case "unset":
        throw new InvalidConfigError(
          "MountBuilder: no mount type set (call .bind(), .named(), .tmpfs(), or .disk())",
        );
      case "bind":
        return {
          kind: "bind",
          host: this.kind.host,
          guest: this.guest,
          readonly: this._readonly,
        };
      case "named":
        return {
          kind: "named",
          name: this.kind.name,
          guest: this.guest,
          readonly: this._readonly,
        };
      case "tmpfs":
        return {
          kind: "tmpfs",
          guest: this.guest,
          sizeMib: this.sizeMib,
          readonly: this._readonly,
        };
      case "disk": {
        const format =
          this.diskFormat ??
          inferDiskFormat(this.kind.host) ??
          "raw";
        return {
          kind: "disk",
          host: this.kind.host,
          guest: this.guest,
          format,
          fstype: this.diskFstype,
          readonly: this._readonly,
        };
      }
    }
  }
}

function inferDiskFormat(host: string): DiskImageFormat | null {
  const i = host.lastIndexOf(".");
  if (i < 0) return null;
  const ext = host.slice(i + 1).toLowerCase();
  if (ext === "qcow2" || ext === "raw" || ext === "vmdk") return ext;
  return null;
}
