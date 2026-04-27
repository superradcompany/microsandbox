/** Container format of a disk-image rootfs or volume. */
export type DiskImageFormat = "qcow2" | "raw" | "vmdk";

export const DiskImageFormats: readonly DiskImageFormat[] = ["qcow2", "raw", "vmdk"] as const;

/** Source of a sandbox's root filesystem. */
export type RootfsSource =
  | { kind: "bind"; path: string }
  | { kind: "oci"; reference: string }
  | { kind: "disk"; path: string; format: DiskImageFormat; fstype?: string };

/**
 * Resolve a string to a `RootfsSource`:
 *   - leading `/`, `./`, `../` → bind (or disk if extension matches)
 *   - `.qcow2`/`.raw`/`.vmdk` extension → disk image
 *   - otherwise → OCI reference
 */
export function intoRootfsSource(input: string | RootfsSource): RootfsSource {
  if (typeof input !== "string") return input;
  const isPath =
    input.startsWith("/") || input.startsWith("./") || input.startsWith("../");
  const ext = lastExtension(input);
  if (ext && (ext === "qcow2" || ext === "raw" || ext === "vmdk")) {
    return { kind: "disk", path: input, format: ext };
  }
  if (isPath) return { kind: "bind", path: input };
  return { kind: "oci", reference: input };
}

function lastExtension(p: string): string | null {
  const slash = p.lastIndexOf("/");
  const tail = slash === -1 ? p : p.slice(slash + 1);
  const dot = tail.lastIndexOf(".");
  if (dot <= 0) return null;
  return tail.slice(dot + 1).toLowerCase();
}
