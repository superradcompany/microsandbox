/** Container format of a disk-image rootfs or volume. */
export type DiskImageFormat = "qcow2" | "raw" | "vmdk";

export const DiskImageFormats: readonly DiskImageFormat[] = ["qcow2", "raw", "vmdk"] as const;

/** Discriminator tags for `RootfsSource`. */
export type RootfsSourceKind = "bind" | "oci" | "disk";

export const RootfsSourceKinds: readonly RootfsSourceKind[] = [
  "bind",
  "oci",
  "disk",
] as const;

/** Source of a sandbox's root filesystem. */
export type RootfsSource =
  | { kind: "bind"; path: string }
  | { kind: "oci"; reference: string }
  | { kind: "disk"; path: string; format: DiskImageFormat; fstype?: string };

/**
 * Resolve a string to a `RootfsSource`:
 *   - a local-path anchor (`/`, `./`, `../`; plus `.\`, `..\`, `\`, `C:\`,
 *     `C:/` on Windows hosts) → bind (or disk if extension matches)
 *   - `.qcow2`/`.raw`/`.vmdk` extension → disk image
 *   - otherwise → OCI reference
 */
export function intoRootfsSource(input: string | RootfsSource): RootfsSource {
  if (typeof input !== "string") return input;
  const ext = lastExtension(input);
  if (ext && (ext === "qcow2" || ext === "raw" || ext === "vmdk")) {
    return { kind: "disk", path: input, format: ext };
  }
  if (looksLikeLocalPath(input)) return { kind: "bind", path: input };
  return { kind: "oci", reference: input };
}

/**
 * Mirrors `microsandbox_utils::looks_like_local_path_text`: POSIX anchors on
 * every platform, Windows anchors only on Windows hosts — keep in sync.
 */
function looksLikeLocalPath(s: string): boolean {
  if (
    s === "." ||
    s === ".." ||
    s.startsWith("/") ||
    s.startsWith("./") ||
    s.startsWith("../")
  ) {
    return true;
  }
  if (process.platform !== "win32") return false;
  return (
    s.startsWith(".\\") ||
    s.startsWith("..\\") ||
    s.startsWith("\\") ||
    /^[A-Za-z]:[\\/]/.test(s)
  );
}

function lastExtension(p: string): string | null {
  const sep = Math.max(p.lastIndexOf("/"), p.lastIndexOf("\\"));
  const tail = sep === -1 ? p : p.slice(sep + 1);
  const dot = tail.lastIndexOf(".");
  if (dot <= 0) return null;
  return tail.slice(dot + 1).toLowerCase();
}
