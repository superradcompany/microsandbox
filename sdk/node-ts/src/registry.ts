/** Discriminator tags for `RegistryAuth`. */
export type RegistryAuthKind = "anonymous" | "basic";

export const RegistryAuthKinds: readonly RegistryAuthKind[] = [
  "anonymous",
  "basic",
] as const;

/** Credentials for pulling private OCI images. */
export type RegistryAuth =
  | { kind: "anonymous" }
  | { kind: "basic"; username: string; password: string };
