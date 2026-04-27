/** Credentials for pulling private OCI images. */
export type RegistryAuth =
  | { kind: "anonymous" }
  | { kind: "basic"; username: string; password: string };
