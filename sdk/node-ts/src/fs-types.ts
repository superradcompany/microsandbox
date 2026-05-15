export type FsEntryKind = "file" | "directory" | "symlink" | "other";

export interface FsEntry {
  readonly path: string;
  readonly kind: FsEntryKind;
  readonly size: number;
  readonly mode: number;
  readonly modified: Date | null;
}

export interface FsMetadata {
  readonly kind: FsEntryKind;
  readonly size: number;
  readonly mode: number;
  readonly readonly: boolean;
  readonly modified: Date | null;
  readonly created: Date | null;
}
