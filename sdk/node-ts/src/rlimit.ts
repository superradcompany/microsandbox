export type RlimitResource =
  | "cpu"
  | "fsize"
  | "data"
  | "stack"
  | "core"
  | "rss"
  | "nproc"
  | "nofile"
  | "memlock"
  | "as"
  | "locks"
  | "sigpending"
  | "msgqueue"
  | "nice"
  | "rtprio"
  | "rttime";

export interface Rlimit {
  readonly resource: RlimitResource;
  readonly soft: number;
  readonly hard: number;
}
