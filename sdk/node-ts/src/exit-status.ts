export interface ExitStatus {
  /** Process exit code. */
  readonly code: number;
  /** `true` when `code === 0`. */
  readonly success: boolean;
}
