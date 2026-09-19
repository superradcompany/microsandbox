/** Validate before N-API's u32 conversion can wrap or truncate the caller's budget. */
export function validateStopTimeout(timeoutMs: number): void {
  if (!Number.isInteger(timeoutMs) || timeoutMs < 0 || timeoutMs > 0xffff_ffff) {
    throw new RangeError("stop timeout must be an integer from 0 to 4294967295 milliseconds");
  }
}
