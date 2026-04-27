import { withMappedErrors } from "./error-mapping.js";

export interface NapiRecvSource<U> {
  recv(): Promise<U | null>;
}

export async function* mapAsyncIterable<U, T>(
  source: NapiRecvSource<U>,
  normalize: (raw: U) => T,
): AsyncGenerator<T, void, void> {
  for (;;) {
    const raw = await withMappedErrors(() => source.recv());
    if (raw === null) return;
    yield normalize(raw);
  }
}
