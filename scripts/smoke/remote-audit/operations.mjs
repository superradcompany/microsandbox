// An audit deadline stops waiting, not the underlying SDK operation. Keep every
// operation alive until it settles so cleanup cannot miss a late create result.
export class AuditOperations {
  #pending = new Set();

  async run(fn, timeoutMs) {
    const operation = Promise.resolve().then(fn);
    this.#pending.add(operation);
    // Attach both handlers immediately: a rejection after the deadline is still
    // observed, and must not become an unhandled rejection during cleanup.
    operation.then(
      () => this.#pending.delete(operation),
      () => this.#pending.delete(operation),
    );
    let timer;
    try {
      return await Promise.race([
        operation,
        new Promise((_, reject) => {
          timer = setTimeout(() => reject(Error("audit timeout")), timeoutMs);
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }

  async settle() {
    // Do not snapshot cleanup handles until every operation that can populate
    // them has completed. A killed process still needs sidecar-based recovery.
    while (this.#pending.size) {
      await Promise.allSettled([...this.#pending]);
    }
  }
}
