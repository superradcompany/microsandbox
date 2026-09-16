import { ClientError } from "./error.js";
import { checkSignal, signalError } from "./timing.js";
import type { RawFrame } from "./wire.js";

type Reservation = { amount: number; grant(release: () => void): void; fail(error: ClientError): void; signal?: AbortSignal; abort(): void };

/** FIFO capacity with bounded waiters and cancellation before admission. */
export class Budget {
  private available: number;
  private readonly waiting: Reservation[] = [];
  private failure?: ClientError;
  constructor(readonly capacity: number, private readonly maxWaiters: number) { this.available = capacity; }

  acquire(amount: number, signal?: AbortSignal): Promise<() => void> {
    checkSignal(signal);
    if (this.failure) return Promise.reject(this.failure);
    if (amount > this.capacity || amount < 0 || !Number.isSafeInteger(amount)) return Promise.reject(new ClientError("capacity"));
    if (this.waiting.length === 0 && amount <= this.available) return Promise.resolve(this.reserve(amount));
    if (this.waiting.length >= this.maxWaiters) return Promise.reject(new ClientError("capacity"));
    return new Promise((grant, fail) => {
      const waiter: Reservation = { amount, grant, fail, signal, abort: () => {
        const index = this.waiting.indexOf(waiter);
        if (index >= 0) this.waiting.splice(index, 1);
        fail(signalError(signal!));
        this.pump();
      } };
      this.waiting.push(waiter);
      signal?.addEventListener("abort", waiter.abort, { once: true });
      if (signal?.aborted) waiter.abort();
    });
  }

  close(error: ClientError): void {
    this.failure = error;
    for (const waiter of this.waiting.splice(0)) {
      waiter.signal?.removeEventListener("abort", waiter.abort);
      waiter.fail(error);
    }
  }

  private reserve(amount: number): () => void {
    this.available -= amount;
    let released = false;
    return () => { if (!released) { released = true; this.available += amount; this.pump(); } };
  }

  private pump(): void {
    while (!this.failure && this.waiting[0] && this.waiting[0].amount <= this.available) {
      const waiter = this.waiting.shift()!;
      waiter.signal?.removeEventListener("abort", waiter.abort);
      waiter.grant(this.reserve(waiter.amount));
    }
  }
}

export type BufferedFrame = { frame: RawFrame; release(): void };
type Receiver = { resolve(value: RawFrame | null): void; reject(error: ClientError): void; signal?: AbortSignal; abort(): void };

/** Sole receiver, bounded response queue, and wakeable connection backpressure. */
export class FrameQueue {
  private readonly frames: BufferedFrame[] = [];
  private receiver?: Receiver;
  private space?: () => void;
  private ended = false;
  private failure?: ClientError;
  constructor(private readonly capacity: number) {}

  async push(value: BufferedFrame): Promise<boolean> {
    while (!this.ended && !this.receiver && this.frames.length >= this.capacity) {
      await new Promise<void>(resolve => { this.space = resolve; });
    }
    if (this.ended) { value.release(); return false; }
    const receiver = this.receiver;
    if (receiver) {
      this.receiver = undefined;
      receiver.signal?.removeEventListener("abort", receiver.abort);
      value.release();
      receiver.resolve(value.frame);
    } else this.frames.push(value);
    return true;
  }

  next(signal?: AbortSignal): Promise<RawFrame | null> {
    checkSignal(signal);
    if (this.receiver) return Promise.reject(new ClientError("receiving"));
    const value = this.frames.shift();
    if (value) { value.release(); this.wakeSpace(); return Promise.resolve(value.frame); }
    if (this.ended) {
      const failure = this.failure;
      this.failure = undefined;
      return failure ? Promise.reject(failure) : Promise.resolve(null);
    }
    return new Promise((resolve, reject) => {
      const receiver: Receiver = { resolve, reject, signal, abort: () => {
        if (this.receiver !== receiver) return;
        this.receiver = undefined;
        reject(signalError(signal!));
      } };
      this.receiver = receiver;
      signal?.addEventListener("abort", receiver.abort, { once: true });
      if (signal?.aborted) receiver.abort();
    });
  }

  finish(error?: ClientError, discard = false): void {
    this.ended = true;
    this.failure ??= error;
    if (discard) for (const frame of this.frames.splice(0)) frame.release();
    if (this.receiver) {
      const receiver = this.receiver;
      this.receiver = undefined;
      receiver.signal?.removeEventListener("abort", receiver.abort);
      if (this.failure) { receiver.reject(this.failure); this.failure = undefined; }
      else receiver.resolve(null);
    }
    this.wakeSpace();
  }

  private wakeSpace(): void { const space = this.space; this.space = undefined; space?.(); }
}
