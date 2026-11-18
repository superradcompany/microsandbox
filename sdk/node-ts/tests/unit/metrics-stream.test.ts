import { describe, expect, it, vi } from "vitest";
import { FsReadStream } from "../../dist/fs.js";
import { VolumeFsReadStream } from "../../dist/volume-fs.js";
import { LogStream } from "../../dist/logs.js";
import { MetricsStream } from "../../dist/metrics-stream.js";

const sample = {
  cpuPercent: 1, vcpuTimeNs: 2, memoryBytes: 3, memoryLimitBytes: 4,
  diskReadBytes: 5, diskWriteBytes: 6, netRxBytes: 7, netTxBytes: 8,
  uptimeMs: 9, timestampMs: 1000,
};

describe("MetricsStream disposal", () => {
  it("stops direct reads and iteration without polling native after disposal", async () => {
    const recv = vi.fn().mockResolvedValue(sample);
    const stream = new MetricsStream({ recv } as never);
    await stream[Symbol.asyncDispose]();
    expect(await stream.recv()).toBeNull();
    expect(await stream[Symbol.asyncIterator]().next()).toEqual({ done: true, value: undefined });
    expect(recv).not.toHaveBeenCalled();
  });

  it("stops an existing iterator between samples", async () => {
    const recv = vi.fn().mockResolvedValue(sample);
    const stream = new MetricsStream({ recv } as never);
    const iterator = stream[Symbol.asyncIterator]();
    const first = await iterator.next();
    expect(first.done).toBe(false);
    expect(first.value.timestamp).toEqual(new Date(1000));
    await stream[Symbol.asyncDispose]();
    expect((await iterator.next()).done).toBe(true);
    expect(recv).toHaveBeenCalledTimes(1);
  });

  it.each([false, true])("suppresses a read completing after disposal (iterator=%s)", async (iterate) => {
    let deliver!: (value: typeof sample) => void;
    const recv = vi.fn(() => new Promise<typeof sample>((resolve) => { deliver = resolve; }));
    const stream = new MetricsStream({ recv } as never);
    const pending = iterate ? stream[Symbol.asyncIterator]().next() : stream.recv();
    await stream[Symbol.asyncDispose]();
    deliver(sample);
    expect(await pending).toEqual(iterate ? { done: true, value: undefined } : null);
    expect(recv).toHaveBeenCalledTimes(1);
  });

  it("does not hide an in-flight read failure during disposal", async () => {
    let reject!: (reason: Error) => void;
    const recv = vi.fn(() => new Promise<never>((_, fail) => { reject = fail; }));
    const stream = new MetricsStream({ recv } as never);
    const pending = stream.recv();
    await stream[Symbol.asyncDispose]();
    const failure = new Error("transport failed");
    reject(failure);
    await expect(pending).rejects.toBe(failure);
  });

  it("checks disposal again between receiving and yielding a sample", async () => {
    let deliver!: (value: typeof sample) => void;
    const recv = vi.fn(() => new Promise<typeof sample>((resolve) => { deliver = resolve; }));
    const stream = new MetricsStream({ recv } as never);
    const pending = stream[Symbol.asyncIterator]().next();
    deliver(sample);
    // Let error mapping and recv settle, before the generator resumes its await.
    await Promise.resolve();
    await Promise.resolve();
    await stream[Symbol.asyncDispose]();
    expect(await pending).toEqual({ done: true, value: undefined });
  });

  it("remembers native EOF across access routes", async () => {
    const recv = vi.fn().mockResolvedValue(null);
    const stream = new MetricsStream({ recv } as never);
    expect((await stream[Symbol.asyncIterator]().next()).done).toBe(true);
    expect(await stream.recv()).toBeNull();
    expect(recv).toHaveBeenCalledTimes(1);
  });
});

describe.each([FsReadStream, VolumeFsReadStream, LogStream])("%s disposal", Stream => {
  it("suppresses pending items and prevents later native reads", async () => {
    let deliver!: (item: unknown) => void;
    const recv = vi.fn(() => new Promise(resolve => { deliver = resolve; }));
    const stream = new Stream({ recv } as never);
    const pending = stream[Symbol.asyncIterator]().next();
    await stream[Symbol.asyncDispose]();
    deliver(Buffer.from("late"));
    expect((await pending).done).toBe(true);
    expect(await stream.recv()).toBeNull();
    expect((await stream[Symbol.asyncIterator]().next()).done).toBe(true);
    expect(recv).toHaveBeenCalledTimes(1);
  });
});
