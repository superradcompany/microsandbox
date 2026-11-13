import { describe, expect, it, vi } from "vitest";
import { LogEntry, LogStream } from "../../dist/logs.js";
import { MetricsStream } from "../../dist/metrics-stream.js";
import { IoError } from "../../dist/errors.js";

const log = {
  timestampMs: 1234, source: "stdout", sessionId: null,
  data: Buffer.from("hello"), cursor: "resume-token",
};
const metrics = {
  cpuPercent: 25, vcpuTimeNs: 42, memoryBytes: 1024, memoryLimitBytes: 2048,
  diskReadBytes: 3, diskWriteBytes: 4, netRxBytes: 5, netTxBytes: 6,
  uptimeMs: 1000, timestampMs: 1234,
};

for (const [kind, Stream, sample] of [
  ["logs", LogStream, log], ["metrics", MetricsStream, metrics],
] as const) {
  describe(`${kind} stream lifecycle`, () => {
    function fixture() {
      const native = { recv: vi.fn(async () => sample as typeof sample | null) };
      return { native, stream: new Stream(native as never) };
    }

    it("normalizes each received value and ends at EOF", async () => {
      const { native, stream } = fixture();
      native.recv.mockResolvedValueOnce(sample).mockResolvedValueOnce(null);
      const values = [];
      for await (const value of stream) values.push(value);
      expect(values).toHaveLength(1);
      expect(values[0]?.timestamp).toEqual(new Date(1234));
      if (kind === "logs") {
        expect(values[0]).toBeInstanceOf(LogEntry);
        expect((values[0] as LogEntry).text()).toBe("hello");
        expect((values[0] as LogEntry).cursor).toBe("resume-token");
      } else {
        expect(values[0]).toMatchObject({ cpuPercent: 25, memoryBytes: 1024, upperUsedBytes: null });
      }
      expect(native.recv).toHaveBeenCalledTimes(2);
    });

    it.each(["before", "after"])("stops an iterator created %s disposal", async timing => {
      const { native, stream } = fixture();
      const before = timing === "before" ? stream[Symbol.asyncIterator]() : null;
      await stream[Symbol.asyncDispose]();
      const iterator = before ?? stream[Symbol.asyncIterator]();
      expect(await iterator.next()).toEqual({ value: undefined, done: true });
      expect(await stream.recv()).toBeNull();
      expect(native.recv).not.toHaveBeenCalled();
    });

    it("stops the next iteration when disposed between yields", async () => {
      const { native, stream } = fixture();
      const iterator = stream[Symbol.asyncIterator]();
      expect((await iterator.next()).done).toBe(false);
      await stream[Symbol.asyncDispose]();
      expect((await iterator.next()).done).toBe(true);
      expect(native.recv).toHaveBeenCalledTimes(1);
    });

    it("does not receive again after direct recv reaches EOF", async () => {
      const { native, stream } = fixture();
      native.recv.mockResolvedValueOnce(null);
      expect(await stream.recv()).toBeNull();
      expect((await stream[Symbol.asyncIterator]().next()).done).toBe(true);
      expect(native.recv).toHaveBeenCalledTimes(1);
    });

    it("remembers EOF reached through iteration for subsequent consumers", async () => {
      const { native, stream } = fixture();
      native.recv.mockResolvedValueOnce(null);
      expect((await stream[Symbol.asyncIterator]().next()).done).toBe(true);
      expect(await stream.recv()).toBeNull();
      expect((await stream[Symbol.asyncIterator]().next()).done).toBe(true);
      expect(native.recv).toHaveBeenCalledTimes(1);
    });

    it("allows an already pending receive to finish after disposal", async () => {
      const { native, stream } = fixture();
      let finish!: (value: typeof sample) => void;
      native.recv.mockImplementationOnce(() => new Promise(resolve => { finish = resolve; }));
      const iterator = stream[Symbol.asyncIterator]();
      const pending = iterator.next();
      await stream[Symbol.asyncDispose]();
      finish(sample);
      expect((await pending).done).toBe(false);
      expect((await iterator.next()).done).toBe(true);
      expect(native.recv).toHaveBeenCalledTimes(1);
    });

    it("maps a native error only once even when its message starts with another tag", async () => {
      const { native, stream } = fixture();
      const error = new Error("[Io] [Runtime] read failed");
      native.recv.mockRejectedValueOnce(error);
      const received = await stream[Symbol.asyncIterator]().next().catch(value => value);
      expect(received).toBeInstanceOf(IoError);
      expect(received.message).toBe("[Runtime] read failed");
      expect(received.cause).toBe(error);
    });

    it.each([new Error("untagged error"), "non-Error failure"])("preserves an unmapped failure", async error => {
      const { native, stream } = fixture();
      native.recv.mockRejectedValueOnce(error);
      await expect(stream[Symbol.asyncIterator]().next()).rejects.toBe(error);
    });
  });
}
