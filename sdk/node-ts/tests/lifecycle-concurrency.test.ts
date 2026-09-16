import { createRequire } from "node:module";
import { execFileSync } from "node:child_process";
import { mkdtemp, open, rmdir, unlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { performance } from "node:perf_hooks";
import { setTimeout as delay } from "node:timers/promises";
import { describe, expect, it } from "vitest";
import { Sandbox, SandboxNotFoundError } from "../dist/index.js";

const native: typeof import("../native/index.js") = createRequire(import.meta.url)("../native/index.cjs");
const consumed = /Sandbox handle has been consumed/;

async function bounded<T>(promise: Promise<T>, label: string, timeoutMs = 2_000): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      promise,
      new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error(`${label} timed out after ${timeoutMs} ms`)), timeoutMs);
      }),
    ]);
  } finally {
    clearTimeout(timer);
  }
}

async function fixture(label: string, run: (source: Sandbox, observer: Sandbox) => Promise<void>) {
  const name = `node-concurrency-${label}-${process.pid}`;
  const source = await Sandbox.builder(name).image("alpine").rootDisk(512).memory(256).create();
  let observer: Sandbox | undefined;
  try {
    observer = await (await Sandbox.get(name)).connect();
    await run(source, observer);
  } finally {
    // A separate handle can recover a paused VM even if the tested wrapper is
    // consumed or regresses to holding its lock while waiting for the guest.
    const handle = await Sandbox.get(name).catch(error => {
      if (error instanceof SandboxNotFoundError) return undefined;
      throw error;
    });
    if (handle) {
      if (handle.status === "paused") await handle.resume();
      await handle.stop();
      await Sandbox.remove(name);
    }
  }
}

async function gatedExec(source: Sandbox, observer: Sandbox) {
  const pending = source.exec("sh", ["-c", "touch /dev/shm/started; while [ ! -e /dev/shm/release ]; do sleep 0.02; done; echo completed"]);
  // Attach a rejection handler immediately so fixture cleanup cannot produce
  // an unhandled rejection if a later assertion fails and stops the VM.
  void pending.catch(() => undefined);
  await bounded((async () => {
    while (!(await observer.fs().exists("/dev/shm/started"))) await delay(10);
  })(), "guest admission");
  return { pending };
}

describe.skipIf(process.env.MSB_NODE_LIFECYCLE_LIVE !== "1")("same-object lifecycle concurrency", () => {
  it("pauses and resumes while exec is pending, then completes the original exec", async () => {
    await fixture("exec", async (source, observer) => {
      const { pending } = await gatedExec(source, observer);
      let settled = false;
      void pending.finally(() => { settled = true; }).catch(() => undefined);
      const pauses: number[] = [];
      const resumes: number[] = [];
      for (let cycle = 0; cycle < 20; cycle++) {
        let started = performance.now();
        await bounded(source.pause(), "pause during exec");
        pauses.push(performance.now() - started);
        expect((await Sandbox.get(source.name)).status).toBe("paused");
        started = performance.now();
        await bounded(source.resume(), "resume during exec");
        resumes.push(performance.now() - started);
        expect(settled).toBe(false);
      }
      await observer.fs().write("/dev/shm/release", "go");
      expect((await bounded(pending, "exec completion")).stdout().trim()).toBe("completed");
      const timings = { platform: process.platform, arch: process.arch, pauses_ms: pauses, resumes_ms: resumes };
      console.log(JSON.stringify(timings));
      if (process.env.MSB_NODE_TIMINGS) await writeFile(process.env.MSB_NODE_TIMINGS, JSON.stringify(timings, null, 2));
    });
  });

  it("does not let a filesystem request to a paused guest block resume", async () => {
    await fixture("fs", async (source) => {
      const fs = source.fs();
      await fs.write("/dev/shm/payload", "retained");
      await source.pause();
      const read = fs.readToString("/dev/shm/payload");
      // Both a prompt paused-state refusal and a read waiting for resume are
      // valid; neither is allowed to monopolize the wrapper lock.
      const outcome = read.then(value => ({ value }), error => ({ error }));
      await delay(50);
      await bounded(source.resume(), "resume during filesystem read");
      const result = await bounded(outcome, "filesystem completion");
      if ("error" in result) expect(String(result.error)).toMatch(/paused/i);
      else expect(result.value).toBe("retained");
      expect(await fs.readToString("/dev/shm/payload")).toBe("retained");
    });
  });

  it("detach consumes new calls and existing filesystem facades without draining exec", async () => {
    await fixture("detach", async (source, observer) => {
      const fs = source.fs();
      const { pending } = await gatedExec(source, observer);
      await bounded(source.detach(), "detach during exec");
      await expect(source.pause()).rejects.toThrow(consumed);
      await expect(source.exec("true")).rejects.toThrow(consumed);
      await expect(fs.exists("/dev/shm/started")).rejects.toThrow(consumed);
      await source.detach(); // Detach remains idempotent.
      await observer.fs().write("/dev/shm/release", "go");
      expect((await bounded(pending, "detached exec completion")).stdout().trim()).toBe("completed");
      expect((await observer.exec("echo", ["alive"])).stdout().trim()).toBe("alive");
    });
  });

  it.skipIf(process.platform === "win32")("pause, resume and detach progress during a blocked filesystem upload", async () => {
    await fixture("upload", async (source, observer) => {
      const directory = await mkdtemp(join(tmpdir(), "msb-node-upload-"));
      const fifo = join(directory, "input");
      execFileSync("mkfifo", [fifo]);
      const fs = source.fs();
      const upload = fs.copyFromHost(fifo, "/dev/shm/uploaded");
      void upload.catch(() => undefined);
      // Opening the writer proves the native filesystem operation has opened
      // its reader. With no bytes or EOF, the upload cannot complete yet.
      const writer = await open(fifo, "w");
      let closed = false;
      try {
        await writer.writeFile("initial ");
        await bounded((async () => {
          while (true) {
            try {
              if ((await observer.fs().stat("/dev/shm/uploaded")).size >= 8) break;
            } catch (error) {
              if (!String(error).includes("No such file")) throw error;
            }
            await delay(10);
          }
        })(), "guest upload admission");
        await bounded(source.pause(), "pause during upload");
        await bounded(source.resume(), "resume during upload");
        await bounded(source.detach(), "detach during upload");
        await expect(fs.exists("/tmp")).rejects.toThrow(consumed);
        await writer.writeFile("private upload payload");
        await writer.close();
        closed = true;
        await bounded(upload, "admitted upload after detach");
        expect(await observer.fs().readToString("/dev/shm/uploaded")).toBe("initial private upload payload");
      } finally {
        if (!closed) await writer.close();
        await unlink(fifo);
        await rmdir(directory);
      }
    });
  });

  it("removal consumes its wrapper while exec is pending, independently of lifecycle locking", async () => {
    await fixture("remove", async (source, observer) => {
      const raw = await (await native.Sandbox.get(source.name)).connect();
      const fs = raw.fs();
      const pending = raw.exec("sh", ["-c", "touch /dev/shm/started; while [ ! -e /dev/shm/release ]; do sleep 0.02; done; echo completed"]);
      void pending.catch(() => undefined);
      await bounded((async () => {
        while (!(await observer.fs().exists("/dev/shm/started"))) await delay(10);
      })(), "native exec admission");
      const removal = raw.removePersisted().then(() => ({ removed: true }), error => ({ error }));
      await delay(50);
      await expect(bounded(raw.pause(), "consumed pause")).rejects.toThrow(consumed);
      await expect(bounded(fs.exists("/dev/shm/started"), "consumed filesystem")).rejects.toThrow(consumed);
      await expect(raw.removePersisted()).rejects.toThrow(consumed);
      await observer.fs().write("/dev/shm/release", "go");
      expect((await bounded(pending, "exec after failed removal")).success).toBe(true);
      // Runtime lifecycle locking can defer removal until shutdown or reject
      // the running VM. Neither should keep the Node admission slot locked.
      const stopError = await observer.stop().then(() => undefined, error => error);
      const result = await bounded(removal, "removal after shutdown", 10_000);
      if (stopError !== undefined) {
        // Removal can win after the VM exits but before stop's final database
        // observation. Accept a missing row only when this removal succeeded.
        expect(stopError).toBeInstanceOf(SandboxNotFoundError);
        expect("removed" in result).toBe(true);
      }
      if ("error" in result) expect(String(result.error)).toMatch(/running|stopped|lock|timed out/i);
    });
  });

  it("a terminal-state waiter does not block stopping and successful removal", async () => {
    const name = `node-concurrency-stopped-${process.pid}`;
    const raw = await new native.SandboxBuilder(name).image("alpine").rootDisk(512).memory(256).create();
    try {
      const fs = raw.fs();
      const waiter = raw.waitUntilStopped();
      void waiter.catch(() => undefined);
      await delay(50);
      await bounded(raw.stop(), "stop during wait", 10_000);
      await bounded(waiter, "terminal-state observation");
      await raw.removePersisted();
      await expect(raw.resume()).rejects.toThrow(consumed);
      await expect(fs.exists("/tmp")).rejects.toThrow(consumed);
      await expect(native.Sandbox.get(name)).rejects.toThrow();
    } finally {
      // Successful removal already deleted the record; only recover a fixture
      // that still exists. Unexpected cleanup errors must remain visible.
      const handle = await Sandbox.get(name).catch(() => undefined);
      if (handle) {
        await handle.stop();
        await Sandbox.remove(name);
      }
    }
  });
});
