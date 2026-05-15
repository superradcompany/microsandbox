import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Sandbox } from "../dist/index.js";
import { msbPath } from "../dist/internal/resolve-binary.js";
import type { PullProgress } from "../dist/index.js";

const SANDBOX_NAME = "sdk-smoke-test";

describe.skipIf(!msbPath())("end-to-end smoke", () => {
  let sb: Sandbox;

  beforeAll(async () => {
    sb = await Sandbox.builder(SANDBOX_NAME)
      .image("mirror.gcr.io/library/alpine")
      .cpus(1)
      .memory(512)
      .replace()
      .create();
  });

  afterAll(async () => {
    await sb?.stopAndWait().catch(() => undefined);
    await Sandbox.remove(SANDBOX_NAME).catch(() => undefined);
  });

  it("exposes name synchronously", () => {
    expect(sb.name).toBe(SANDBOX_NAME);
  });

  it("runs a command via exec()", async () => {
    const out = await sb.exec("echo", ["hello"]);
    expect(out.success).toBe(true);
    expect(out.stdout()).toBe("hello\n");
  });

  it("streams events via execStream()", async () => {
    const handle = await sb.execStream("sh", [
      "-c",
      "echo a; echo b 1>&2; exit 7",
    ]);
    let stdout = "";
    let stderr = "";
    let code: number | null = null;
    for await (const ev of handle) {
      if (ev.kind === "stdout") stdout += new TextDecoder().decode(ev.data);
      if (ev.kind === "stderr") stderr += new TextDecoder().decode(ev.data);
      if (ev.kind === "exited") code = ev.code;
    }
    expect(stdout).toBe("a\n");
    expect(stderr).toBe("b\n");
    expect(code).toBe(7);
  });

  it("reads and writes files via SandboxFs", async () => {
    const fs = sb.fs();
    await fs.write("/tmp/x.txt", "data\n");
    expect(await fs.readToString("/tmp/x.txt")).toBe("data\n");
    expect(await fs.exists("/tmp/x.txt")).toBe(true);
    expect(await fs.exists("/tmp/missing.txt")).toBe(false);
  });

  it("snapshots metrics", async () => {
    const m = await sb.metrics();
    expect(m.timestamp).toBeInstanceOf(Date);
    expect(typeof m.cpuPercent).toBe("number");
  });
});

describe("Node.js SDK Pull Progress", () => {
	const NAME_ITER = "sdk-pp-i";
	const NAME_RECV = "sdk-pp-r";
	const NAME_DETACHED = "sdk-pp-d";
	const NAME_ERROR = "sdk-pp-e";
	const NAME_DOUBLE = "sdk-pp-x";

	afterAll(async () => {
		for (const n of [NAME_ITER, NAME_RECV, NAME_DETACHED, NAME_ERROR, NAME_DOUBLE]) {
			await Sandbox.remove(n).catch(() => {});
		}
	});

	it("emits resolving → resolved → complete in order with populated fields", async () => {
		// pullPolicy:"always" forces a fresh resolve so we reliably see the
		// resolving→resolved→complete milestone sequence. Layer events may or
		// may not appear depending on local cache state.
		const session = await Sandbox.builder(NAME_ITER)
			.image("mirror.gcr.io/library/alpine")
			.cpus(1)
			.memory(512)
			.replace()
			.pullPolicy("always")
			.createWithPullProgress();

		const events: PullProgress[] = [];
		for await (const ev of session) events.push(ev);

		expect(events.length).toBeGreaterThan(0);

		const first = events[0];
		if (first.kind !== "resolving") throw new Error(`expected first event to be resolving, got ${first.kind}`);
		expect(first.reference).toBeTruthy();
		const reference = first.reference;

		const resolved = events.find((e) => e.kind === "resolved");
		if (resolved?.kind !== "resolved") throw new Error("resolved event missing");
		expect(resolved.reference).toBe(reference);
		expect(resolved.manifestDigest).toBeTruthy();
		expect(resolved.layerCount).toBeGreaterThan(0);

		const last = events[events.length - 1];
		if (last.kind !== "complete") throw new Error(`expected last event to be complete, got ${last.kind}`);
		expect(last.reference).toBe(reference);
		expect(last.layerCount).toBe(resolved.layerCount);

		const idx = (t: PullProgress["kind"]) => events.findIndex((e) => e.kind === t);
		expect(idx("resolving")).toBeLessThan(idx("resolved"));
		expect(idx("resolved")).toBeLessThan(idx("complete"));

		// Field population is best-effort — layer events only fire on cache miss.
		const progress = events.find((e) => e.kind === "layerDownloadProgress");
		if (progress?.kind === "layerDownloadProgress") {
			expect(progress.layerIndex).toBeGreaterThanOrEqual(0);
			expect(progress.digest).toBeTruthy();
			expect(progress.downloadedBytes).toBeGreaterThanOrEqual(0);
		}

		const sb = await session.awaitSandbox();
		expect(sb.name).toBe(NAME_ITER);
		await sb.stopAndWait();
	}, 180_000);

	it("streams events via recv() without the async iterator", async () => {
		const session = await Sandbox.builder(NAME_RECV)
			.image("mirror.gcr.io/library/alpine")
			.cpus(1)
			.memory(512)
			.replace()
			.createWithPullProgress();

		const eventTypes: string[] = [];
		let ev = await session.progress.recv();
		while (ev !== null) {
			eventTypes.push(ev.kind);
			ev = await session.progress.recv();
		}

		expect(eventTypes.length).toBeGreaterThanOrEqual(3);
		expect(eventTypes[0]).toBe("resolving");
		expect(eventTypes).toContain("resolved");
		expect(eventTypes[eventTypes.length - 1]).toBe("complete");

		const sb = await session.awaitSandbox();
		await sb.stopAndWait();
	}, 120_000);

	it("createDetachedWithPullProgress yields events and creates a detached sandbox", async () => {
		const session = await Sandbox.builder(NAME_DETACHED)
			.image("mirror.gcr.io/library/alpine")
			.cpus(1)
			.memory(512)
			.replace()
			.createDetachedWithPullProgress();

		const types: string[] = [];
		for await (const ev of session) types.push(ev.kind);

		expect(types[0]).toBe("resolving");
		expect(types).toContain("resolved");
		expect(types[types.length - 1]).toBe("complete");

		const sb = await session.awaitSandbox();
		expect(sb.name).toBe(NAME_DETACHED);

		await sb.stopAndWait();
	}, 120_000);

	it("result() rejects when the image cannot be pulled", async () => {
		// pullPolicy:"never" with an image that is not in the local cache
		// forces a fast failure without hitting any network.
		const session = await Sandbox.builder(NAME_ERROR)
			.image("sdk-nonexistent-image-xyz789:never")
			.cpus(1)
			.memory(512)
			.replace()
			.pullPolicy("never")
			.createWithPullProgress();

		for await (const _ev of session) {}

		await expect(session.awaitSandbox()).rejects.toThrow(/not.*cache|cached|not found/i);
	}, 60_000);

	it("awaitSandbox() rejects on the second call", async () => {
		const session = await Sandbox.builder(NAME_DOUBLE)
			.image("mirror.gcr.io/library/alpine")
			.cpus(1)
			.memory(512)
			.replace()
			.createWithPullProgress();

		for await (const _ev of session) {}

		const sb = await session.awaitSandbox();
		expect(sb.name).toBe(NAME_DOUBLE);
		await expect(session.awaitSandbox()).rejects.toThrow(/already (called|consumed)/);

		await sb.stopAndWait();
	}, 120_000);
});
