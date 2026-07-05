import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { Sandbox } from "../dist/index.js";
import { msbPath } from "../dist/internal/resolve-binary.js";
import type { PullProgress } from "../dist/index.js";

const SANDBOX_NAME = "sdk-smoke-test";


async function waitForSandboxMetrics(sb: Sandbox) {
  let lastError: unknown;

  // The runtime publishes the live metrics slot asynchronously after boot
  // readiness, so `create()` can return just before the first slot appears.
  for (let attempt = 0; attempt < 20; attempt++) {
    try {
      return await sb.metrics();
    } catch (error) {
      if (
        !(error instanceof Error) ||
        !error.message.includes("no live metrics slot")
      ) {
        throw error;
      }
      lastError = error;
      await new Promise((resolve) => setTimeout(resolve, 100));
    }
  }

  throw lastError;
}

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
    await sb?.stop().catch(() => undefined);
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

  it("reads and writes files via SandboxFsOps", async () => {
    const fs = sb.fs();
    await fs.write("/tmp/x.txt", "data\n");
    expect(await fs.readToString("/tmp/x.txt")).toBe("data\n");
    expect(await fs.exists("/tmp/x.txt")).toBe(true);
    expect(await fs.exists("/tmp/missing.txt")).toBe(false);
  });

  it("snapshots metrics", async () => {
    const m = await waitForSandboxMetrics(sb);
    expect(m.timestamp).toBeInstanceOf(Date);
    expect(typeof m.cpuPercent).toBe("number");
  });

  it("pings and touches the running sandbox", async () => {
    const ping = await sb.ping();
    expect(ping.name).toBe(SANDBOX_NAME);
    expect(ping.latencyMs).toBeGreaterThanOrEqual(0);

    const touch = await sb.touch();
    expect(touch.name).toBe(SANDBOX_NAME);
    expect(touch.activitySeq).toBeGreaterThan(0);

    const handle = await Sandbox.get(SANDBOX_NAME);
    await expect(handle.ping()).resolves.toMatchObject({ name: SANDBOX_NAME });
    await expect(handle.touch()).resolves.toMatchObject({ name: SANDBOX_NAME });
  });

  it("plans a dry-run modification without applying it", async () => {
    const plan = await sb.modify({
      cpus: 2,
      labels: { tier: "gold" },
      dryRun: true,
    });
    expect(plan.sandbox).toBe(SANDBOX_NAME);
    expect(plan.applied).toBe(false);
    expect(plan.policy).toBe("no_restart");
    const fields = plan.changes.map((change) => change.field);
    expect(fields).toContain("cpus");
    expect(fields).toContain("label");

    const handle = await Sandbox.get(SANDBOX_NAME);
    const handlePlan = await handle.modify({
      env: { MODIFIED: "1" },
      dryRun: true,
    });
    expect(handlePlan.sandbox).toBe(SANDBOX_NAME);
    expect(handlePlan.applied).toBe(false);
  });
});

describe("Node.js SDK Pull Progress", () => {
	const NAME_ITER = "sdk-pp-i";
	const NAME_RECV = "sdk-pp-r";
	const NAME_DETACHED = "sdk-pp-d";
	const NAME_ERROR = "sdk-pp-e";
	const NAME_DOUBLE = "sdk-pp-x";
	const STARTUP_TEST_TIMEOUT_MS = 300_000;

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
		await sb.stop();
	}, STARTUP_TEST_TIMEOUT_MS);

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
		await sb.stop();
	}, STARTUP_TEST_TIMEOUT_MS);

	it("detached createWithPullProgress yields events and creates a detached sandbox", async () => {
		const session = await Sandbox.builder(NAME_DETACHED)
			.image("mirror.gcr.io/library/alpine")
			.cpus(1)
			.memory(512)
			.replace()
			.detached(true)
			.createWithPullProgress();

		const types: string[] = [];
		for await (const ev of session) types.push(ev.kind);

		expect(types[0]).toBe("resolving");
		expect(types).toContain("resolved");
		expect(types[types.length - 1]).toBe("complete");

		const sb = await session.awaitSandbox();
		expect(sb.name).toBe(NAME_DETACHED);

		await sb.stop();
	}, STARTUP_TEST_TIMEOUT_MS);

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

		await sb.stop();
	}, STARTUP_TEST_TIMEOUT_MS);
});

describe.skipIf(!msbPath())("listWith by labels", () => {
  const owner = `sdk-owner-${process.pid}`;
  const webName = "sdk-label-web";
  const jobName = "sdk-label-job";
  const otherName = "sdk-label-other";
  let created: Sandbox[] = [];

  const build = (name: string) =>
    Sandbox.builder(name)
      .image("mirror.gcr.io/library/alpine")
      .cpus(1)
      .memory(512)
      .replace();

  beforeAll(async () => {
    created = [
      await build(webName).label("owner", owner).label("tier", "web").create(),
      await build(jobName).label("owner", owner).label("tier", "job").create(),
      await build(otherName).label("owner", `${owner}-else`).create(),
    ];
  }, 300_000);

  afterAll(async () => {
    for (const sb of created) await sb.stop().catch(() => undefined);
    for (const n of [webName, jobName, otherName]) {
      await Sandbox.remove(n).catch(() => undefined);
    }
  });

  it("filters by a single label (AND across sandboxes)", async () => {
    const handles = await Sandbox.listWith({ labels: { owner } });
    const names = handles.map((h) => h.name);
    expect(names).toContain(webName);
    expect(names).toContain(jobName);
    expect(names).not.toContain(otherName);

    const web = handles.find((h) => h.name === webName);
    expect(web).toBeDefined();
    await expect(web!.refresh()).resolves.toMatchObject({ name: webName });
  });

  it("AND-matches multiple labels", async () => {
    const names = (
      await Sandbox.listWith({ labels: { owner, tier: "web" } })
    ).map((h) => h.name);
    expect(names).toContain(webName);
    expect(names).not.toContain(jobName);
    expect(names).not.toContain(otherName);
  });
});
