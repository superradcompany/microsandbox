/// <reference types="node" />
import { describe, it, expect, afterAll, beforeAll } from "vitest";
import { Sandbox, isInstalled } from "../index.mjs";
import type { PullEvent } from "../index.d.cts";

const SANDBOX_NAME = "sdk-smoke-test";

describe("Node.js SDK Smoke Tests", () => {
	let sandbox: Awaited<ReturnType<typeof Sandbox.create>>;

	beforeAll(async () => {
		sandbox = await Sandbox.create({
			name: SANDBOX_NAME,
			image: "alpine",
			cpus: 1,
			memoryMib: 512,
			replace: true,
		});
	});

	afterAll(async () => {
		await sandbox.stopAndWait().catch((e: unknown) => console.warn("cleanup stop:", e));
		await Sandbox.remove(SANDBOX_NAME).catch((e: unknown) => console.warn("cleanup remove:", e));
	});

	it("should report msb as installed", () => {
		expect(isInstalled()).toBe(true);
	});

	it("should create a sandbox", async () => {
		expect(await sandbox.name).toBe(SANDBOX_NAME);
	});

	it("should execute a command via exec()", async () => {
		const output = await sandbox.exec("echo", ["hello from sdk test"]);

		expect(output.code).toBe(0);
		expect(output.success).toBe(true);
		expect(output.stdout()).toBe("hello from sdk test\n");
	});

	it("should execute a shell command", async () => {
		const output = await sandbox.shell("uname -a");

		expect(output.code).toBe(0);
		expect(output.success).toBe(true);
		expect(output.stdout()).toContain("Linux");
	});

	it("should read and write files via sandbox fs", async () => {
		const fs = sandbox.fs();
		const content = "hello from sdk test\n";

		await fs.write("/tmp/test.txt", Buffer.from(content));

		const readBack = await fs.readString("/tmp/test.txt");
		expect(readBack).toBe(content);

		const exists = await fs.exists("/tmp/test.txt");
		expect(exists).toBe(true);

		const stat = await fs.stat("/tmp/test.txt");
		expect(stat.kind).toBe("file");
		expect(stat.size).toBe(content.length);
	});

	it("should get sandbox metrics", async () => {
		const metrics = await sandbox.metrics();

		expect(metrics.cpuPercent).toBeGreaterThanOrEqual(0);
		expect(metrics.memoryBytes).toBeGreaterThan(0);
		expect(metrics.memoryLimitBytes).toBe(512 * 1024 * 1024);
		expect(metrics.diskReadBytes).toBeGreaterThanOrEqual(0);
		expect(metrics.diskWriteBytes).toBeGreaterThanOrEqual(0);
		expect(metrics.netRxBytes).toBeGreaterThanOrEqual(0);
		expect(metrics.netTxBytes).toBeGreaterThanOrEqual(0);
		expect(metrics.uptimeMs).toBeGreaterThan(0);
		expect(metrics.timestampMs).toBeGreaterThan(0);
	});

	it("should list sandboxes and find the running one", async () => {
		const list = await Sandbox.list();

		expect(Array.isArray(list)).toBe(true);
		const found = list.find((s) => s.name === SANDBOX_NAME);
		expect(found).toBeDefined();
		expect(found!.status).toBe("running");
	});

	it("should stream stdout via execStream", async () => {
		const handle = await sandbox.execStream("sh", [
			"-c",
			"for i in 1 2 3; do echo line-$i; done",
		]);

		const lines: string[] = [];
		let exitCode: number | null = null;
		let event = await handle.recv();
		while (event !== null) {
			if (event.eventType === "stdout" && event.data) {
				lines.push(event.data.toString("utf8"));
			} else if (event.eventType === "exited") {
				exitCode = event.code ?? null;
			}
			event = await handle.recv();
		}

		const combined = lines.join("");
		expect(combined).toContain("line-1");
		expect(combined).toContain("line-2");
		expect(combined).toContain("line-3");
		expect(exitCode).toBe(0);
	});

	it("should return null from takeStdin when stdin was not piped", async () => {
		const handle = await sandbox.execStream("echo", ["no-stdin"]);
		const stdin = await handle.takeStdin();
		expect(stdin).toBeNull();

		// Drain the stream so the session ends cleanly.
		let event = await handle.recv();
		while (event !== null) {
			event = await handle.recv();
		}
	});

	it("should pipe stdin via execStreamWithConfig and stream responses", async () => {
		const handle = await sandbox.execStreamWithConfig({
			cmd: "sh",
			args: [
				"-c",
				"while IFS= read -r line; do echo \"echo:$line\"; done",
			],
			stdin: "pipe",
		});

		const stdin = await handle.takeStdin();
		expect(stdin).not.toBeNull();

		await stdin!.write(Buffer.from("hello\n"));
		await stdin!.write(Buffer.from("world\n"));
		await stdin!.close();

		let combined = "";
		let exitCode: number | null = null;
		let event = await handle.recv();
		while (event !== null) {
			if (event.eventType === "stdout" && event.data) {
				combined += event.data.toString("utf8");
			} else if (event.eventType === "exited") {
				exitCode = event.code ?? null;
			}
			event = await handle.recv();
		}

		expect(combined).toContain("echo:hello");
		expect(combined).toContain("echo:world");
		expect(exitCode).toBe(0);
	});

	it("should support bidirectional JSONL exchange via execStreamWithConfig", async () => {
		// Echo server: reads JSON lines from stdin, echoes each back with {"echo": true} added
		const script = [
			"while IFS= read -r line; do",
			'  printf \'{"received":%s,"echo":true}\\n\' "$line"',
			"done",
		].join("\n");

		const handle = await sandbox.execStreamWithConfig({
			cmd: "sh",
			args: ["-c", script],
			stdin: "pipe",
		});

		const stdin = await handle.takeStdin();
		expect(stdin).not.toBeNull();

		const commands = [
			{ id: 1, type: "prompt", message: "hi" },
			{ id: 2, type: "get_state" },
			{ id: 3, type: "abort" },
		];
		for (const cmd of commands) {
			await stdin!.write(Buffer.from(`${JSON.stringify(cmd)}\n`));
		}
		await stdin!.close();

		let buffer = "";
		const received: Array<{ received: unknown; echo: boolean }> = [];
		let exitCode: number | null = null;
		let event = await handle.recv();
		while (event !== null) {
			if (event.eventType === "stdout" && event.data) {
				buffer += event.data.toString("utf8");
				while (true) {
					const idx = buffer.indexOf("\n");
					if (idx === -1) break;
					const line = buffer.slice(0, idx);
					buffer = buffer.slice(idx + 1);
					if (line.length > 0) received.push(JSON.parse(line));
				}
			} else if (event.eventType === "exited") {
				exitCode = event.code ?? null;
			}
			event = await handle.recv();
		}

		expect(received).toHaveLength(3);
		expect(received[0]).toMatchObject({ echo: true, received: commands[0] });
		expect(received[1]).toMatchObject({ echo: true, received: commands[1] });
		expect(received[2]).toMatchObject({ echo: true, received: commands[2] });
		expect(exitCode).toBe(0);
	});

	it("should propagate env vars via execStreamWithConfig", async () => {
		const handle = await sandbox.execStreamWithConfig({
			cmd: "sh",
			args: ["-c", "echo $MY_VAR"],
			env: { MY_VAR: "from-config" },
		});

		let combined = "";
		let exitCode: number | null = null;
		let event = await handle.recv();
		while (event !== null) {
			if (event.eventType === "stdout" && event.data) {
				combined += event.data.toString("utf8");
			} else if (event.eventType === "exited") {
				exitCode = event.code ?? null;
			}
			event = await handle.recv();
		}

		expect(combined).toContain("from-config");
		expect(exitCode).toBe(0);
	});

	it("should stop the sandbox", async () => {
		const status = await sandbox.stopAndWait();

		expect(status.code).toBe(0);
		expect(status.success).toBe(true);
	});
});

describe("Node.js SDK Pull Progress", () => {
	const NAME_ITER = "sdk-smoke-progress-iter";
	const NAME_RECV = "sdk-smoke-progress-recv";
	const NAME_DETACHED = "sdk-smoke-progress-detached";
	const NAME_ERROR = "sdk-smoke-progress-error";
	const NAME_DOUBLE = "sdk-smoke-progress-double";

	afterAll(async () => {
		for (const n of [NAME_ITER, NAME_RECV, NAME_DETACHED, NAME_ERROR, NAME_DOUBLE]) {
			await Sandbox.remove(n).catch(() => {});
		}
	});

	it("emits resolving → resolved → complete in order with populated fields", async () => {
		// pullPolicy:"always" forces a fresh resolve so we reliably see the
		// resolving→resolved→complete milestone sequence. Layer events may or
		// may not appear depending on local cache state.
		const session = await Sandbox.createWithProgress({
			name: NAME_ITER,
			image: "alpine",
			cpus: 1,
			memoryMib: 512,
			replace: true,
			pullPolicy: "always",
		});

		const events: PullEvent[] = [];
		for await (const ev of session) events.push(ev);

		expect(events.length).toBeGreaterThan(0);

		// First event is resolving and carries the reference.
		expect(events[0].eventType).toBe("resolving");
		expect(events[0].reference).toBeTruthy();
		const reference = events[0].reference;

		// resolved event appears with manifest + layer info.
		const resolved = events.find((e) => e.eventType === "resolved");
		expect(resolved).toBeDefined();
		expect(resolved!.reference).toBe(reference);
		expect(resolved!.manifestDigest).toBeTruthy();
		expect(resolved!.layerCount).toBeGreaterThan(0);

		// Final event is complete with matching reference and layerCount.
		const last = events[events.length - 1];
		expect(last.eventType).toBe("complete");
		expect(last.reference).toBe(reference);
		expect(last.layerCount).toBe(resolved!.layerCount);

		// Ordering: resolving before resolved before complete.
		const idx = (t: string) => events.findIndex((e) => e.eventType === t);
		expect(idx("resolving")).toBeLessThan(idx("resolved"));
		expect(idx("resolved")).toBeLessThan(idx("complete"));

		// If any layer_download_progress event appears, its fields are populated.
		const progress = events.find((e) => e.eventType === "layer_download_progress");
		if (progress) {
			expect(progress.layerIndex).toBeGreaterThanOrEqual(0);
			expect(progress.digest).toBeTruthy();
			expect(progress.downloadedBytes).toBeGreaterThanOrEqual(0);
		}

		// result() yields the live sandbox.
		const sb = await session.result();
		expect(await sb.name).toBe(NAME_ITER);
		await sb.stopAndWait();
	}, 180_000);

	it("streams events via recv() without the async iterator", async () => {
		const session = await Sandbox.createWithProgress({
			name: NAME_RECV,
			image: "alpine",
			cpus: 1,
			memoryMib: 512,
			replace: true,
		});

		const eventTypes: string[] = [];
		let ev = await session.recv();
		while (ev !== null) {
			eventTypes.push(ev.eventType);
			ev = await session.recv();
		}

		expect(eventTypes[0]).toBe("resolving");
		expect(eventTypes[eventTypes.length - 1]).toBe("complete");

		const sb = await session.result();
		await sb.stopAndWait();
	}, 120_000);

	it("createDetachedWithProgress yields events and creates a detached sandbox", async () => {
		const session = await Sandbox.createDetachedWithProgress({
			name: NAME_DETACHED,
			image: "alpine",
			cpus: 1,
			memoryMib: 512,
			replace: true,
		});

		const types: string[] = [];
		for await (const ev of session) types.push(ev.eventType);

		expect(types).toContain("complete");

		const sb = await session.result();
		expect(await sb.name).toBe(NAME_DETACHED);

		await sb.stopAndWait();
	}, 120_000);

	it("result() rejects when the image cannot be pulled", async () => {
		// pullPolicy:"never" with an image that is not in the local cache
		// forces a fast failure without hitting any network.
		const session = await Sandbox.createWithProgress({
			name: NAME_ERROR,
			image: "sdk-nonexistent-image-xyz789:never",
			cpus: 1,
			memoryMib: 512,
			replace: true,
			pullPolicy: "never",
		});

		// Iterator should terminate cleanly even though creation fails.
		for await (const _ev of session) {
			// drain
		}

		await expect(session.result()).rejects.toThrow();
	}, 60_000);

	it("result() throws 'already consumed' on the second call", async () => {
		const session = await Sandbox.createWithProgress({
			name: NAME_DOUBLE,
			image: "alpine",
			cpus: 1,
			memoryMib: 512,
			replace: true,
		});

		for await (const _ev of session) {
			// drain
		}

		const sb = await session.result();
		await expect(session.result()).rejects.toThrow(/already consumed/);

		await sb.stopAndWait();
	}, 120_000);
});
