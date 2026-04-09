/// <reference types="node" />
import { describe, it, expect, afterAll, beforeAll } from "vitest";
import { Sandbox, isInstalled } from "../index.mjs";

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
		await Sandbox.remove(SANDBOX_NAME);
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
		expect(metrics.diskReadBytes).toBeGreaterThan(0);
		expect(metrics.diskWriteBytes).toBeGreaterThan(0);
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

	it("should stop the sandbox", async () => {
		const status = await sandbox.stopAndWait();

		expect(status.code).toBe(0);
		expect(status.success).toBe(true);
	});
});
