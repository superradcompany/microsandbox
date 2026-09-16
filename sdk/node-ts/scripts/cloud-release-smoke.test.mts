/** Credential-free checks for the release probe and cleanup failure paths. */
import assert from "node:assert/strict";
import { test } from "node:test";
import { cleanup, exercise, MARKER, type SmokeSdk } from "./cloud-release-smoke.mts";

class NotFound extends Error {}
const pause = async () => {};

function fakeSdk(options: {
  code?: number;
  stdout?: string;
  createError?: Error;
  get?: () => Promise<unknown>;
} = {}) {
  const calls: Array<[string, unknown]> = [];
  const builder: Record<string, unknown> = {};
  for (const method of ["image", "cpus", "memory", "ephemeral", "maxDuration", "idleTimeout"]) {
    builder[method] = (value: unknown) => { calls.push([method, value]); return builder; };
  }
  builder.create = async () => {
    if (options.createError) throw options.createError;
    return { shell: async () => ({ code: options.code ?? 0, stdout: () => options.stdout ?? `${MARKER}\n` }) };
  };
  const sdk = {
    Sandbox: { builder: () => builder, get: options.get },
    SandboxNotFoundError: NotFound,
  } as unknown as SmokeSdk;
  return { sdk, calls };
}

test("candidate creates a bounded ephemeral sandbox and executes a command", async () => {
  const { sdk, calls } = fakeSdk();
  await exercise(sdk, "release-smoke-1-1");
  assert.ok(calls.some(([key, value]) => key === "ephemeral" && value === true));
  assert.ok(calls.some(([key, value]) => key === "maxDuration" && value === 600));
});

test("create rejection blocks release", async () => {
  const { sdk } = fakeSdk({ createError: new Error("API rejected request") });
  await assert.rejects(exercise(sdk, "release-smoke-1-1"), /API rejected/);
});

test("command failure and incorrect output block release", async () => {
  for (const options of [{ code: 1 }, { stdout: "unexpected" }]) {
    await assert.rejects(exercise(fakeSdk(options).sdk, "release-smoke-1-1"), /unexpected/);
  }
});

test("cleanup confirms absence after destroy", async () => {
  let gets = 0;
  let destroyed = false;
  const { sdk } = fakeSdk({ get: async () => {
    if (++gets === 3) throw new NotFound();
    return { destroy: async () => { destroyed = true; } };
  } });
  await cleanup(sdk, "release-smoke-1-1", pause);
  assert.equal(destroyed, true);
  assert.equal(gets, 3);
});

test("cleanup accepts an already removed sandbox", async () => {
  const { sdk } = fakeSdk({ get: async () => { throw new NotFound(); } });
  await cleanup(sdk, "release-smoke-1-1", pause);
});

test("cleanup does not treat server errors as absence", async () => {
  const { sdk } = fakeSdk({ get: async () => { throw new Error("server unavailable"); } });
  await assert.rejects(cleanup(sdk, "release-smoke-1-1", pause), /server unavailable/);
});

test("cleanup failure blocks release", async () => {
  const { sdk } = fakeSdk({ get: async () => ({ destroy: async () => {} }) });
  await assert.rejects(cleanup(sdk, "release-smoke-1-1", pause), /still exists/);
});
