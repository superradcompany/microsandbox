import assert from "node:assert/strict";
import { test } from "node:test";
import { AuditOperations } from "./operations.mjs";

function deferred() {
  return Promise.withResolvers();
}

test("cleanup captures a create that returns after the audit deadline", async () => {
  const operations = new AuditOperations();
  const create = deferred();
  let resource;
  let destroyed = false;
  await assert.rejects(operations.run(async () => {
    resource = await create.promise;
  }, 1), /audit timeout/);
  let cleanupFinished = false;
  const cleanup = (async () => {
    await operations.settle();
    for (const item of [resource].filter(Boolean)) await item.destroy();
    cleanupFinished = true;
  })();
  await Promise.resolve();
  assert.equal(cleanupFinished, false);
  create.resolve({ destroy: async () => { destroyed = true; } });
  await cleanup;
  assert.equal(destroyed, true);
});

test("late failure is observed and does not prevent other late resources from cleanup", async () => {
  const operations = new AuditOperations();
  const first = deferred(), second = deferred();
  const resources = [];
  const run = task => operations.run(async () => resources.push(await task.promise), 1);
  await Promise.all([assert.rejects(run(first), /audit timeout/), assert.rejects(run(second), /audit timeout/)]);
  const settling = operations.settle();
  first.reject(Error("provider rejected creation"));
  second.resolve("second-resource");
  await settling;
  assert.deepEqual(resources, ["second-resource"]);
});

test("normal results, synchronous errors and asynchronous errors remain observable", async () => {
  const operations = new AuditOperations();
  assert.equal(await operations.run(() => "result", 1000), "result");
  await assert.rejects(operations.run(() => { throw Error("sync"); }, 1000), /sync/);
  await assert.rejects(operations.run(async () => { throw Error("async"); }, 1000), /async/);
  await operations.settle();
});
