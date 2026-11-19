import assert from "node:assert/strict";
import { join } from "node:path";
import { LocalContext, Volume } from "../../dist/index.js";

const root = process.argv[2];
// Returning only builders ensures the caller does not retain the context variables.
const builders = ["first", "second"].map((home) => {
  const context = LocalContext.builder().home(join(root, home)).build();
  return Volume.ctx(context).builder("same-name");
});
const volumes = [];
try {
  for (const builder of builders) volumes.push(await builder.create());
  const [first, second] = volumes;
  // Resource IDs are destination-scoped; two catalogs can both allocate local:1.
  assert.notEqual(first.path, second.path);
  await first.fs().write("marker", "first");
  await second.fs().write("marker", "second");
  const fetched = await first.context.volumes.get("same-name");
  assert.equal(await fetched.fs().readToString("marker"), "first");
  await first.destroy();
  await assert.rejects(fetched.info());
  assert.equal(await second.fs().readToString("marker"), "second");
} finally {
  for (const volume of volumes) await volume.destroy().catch(() => undefined);
}
