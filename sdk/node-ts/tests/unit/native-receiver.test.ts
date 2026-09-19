import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";
import { describe, expect, it } from "vitest";

// Keep the override local to the child: NAPI_RS_NATIVE_LIBRARY_PATH also affects
// native dependencies of the test runner. Normally use the package's raw loader.
const nativePath = process.env.MSB_TEST_NATIVE_LIBRARY_PATH ??
  fileURLToPath(new URL("../../native/index.cjs", import.meta.url));

// A native crash must fail one test, not kill Vitest. Do not use the TS wrapper
// or mocks: these calls exercise the real receiver-unwrapping boundary. That is
// distinct from directly testing generated FromNapiRef/FromNapiMutRef traits.
const receiverProbe = String.raw`
import assert from "node:assert/strict";
import { createRequire } from "node:module";

const [nativePath, className, methodName, receiverKind] = process.argv.slice(1);
const native = createRequire(import.meta.url)(nativePath);
const NativeClass = native[className];
assert.equal(typeof NativeClass, "function", "native class must be exported");

let invoke;
if (receiverKind === "constructor") {
  invoke = () => Reflect.construct(NativeClass, []);
} else {
  // Read the accessor itself without invoking it on the unwrapped prototype.
  // This exercises the getter's native receiver check, not a JS property read.
  const getterName = methodName.startsWith("get:") ? methodName.slice(4) : null;
  const method = getterName === null ? NativeClass.prototype[methodName]
    : Object.getOwnPropertyDescriptor(NativeClass.prototype, getterName)?.get;
  assert.equal(typeof method, "function", "native method must exist");
  let receiver;
  switch (receiverKind) {
    case "null": receiver = null; break;
    case "plain": receiver = {}; break;
    case "prototype": receiver = Object.create(NativeClass.prototype); break;
    case "wrong-class":
    case "wrong-class-prototype": {
      // Both constructors are pure builders; neither starts a VM. The other
      // native class supplies a genuine wrapped pointer with the wrong type.
      const OtherClass = className === "SnapshotBuilder"
        ? native.SandboxBuilder : native.SnapshotBuilder;
      receiver = new OtherClass("receiver-probe");
      if (receiverKind === "wrong-class-prototype") {
        Object.setPrototypeOf(receiver, NativeClass.prototype);
      }
      break;
    }
    default: assert.fail("unknown receiver probe");
  }
  const args = methodName === "exists" ? ["/unused"]
    : methodName === "cpus" ? [1]
    : methodName === "label" ? ["key", "value"] : [];
  invoke = () => Reflect.apply(method, receiver, args);
}

let rejected = false;
try {
  await invoke();
} catch (error) {
  assert.ok(error instanceof Error, "expected a JavaScript error");
  assert.ok(error.message.length > 0, "error must explain the refusal");
  if (receiverKind === "constructor") {
    assert.match(error.message, /constructor/i);
  } else {
    // A later SDK or VM failure is not evidence of receiver validation.
    assert.match(error.message,
      /illegal invocation|failed to unwrap|not an instance|type tag check failed|cannot borrow a null native value/i);
  }
  rejected = true;
}
assert.ok(rejected, "malformed receiver or factory-only constructor was accepted");
process.stdout.write("native receiver rejected\n");
`;

function expectCleanRefusal(className: string, method: string, receiver: string) {
  const child = spawnSync(process.execPath, [
    "--input-type=module", "--eval", receiverProbe,
    nativePath, className, method, receiver,
  ], {
    encoding: "utf8",
    timeout: 10_000,
    maxBuffer: 128 * 1024,
  });
  const diagnostic = `${className}.${method} (${receiver})\n${child.stdout ?? ""}${child.stderr ?? ""}`;
  expect(child.error, diagnostic).toBeUndefined();
  expect(child.signal, diagnostic).toBeNull();
  expect(child.status, diagnostic).toBe(0);
  expect(child.stdout, diagnostic).toBe("native receiver rejected\n");
}

describe("native receiver validation", () => {
  const methods = [
    ["SandboxFsOps", "exists"],
    ["Sandbox", "fs"],
    ["LogStream", "recv"],
    ["SandboxBuilder", "cpus"],
    ["SnapshotBuilder", "label"],
    ["SnapshotBuilder", "build"],
    ["SnapshotArchive", "get:id"],
    ["SnapshotArchive", "get:descriptorDigest"],
    ["SnapshotArchive", "get:path"],
  ] as const;

  for (const [className, method] of methods) {
    for (const receiver of [
      "null", "plain", "prototype", "wrong-class", "wrong-class-prototype",
    ]) {
      it(`${className}.${method} rejects a ${receiver} receiver without crashing`, () => {
        expectCleanRefusal(className, method, receiver);
      });
    }
  }

  for (const className of ["SandboxFsOps", "Sandbox", "LogStream", "SnapshotArchive"]) {
    it(`${className} rejects direct construction without crashing`, () => {
      expectCleanRefusal(className, "constructor", "constructor");
    });
  }
});
