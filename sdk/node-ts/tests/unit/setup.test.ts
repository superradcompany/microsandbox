import { chmod, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";

import { resolveRuntimeVersion } from "../../dist/index.js";

const directories: string[] = [];

// An ELF header fixture can be inspected on any host, without execute permission
// or firmware. Bytes outside the named section must never become a version.
async function executable(version: string, present = true): Promise<string> {
  const directory = await mkdtemp(join(tmpdir(), "msb-version-test-"));
  directories.push(directory);
  const payload = Buffer.from(version);
  const bytes = Buffer.alloc(384 + payload.length);
  Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1]).copy(bytes);
  bytes.writeUInt16LE(2, 16);
  bytes.writeUInt16LE(62, 18);
  bytes.writeUInt32LE(1, 20);
  bytes.writeBigUInt64LE(128n, 40);
  bytes.writeUInt16LE(64, 52);
  bytes.writeUInt16LE(64, 58);
  bytes.writeUInt16LE(3, 60);
  bytes.writeUInt16LE(1, 62);
  const names = Buffer.from("\0.shstrtab\0.msbver\0.other\0");
  names.copy(bytes, 64);
  bytes.writeUInt32LE(1, 192);
  bytes.writeUInt32LE(3, 196);
  bytes.writeBigUInt64LE(64n, 216);
  bytes.writeBigUInt64LE(BigInt(names.length), 224);
  bytes.writeUInt32LE(present ? 11 : 19, 256);
  bytes.writeUInt32LE(1, 260);
  bytes.writeBigUInt64LE(384n, 280);
  bytes.writeBigUInt64LE(BigInt(payload.length), 288);
  payload.copy(bytes, 384);
  const path = join(directory, "msb");
  await writeFile(path, bytes, { mode: 0o600 });
  return path;
}

afterEach(async () => {
  await Promise.all(directories.splice(0).map((path) => rm(path, { recursive: true })));
});

describe("resolveRuntimeVersion", () => {
  it("reads a foreign executable's version without executing it", async () => {
    await expect(resolveRuntimeVersion(await executable("1.2.3-rc.1+build.42")))
      .resolves.toBe("1.2.3-rc.1+build.42");
  });

  it("returns null when the embedded section is absent", async () => {
    await expect(resolveRuntimeVersion(await executable("1.2.3", false))).resolves.toBeNull();
  });

  it("rejects malformed versions and missing files", async () => {
    const path = await executable("not-semver");
    await expect(resolveRuntimeVersion(path)).rejects.toThrow();
    await expect(resolveRuntimeVersion(`${path}.missing`)).rejects.toThrow();
  });

  it("does not execute a script as a fallback", async () => {
    const path = await executable("1.2.3");
    await writeFile(path, "#!/bin/sh\necho 9.9.9\n", { mode: 0o700 });
    await chmod(path, 0o700);
    await expect(resolveRuntimeVersion(path)).rejects.toThrow();
  });
});
