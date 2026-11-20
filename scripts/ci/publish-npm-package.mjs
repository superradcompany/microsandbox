#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { readFileSync, realpathSync } from "node:fs";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";
import channels from "./release-channel.cjs";

export async function publishPackage(directory, { fetchRegistry = fetch, run = execFileSync,
  releaseTag = process.env.MSB_RELEASE_TAG } = {}) {
  directory = resolve(directory);
  const pkg = JSON.parse(readFileSync(resolve(directory, "package.json"), "utf8"));
  const { npm_tag: tag } = channels.releaseChannel(pkg.version);
  // A stale SDK or submodule must fail before touching the registry.
  if (releaseTag && releaseTag !== `v${pkg.version}`) {
    throw new Error(`Release tag ${releaseTag} does not match ${pkg.name}@${pkg.version}`);
  }
  const url = `https://registry.npmjs.org/${encodeURIComponent(pkg.name)}/${pkg.version}`;
  const response = await fetchRegistry(url, { signal: AbortSignal.timeout(30_000) });
  if (response.ok) {
    const published = await response.json();
    if (published.name !== pkg.name || published.version !== pkg.version) {
      throw new Error(`Unexpected registry metadata for ${pkg.name}@${pkg.version}`);
    }
    // Retrying an old release must not move a channel backwards.
    console.log(`Already published: ${pkg.name}@${pkg.version}`);
  } else if (response.status === 404) {
    run("npm", ["publish", "--access", "public", "--tag", tag], {
      cwd: directory,
      stdio: "inherit",
    });
  } else {
    throw new Error(`Registry lookup failed: HTTP ${response.status} for ${pkg.name}@${pkg.version}`);
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(realpathSync(process.argv[1])).href) {
  await publishPackage(process.argv[2] ?? ".");
}
