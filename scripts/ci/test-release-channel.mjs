import assert from 'node:assert/strict';
import { test } from 'node:test';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import channels from './release-channel.cjs';
import { publishPackage } from './publish-npm-package.mjs';

for (const [version, channel, tag] of [
  ['0.7.14', 'stable', 'latest'], ['0.7.14+build.1', 'stable', 'latest'],
  ['0.8.0-rc.1', 'rc', 'rc'], ['0.8.0-rc.10', 'rc', 'rc'],
  ['0.8.0-beta.2', 'beta', 'beta'], ['0.8.0-alpha.1', 'alpha', 'alpha'],
  ['0.8.0-dev.1', 'dev', 'dev'], ['0.8.0-preview.1', 'prerelease', 'prerelease'],
]) {
  test(`classifies and publishes ${version} through ${tag}`, async () => {
    assert.deepEqual(channels.releaseChannel(version), {
      channel, npm_tag: tag, prerelease: String(channel !== 'stable'),
    });
    const directory = mkdtempSync(join(tmpdir(), 'msb-publish-test-'));
    try {
      writeFileSync(join(directory, 'package.json'), JSON.stringify({ name: '@example/sdk', version }));
      const calls = [];
      await publishPackage(directory, {
        releaseTag: `v${version}`,
        fetchRegistry: async url => {
          assert.equal(url, `https://registry.npmjs.org/%40example%2Fsdk/${version}`);
          return { status: 404 };
        },
        run: (...args) => calls.push(args),
      });
      assert.equal(calls.length, 1);
      assert.deepEqual(calls[0].slice(0, 2), ['npm', ['publish', '--access', 'public', '--tag', tag]]);
    } finally { rmSync(directory, { recursive: true, force: true }); }
  });
}

test('rejects malformed SemVer rather than guessing a publishing channel', () => {
  for (const version of ['v0.8.0', '01.2.3', '1.2', '1.2.3-', '1.2.3-rc..1', '1.2.3-rc.01', '1.2.3\n']) {
    assert.throws(() => channels.releaseChannel(version), /Invalid release version/);
  }
});

test('mismatched packages fail before network access; retries and registry errors never publish', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'msb-publish-test-'));
  try {
    const pkg = { name: 'fixture', version: '0.8.0-rc.1' };
    writeFileSync(join(directory, 'package.json'), JSON.stringify(pkg));
    const never = () => assert.fail('unexpected side effect');
    await assert.rejects(publishPackage(directory, { releaseTag: 'v0.8.0', fetchRegistry: never, run: never }), /does not match/);
    await publishPackage(directory, { releaseTag: 'v0.8.0-rc.1', run: never,
      fetchRegistry: async () => ({ ok: true, json: async () => pkg }) });
    for (const status of [401, 403, 429, 500]) {
      await assert.rejects(publishPackage(directory, { releaseTag: '', run: never,
        fetchRegistry: async () => ({ status }) }), /Registry lookup failed/);
    }
    await assert.rejects(publishPackage(directory, { releaseTag: '', run: never,
      fetchRegistry: async () => ({ ok: true, json: async () => ({ ...pkg, version: '0.8.0' }) }) }), /Unexpected registry metadata/);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});
