const assert = require('node:assert/strict');
const { test } = require('node:test');
const { spawnSync } = require('node:child_process');
const { resolve } = require('node:path');
const { resolveReleaseContext } = require('./release-context.cjs');

const root = resolve(__dirname, '../..');
const sourceSha = 'a'.repeat(40);
const workflowSha = 'b'.repeat(40);
const tag = 'v0.7.12';

function fixture(options = {}) {
  const calls = [];
  return {
    calls,
    context: { eventName: 'workflow_dispatch', ref: 'refs/heads/main', sha: workflowSha,
      repo: { owner: 'example', repo: 'project' }, ...options.context },
    releaseTag: tag,
    github: { rest: { repos: { getReleaseByTag: async args => {
      calls.push(['release', args.tag]);
      if (options.releaseExists) return { data: {} };
      throw Object.assign(new Error('release API error'), { status: options.status || 404 });
    } } } },
    runGit: (...args) => {
      calls.push(args);
      if (args[0] === 'rev-parse') {
        if (options.missingTag) throw new Error('missing tag');
        assert.equal(args[2], `refs/tags/${tag}^{commit}`);
        return sourceSha;
      }
      if (args[0] === 'merge-base') {
        assert.deepEqual(args, ['merge-base', '--is-ancestor', sourceSha, workflowSha]);
        if (options.notAncestor) throw new Error('not an ancestor');
        return '';
      }
      if (args[0] === 'show') {
        assert.equal(args[1], `${sourceSha}:Cargo.toml`);
        return `[workspace.package]\nversion = "${options.version || '0.7.12'}"\n`;
      }
      throw new Error(`Unexpected git command: ${args}`);
    },
  };
}

test('recovery resolves a version-matched unpublished tag in main', async () => {
  const input = fixture();
  assert.deepEqual(await resolveReleaseContext(input), { source_sha: sourceSha, tag, publish: 'true' });
  assert.equal(input.calls.filter(call => call[0] === 'rev-parse').length, 1);
});

test('PRs and ordinary manual builds never enable publication or inspect tags', async () => {
  for (const context of [
    { eventName: 'pull_request', ref: 'refs/pull/123/merge' },
    { eventName: 'workflow_dispatch', ref: 'refs/heads/main' },
    { eventName: 'workflow_dispatch', ref: 'refs/heads/feature' },
    { eventName: 'push', ref: 'refs/heads/main' },
  ]) {
    const input = fixture({ context });
    input.releaseTag = '';
    assert.deepEqual(await resolveReleaseContext(input), { source_sha: workflowSha, tag: '', publish: 'false' });
    assert.deepEqual(input.calls, []);
  }
});

test('recovery refuses non-main workflows and unsafe tag inputs before git access', async () => {
  const input = fixture({ context: { ref: 'refs/heads/feature' } });
  await assert.rejects(resolveReleaseContext(input), /must run from main/);
  assert.deepEqual(input.calls, []);
  for (const releaseTag of ['main', 'v0.7.12\n', 'v0.7.12\nmalicious', 'v0.7.12;echo', '../v0.7.12', '--help']) {
    const input = fixture();
    await assert.rejects(resolveReleaseContext({ ...input, releaseTag }), /Expected a version tag/);
    assert.deepEqual(input.calls, []);
  }
});

test('recovery refuses missing, unrelated, mismatched, and already published tags', async () => {
  for (const [options, message] of [
    [{ missingTag: true }, /missing tag/],
    [{ notAncestor: true }, /not an ancestor/],
    [{ version: '0.7.11' }, /workspace version/],
    [{ releaseExists: true }, /already exists/],
    [{ status: 403 }, /release API error/],
    [{ status: 503 }, /release API error/],
  ]) await assert.rejects(resolveReleaseContext(fixture(options)), message);
});

test('normal tag pushes retain publication but reject a moved tag', async () => {
  const input = fixture({ context: { eventName: 'push', ref: `refs/tags/${tag}`, sha: sourceSha } });
  input.releaseTag = '';
  assert.deepEqual(await resolveReleaseContext(input), { source_sha: sourceSha, tag, publish: 'true' });
  assert.ok(!input.calls.some(call => call[0] === 'release' || call[0] === 'merge-base'));
  await assert.rejects(resolveReleaseContext({ ...input, context: { ...input.context, sha: workflowSha } }), /triggering commit/);
});

function workflow(name) {
  const result = spawnSync(process.env.PYTHON || 'python3', ['-c',
    'import json,sys,yaml; print(json.dumps(yaml.load(open(sys.argv[1]), Loader=yaml.BaseLoader)))',
    resolve(root, '.github/workflows', name),
  ], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

test('workflow pins every active source checkout and keeps maintenance destinations', () => {
  const release = workflow('release.yml');
  for (const [name, job] of Object.entries(release.jobs)) {
    if (name === 'release-context' || job.if === '${{ false }}') continue;
    const needs = Array.isArray(job.needs) ? job.needs : [job.needs];
    assert.ok(needs.includes('release-context'), `${name} must depend on validated context`);
    if (job.uses) assert.equal(job.with.source_sha, '${{ needs.release-context.outputs.source_sha }}');
    for (const step of job.steps || []) {
      if (!step.uses?.startsWith('actions/checkout@')) continue;
      const expected = name === 'sync-mintlify' ? 'mintlify' : name === 'refresh-lockfile' ? 'main'
        : '${{ needs.release-context.outputs.source_sha }}';
      assert.equal(step.with.ref, expected, name);
    }
  }
  for (const filename of ['release-linux.yml', 'release-macos.yml', 'release-windows.yml']) {
    const platform = workflow(filename);
    assert.equal(platform.on.workflow_call.inputs.source_sha.required, 'true');
    for (const job of Object.values(platform.jobs)) {
      for (const step of job.steps || []) {
        if (step.uses?.startsWith('actions/checkout@')) assert.equal(step.with.ref, '${{ inputs.source_sha }}', filename);
      }
    }
  }
  assert.equal(release.jobs['darwin-aarch64'].with.runner, 'macos-15');
  assert.equal(workflow('release-macos.yml').env.MACOSX_DEPLOYMENT_TARGET, '14.0');
});

test('all publishers retain the complete platform and production validation gate', () => {
  const { jobs } = workflow('release.yml');
  const publishers = ['assemble', 'npm-publish', 'crates-publish', 'pypi-publish', 'docker-build',
    'docker-manifest', 'go-sdk-tag', 'mcp-publish', 'sync-mintlify', 'update-homebrew', 'update-winget', 'refresh-lockfile'];
  function dependsOn(job, target) {
    const needs = Array.isArray(job.needs) ? job.needs : [job.needs];
    return needs.includes(target) || needs.some(name => name && dependsOn(jobs[name], target));
  }
  for (const name of publishers) {
    assert.match(jobs[name].if, /needs\.release-context\.outputs\.publish == 'true'/, name);
    assert.ok(dependsOn(jobs[name], 'release-ready'), name);
  }
  const ready = jobs['release-ready'];
  const assertion = ready.steps.find(step => step.name === 'Assert every platform build succeeded').run;
  for (const name of ['release-context', 'linux-x86_64', 'linux-aarch64', 'darwin-aarch64', 'windows-x86_64', 'windows-aarch64']) {
    assert.ok(ready.needs.includes(name));
    assert.ok(assertion.includes(`needs.${name}.result`));
  }
  assert.ok(ready.steps.some(step => step.name === 'Verify release tag still identifies the built source'));
  assert.ok(ready.steps.some(step => step.name === 'Smoke test candidate SDK against production'));
  assert.ok(jobs.assemble.steps.some(step => step.run?.includes('--verify-tag')));
  const metadata = jobs['docker-manifest'].steps.find(step => step.uses?.startsWith('docker/metadata-action@'));
  for (const line of metadata.with.tags.split('\n').filter(line => line.includes('type=semver'))) {
    assert.ok(line.includes('value=${{ needs.release-context.outputs.tag }}'));
  }
});
