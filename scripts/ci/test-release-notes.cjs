const assert = require('node:assert/strict');
const { test } = require('node:test');
const { readFileSync, writeFileSync, mkdtempSync, rmSync } = require('node:fs');
const { tmpdir } = require('node:os');
const { resolve, join } = require('node:path');
const { spawnSync } = require('node:child_process');
const { createRequire } = require('node:module');
const { labelPullRequest, prepareReleaseNotes } = require('./release-notes.cjs');

const root = resolve(__dirname, '../..');
const repo = { owner: 'superradcompany', repo: 'microsandbox' };
const serverUrl = 'https://github.com';
const prUrl = number => `${serverUrl}/${repo.owner}/${repo.repo}/pull/${number}`;
const pull = (number, title, options = {}) => ({
  number, title, merged: true, labels: [], user: { login: 'developer' },
  base: { ref: 'main' }, head: { ref: 'feature' }, ...options,
});

function api(prs) {
  const additions = [];
  const labels = new Set();
  const github = { rest: {
    pulls: { get: async ({ pull_number }) => ({ data: prs.find(pr => pr.number === pull_number) }) },
    issues: {
      getLabel: async ({ name }) => {
        if (!labels.has(name)) throw Object.assign(new Error('missing label'), { status: 404 });
      },
      createLabel: async ({ name }) => { labels.add(name); },
      addLabels: async ({ issue_number, labels: names }) => {
        await new Promise(setImmediate);
        additions.push([issue_number, names]);
        prs.find(pr => pr.number === issue_number).labels.push(...names.map(name => ({ name })));
      },
    },
    repos: {},
  } };
  return { github, additions };
}

function workflow(path) {
  const result = spawnSync(process.env.PYTHON || 'python3', ['-c',
    'import json,sys,yaml; print(json.dumps(yaml.safe_load(open(sys.argv[1]))))', path,
  ], { encoding: 'utf8' });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function render(script) {
  const values = { 'github.ref_name': 'v1.0.0', 'github.sha': 'abc123', 'steps.merge.outputs.result': 'clean' };
  return script.replace(/\$\{\{\s*([^}]+?)\s*\}\}/g, (_, key) => {
    assert.ok(Object.hasOwn(values, key), `Unsupported workflow expression: ${key}`);
    return values[key];
  });
}

function shell(script, directory) {
  // Exercise the workflow's actual argument construction without git/network writes.
  writeFileSync(join(directory, 'git'), '#!/bin/sh\nexit 0\n', { mode: 0o755 });
  writeFileSync(join(directory, 'gh'), `#!/usr/bin/env node
require('node:fs').appendFileSync(process.env.CAPTURE, JSON.stringify(process.argv.slice(2)) + '\\n');
`, { mode: 0o755 });
  const result = spawnSync('bash', ['-e', '-c', render(script)], {
    cwd: directory, encoding: 'utf8',
    env: { ...process.env, PATH: `${directory}:${process.env.PATH}`, RUNNER_TEMP: directory,
      CAPTURE: join(directory, 'calls.jsonl') },
  });
  assert.equal(result.status, 0, result.stderr);
  return readFileSync(join(directory, 'calls.jsonl'), 'utf8').trim().split('\n').map(JSON.parse);
}

test('merged metadata preserves overrides and classifies changes without hiding human docs', async () => {
  const cases = [
    [pull(1, 'fix(release): repair publication'), ['release:fix']],
    [pull(2, 'feat(snapshot)!: capture memory'), ['release:feat', 'release:breaking']],
    [pull(3, 'chore(deps-dev): update tools'), ['release:deps']],
    [pull(4, 'chore(release): bundled features', { labels: [{ name: 'release:feat' }] }), ['release:feat']],
    [pull(5, 'Apply writing style', { user: { login: 'mintlify[bot]' } }), ['release:skip']],
    [pull(6, 'docs: explain mintlify'), ['release:docs']],
    [pull(7, 'fix(ci): repair mintlify-sync workflow'), ['release:fix']],
    [pull(8, 'A nonsemantic title'), []],
    [pull(9, 'fix: kept private', { labels: [{ name: 'release:skip' }] }), ['release:skip', 'release:fix']],
    [pull(10, 'fix!: breaking with override', { labels: [{ name: 'release:feat' }] }), ['release:feat', 'release:breaking']],
  ];
  const { github, additions } = api(cases.map(([pr]) => pr));
  for (const [pr, expected] of cases) {
    await labelPullRequest({ github, repo, number: pr.number });
    assert.deepEqual(pr.labels.map(l => l.name).sort(), [...expected].sort(), pr.title);
  }
  const count = additions.length;
  for (const [pr] of cases) await labelPullRequest({ github, repo, number: pr.number });
  assert.equal(additions.length, count, 'reruns must not add duplicate labels');
});

test('the real sync PR producer remains excluded, without excluding lookalikes', async () => {
  const release = workflow(join(root, '.github/workflows/release.yml'));
  const scripts = Object.values(release.jobs).flatMap(job => job.steps || [])
    .filter(step => step.run?.includes('gh pr create'));
  assert.equal(scripts.length, 1);
  const directory = mkdtempSync(join(tmpdir(), 'msb-release-sync-'));
  try {
    const args = shell(scripts[0].run, directory).find(args => args[0] === 'pr' && args[1] === 'create');
    const value = name => args[args.indexOf(name) + 1];
    const sync = pull(1, value('--title'), { user: { login: 'github-actions[bot]' },
      base: { ref: value('--base') }, head: { ref: value('--head') } });
    const human = { ...sync, number: 2, labels: [], user: { login: 'developer' } };
    const otherBase = { ...sync, number: 3, labels: [], base: { ref: 'main' } };
    const { github } = api([sync, human, otherBase]);
    for (const pr of [sync, human, otherBase]) await labelPullRequest({ github, repo, number: pr.number });
    assert.deepEqual(sync.labels, [{ name: 'release:skip' }]);
    assert.deepEqual(human.labels, []);
    assert.deepEqual(otherBase.labels, []);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('release workflow backfills included PRs before generating and publishing its body', async () => {
  const prs = [pull(11, 'feat: snapshots'), pull(12, 'sync mintlify to v0.7.3', {
    user: { login: 'github-actions[bot]' }, base: { ref: 'mintlify' }, head: { ref: 'mintlify-sync-v0.7.3' },
  })];
  const { github, additions } = api(prs);
  let generations = 0;
  github.rest.repos.generateReleaseNotes = async ({ configuration_file_path }) => {
    generations++;
    if (configuration_file_path === '.github/release-inventory.yml') {
      return { data: { body: `## What's Changed\n* feat by @dev in ${prUrl(11)}\n* sync by @bot in ${prUrl(12)}\n\n## New Contributors\n* @dev made their first contribution in ${prUrl(11)}` } };
    }
    assert.deepEqual(additions, [[11, ['release:feat']], [12, ['release:skip']]]);
    return { data: { body: '## Features\n* snapshots\n' } };
  };
  const directory = mkdtempSync(join(tmpdir(), 'msb-release-publish-'));
  try {
    const release = workflow(process.env.RELEASE_WORKFLOW_PATH || join(root, '.github/workflows/release.yml'));
    const AsyncFunction = Object.getPrototypeOf(async function () {}).constructor;
    let published = false;
    for (const step of release.jobs.assemble.steps) {
      if (step.uses?.startsWith('actions/github-script@')) {
        await new AsyncFunction('require', 'github', 'context', 'process', step.with.script)(
          createRequire(join(root, 'workflow-runner.cjs')), github, { repo, serverUrl },
          { env: { ...process.env, GITHUB_REF_NAME: 'v1.0.0', RUNNER_TEMP: directory } },
        );
      }
      if (step.run?.includes('gh release create')) {
        assert.equal(generations, 2, 'release must backfill and regenerate before publishing');
        const args = shell(step.run, directory).find(args => args[0] === 'release');
        assert.ok(args.includes('--notes-file'), 'publish the prepared body');
        assert.equal(readFileSync(args[args.indexOf('--notes-file') + 1], 'utf8'), '## Features\n* snapshots\n');
        assert.ok(!args.includes('--generate-notes'));
        published = true;
      }
    }
    assert.ok(published);
  } finally { rmSync(directory, { recursive: true, force: true }); }
});

test('labeling failures and unknown inventory formats cannot produce final notes', async () => {
  for (const body of [`* fix by @dev in ${prUrl(21)}`, '* a changed format', `- fix in ${prUrl(21)}`]) {
    const { github } = api([pull(21, 'fix: repair')]);
    let generations = 0;
    github.rest.repos.generateReleaseNotes = async () => { generations++; return { data: { body } }; };
    github.rest.issues.addLabels = async () => { throw new Error('write denied'); };
    await assert.rejects(prepareReleaseNotes({ github, repo, tag: 'v1.0.0', serverUrl }),
      /write denied|Unrecognized|not recognized/);
    assert.equal(generations, 1);
  }
});

test('inventory ignores title links and supports releases with no PRs', async () => {
  for (const body of [`* docs mention ${prUrl(999)} by @dev in ${prUrl(31)}`, '**Full Changelog**: https://github.com/example/compare/v1...v2']) {
    const { github, additions } = api([pull(31, 'docs: guide')]);
    let generations = 0;
    github.rest.repos.generateReleaseNotes = async () => ({ data: { body: ++generations === 1 ? body : 'final' } });
    assert.equal(await prepareReleaseNotes({ github, repo, tag: 'v1.0.0', serverUrl }), 'final');
    assert.deepEqual(additions, body.startsWith('* ') ? [[31, ['release:docs']]] : []);
  }
});
