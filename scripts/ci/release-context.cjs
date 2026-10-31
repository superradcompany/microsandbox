const { execFileSync } = require('node:child_process');

const git = (...args) => execFileSync('git', args, { encoding: 'utf8' }).trim();

// Recovery uses the workflow on main, but every artifact must use one immutable
// source commit. Resolve once, before jobs with publishing credentials can run.
async function resolveReleaseContext({ context, github, releaseTag = '', runGit = git }) {
  const recovery = context.eventName === 'workflow_dispatch' && releaseTag !== '';
  const tagPush = context.eventName === 'push' && context.ref.startsWith('refs/tags/v');
  if (!recovery && !tagPush) return { source_sha: context.sha, tag: '', publish: 'false' };
  if (recovery && context.ref !== 'refs/heads/main') {
    throw new Error('Release recovery must run from main');
  }
  const tag = recovery ? releaseTag : context.ref.slice('refs/tags/'.length);
  if (tag !== tag.trim() || !/^v\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/.test(tag)) {
    throw new Error('Expected a version tag such as v0.7.12');
  }
  // Full tag refs prevent branch-name ambiguity; ^{commit} also peels signed tags.
  const sourceSha = runGit('rev-parse', '--verify', `refs/tags/${tag}^{commit}`);
  if (!/^[0-9a-f]{40}$/.test(sourceSha)) throw new Error('Invalid release commit');
  if (recovery) {
    runGit('merge-base', '--is-ancestor', sourceSha, context.sha);
    // Only a 404 means unpublished. Permission and service errors must fail closed.
    try {
      await github.rest.repos.getReleaseByTag({ ...context.repo, tag });
    } catch (error) {
      if (error.status !== 404) throw error;
      return checkedContext(sourceSha, tag, runGit);
    }
    throw new Error(`Release ${tag} already exists; recovery cannot replace it`);
  }
  if (sourceSha !== context.sha) throw new Error('Tag no longer matches the triggering commit');
  return checkedContext(sourceSha, tag, runGit);
}

function checkedContext(sourceSha, tag, runGit) {
  // Use TOML's parser rather than matching unrelated dependency version fields.
  const manifest = runGit('show', `${sourceSha}:Cargo.toml`);
  const version = execFileSync('python3', ['-c',
    'import sys,tomllib; print(tomllib.loads(sys.stdin.read())["workspace"]["package"]["version"])',
  ], { input: manifest, encoding: 'utf8' }).trim();
  if (tag !== `v${version}`) throw new Error('Tag does not match the workspace version');
  return { source_sha: sourceSha, tag, publish: 'true' };
}

module.exports = { resolveReleaseContext };
