// Shared by the trusted merge workflow and the tagged release workflow.
async function labelPullRequest({ github, repo, number }) {
  // Read current metadata rather than a queued event's stale labels/title.
  const { data: pr } = await github.rest.pulls.get({ ...repo, pull_number: number });
  if (!pr.merged) throw new Error(`PR #${number} is not merged`);
  const current = new Set(pr.labels.map(label => label.name));
  const wanted = new Set();
  const match = pr.title.match(/^(feat|fix|perf|docs|refactor|build|ci|test|style|chore|deps)(?:\(([^)]+)\))?(!)?:\s/i);

  if (pr.user.login === 'mintlify[bot]' || (
    pr.user.login === 'github-actions[bot]' &&
    pr.base.ref === 'mintlify' &&
    pr.head.ref.startsWith('mintlify-sync-') &&
    /^sync mintlify to v\S+$/i.test(pr.title)
  )) {
    wanted.add('release:skip');
  } else if (match) {
    const hasCategory = [...current].some(label =>
      /^release:(feat|fix|perf|docs|refactor|build|ci|test|style|chore|deps)$/.test(label)
    );
    if (!hasCategory) {
      const type = /^deps(?:-dev)?$/i.test(match[2] || '') ? 'deps' : match[1].toLowerCase();
      wanted.add(`release:${type}`);
    }
    if (match[3]) wanted.add('release:breaking');
  }

  const labels = [...wanted].filter(name => !current.has(name));
  for (const name of labels) {
    try {
      await github.rest.issues.getLabel({ ...repo, name });
    } catch (error) {
      if (error.status !== 404) throw error;
      try {
        await github.rest.issues.createLabel({
          ...repo, name, color: 'c5def5', description: 'Category for generated release notes',
        });
      } catch (error) {
        if (error.status !== 422) throw error;
        await github.rest.issues.getLabel({ ...repo, name });
      }
    }
  }
  if (labels.length) {
    await github.rest.issues.addLabels({ ...repo, issue_number: number, labels });
  }
}

async function prepareReleaseNotes({ github, repo, tag, serverUrl }) {
  // Let GitHub select its native release range. This draft is never published.
  // The unfiltered inventory also includes PRs that the final config excludes.
  const request = { ...repo, tag_name: tag };
  const { data: inventory } = await github.rest.repos.generateReleaseNotes({
    ...request, configuration_file_path: '.github/release-inventory.yml',
  });
  const prefix = `${serverUrl}/${repo.owner}/${repo.repo}/pull/`;
  const numbers = new Set();
  for (const line of inventory.body.split('\n')) {
    if (!line.startsWith('* ')) continue;
    // GitHub's change and contributor bullets end with the canonical PR URL.
    // Do not collect arbitrary links embedded in an untrusted PR title.
    const url = line.trimEnd().split(' ').at(-1);
    if (!url.startsWith(prefix) || !/^\d+$/.test(url.slice(prefix.length))) {
      throw new Error('Unrecognized release-note inventory bullet; refusing partial labeling');
    }
    numbers.add(Number(url.slice(prefix.length)));
  }
  // Avoid publishing an empty inventory if GitHub changes the list format.
  if (!numbers.size && inventory.body.includes('/pull/')) {
    throw new Error('Release-note PR links were not recognized');
  }
  for (const number of numbers) {
    await labelPullRequest({ github, repo, number });
  }
  const { data: notes } = await github.rest.repos.generateReleaseNotes({
    ...request, configuration_file_path: '.github/release.yml',
  });
  return notes.body;
}

module.exports = { labelPullRequest, prepareReleaseNotes };
