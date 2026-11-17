// One release classification for the workflow and npm publishers. Build metadata
// does not make a release a prerelease; only the SemVer prerelease field does.
function releaseChannel(version) {
  const match = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$/.exec(version);
  if (!match || match[4]?.split('.').some(part => /^0\d+$/.test(part))) {
    throw new Error(`Invalid release version: ${version}`);
  }
  if (!match[4]) return { channel: 'stable', prerelease: 'false', npm_tag: 'latest' };
  const kind = /^(rc|alpha|beta|dev)(?:[.\d-]|$)/.exec(match[4])?.[1];
  // Unknown prerelease names must still never reach a stable channel.
  return { channel: kind || 'prerelease', prerelease: 'true', npm_tag: kind || 'prerelease' };
}

module.exports = { releaseChannel };
