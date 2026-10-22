"""Verify group path isolation using a native guest-generated archive.

Usage: python snapshot-group-paths.py MSB_BINARY DISK_ARCHIVE EVIDENCE_DIRECTORY
The script uses a temporary local catalog and never starts a guest.
"""
import hashlib, json, os, subprocess, sys, tempfile
from pathlib import Path
cli, archive, out = map(Path, sys.argv[1:4])
out.mkdir(parents=True, exist_ok=True)
with tempfile.TemporaryDirectory(prefix='msb-group-open-cli-') as temp:
    root = Path(temp).resolve()
    home = root / 'home'
    home.mkdir()
    env = dict(os.environ, MSB_HOME=str(home), MSB_CONFIG_PATH=str(root / 'absent.json'), MSB_BACKEND='local')
    report = {'cases': [], 'status': 'running'}

    def fingerprint(directory):
        result = {}
        for p in directory.rglob('*'):
            if p.is_file() and (not p.name.startswith('.')):
                with p.open('rb') as stream:
                    result[str(p.relative_to(directory))] = hashlib.file_digest(stream, 'sha256').hexdigest()
        return result

    def run(label, *args, ok=True):
        result = subprocess.run([str(cli), *map(str, args)], cwd=root, env=env, text=True, capture_output=True, timeout=120)
        (out / (label + '.stdout')).write_text(result.stdout)
        (out / (label + '.stderr')).write_text(result.stderr)
        report['cases'].append({'name': label, 'returncode': result.returncode})
        if ok:
            assert result.returncode == 0, (label, result.stdout, result.stderr)
        else:
            assert result.returncode != 0, (label, result.stdout, result.stderr)
        return result
    try:
        run('default-import', 'snapshot', 'import', 'history', '--file', archive)
        run('external-import', 'snapshot', 'import', 'history', '--dest', root / 'exports', '--file', archive)
        external = root / 'exports' / 'history'
        default = home / 'snapshots' / 'history'
        before = fingerprint(default)
        inspect = run('external-inspect', 'snapshot', 'inspect', './exports/history')
        assert str(external) in inspect.stdout
        run('default-inspect', 'snapshot', 'inspect', 'history')
        head = json.loads(run('head', 'snapshot', 'head', './exports/history', '--format', 'json').stdout)['head']
        assert head
        members = json.loads(run('list', 'snapshot', 'list', './exports/history', '--format', 'json').stdout)
        assert len(members) == 1
        run('export', 'snapshot', 'export', './exports/history', '--output', root / 'roundtrip.msb')
        run('reimport', 'snapshot', 'import', 'roundtrip', '--file', root / 'roundtrip.msb')
        roundtrip = json.loads(run('roundtrip-head', 'snapshot', 'head', 'roundtrip', '--format', 'json').stdout)['head']
        assert head == roundtrip
        verification = run('verify', 'snapshot', 'verify', './exports/history', '--all', ok=False)
        assert 'incomplete' in verification.stderr
        run('clear', 'snapshot', 'modify', './exports/history', '--clear-head')
        assert json.loads(run('headless', 'snapshot', 'head', './exports/history', '--format', 'json').stdout)['head'] is None
        run('replace', 'snapshot', 'modify', './exports/history', '--set-head', head)
        refused = run('unbound-checkpoint', 'snapshot', 'checkpoint', './exports/history', ok=False)
        assert 'unbound' in refused.stderr
        missing = run('missing-inspect', 'snapshot', 'inspect', './missing/history', ok=False)
        assert not (root / 'missing').exists()
        run('remove', 'snapshot', 'remove', './exports/history', '--all')
        assert not external.exists()
        after = fingerprint(default)
        assert before == after
        report['preserved_default_files'] = len(before)
        report['status'] = 'passed'
    finally:
        (out / 'report.json').write_text(json.dumps(report, indent=2))
print('CLI_GROUP_OPEN_OK')
