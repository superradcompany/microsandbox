#!/usr/bin/env python3
"""Cross-version capture receipts: optional negotiated execution policy, never defaults."""
import argparse, json, os, sqlite3, sys, tarfile, tempfile, traceback, subprocess
from pathlib import Path
p = argparse.ArgumentParser()
for name in ('baseline', 'candidate', 'agent', 'old-agent', 'firmware', 'image', 'support', 'output', 'temp-root'):
    p.add_argument('--' + name, type=Path, required=True)
a = p.parse_args()
for name, value in vars(a).items():
    setattr(a, name, value.resolve())
sys.path.insert(0, str(a.support))
import lifecycle_evidence as e
e.install_termination_handler()
a.output.mkdir(exist_ok=False)
with tarfile.open(a.image) as archive:
    tag = json.load(archive.extractfile('manifest.json'))[0]['RepoTags'][0]
report = {'status': 'running', 'cases': [], 'artifacts': {str(f): e.digest(f) for f in (a.baseline, a.candidate, a.agent, a.old_agent, a.firmware, a.image)}, 'harness_sha256': e.digest(Path(__file__))}
for case, client, runtime, guest, expected in [('old-client-new-runtime', a.baseline, a.candidate, a.agent, False), ('new-client-old-runtime', a.candidate, a.baseline, a.agent, False), ('new-client-new-runtime', a.candidate, a.candidate, a.agent, True), ('new-client-old-guest', a.candidate, a.candidate, a.old_agent, False)]:
    home = Path(tempfile.mkdtemp(prefix='exec-evidence-', dir=a.temp_root))
    out = a.output / case
    runner = e.Runner(client, e.environment(runtime, a.firmware, home, guest), out / 'commands')
    row = {'case': case, 'home': str(home), 'status': 'running', 'cleanup': {}, 'captures': []}
    report['cases'].append(row)
    pids = set()

    def rows(q):
        with sqlite3.connect((home / 'db/msb.db').as_uri() + '?mode=ro', uri=True) as db:
            return db.execute(q).fetchall()

    def collect():
        pids.update((p for p, in rows('SELECT pid FROM run') if p))

    def audit():
        row['remaining_sandboxes'] = rows('SELECT count(*) FROM sandbox')[0][0]
        row['remaining_live_runs'] = rows('SELECT count(*) FROM run WHERE terminated_at IS NULL')[0][0]
        row['surviving_pids'] = []
        for pid in pids:
            try:
                os.kill(pid, 0)
                row['surviving_pids'].append(pid)
            except ProcessLookupError:
                pass
        assert row['remaining_sandboxes'] == row['remaining_live_runs'] == 0 and (not row['surviving_pids'])
    try:
        runner.run('load', 'image', 'load', '--input', a.image)
        runner.run('create', 'create', tag, '--name', 'evidence', '--root-disk', '512M', '--memory', '256M', '--cpus', '1', '--max-duration', '10m', '--net', 'none')
        collect()
        row['before'] = rows('SELECT id,pid FROM run WHERE terminated_at IS NULL')
        runner.run('seed', 'exec', 'evidence', '--', 'sh', '-ec', 'echo marker >/dev/shm/retained; cat /proc/sys/kernel/random/boot_id >/root/boot-id; sync')
        for kind in ('disk', 'full'):
            before = set(home.rglob('last-active/captures/*.json'))
            archive = out / (kind + '.msb')
            runner.run('capture-' + kind, 'snapshot', 'create', '--sandbox', 'evidence', '--output', archive, *(['--full'] if kind == 'full' else []))
            added = set(home.rglob('last-active/captures/*.json')) - before
            assert len(added) == 1, len(added)
            receipt = json.loads(added.pop().read_bytes())
            assert ('exec_limits' in receipt) == expected, (case, kind, receipt.keys())
            if expected:
                limits = receipt['exec_limits']
                assert limits == {'max_executions': 128, 'input_limit': 65536, 'output_limit': 1048576, 'stdin_chunk_size': 16384, 'output_chunk_size': 16384}, limits
            names = subprocess.check_output(['tar', '-tf', str(archive)], text=True).splitlines()
            assert not any(('last-active' in n or 'captures/' in n for n in names))
            runner.run('still-running-' + kind, 'exec', 'evidence', '--', 'sh', '-ec', 'test "$(cat /dev/shm/retained)" = marker; test "$(cat /root/boot-id)" = "$(cat /proc/sys/kernel/random/boot_id)"')
            row['captures'].append({'kind': kind, 'execution_evidence_present': expected, 'archive_excludes_private_receipts': True})
        row['after'] = rows('SELECT id,pid FROM run WHERE terminated_at IS NULL')
        assert row['before'] == row['after']
        row['status'] = 'passed'
    except BaseException as error:
        row.update(status='failed', error=str(error), traceback=traceback.format_exc())
        report['status'] = 'failed'
        if not isinstance(error, Exception):
            raise
    finally:
        e.finish_saved_evidence(runner, {'evidence': row['cleanup']}, row, report, a.output, audit, prepare=collect)
report['status'] = 'passed' if all((c['status'] == 'passed' for c in report['cases'])) else 'failed'
(a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print(report['status'])
sys.exit(report['status'] != 'passed')
