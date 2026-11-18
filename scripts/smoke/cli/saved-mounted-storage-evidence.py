#!/usr/bin/env python3
"""Qualify negotiated private mounted-storage receipts with old/new capture clients."""
import argparse, json, os, sqlite3, sys, tarfile, tempfile, traceback
from pathlib import Path
p = argparse.ArgumentParser()
for name in ('baseline', 'candidate', 'agent', 'firmware', 'image', 'support', 'output', 'temp-root'):
    p.add_argument('--' + name, type=Path, required=True)
p.add_argument('--large-script', action='store_true',
               help='Qualify unknown configuration receipts with a 9 MiB registered script')
a = p.parse_args()
sys.path.insert(0, str(a.support.resolve()))
import lifecycle_evidence as h
h.install_termination_handler()
a.output.mkdir(exist_ok=False)
report = {'cases': [], 'status': 'running', 'artifacts': {str(x): h.digest(x) for x in (a.baseline, a.candidate, a.agent, a.firmware, a.image)}, 'harness_sha256': h.digest(Path(__file__))}
with tarfile.open(a.image) as t:
    image = json.load(t.extractfile('manifest.json'))[0]['RepoTags'][0]
cases = [('current', a.candidate, a.candidate, True),
         ('old-runtime', a.baseline, a.candidate, False),
         ('old-client', a.candidate, a.baseline, False)]
if a.large_script:
    # The preceding runtime has the reproduced receipt-size bug. Verify the fixed
    # runtime through both client generations, including the strict old decoder.
    cases = [case for case in cases if case[0] != 'old-runtime']
for kind, binary, capture_binary, expected in cases:
    expected = expected and not a.large_script
    for quota in (('32M',) if a.large_script else ('0', '32M')):
        home = Path(tempfile.mkdtemp(prefix='mounted-', dir=a.temp_root))
        source = home / 'source'
        source.mkdir()
        (source / 'file').write_text('file-marker\n')
        (source / 'dir').mkdir()
        (source / 'dir/marker').write_text('dir-marker\n')
        row = {'kind': kind, 'quota': quota, 'home': str(home), 'status': 'running', 'cleanup': {}}
        report['cases'].append(row)
        pids = set()
        r = h.Runner(a.candidate, h.environment(binary, a.firmware, home, a.agent), a.output / (kind + '-' + quota))
        capture = h.Runner(capture_binary, r.env, a.output / (kind + '-' + quota + '-capture'))

        def sql(q):
            with sqlite3.connect((home / 'db/msb.db').as_uri() + '?mode=ro', uri=True) as c:
                return c.execute(q).fetchall()

        def collect():
            pids.update((pid for pid, in sql('SELECT pid FROM run') if pid))

        def audit():
            for volume in ('ndir', 'ndisk'):
                r.run('remove-' + volume, 'volume', 'rm', volume, required=False)
            row['remaining_sandboxes'] = sql('SELECT count(*) FROM sandbox')[0][0]
            row['remaining_live_runs'] = sql('SELECT count(*) FROM run WHERE terminated_at IS NULL')[0][0]
            row['remaining_volumes'] = sql('SELECT count(*) FROM volume')[0][0]
            row['surviving_pids'] = []
            for pid in pids:
                try:
                    os.kill(pid, 0)
                    row['surviving_pids'].append(pid)
                except ProcessLookupError:
                    pass
            assert row['remaining_sandboxes'] == row['remaining_live_runs'] == row['remaining_volumes'] == 0
            assert not row['surviving_pids']
        try:
            r.run('load', 'image', 'load', '--input', a.image)
            r.run('named-directory', 'volume', 'create', 'ndir')
            r.run('named-disk', 'volume', 'create', 'ndisk', '--kind', 'disk', '--size', '512M')
            extra = []
            if a.large_script:
                configuration = home / 'large-script.json'
                configuration.write_text(json.dumps({'scripts': {'large': '#' + 'x' * (9 * 1024 * 1024) + '\n'}}))
                extra = ['--conf', configuration]
            r.run('create', 'create', image, *extra, '--name', 'mounts', '--memory', '256M', '--max-memory', '256M', '--cpus', '1', '--max-cpus', '1', '--root-disk', '512M', '--max-duration', '5m', '--mount-file', str(source / 'file') + ':/mnt/file', '--mount-dir', str(source / 'dir') + ':/mnt/dir:quota=' + quota, '--mount-named', 'ndir:/mnt/named', '--mount-named', 'ndisk:/mnt/disk:kind=disk,size=512M', '--mount-owned', '/mnt/owned')
            collect()
            q = 'if echo growth >/mnt/dir/new; then exit 42; fi' if quota == '0' else 'echo growth >/mnt/dir/new'
            r.run('exercise', 'exec', 'mounts', '--', 'sh', '-ec', 'test "$(cat /mnt/file)" = file-marker; test "$(cat /mnt/dir/marker)" = dir-marker; ' + q + '; for d in named disk owned; do echo persisted >/mnt/$d/marker; done; sync')
            receipts = home / 'sandboxes/mounts/last-active/captures'
            row['captures'] = []
            for full in (False, True):
                before = set(receipts.glob('*.json')) if receipts.exists() else set()
                label = 'full' if full else 'disk'
                archive = a.output / (kind + '-' + quota + '-' + label + '.msb')
                capture.run(label, 'snapshot', 'create', '--sandbox', 'mounts', '--output', archive, '--plain-tar', *(['--full'] if full else []))
                after = set(receipts.glob('*.json'))
                created = after - before
                assert len(created) == 1, (kind, label, 'private receipt count', len(created))
                receipt = json.loads(next(iter(created)).read_text())
                if a.large_script:
                    assert receipt['source'] is None
                    assert set(receipt) == {'schema', 'checkpoint_id', 'capture_root', 'source'}
                    assert next(iter(created)).stat().st_size < 1024
                storage = receipt.get('storage')
                assert (storage is not None) == expected, (kind, label, 'negotiation mismatch')
                if expected:
                    # Existing implicit bind/owned quota is 4 GiB; named directories are unlimited.
                    assert storage['/mnt/file'] == {'kind': 'file', 'quota_bytes': 4 * 1024 ** 3}, storage
                    assert storage['/mnt/dir'] == {'kind': 'directory', 'quota_bytes': 0 if quota == '0' else 32 * 1024 * 1024}, storage
                    assert storage['/mnt/named'] == {'kind': 'directory', 'quota_bytes': None}, storage
                    assert storage['/mnt/owned'] == {'kind': 'directory', 'quota_bytes': 4 * 1024 ** 3}, storage
                    assert '/mnt/disk' not in storage, 'block device must not be fabricated as filesystem backend'
                    assert str(source) not in json.dumps(storage) and 'ndir' not in json.dumps(storage)
                with tarfile.open(archive) as package:
                    names = package.getnames()
                    assert not any(('last-active' in name for name in names)), names
                row['captures'].append({'mode': label, 'storage': storage, 'private_receipt_kept_out_of_archive': True})
                r.run(label + '-still-running', 'exec', 'mounts', '--', 'sh', '-ec', 'test "$(cat /mnt/file)" = file-marker')
            r.run('stop', 'stop', 'mounts')
            r.run('restart', 'start', 'mounts')
            collect()
            r.run('persisted', 'exec', 'mounts', '--', 'sh', '-ec', 'test "$(cat /mnt/file)" = file-marker; test "$(cat /mnt/dir/marker)" = dir-marker; for d in named disk owned; do test "$(cat /mnt/$d/marker)" = persisted; done')
            if a.large_script:
                r.run('large-script-preserved', 'exec', 'mounts', '--', 'sh', '-ec',
                      'test $(wc -c < /.msb/scripts/large) -gt 9000000')
                row['large_script_preserved'] = True
            row['status'] = 'passed'
        except BaseException as e:
            row.update(status='failed', error=str(e), traceback=traceback.format_exc())
            report['status'] = 'failed'
            if not isinstance(e, Exception):
                raise
        finally:
            h.finish_saved_evidence(r, {'mounts': row['cleanup']}, row, report, a.output, audit, prepare=collect)
report['status'] = 'passed' if all((c['status'] == 'passed' for c in report['cases'])) else 'failed'
(a.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
print(report['status'])
sys.exit(report['status'] != 'passed')
