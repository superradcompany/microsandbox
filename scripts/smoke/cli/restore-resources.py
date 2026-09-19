"""Isolated live restore-resource qualification (macOS, Linux, Windows).

Run explicitly with --msb PATH --firmware PATH --out DIRECTORY. The matching
guest agentd must sit beside the firmware. Requires working virtualization and
network access to pull alpine:3.21. Leaves artifacts/logs for inspection, but
stops/removes only its own uniquely named sandboxes, even after failures.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import traceback
import uuid

p = argparse.ArgumentParser()
p.add_argument('--msb', required=True, help='Candidate executable')
p.add_argument('--firmware', required=True, help='Firmware beside matching agentd')
p.add_argument('--out', required=True, help='New evidence directory')
a = p.parse_args()
out = Path(a.out).absolute()
out.mkdir(parents=True, exist_ok=False)
home = Path(tempfile.mkdtemp(prefix='rr-', dir=None if os.name == 'nt' else '/tmp')).resolve()
env = {k: v for k, v in os.environ.items() if not k.startswith('MSB_')}
config = home / 'config.json'
config.write_text('{}')
env.update(MSB_HOME=str(home), MSB_PATH=str(Path(a.msb).absolute()),
           MSB_LIBKRUNFW_PATH=str(Path(a.firmware).absolute()), MSB_CONFIG_PATH=str(config))
env['MSB_AGENTD_PATH'] = str(Path(a.firmware).absolute().parent/'agentd')
prefix = 'rr-' + uuid.uuid4().hex[:8]
names = []
results = []
(out / 'home.txt').write_text(str(home))

def run(*args, check=True, timeout=120):
    start = time.monotonic()
    cp = subprocess.run([a.msb, *map(str, args)], env=env, capture_output=True,
                        text=True, encoding='utf-8', errors='replace', timeout=timeout)
    entry = dict(args=list(map(str, args)), rc=cp.returncode,
                 seconds=round(time.monotonic()-start, 3), stdout=cp.stdout, stderr=cp.stderr)
    with (out / 'commands.jsonl').open('a') as f:
        f.write(json.dumps(entry)+'\n')
    if check and cp.returncode:
        raise AssertionError(entry)
    return entry

def record(label, fn):
    start = time.monotonic()
    try:
        info = fn()
        row = dict(case=label, passed=True, detail=info)
    except Exception:
        row = dict(case=label, passed=False, error=traceback.format_exc())
    row['seconds'] = round(time.monotonic()-start, 3)
    results.append(row)
    (out / 'results.json').write_text(json.dumps(results, indent=2))
    print(json.dumps(row), flush=True)

def child(label):
    name = prefix+'-'+label
    names.append(name)
    return name

def cleanup(name):
    run('stop', name, check=False, timeout=45)
    run('rm', name, '--force', check=False, timeout=45)

def exec_(name, command):
    return run('exec', name, '--', 'sh', '-c', command)

def restore(label, ref, options=(), required=(), rejected=False, cold=False):
    name = child(label)
    r = run('restore', ref, '--name', name, *options, check=False)
    text = r['stdout']+r['stderr']
    assert (r['rc'] != 0) == rejected, r
    for word in required:
        assert word in text, (word, r)
    if rejected:
        # A rejected restore must not create an executable cold-boot substitute.
        probe = run('exec', name, '--', 'true', check=False, timeout=15)
        assert probe['rc'] != 0, probe
    else:
        marker = exec_(name, 'cat /root-marker')
        assert 'root-preserved' in marker['stdout'], marker
        ram = exec_(name, 'cat /dev/shm/marker' if not cold else 'test ! -e /dev/shm/marker')
        if not cold:
            assert 'ram-preserved' in ram['stdout'], ram
        if 'filesystem operations return EIO' in text:
            unavailable = run('exec', name, '--', 'mkdir', '/work/must-not-be-created', check=False)
            assert unavailable['rc'] != 0, unavailable
        if '-v' in options and '/data' in options:
            data = exec_(name, 'cat /data/marker')
            assert 'disk-preserved' in data['stdout'], data
    cleanup(name)
    return dict(restore_seconds=r['seconds'], output=text)

try:
    help_ = run('restore', '--help')
    assert '--allow-missing-resources' in help_['stdout'], 'stale candidate'
    directory = prefix+'-dir'
    disk = prefix+'-disk'
    run('volume', 'create', directory, '--kind', 'dir')
    run('volume', 'create', disk, '--kind', 'disk', '--size', '256M')
    source = child('source')
    run('create', 'alpine:3.21', '--name', source, '--cpus', '1', '--memory', '256M',
        '-v', directory+':/work', '--mount-named', disk+':/data:kind=disk,size=256M')
    exec_(source, 'echo root-preserved > /root-marker; echo ram-preserved > /dev/shm/marker; '
                 'echo disk-preserved > /data/marker; echo dir-preserved > /work/marker; '
                 'cat /work/marker; sync')
    archive = out / 'full.msnap'
    run('snapshot', 'create', 'capture', '--from-sandbox', source, '--full', '-o', archive)
    archive_hash = hashlib.sha256(archive.read_bytes()).hexdigest()
    run('snapshot', 'load', archive, '--group', prefix+'-loaded')
    installed = prefix+'-loaded:capture'
    missing = ('disk /data', 'filesystem /work', '--allow-missing-resources')
    record('archive-default-missing', lambda: restore('default', archive, required=missing, rejected=True))
    record('archive-forked-missing', lambda: restore('forkmiss', archive, ['--forked'], missing, True))
    record('relaxed-is-not-opt-out', lambda: restore('relaxed', archive, ['--external-mount-policy', 'relaxed'], missing, True))
    record('installed-default-missing', lambda: restore('installed', installed, required=missing, rejected=True))
    record('partial-directory-mapping', lambda: restore('partialdir', archive, ['-v', directory+':/work'], ['disk /data'], True))
    record('partial-captured-disk', lambda: restore('partialdisk', archive, ['-v', '/data'], ['filesystem /work'], True))
    record('allow-missing-eager', lambda: restore('allowed', archive, ['--allow-missing-resources'], ['warn:', 'EIO']))
    record('allow-missing-forked-quiet', lambda: restore('allowfork', installed, ['--forked', '--quiet', '--allow-missing-resources'], ['warn:', 'EIO']))
    mapping = ['-v', directory+':/work', '-v', '/data']
    record('complete-eager', lambda: restore('complete', archive, mapping))
    record('complete-forked', lambda: restore('completefork', installed, mapping+['--forked']))
    record('complete-relaxed', lambda: restore('completerel', archive, mapping+['--external-mount-policy', 'relaxed']))
    record('source-local-inheritance', lambda: restore('inherit', archive, ['--dangerously-inherit-resources']))
    absent = prefix+'-absent'
    absent_mapping = ['-v', absent+':/work', '-v', '/data']
    record('nonexistent-named-default', lambda: restore('absent', archive, absent_mapping, ['filesystem /work'], True))
    record('nonexistent-named-opt-out', lambda: restore('absentallow', archive, absent_mapping+['--allow-missing-resources'], ['warn:', 'EIO']))
    assert not (home/'volumes'/absent).exists(), 'missing named volume was created'
    record('full-disk-only', lambda: restore('diskonly', archive, ['--disk-only'], cold=True))
    backing = home/'volumes'/directory
    hidden = backing.with_name(directory+'-held')
    backing.rename(hidden)
    try:
        record('missing-backing-default', lambda: restore('backing', archive, mapping, ['filesystem /work'], True))
        record('missing-backing-relaxed-still-required', lambda: restore('backingrel', archive, mapping+['--external-mount-policy', 'relaxed'], ['filesystem /work'], True))
        record('missing-backing-opt-out', lambda: restore('backingallow', archive, mapping+['--allow-missing-resources'], ['warn:', 'EIO']))
    finally:
        hidden.rename(backing)
    # Remove only our fixture's source-local authorization temporarily; no user state.
    authorization = home/'sandboxes'/source/'external-mounts.json'
    if authorization.exists():
        held = authorization.with_suffix('.held')
        authorization.rename(held)
        try:
            record('missing-inherited-authorization', lambda: restore('noauth', archive, ['--dangerously-inherit-resources'], ['filesystem /work'], True))
            record('missing-inherited-authorization-opt-out', lambda: restore('noauthallow', archive, ['--dangerously-inherit-resources', '--allow-missing-resources'], ['warn:', 'EIO']))
        finally:
            held.rename(authorization)
    else:
        record('authorization-fixture', lambda: (_ for _ in ()).throw(AssertionError(str(authorization))))
    # Change a tracked host inode after capture. Opt-out must not waive mismatches.
    exec_(source, 'echo changed-external-file-with-different-size > /work/marker; sync')
    record('changed-object-strict', lambda: restore('changed', archive, mapping, rejected=True))
    record('changed-object-opt-out-still-strict', lambda: restore('changedallow', archive, mapping+['--allow-missing-resources'], rejected=True))
    record('changed-object-relaxed', lambda: restore('changedrel', archive, mapping+['--external-mount-policy', 'relaxed']))
    run('stop', source)
    disk_archive = out/'disk.msnap'
    run('snapshot', 'create', 'disk', '--from-sandbox', source, '-o', disk_archive)
    record('ordinary-disk-snapshot', lambda: restore('disksnap', disk_archive, cold=True))
    owned = child('ownedsource')
    run('create', 'alpine:3.21', '--name', owned, '--cpus', '1', '--memory', '256M',
        '--mount-owned', '/cache:kind=disk,size=256M')
    exec_(owned, 'echo root-preserved > /root-marker; echo ram-preserved > /dev/shm/marker; echo owned-preserved > /cache/marker; sync')
    owned_archive = out/'owned.msnap'
    run('snapshot', 'create', 'owned', '--from-sandbox', owned, '--full', '-o', owned_archive)
    def owned_case():
        name = child('ownedchild')
        r = run('restore', owned_archive, '--name', name)
        assert 'owned-preserved' in exec_(name, 'cat /cache/marker')['stdout']
        exec_(name, 'echo child-private > /cache/marker')
        assert 'owned-preserved' in exec_(owned, 'cat /cache/marker')['stdout']
        cleanup(name)
        return r['seconds']
    record('owned-disk-needs-no-mapping-and-is-private', owned_case)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == archive_hash, 'archive changed'
except Exception:
    record('fixture-setup-or-teardown', lambda: (_ for _ in ()).throw(RuntimeError(traceback.format_exc())))
finally:
    for name in reversed(names):
        try:
            cleanup(name)
        except Exception as error:
            print('cleanup error', name, error, flush=True)
    try:
        remaining = run('ps', '--format', 'json')
        (out/'remaining.json').write_text(remaining['stdout'])
    except Exception as error:
        print(error, flush=True)
print(json.dumps(dict(passed=sum(r['passed'] for r in results), total=len(results), home=str(home))), flush=True)
raise SystemExit(any(not r['passed'] for r in results))
