#!/usr/bin/env python3
"""Live no-sync checkpoint qualification in an isolated MSB_HOME.

Requires a matching release runtime/guest agent. Checks dirty block-backed page
cache, shared/private mmap, heap, tmpfs, inherited incremental memory, and the
separate crash-consistent disk-only contract. It does not benchmark throughput.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time


WORKER = r'''
import json, mmap, os, time, uuid
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

# Make the dirty-memory case deliberate: normal background writeback must not
# turn this into a test that passes only because everything reached disk first.
Path('/proc/sys/vm/dirty_writeback_centisecs').write_text('0')
Path('/proc/sys/vm/dirty_expire_centisecs').write_text('600000')
Path('/proc/sys/vm/dirty_ratio').write_text('90')
Path('/proc/sys/vm/dirty_background_ratio').write_text('80')
Path('/persisted').write_bytes(b'persisted-before-checkpoint')
fd = os.open('/persisted', os.O_RDONLY); os.fsync(fd); os.close(fd)
fd = os.open('/', os.O_RDONLY); os.fsync(fd); os.close(fd)
size = 64 * 1024 * 1024
fd = os.open('/dirty-cache', os.O_RDWR | os.O_CREAT | os.O_TRUNC, 0o600)
os.ftruncate(fd, size)
shared = mmap.mmap(fd, size, access=mmap.ACCESS_WRITE)
shared[:] = b'A' * size
private = mmap.mmap(fd, size, access=mmap.ACCESS_COPY)
private[:8] = b'private0'
heap = bytearray(b'heap0000')
Path('/dev/shm/latch-marker').write_bytes(b'tmpfs000')
nonce = str(uuid.uuid4())
class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        if self.path == '/mutate':
            shared[:8] = b'shared01'; private[:8] = b'private1'; heap[:] = b'heap0001'
            Path('/dev/shm/latch-marker').write_bytes(b'tmpfs001')
        dirty = next(int(x.split()[1]) for x in Path('/proc/meminfo').read_text().splitlines() if x.startswith('Dirty:'))
        # Poll only the marker: copying 64 MiB per request dirties unrelated heap pages
        # and can turn this sparse mutation check into a legitimate dense full capture.
        with open('/dirty-cache', 'rb') as disk_file:
            disk_cache = disk_file.read(8).decode()
        body = json.dumps(dict(nonce=nonce, heap=heap.decode(), shared=shared[:8].decode(),
            private=private[:8].decode(), tmpfs=Path('/dev/shm/latch-marker').read_text(),
            disk_cache=disk_cache, dirty_kib=dirty,
            clock=time.time())).encode()
        self.send_response(200); self.send_header('Content-Length', str(len(body))); self.end_headers(); self.wfile.write(body)
HTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
'''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    parser.add_argument('--output', required=True, type=Path)
    parser.add_argument('--layout', choices=['flat', 'layered'], required=True)
    parser.add_argument('--home-parent', type=Path, help='Filesystem for the isolated sandbox home')
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    parent = args.home_parent or Path('/private/tmp' if os.uname().sysname == 'Darwin' else '/tmp')
    home = Path(tempfile.mkdtemp(prefix='dirty-', dir=parent))
    env = dict(os.environ, MSB_HOME=str(home), MSB_BACKEND='local')
    names, rows = [], []
    active = 'source'
    report = dict(home=str(home), binary=args.binary, layout=args.layout, rows=rows, status='running')

    def run(label, *command):
        start = time.monotonic()
        result = subprocess.run([args.binary, *command], env=env, capture_output=True, text=True, timeout=180)
        row = dict(case=label, seconds=time.monotonic()-start, returncode=result.returncode,
                   stdout=result.stdout, stderr=result.stderr)
        rows.append(row)
        (args.output / 'report.json').write_text(json.dumps(report, indent=2))
        print(json.dumps({k: row[k] for k in ('case', 'seconds', 'returncode')}), flush=True)
        assert result.returncode == 0, row
        return result.stdout

    def state(path='/'):
        # Use the guest loopback endpoint. A branch must not inherit host port
        # publications, and this test is about memory, not ingress reconfiguration.
        return json.loads(run('state-' + active, 'exec', active, '--', 'python3', '-c',
            f"import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080{path}').read().decode())"))

    def matches(expected, actual=None):
        actual = state() if actual is None else actual
        for key in ('nonce', 'heap', 'shared', 'private', 'tmpfs', 'disk_cache'):
            assert actual[key] == expected[key], (key, actual, expected)
        assert abs(actual['clock'] - time.time()) < 3, actual
        return actual

    def stop(name):
        run('stop-' + name, 'stop', name)

    try:
        source = 'source'; names.append(source)
        run('create', 'run', '-d', '--name', source, '--memory', '512M', '--cpus', '2',
            '--root-disk', 'flat:1G' if args.layout == 'flat' else '1G',
            'python:3.13-alpine3.22', '--', 'python3', '-u', '-c', WORKER)
        deadline = time.monotonic() + 30
        while True:
            try: initial = state(); break
            except Exception:
                if time.monotonic() >= deadline: raise
                time.sleep(.1)
        assert initial['dirty_kib'] >= 32 * 1024, initial
        report['initial'] = initial
        run('full-dirty', 'snapshot', 'create', 'dirty-full', '--from-sandbox', source, '--full')
        matches(initial)
        names.append('running-branch')
        run('branch-dirty', 'branch', source, '--name', 'running-branch')
        matches(initial, json.loads(run('branch-state', 'exec', 'running-branch', '--', 'python3', '-c',
            "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080').read().decode())")))
        branch_changed = json.loads(run('mutate-branch', 'exec', 'running-branch', '--', 'python3', '-c',
            "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080/mutate').read().decode())"))
        matches(initial)
        names.append('branch-grandchild')
        run('branch-of-branch', 'branch', 'running-branch', '--name', 'branch-grandchild')
        matches(branch_changed, json.loads(run('branch-grandchild-state', 'exec', 'branch-grandchild', '--', 'python3', '-c',
            "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080').read().decode())")))
        stop('branch-grandchild')
        stop('running-branch'); matches(initial)
        run('pause', 'pause', source)
        for suffix in ('one', 'two'):
            run('capture-paused-' + suffix, 'snapshot', 'create', 'paused-' + suffix, '--from-sandbox', source, '--full')
            assert json.loads(run('inspect-paused-' + suffix, 'inspect', source, '--format', 'json'))['status'] == 'Paused'
        names.append('paused-branch')
        run('branch-paused-dirty', 'branch', source, '--name', 'paused-branch')
        matches(initial, json.loads(run('paused-branch-state', 'exec', 'paused-branch', '--', 'python3', '-c',
            "import urllib.request; print(urllib.request.urlopen('http://127.0.0.1:8080').read().decode())")))
        assert json.loads(run('source-still-paused', 'inspect', source, '--format', 'json'))['status'] == 'Paused'
        stop('paused-branch')
        run('resume', 'resume', source); matches(initial)
        # Source shutdown also proves restored state does not rely on live source RAM.
        stop(source)
        for mode in ('eager', 'forked'):
            child = mode; names.append(child)
            run('restore-' + mode, 'create', '--name', child, '--from-snapshot', 'source:dirty-full',
                *(['--forked'] if mode == 'forked' else []))
            active = child
            matches(initial)
            if mode == 'forked':
                # A restored child starts a fresh dirty-tracking baseline while retaining
                # snapshot ancestry. Capture before mutating, then verify an incremental cut.
                run('child-baseline', 'snapshot', 'create', 'child-baseline', '--from-sandbox', child, '--full')
                changed = state('/mutate')
                assert changed['private'] == 'private1'
                captured = run('incremental-dirty', 'snapshot', 'create', 'dirty-incremental', '--from-sandbox', child, '--full')
                # Capture returns the exact installed member path, independent of its alias.
                checkpoint = Path(captured.strip().splitlines()[-1]) / 'checkpoint'
                descriptor = json.loads((checkpoint / 'checkpoint.json').read_text())
                algorithm, digest = descriptor['memory'].split(':', 1)
                memory = json.loads((checkpoint / 'objects' / algorithm / digest[:2] / digest).read_text())
                report['incremental_capture_mode'] = memory['capture_mode']
                assert memory['capture_mode'] == 'incremental', memory['capture_mode']
                matches(changed)
            stop(child)
        names.append('grandchild')
        run('restore-incremental', 'create', '--name', 'grandchild', '--from-snapshot', 'forked:dirty-incremental', '--forked')
        active = 'grandchild'
        matches(changed); stop('grandchild')
        names.append('disk-only')
        run('disk-only', 'create', '--name', 'disk-only', '--from-snapshot', 'source:dirty-full', '--disk-only')
        assert run('persisted-disk-data', 'exec', 'disk-only', '--', 'cat', '/persisted').strip() == 'persisted-before-checkpoint'
        run('no-tmpfs-in-disk-view', 'exec', 'disk-only', '--', 'test', '!', '-e', '/dev/shm/latch-marker')
        # Unsynced disk bytes are deliberately not asserted either present or absent.
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed', error=repr(error)); raise
    finally:
        errors = []
        for name in reversed(names):
            result = subprocess.run([args.binary, 'stop', name], env=env, capture_output=True, text=True, timeout=30)
            if result.returncode and 'already stopped' not in result.stderr.lower():
                errors.append(dict(name=name, error=result.stderr))
        report['cleanup_errors'] = errors
        (args.output / 'report.json').write_text(json.dumps(report, indent=2))


if __name__ == '__main__':
    main()
