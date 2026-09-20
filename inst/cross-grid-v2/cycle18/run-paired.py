"""Run full package suites serially against the pinned cycle18 paired snapshot."""
import datetime
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import traceback

root = Path.cwd().resolve()
logs = root / 'logs'
manifest = json.loads((root / 'frozen-source-manifest.json').read_text())
env = dict(os.environ, R_LIBS_USER='/workspace/dsvert/gobase/R-library',
           PATH='/usr/local/go/bin:' + os.environ.get('PATH', ''),
           GOMAXPROCS='2', GOMEMLIMIT='8GiB', OPENBLAS_NUM_THREADS='1',
           OMP_NUM_THREADS='1', DSVERT_RELEASE_TTL_SECONDS='900',
           DSVERT_RELEASE_MAX_RUNTIME_SECONDS='86400')


def verify_source(label):
    bad = [name for name, digest in manifest['sha256'].items()
           if hashlib.sha256((root / name).read_bytes()).hexdigest() != digest]
    assert not bad, (label, bad)
    print(label, len(manifest['sha256']), 'pinned files unchanged', flush=True)


records = []
status = 1
try:
    verify_source('PRE_SUITE')
    for package in ('dsVert', 'dsVertClient'):
        started = time.monotonic()
        record = {'package': package,
                  'started_utc': datetime.datetime.now(datetime.timezone.utc).isoformat()}
        with (logs / (package + '-paired.log')).open('x') as log:
            child = subprocess.Popen(
                ['Rscript', '--vanilla', 'dsVert/inst/cross-grid-v2/cycle16/run-paired.R',
                 str(root), package], cwd=root, env=env, stdin=subprocess.DEVNULL,
                stdout=log, stderr=subprocess.STDOUT)
            record['pid'] = child.pid
            record['stdin'] = os.readlink('/proc/' + str(child.pid) + '/fd/0')
            (logs / (package + '-paired.launch.json')).write_text(json.dumps(record, indent=2) + '\n')
            record['returncode'] = child.wait()
        record['shell_exit_status'] = (record['returncode'] if record['returncode'] >= 0
                                       else 128 - record['returncode'])
        record['elapsed_seconds'] = time.monotonic() - started
        record['finished_utc'] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        (logs / (package + '-paired.exit')).write_text(str(record['shell_exit_status']) + '\n')
        (logs / (package + '-paired.resources.json')).write_text(json.dumps(record, indent=2) + '\n')
        records.append(record)
        print(json.dumps(record), flush=True)
        verify_source('POST_' + package)
    status = 0 if all(record['returncode'] == 0 for record in records) else 1
except BaseException:
    traceback.print_exc()
finally:
    (logs / 'paired-results.json').write_text(json.dumps(records, indent=2) + '\n')
    (logs / 'paired-driver.exit').write_text(str(status) + '\n')
sys.exit(status)
