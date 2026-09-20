"""Fresh LMM/GLMM proof sequence; immutable inputs, isolated peers, no promotion."""
import datetime
import fcntl
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import traceback

root = Path.cwd().resolve()
family = os.environ.get('DSVERT_RELEASE_FAMILY', 'lmm')
assert family in ('lmm', 'binomial_glmm', 'poisson_glmm')
logs = root / 'logs' if family == 'lmm' else root / 'logs' / family
if family != 'lmm':
    logs.mkdir()
scripts = Path('dsVert/inst/cross-grid-v2/cycle16')
events = (logs / 'sequence.jsonl').open('x')
lock = Path('/workspace/dsvert/cycle14-heavy-release.lock').open('a')
manifest = json.loads((root / 'frozen-source-manifest.json').read_text())


def emit(event, **fields):
    record = dict(utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
                  event=event, promoted=False, **fields)
    events.write(json.dumps(record) + '\n')
    events.flush()
    (logs / 'progress.json').write_text(json.dumps(record, indent=2) + '\n')
    print(json.dumps(record), flush=True)


def verify():
    for name, digest in manifest['sha256'].items():
        assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name


status = 1
try:
    verify()
    emit('waiting_for_shared_release_lock')
    fcntl.flock(lock, fcntl.LOCK_EX)
    emit('shared_release_lock_acquired')
    # Legacy immutable jobs have independent callr/DSLite processes and state
    # roots. The user permits isolated transports; no legacy process is stopped.
    # This lock serializes new LMM/Poisson sequences, while the harness creates
    # fresh peer processes and a unique state directory for every release.
    emit('isolated_transport_policy', legacy_jobs='separate peer processes; unchanged',
         new_sequences='serialized with queued Poisson', native_gomaxprocs=2)
    for n, owners, recovery in [(4, 2, 0), (2000, 2, 0), (2000, 3, 0),
                               (2000, 5, 0), (2000, 2, 1)]:
        verify()
        emit('release_start', n=n, owners=owners, recovery=recovery)
        subprocess.run([sys.executable, str(scripts / 'run-release.py'),
                        str(n), str(owners), str(recovery)], stdin=subprocess.DEVNULL,
                       check=True)
        label = f'{family}-n{n}-k{owners}-' + ('recovery' if recovery else 'baseline')
        proof = json.loads((logs / (label + '-resources.json')).read_text())
        assert proof['proof_passed'], label
        emit('release_pass', label=label, capacity=proof['capacity_gate'])
    env = dict(os.environ, DSVERT_PAIRED_LOG_DIR=str(logs), R_LIBS_USER='/workspace/dsvert/gobase/R-library',
               PATH='/usr/local/go/bin:' + os.environ.get('PATH', ''),
               GOMAXPROCS='2', GOMEMLIMIT='8GiB', OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1')
    for package in ('dsVert', 'dsVertClient'):
        verify()
        emit('paired_start', package=package)
        with (logs / (package + '-paired.log')).open('x') as log:
            result = subprocess.run(['Rscript', '--vanilla', str(scripts / 'run-paired.R'),
                                     str(root), package], env=env, stdin=subprocess.DEVNULL,
                                    stdout=log, stderr=subprocess.STDOUT)
        (logs / (package + '-paired.exit')).write_text(str(result.returncode) + '\n')
        assert result.returncode == 0, package
    verify()
    emit('completed_requires_review', review='Review paired warnings/skips and every proof before promotion')
    status = 0
except BaseException as error:
    emit('stopped_requires_review', error=str(error))
    traceback.print_exc()
finally:
    (logs / 'sequence.exit').write_text(str(status) + '\n')
    events.close()
sys.exit(status)
