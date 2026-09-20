"""Build and test only this isolated pod snapshot; record every exit status."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time

root = Path.cwd().resolve()
assert root.parent == Path('/workspace/dsvert') and root.name.startswith('gee-')
logs = root / 'logs'
logs.mkdir(exist_ok=True)
env = dict(os.environ, GOTOOLCHAIN='go1.25.7', GOMAXPROCS='2', GOMEMLIMIT='8GiB',
           R_LIBS_USER='/workspace/dsvert/gobase/R-library',
           OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1', NOT_CRAN='true',
           PROCESSX_NOTIFY_OLD_SIGCHLD='true')
records = []

def run(name, args, cwd=root):
    started = time.monotonic()
    with (logs / (name + '.log')).open('x') as output:
        result = subprocess.run(args, cwd=cwd, env=env, stdin=subprocess.DEVNULL,
                                stdout=output, stderr=subprocess.STDOUT)
    record = dict(name=name, command=args, returncode=result.returncode,
                  elapsed_seconds=time.monotonic()-started)
    records.append(record)
    (logs / (name + '.exit')).write_text(str(result.returncode)+'\n')
    (logs / 'build-focused-results.json').write_text(json.dumps(records, indent=2)+'\n')
    print(json.dumps(record), flush=True)
    return result.returncode

status = run('runtime-build', ['make', 'all'], root / 'dsVert/inst/dsvert-mpc')
if status == 0:
    status = run('oracle-build', ['go', 'test', '-c', '-tags',
                 'grouped_reference_test,dsvert_family_reference', '-o',
                 str(logs / 'structured-oracle.test'), '.'], root / 'dsVert/inst/dsvert-mpc')
if status == 0:
    oracle_dir = root / 'dsVert/inst/cross-grid-v2/build'
    oracle_dir.mkdir(exist_ok=True)
    shutil.copy2(logs/'structured-oracle.test', oracle_dir/'cross-grid-oracle.test')
    files = sorted(path for package in ('dsVert','dsVertClient')
                   for path in (root / package).rglob('*') if path.is_file())
    manifest = dict(repositories=json.loads((root/'base-commits.json').read_text()),
                    sha256={str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest()
                            for p in files},
                    oracle_sha256=hashlib.sha256((logs/'structured-oracle.test').read_bytes()).hexdigest(),
                    go_toolchain='go1.25.7')
    (root/'frozen-source-manifest.json').write_text(json.dumps(manifest, indent=2)+'\n')
    status = run('gee-native-focused', ['go','test','-v','-count=1','-run','^TestGroupedGEE',
                 '-timeout=30m','.'], root / 'dsVert/inst/dsvert-mpc')
    r_status = run('gee-r-focused', ['Rscript','--vanilla',
                   'dsVert/inst/cross-grid-v2/gee-fixed-rho/run-focused.R',str(root)])
    status = status or r_status
(logs/'build-focused.exit').write_text(str(status)+'\n')
sys.exit(status)
