"""Freeze the local pair and detach a small Cox proof or source-only oracle."""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

parser = argparse.ArgumentParser()
parser.add_argument('name')
parser.add_argument('--n', type=int, default=4)
parser.add_argument('--p', type=int, default=5)
parser.add_argument('--owners', type=int, default=2)
parser.add_argument('--recovery', action='store_true')
parser.add_argument('--oracle-only', action='store_true')
args = parser.parse_args()
assert 2 <= args.n <= 400 and (args.oracle_only or args.n <= 4)
out = Path(__file__).resolve().parent
root = out.parents[1]
snap = out / args.name
snap.mkdir()
files = {}
heads = {}
for repo in ('dsVert', 'dsVertClient'):
    heads[repo] = subprocess.check_output(['git', '-C', str(root / repo), 'rev-parse', 'HEAD'], text=True).strip()
    for name in subprocess.check_output(['git', '-C', str(root / repo), 'ls-files'], text=True).splitlines():
        src = root / repo / name
        if not src.is_file():
            continue
        dst = snap / repo / name
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dst)
        files[repo + '/' + name] = hashlib.sha256(dst.read_bytes()).hexdigest()
(snap / 'source-manifest.json').write_text(json.dumps({'sha256': files, 'base_commits': heads}, indent=2) + '\n')
(snap / 'frozen-source-manifest.json').write_text(json.dumps({'repositories': heads}, indent=2) + '\n')
(snap / 'integrator-validation').symlink_to('dsVert/inst/cross-grid-v2/integrator-validation', target_is_directory=True)
(snap / 'logs').mkdir()
binary = snap / 'dsVert/inst/cross-grid-v2/build/cross-grid-oracle.test'
binary.parent.mkdir(exist_ok=True)
shutil.copy2(root / 'dsVert/inst/cross-grid-v2/build/cross-grid-oracle.test', binary)
env = os.environ.copy()
env.update(dict(GOMAXPROCS='2', GOMEMLIMIT='16GiB', OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1', NOT_CRAN='true',
    DSVERT_RELEASE_TTL_SECONDS='900', DSVERT_RELEASE_MAX_RUNTIME_SECONDS='86400',
    DSVERT_GRID_VALIDATION_N=str(args.n), DSVERT_GRID_VALIDATION_P=str(args.p),
    DSVERT_GRID_VALIDATION_GRID='2', DSVERT_GRID_VALIDATION_EPSILON='8',
    DSVERT_GRID_VALIDATION_OWNERS=str(args.owners), DSVERT_GRID_VALIDATION_REAL_COUNT='0' if args.oracle_only else '1',
    DSVERT_GRID_VALIDATION_ORACLE_ONLY='1' if args.oracle_only else '0',
    DSVERT_GRID_VALIDATION_COLD='1', DSVERT_GRID_VALIDATION_INTERRUPT='1' if args.recovery else '0',
    DSVERT_GRID_VALIDATION_KEEP_STATE='1', DSVERT_GRID_VALIDATION_PROGRESS='1',
    DSVERT_GRID_VALIDATION_METRICS_PATH=str(snap / 'logs/metrics.json')))
command = ['Rscript', '--vanilla', 'dsVert/inst/cross-grid-v2/integrator-validation/validate_cox_dslite.R', str(snap)]
runner = 'import subprocess,json,sys; r=subprocess.run(sys.argv[2:],stdin=subprocess.DEVNULL); open(sys.argv[1],"w").write(json.dumps({"exit_code":r.returncode})+"\\n"); sys.exit(r.returncode)'
with (snap / 'logs/proof.log').open('x') as log:
    child = subprocess.Popen(['python3', '-c', runner, str(snap / 'logs/exit.json'), *command],
        cwd=snap, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
record = dict(pid=child.pid, started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
    snapshot=str(snap), command=command, env={k: v for k, v in env.items() if k.startswith('DSVERT_')},
    source_commits=heads, manifest_sha256=hashlib.sha256((snap / 'source-manifest.json').read_bytes()).hexdigest(),
    oracle_binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest(),
    scope='source-only oracle commitment' if args.oracle_only else 'small signed native joint-DP proof; not fleet capacity or promotion')
(snap / 'launch.json').write_text(json.dumps(record, indent=2) + '\n')
print(json.dumps(record, indent=2))
