"""Run one signed LMM/GLMM proof in this snapshot; never sets promotion."""
import json
import math
import os
from pathlib import Path
import resource
import subprocess
import sys
import time

CAPACITY = json.loads((Path(__file__).resolve().parents[1] / 'integrator-validation/release-capacity.json').read_text())
root = Path.cwd().resolve()
family = os.environ.get('DSVERT_RELEASE_FAMILY', 'lmm')
assert family in ('lmm', 'binomial_glmm', 'poisson_glmm')
logs = root / 'logs' if family == 'lmm' else root / 'logs' / family
marker = 'DSLITE_LMM' if family == 'lmm' else 'DSLITE_GLMM'
n, owners, interrupts = map(int, sys.argv[1:])
assert n in (4, 2000) and owners in (2, 3, 5) and interrupts in (0, 1)
label = f'{family}-n{n}-k{owners}-' + ('recovery' if interrupts else 'baseline')
log_path = logs / (label + '.log')
metrics_path = logs / (label + '-metrics.json')
result_path = logs / (label + '-resources.json')
exit_path = logs / (label + '.exit')
assert all(not p.exists() for p in (log_path, metrics_path, result_path, exit_path)), 'Use a fresh snapshot for each retry'
manifest = json.loads((root / 'frozen-source-manifest.json').read_text())
import hashlib
for name, digest in manifest['sha256'].items():
    assert hashlib.sha256((root / name).read_bytes()).hexdigest() == digest, name
env = os.environ.copy()
env.update(R_LIBS_USER='/workspace/dsvert/gobase/R-library',
    GOMAXPROCS=env.get('GOMAXPROCS', '2'), GOMEMLIMIT=env.get('GOMEMLIMIT', '16GiB'),
    OPENBLAS_NUM_THREADS='1', OMP_NUM_THREADS='1', NOT_CRAN='true',
    PROCESSX_NOTIFY_OLD_SIGCHLD='true', DSVERT_RELEASE_TTL_SECONDS='900', DSVERT_RELEASE_MAX_RUNTIME_SECONDS='86400',
    DSVERT_GRID_VALIDATION_N=str(n),
    DSVERT_GRID_VALIDATION_P='3', DSVERT_GRID_VALIDATION_GRID='2',
    DSVERT_GRID_VALIDATION_OWNERS=str(owners), DSVERT_GRID_VALIDATION_EPSILON='4',
    DSVERT_GRID_VALIDATION_INSTANCE='1', DSVERT_GRID_VALIDATION_INSTANCE_COUNT='1',
    DSVERT_GRID_VALIDATION_REAL_COUNT='1', DSVERT_GRID_VALIDATION_COLD='1',
    DSVERT_GRID_VALIDATION_ORACLE_ONLY='0', DSVERT_GRID_VALIDATION_REPLAY_ONLY='0',
    DSVERT_GRID_VALIDATION_INTERRUPT=str(interrupts), DSVERT_GRID_VALIDATION_KEEP_STATE='1',
    DSVERT_GRID_VALIDATION_PROGRESS='1', DSVERT_GRID_VALIDATION_METRICS_PATH=str(metrics_path),
    DSVERT_GRID_VALIDATION_STATE_PARENT=f'/var/lib/{root.name}/{label}')
started = time.monotonic()
with log_path.open('x') as log:
    result = subprocess.run(['Rscript', '--vanilla',
        f'integrator-validation/validate_{family}_dslite.R', str(root)],
        cwd=root, env=env, stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT)
usage = resource.getrusage(resource.RUSAGE_CHILDREN)
required = ['DSLITE_ORACLE_BITWISE_EQUAL_STICKY_TAMPER_REJECTED ' + family,
    'DIRECT_R_COLD_LIFECYCLE_EQUAL_TAMPER_REJECTED',
    marker + '_COLD_EXPORTED_API_EQUAL_AUTHENTICATED']
if interrupts:
    required += [marker + '_NATIVE_PREPARE_REMASK_AND_UNILATERAL_COMMIT_EXACT_REPLAY_VERIFIED']
    required += [marker + '_RECOVERY_BOUNDARY ' + mode + ' OBSERVED' for mode in
        ('prepared', 'bilateral_prepare', 'unilateral_commit', 'committed', 'unilateral')]
log = log_path.read_text(errors='replace')
record = {'measurement': label, 'transport_policy': {'ttl_seconds': 900, 'max_runtime_seconds': 86400}, 'process_wall_seconds': time.monotonic() - started,
    'max_child_rss_kib_linux': usage.ru_maxrss, 'user_seconds': usage.ru_utime,
    'system_seconds': usage.ru_stime, 'process_exit_code': result.returncode,
    'markers': {marker: marker in log for marker in required},
    'recovery_metrics_passed': not interrupts, 'metric_shape_passed': False, 'promoted': False}
if metrics_path.exists():
    metrics = json.loads(metrics_path.read_text())
    values = [metrics.get('end_to_end_serialized_rpc_bytes'), metrics.get('end_to_end_release_elapsed')]
    record['release_metrics'] = metrics
    record['metric_shape_passed'] = (metrics.get('family') == family and
        metrics.get('n') == n and metrics.get('p') == 3 and metrics.get('grid') == 2 and metrics.get('candidates') == 4 and
        metrics.get('owners') == owners and metrics.get('slots') == 4 and
        metrics.get('clusters') == math.ceil(n / 4) and metrics.get('oracle_only') is False)
    record['capacity_gate'] = {'ceiling_bytes': CAPACITY['capacity_bytes'], 'ceiling_seconds': CAPACITY['capacity_seconds'],
        'measured_serialized_rpc_bytes': values[0], 'measured_release_seconds': values[1],
        'scope': metrics.get('end_to_end_scope'), 'wire_scope': metrics.get('serialized_rpc_scope'),
        'passed': all(type(v) in (int, float) and math.isfinite(v) and 0 <= v <= limit
            for v, limit in zip(values, [CAPACITY['capacity_bytes'], CAPACITY['capacity_seconds']])), 'budget_stop': False}
    if interrupts:
        record['recovery_metrics_passed'] = metrics.get('recovery') == 'exercised' and metrics.get('native_recovery') == 'prepare_remask_and_unilateral_commit_exact_replay'
record['proof_passed'] = result.returncode == 0 and all(record['markers'].values()) and record.get('capacity_gate', {}).get('passed', False) and record['recovery_metrics_passed'] and record['metric_shape_passed']
record['exit_code'] = 0 if record['proof_passed'] else result.returncode or 1
result_path.write_text(json.dumps(record, indent=2) + '\n')
exit_path.write_text(str(record['exit_code']) + '\n')
print(json.dumps(record), flush=True)
sys.exit(record['exit_code'])
