"""Measure integer-n NB frontier at fixed p10/grid50; no extrapolated admission.
Continues only after the two already-running bracket measurements complete.
"""
import json
import os
from pathlib import Path
import subprocess
import time

root = Path('/workspace/dsvert/integrator-cycle3')
logs = root / 'logs'

def result(n):
    prefix = logs / f'nb-capacity-n{n}'
    while not prefix.with_suffix('.exit').exists():
        time.sleep(20)
    text = prefix.with_suffix('.log').read_text()
    lines = [line.split('FULL_MEASUREMENT ', 1)[1] for line in text.splitlines()
             if 'FULL_MEASUREMENT ' in line]
    if len(lines) != 1:
        raise RuntimeError(f'n={n} did not produce exactly one completed measurement')
    report = json.loads(lines[0])
    code = int(prefix.with_suffix('.exit').read_text())
    passed = report['total_wire_bytes'] <= 110_000_000_000 and report['total_seconds'] <= 14400
    if not report['integer_and_dp_oracle_equal'] or (code == 0) != passed:
        raise RuntimeError(f'n={n} has inconsistent measurement evidence')
    return report, passed

low, high = 7616, 7648
measurements = {}
for n in (low, high):
    measurements[n], passed = result(n)
    if passed != (n == low):
        raise RuntimeError('Expected measured bracket absent; inspect the completed reports')
env = dict(os.environ, GOMAXPROCS='2', GOMEMLIMIT='8GiB', GOGC='100',
           DSVERT_CROSS_FULL_MEASURE='1', DSVERT_CROSS_P='10', DSVERT_CROSS_GRID='50',
           DSVERT_CROSS_WORKERS='2')
while high - low > 1:
    # The measured lower endpoint leaves only 4.54 MB. Test its immediate
    # neighbour first; if that passes, continue the measured bracket search.
    n = low + 1 if len(measurements) == 2 else (low + high) // 2
    prefix = logs / f'nb-capacity-n{n}'
    if prefix.with_suffix('.log').exists() or prefix.with_suffix('.exit').exists():
        raise RuntimeError(f'Refusing to overwrite n={n} evidence')
    env['DSVERT_CROSS_N'] = str(n)
    prefix.with_suffix('.started').write_text(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())+'\n')
    with prefix.with_suffix('.log').open('w') as out:
        run = subprocess.run(['go', 'test', '-run', '^TestCrossGridFullMeasurement$/^nb$',
                              '-v', '-count=1', '-timeout=5h', '.'],
                             cwd=root/'dsVert/inst/dsvert-mpc', env=env,
                             stdin=subprocess.DEVNULL, stdout=out, stderr=subprocess.STDOUT)
    prefix.with_suffix('.exit').write_text(str(run.returncode)+'\n')
    prefix.with_suffix('.finished').write_text(time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime())+'\n')
    measurements[n], passed = result(n)
    if passed:
        low = n
    else:
        high = n
    summary = dict(family='nb', p=10, grid=50, gate_bytes=110_000_000_000,
                   gate_seconds=14400, largest_measured_passing_n=low,
                   smallest_measured_failing_n=high, adjacent=high-low == 1,
                   authenticated_server_release=False, release_admitted=False,
                   scope='fixed benchmark profile; max_outcome16, all theta exponents7; K2 kernel + joint noise',
                   measurements=measurements)
    temporary = logs/'nb-frontier.tmp'
    temporary.write_text(json.dumps(summary, indent=2)+'\n')
    temporary.replace(logs/'nb-frontier.json')
    print(f'MEASURED_FRONTIER low={low} high={high}', flush=True)
