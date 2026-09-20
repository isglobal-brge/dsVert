"""Run fresh isolated binomial then Poisson sequences with cycle16 leases."""
import json
import os
from pathlib import Path
import subprocess
import sys

logs = Path('logs')
status = 1
try:
    for family in ('binomial_glmm', 'poisson_glmm'):
        (logs / 'queue-progress.json').write_text(json.dumps(dict(family=family, promoted=False)) + '\n')
        result = subprocess.run([sys.executable, '-u',
            'dsVert/inst/cross-grid-v2/cycle16/run-sequence.py'],
            env=dict(os.environ, DSVERT_RELEASE_FAMILY=family),
            stdin=subprocess.DEVNULL)
        if result.returncode:
            sys.exit(result.returncode)
    status = 0
finally:
    (logs / 'queue.exit').write_text(str(status) + '\n')
sys.exit(status)
