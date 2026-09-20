#!/usr/bin/env python3
"""Reproduce the embedded fused-kernel tables from accepted certificates."""
import argparse
import json
import sys
from pathlib import Path
sys.dont_write_bytecode = True
import mpmath as mp
from generate_profile import rounded

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
profiles = json.loads((root / 'profile_candidate.json').read_text())['profiles']
exp = json.loads((root / 'exp_reduced_candidate.json').read_text())['profiles'][2]
mp.iv.dps = 90
lf, value = [0], mp.iv.mpf(0)
for i in range(1, 1025):
    value += mp.iv.log(i)
    lf.append(rounded(value, 65536))
result = dict(binomial=[p for p in profiles if p['family'] == 'binomial' and p['pieces'] == 64],
              poisson=exp, log_factorial=lf)
text = json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n'
target = root.parent / 'dsvert-mpc' / 'cross_grid_profiles_v2.json'
if args.check:
    assert target.read_text() == text, 'embedded profile reproduction mismatch'
else:
    target.write_text(text)
print('KERNEL_PROFILES_REPRODUCED')
