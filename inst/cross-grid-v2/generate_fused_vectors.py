#!/usr/bin/env python3
"""Synthetic full-dot fixtures shared by independent Go and R checks."""
import json
import random
import sys
from pathlib import Path
sys.dont_write_bytecode = True
from generate_profile import oracle, round_even
from generate_exp_reduced import evaluate
root = Path(__file__).resolve().parent
profiles = json.loads((root.parent/'dsvert-mpc/cross_grid_profiles_v2.json').read_text())
rng = random.Random(20260918)
result = []
for family in ('binomial', 'poisson'):
    for g in (8, 16, 18):
        for a in (4, 16):
            # Full-range beta sum is exactly A, including signed half-ulp cases.
            beta = [str((a//2)*2**50), str(-(a//2)*2**50), '0']
            p = dict(Family=family, Rows=1, Predictors=2, Owners=2, A=a,
                     GridBits=g, MaxOutcome=1 if family=='binomial' else 4,
                     Beta=[beta], Caps=[2**40])
            bp = next(v for v in profiles['binomial'] if v['a']==a)
            vectors = []
            for i in range(24):
                x = [rng.randrange(2**50+1),1,rng.randrange(2**50+1),1,
                     rng.randrange(p['MaxOutcome']+1),1,37,91,37,91]
                if i == 0: x[0] = 0
                if i == 1: x[0] = 2**50
                if i == 2: x[0] = 2**50+1
                if i == 3: x[1] = 0
                if i == 4: x[1] = 2
                if i == 5: x[-1] = 92
                if i == 6: x[4] = p['MaxOutcome']+1
                if i == 7: x[0] = 2**128-1
                valid = (x[0]<=2**50 and x[1]==1 and x[3]==1 and
                         x[4]<=p['MaxOutcome'] and x[5]==1 and x[7]==x[9])
                q = 16 if family=='binomial' else 26
                dot = int(beta[0])*2**50+int(beta[1])*x[0]+int(beta[2])*x[2]
                eta = min(a*2**q, max(-a*2**q, round_even(dot, 2**(100-q))))
                if family=='binomial':
                    loss = oracle(bp['coefficients'],bp['interval_integer_width'],eta+a*65536)-x[4]*eta
                else:
                    loss = (evaluate(profiles['poisson'],eta)[0]<<10)-x[4]*eta
                    if x[4]<=1024: loss += profiles['log_factorial'][x[4]]<<10
                loss = max(0,loss) if valid else 0
                z = round_even(loss,2**(q-g)) if q>=g else loss*2**(g-q)
                vectors.append(dict(source=list(map(str,x)), expected=[str(min(p['Caps'][0],z))]))
            result.append(dict(plan=p,vectors=vectors))
text = json.dumps(result,sort_keys=True,separators=(',',':'))+'\n'
target=root/'fused_vectors.json'
if '--check' in sys.argv:
    assert target.read_text()==text, 'fused fixtures differ'
else:
    target.write_text(text)
print('FUSED_VECTORS_REPRODUCED',sum(len(v['vectors']) for v in result))
