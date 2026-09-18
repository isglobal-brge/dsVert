#!/usr/bin/env python3
"""Pin envelope caps for every admitted bounded count; no runtime libm proof."""
import argparse
import hashlib
import json
from pathlib import Path
import mpmath as mp

root = Path(__file__).resolve().parent
parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
mp.iv.dps = 90
source = root.parent / 'dsvert-mpc' / 'cross_grid_profiles_v2.json'
profiles = json.loads(source.read_text())
logfact = [mp.iv.mpf(0)]
for y in range(1, 1025):
    logfact.append(logfact[-1] + mp.iv.log(y))

def cap(value):
    # Converting the upper endpoint to an mp scalar preserves its exact value.
    return int(mp.ceil(mp.mpf(value.b)))

mp.mp.dps = 100
entries = []
for profile in profiles['binomial']:
    a = profile['a']
    eb = profile['loss_error']
    ep = profiles['poisson']['loss_errors'][str(a)]
    binomial = mp.iv.log(1 + mp.iv.exp(a))
    poisson = []
    for y in range(1, 1025):
        corners = [mp.iv.exp(eta) - count * eta + logfact[count]
                   for eta in [-a, a] for count in [0, y]]
        upper = max(c.b for c in corners)
        poisson.append(cap((upper + 2 * mp.iv.mpf(ep)) * 2**18))
    entries.append(dict(a=a, binomial_error=eb, poisson_error=ep,
        binomial_cap18=cap((binomial + 2 * mp.iv.mpf(eb)) * 2**18),
        poisson_caps18=poisson))
result = dict(version='cross-grid-envelope-certificate-v2',
    profile_identity='cross-grid-certified-piecewise-k64-v2',
    kernel_profiles_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
    cap_rule='ceil(S*(outward_real_envelope_loss+2*certified_loss_error))',
    envelope_rule='smallest_power_of_two_in_1_2_4_8_16_enclosing_all_signed_candidate_l1',
    caps18=entries)
text = json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n'
target = root / 'admission_certificate.json'
if args.check:
    assert target.read_text() == text, 'admission certificate mismatch'
else:
    target.write_text(text)
print('ADMISSION_CERTIFICATE_REPRODUCED sha256=' + hashlib.sha256(text.encode()).hexdigest())
