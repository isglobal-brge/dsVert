#!/usr/bin/env python3
"""Exact rational proof checks for the fused p3 q16/q12 producer.

This verifies analytic envelopes and committed link knots, not sampled floating
point errors. The full finite-DAG bit-exact comparison is a separate Go test.
"""
from fractions import Fraction as F
import hashlib
import json
from pathlib import Path
import sys
sys.dont_write_bytecode = True
from grouped_exp_certificate import exp_interval, profile_interval

here = Path(__file__).parent
raw = (here / "grouped_pwlinear_q16_v1.json").read_bytes()
assert hashlib.sha256(raw).hexdigest() == "f72e66abaf2e503a809f23d4563418d2889843174109398ae48b02f0ec7edb84"
manifest = json.loads(raw)
knots = 0
for p in manifest["profiles"]:
    if p["name"] not in ("sigmoid", "exp_reduced"):
        continue
    for i, knot in enumerate(p["knots"]):
        x = F(p["lower"] + i * p["step"], 65536)
        lo, hi = profile_interval(p["name"], x)
        assert round(lo * 65536) == knot == round(hi * 65536)
        knots += 1

# Sigmoid |f''| <=1/(6sqrt(3)) <1/10 since 100<108. Linear
# interpolation error <=M*h^2/8; knot and product rounding total <=2^-16.
assert 100 < 108
sigmoid_error = F(1, 10) * F(1, 8)**2 / 8 + F(1, 65536)
assert sigmoid_error == F(69, 327680)

# exp uses q16 ln2=45426/65536, with |ln2-L|<1.5e-6.
ll = 2 * sum((F(1, 3)**(2*j+1) / (2*j+1) for j in range(40)), F(0))
lh = ll + 2 * F(1, 3)**81 / (81 * (1 - F(1, 9)))
assert max(abs(ll-F(45426,65536)), abs(lh-F(45426,65536))) < F(3,2000000)
assert exp_interval(F(1,2))[1] < 2
assert exp_interval(F(4))[1] < 55
assert exp_interval(F(-4))[0] > F(1200,65536)
assert exp_interval(F(9,1000000))[1] < F(10001,10000)
reduced_error = F(2, 8*64**2) + F(1, 65536)
exp_error = 64*reduced_error + 55*F(10001,10000)*6*F(3,2000000) + F(1,131072)
assert exp_error < F(11,2000)

# Exact q32 dot and offset; only one q16 rounding, then a nonexpansive
# clamp. Multiplication by public q16 beta is exact, so no p-fold slack.
eta_error = F(1,131072)
for family, link, slope, weight_round, gcap, hcap in (
    ("binomial", sigmoid_error, F(1,4), F(1,131072), 4096, 1024),
    ("poisson", F(11,2000), F(55), F(0), 225280, 225280),
):
    g_error = link + slope*eta_error + F(1,8192)
    h_error = g_error + weight_round
    expected = (F(877,2621440), F(897,2621440)) if family == "binomial" else (F(98987,16384000),)*2
    assert (g_error, h_error) == expected
    # RN is monotone and fixes integer endpoints, so integer cap has no
    # additional ceil(half-unit) term. Absence is exactly zero.
    for capacity in range(1,65):
        assert 2*capacity*max(gcap,hcap) < 2**25 < 2**127
    print(f"{family}: score_error={g_error}, H_error={h_error}, S1=({3*gcap},{6*hcap})")

# All deterministic post-clamp arithmetic fits int64, including a deliberately
# looser bound in which all 64 raw H rows were added before final rounding.
assert 4*2**32 < 2**35
assert 55*2**32 < 2**38
assert 55*2**48 < 2**54
assert 64*55*2**48 < 2**60 < 2**63
print(f"PASS: {knots} exact-rational knots, link/rounding errors, 64 capacities, int64/Ring128 headroom")
