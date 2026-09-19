#!/usr/bin/env python3
"""Exact-rational certificate for the grouped range-reduced q16 exp table.
No third-party dependencies. --check verifies the committed coefficients.
"""
import argparse
import json
import functools
from fractions import Fraction as F
from pathlib import Path


@functools.lru_cache(None)
def exp_interval(x):
    # Exact rational Taylor sum; for |x|<=4, tail ratio after degree 64
    # is <=4/66. The reciprocal reverses interval endpoints for x<0.
    assert abs(x) <= 4
    term = total = F(1)
    for n in range(1, 65):
        term *= abs(x) / n
        total += term
    tail = term * abs(x) / 65 / (1-abs(x)/66)
    lo, hi = total, total + tail
    return (lo, hi) if x >= 0 else (1 / hi, 1 / lo)


@functools.lru_cache(None)
def log_interval(x):
    assert x > 0
    k = 0
    while x >= 2:
        x /= 2
        k += 1
    while x < 1:
        x *= 2
        k -= 1
    def series(z):
        z2 = z*z
        term = z
        total = F(0)
        for j in range(40):
            total += term/(2*j+1)
            term *= z2
        return 2*total, 2*total+2*term/(81*(1-z2))
    lo, hi = series((x-1)/(x+1))
    ll, lh = series(F(1,3))
    return lo+k*(ll if k>=0 else lh), hi+k*(lh if k>=0 else ll)


def profile_interval(name, x):
    if name == "log":
        return log_interval(x)
    if name == "softplus":
        lo, hi = exp_interval(x)
        return log_interval(1+lo)[0], log_interval(1+hi)[1]
    if name == "sigmoid":
        lo, hi = exp_interval(-x)
        return 1/(1+hi), 1/(1+lo)
    if name in ("sqrt_variance", "inverse_sqrt_variance"):
        lo, hi = exp_interval(x/2)
        nl, nh = exp_interval(-x/2)
        return (1/(hi+nh), 1/(lo+nl)) if name == "sqrt_variance" else (lo+nl, hi+nh)
    return exp_interval(x)


def certificate():
    knots = []
    for i in range(65):
        lo, hi = exp_interval(F(i-32, 64))
        assert round(lo*65536) == round(hi*65536)
        knots.append(round(lo*65536))
    # ln(2) = 2*atanh(1/3). Tail <= 2*(1/3)^81/(81*(1-1/9)).
    loglo = 2*sum((F(1, 3)**(2*j+1)/ (2*j+1) for j in range(40)), F(0))
    loghi = loglo + 2*F(1, 3)**81 / (81*(1-F(1,9)))
    assert max(abs(loglo-F(45426,65536)), abs(loghi-F(45426,65536))) < F(3,2000000)
    # e^(1/2)<2 gives a simple outward curvature bound throughout the table.
    assert exp_interval(F(1,2))[1] < 2
    return dict(name="exp_reduced", lower=-32768, upper=32768, step=1024,
                knots=knots, error=float(F(2,8*64**2)+F(1,65536)),
                second_derivative_bound=2)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    entry = certificate()
    if args.check:
        manifest = json.loads(Path(__file__).with_name('grouped_pwlinear_q16_v1.json').read_text())
        assert entry == next(p for p in manifest['profiles'] if p['name'] == 'exp_reduced')
        count = 0
        for profile in manifest['profiles']:
            for i, knot in enumerate(profile['knots']):
                x = F(profile['lower']+i*profile['step'], 65536)
                lo, hi = profile_interval(profile['name'], x)
                assert round(lo*65536) == knot == round(hi*65536), (profile['name'], i)
                count += 1
        print(f'exact-rational {count} profile knots and ln2 enclosure: PASS')
    else:
        print(json.dumps(entry))
