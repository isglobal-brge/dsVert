#!/usr/bin/env python3
"""Public, reproducible interval certificate for quadratic cross-grid profiles.

This candidate profile is not admitted by the V1 signed-contract validator.
Uses mpmath 1.3.0; all coefficient/error bounds use outward intervals.
"""
import argparse
import hashlib
import json
import random
from pathlib import Path
import mpmath as mp

mp.mp.dps = 100
mp.iv.dps = 90
S = 1 << 16


def canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


def rounded(v, scale):
    lo, hi = mp.mpf(v.a) * scale, mp.mpf(v.b) * scale
    n = int(mp.nint((lo + hi) / 2))
    assert int(mp.nint(lo)) == n == int(mp.nint(hi))
    assert max(abs(lo - n), abs(hi - n)) <= mp.mpf("0.5")
    return n


def upper_decimal(v):
    # Round the interval's upper endpoint upwards to 18 decimal places.
    return str(mp.mpf(int(mp.ceil(mp.mpf(v.b) * 10**18))) / 10**18)


def round_even(n, d):
    q, r = divmod(n, d)
    return q + int(2*r > d or (2*r == d and q % 2))


def oracle(coeff, width, offset):
    j = min(offset // width, len(coeff)-1)
    r = offset - j*width
    c0, c1, c2 = coeff[j]
    return c0 + round_even((c1 + round_even(c2*r, width))*r, width)


def build():
    profiles = []
    factorials = [mp.iv.mpf(0)]
    for y in range(1,1025):
        factorials.append(factorials[-1] + mp.iv.log(y))
    log_tables = {f: [rounded(v, 1 << f) for v in factorials] for f in (6,16)}
    eta_encoding = mp.iv.mpf(33) / 2**51 + mp.iv.mpf(16) / 2**102
    for family in ("binomial", "poisson"):
        for a in (1, 2, 4, 8, 16):
            for k in (16, 32, 64):
                f = 6 if family == "poisson" and a == 16 else 16
                q = 1 << f
                h = mp.iv.mpf(2*a) / k
                fun = (lambda x: mp.iv.log(1 + mp.iv.exp(x))) if family == "binomial" else mp.iv.exp
                coeff = []
                max_raw = 0
                # P(t)=c0+c1*t+c2*t^2, t in [0,1]. Interpolates at 0,1/2,1.
                for j in range(k):
                    x = -a + j*h
                    y0, ym, y1 = fun(x), fun(x + h/2), fun(x + h)
                    c2 = 2*(y1 - 2*ym + y0)
                    c1 = y1 - y0 - c2
                    row = [rounded(y0, q), rounded(c1, q), rounded(c2, q)]
                    assert all(0 <= v < 2**31 for v in row)
                    coeff.append(row)
                    # Every Horner word fits signed32, every raw product signed64.
                    assert abs(row[1]) + abs(row[2]) + 1 < 2**31
                    assert sum(abs(v) for v in row) + 2 < 2**31
                    max_raw = max(max_raw, (abs(row[1])+abs(row[2])+1) * (2*a*S//k))
                # max |t(t-1/2)(t-1)| = 1/(12 sqrt(3)); divide by 3!.
                third = mp.iv.mpf(1)/(6*mp.iv.sqrt(3)) if family == "binomial" else mp.iv.exp(a)
                interp = third*h**3/(72*mp.iv.sqrt(3))
                # Three nearest coefficients + two nearest Horner products.
                arithmetic = mp.iv.mpf(5)/(2*q)
                # Loss derivative: <=1 for binary; <=exp(a)+1024 for Poisson.
                derivative = 1 if family == "binomial" else mp.iv.exp(a)+1024
                eta_error = eta_encoding + mp.iv.mpf(1)/(2*S)
                # Clamp eta to [-a,a] after one complete-dot rounding. Projection
                # cannot increase its distance from any real eta in [-a,a].
                # Log-factorial is to be rounded independently to the same f.
                log_error = 0 if family == "binomial" else mp.iv.mpf(1)/(2*q)
                error = interp + arithmetic + derivative*eta_error + log_error
                width = 2*a*S//k
                rng = random.Random(20260918)
                offsets = sorted(set([0, 2*a*S] +
                    [j*width+d for j in range(1,k) for d in (-1,0,1)] +
                    [rng.randrange(2*a*S+1) for _ in range(32)]))
                vectors = [[x, oracle(coeff, width, x)] for x in offsets]
                caps = []
                outcomes = (1,) if family == "binomial" else (4, 1024)
                for m in outcomes:
                    if family == "binomial":
                        bound = fun(mp.iv.mpf(a))
                    else:
                        # Convexity separately in eta and y bounds the rectangle
                        # by four corners (log-Gamma is convex for y >= 0).
                        factorial = factorials[m]
                        corners = [mp.iv.exp(sign*a)-y*sign*a+(factorial if y else 0)
                                   for sign in (-1,1) for y in (0,m)]
                        bound = mp.iv.mpf([max(mp.mpf(v.a) for v in corners),
                                          max(mp.mpf(v.b) for v in corners)])
                    # Enclose max approximated loss plus another profile error.
                    cap = int(mp.ceil(mp.mpf((bound + 2*error).b)*65536))
                    caps.append(dict(max_outcome=m, g=16, per_patient_cap=cap,
                                     real_loss_bound=upper_decimal(bound)))
                log_table = log_tables[f] if family == "poisson" else []
                profiles.append(dict(caps=caps, log_factorial=log_table, test_vectors=vectors, identity=f"cross-grid-pwq-{family}-a{a}-k{k}-q{f}-eta16-v2",
                    family=family, a=a, pieces=k, fraction_bits=f,
                    eta_fraction_bits=16, interval_integer_width=2*a*S//k,
                    coefficients=coeff, max_raw_product=str(max_raw),
                    interpolation_error=upper_decimal(interp),
                    arithmetic_error=upper_decimal(arithmetic),
                    loss_error=upper_decimal(error)))
    result = dict(version="cross-grid-piecewise-candidate-v2", status="not-admitted",
                  rounding="nearest-ties-to-even", profiles=profiles)
    result["sha256"] = hashlib.sha256(canonical(result).encode()).hexdigest()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    path = Path(__file__).with_name("profile_candidate.json")
    data = json.dumps(build(), sort_keys=True, indent=2) + "\n"
    if args.check:
        assert path.read_text() == data, "public profile differs from interval generator"
    else:
        path.write_text(data)
    print("profile certificate reproduced")


if __name__ == "__main__":
    main()
