#!/usr/bin/env python3
"""Analytic rational certificate plus dense regression for family-B q16 profiles.

The rational inequalities establish the bound. Dense checks regress the pinned
implementation and tables and are deliberately not represented as a proof.
"""
from fractions import Fraction as F
from pathlib import Path
import hashlib
import json
import math
from generate_piecewise_profile import canonical, make_profile, make_certificate

ROOT = Path(__file__).resolve().parent
Q = 65536

def rnd(value, bits):
    if bits <= 0:
        return value << -bits
    sign = -1 if value < 0 else 1
    q, r = divmod(abs(value), 1 << bits)
    return sign*(q + int(2*r > 1 << bits or (2*r == 1 << bits and q % 2)))

def piece(value, table):
    lower, step = table["lower_q16"], table["step_q16"]
    assert lower <= value <= lower+64*step
    index = min(63, (value-lower)//step)
    t = value-lower-index*step
    c, b, a = table["coefficients_c_b_a_q16"][index]
    inner = b+rnd(a*t, 16)
    assert abs(a*t) < 2**31 and abs(inner*t) < 2**31
    result = c+rnd(inner*t, 16)
    assert abs(inner) < 2**31 and abs(result) < 2**31
    return result

def exp16(value, profile):
    assert -32*Q <= value <= 0
    return Q if value == 0 else (0 if value < -16*Q else piece(value, profile["tables"]["exp"]))

def log16(value, profile):
    assert Q <= value <= 8*Q
    exponent = value.bit_length()-17
    return piece(rnd(value, exponent), profile["tables"]["log"])+exponent*profile["log2_q16"]

def soft16(value, profile):
    assert abs(value) <= 16*Q
    return max(value, 0)+piece(abs(value), profile["tables"]["softminus"])

def legacy_public_gap_bound():
    # Retained high-precision arithmetic is only for candidate-signed PUBLIC
    # threshold differences; it is never emitted as a protected-row circuit.
    u = F(1, 2**64)
    lo = 2*sum((F(1, (2*k+1)*3**(2*k+1)) for k in range(100)), F(0))
    hi = lo + F(2, 201*3**201)/(1-F(1, 9))
    assert F(2*12786308645202655660-1, 2**65) < lo < hi < F(2*12786308645202655660+1, 2**65)
    z = F(1, 3)+u/2
    tail = 2*z**49/(49*(1-z*z))
    assert 1024*u+tail < F(1, 2**50)
    # Gap >=1/16 gives 1-exp(-gap)>1/32, and inherited exp error<4e-9.
    exp_error = F(4, 10**9)
    error = exp_error/(F(1, 32)-exp_error)+F(1, 2**50)
    assert error < F(14, 10**8)
    return F(14, 10**8)

def verify(dense=True):
    document = json.loads((ROOT/"piecewise_profile_v1.json").read_text())
    assert document == make_profile(), "public table generation drift"
    certificate = json.loads((ROOT/"piecewise_certificate_v1.json").read_text())
    assert certificate == make_certificate(document), "analytic certificate drift"
    profile = document["profile"]
    assert document["profile_sha256"] == hashlib.sha256(canonical(profile)).hexdigest()
    u, he, hl = F(1, Q), F(1, 4), F(1, 64)
    # Endpoint/midpoint interpolation: ||error|| <= sup|f'''| h^3/(72 sqrt(3)).
    # sqrt(3)>17/10; softminus sup|f'''|=1/(6 sqrt(3)).
    rounding = lambda h: u/2*(2+2*h+h*h)
    exp_error = he**3/F(72)*F(10, 17)+rounding(he)
    soft_error = he**3/F(1296)+rounding(he)
    # Below -16 the clipped exponential error is exp(-16)<2^-23.
    assert math.exp(-16) < 2**-23 < exp_error
    log_polynomial_error = 2*hl**3/F(72)*F(10, 17)+rounding(hl)
    log_error = log_polynomial_error+u/(2-u)+3*u/2
    # q16 eta rounding: logsumexp-minus-observed gradient L1<=2.
    multi = 7*exp_error/(1-7*exp_error)+log_error+u+F(1, 10**12)
    # Each ordinal endpoint argument is perturbed by <=u. The stable interior
    # identity has derivative magnitudes <=1 in each endpoint argument.
    ordinal = 2*soft_error+u/2+legacy_public_gap_bound()+2*u+F(1, 10**12)
    assert multi < F(11, 10000)
    assert ordinal < F(12, 100000)
    assert exp16(0, profile) == Q
    for table in profile["tables"].values():
        assert float(table["coefficient_rounding_slack_raw_lower_bound"]) > 1e-5
        assert all(abs(c) < 2**31 for row in table["coefficients_c_b_a_q16"] for c in row)
        # Universal interval bounds, not a sampled argument: 0<=t<=step.
        step = table["step_q16"]
        for c, b, a in table["coefficients_c_b_a_q16"]:
            first = abs(a)*step
            second = (abs(b)+(first+Q-1)//Q)*step
            result = abs(c)+(second+Q-1)//Q
            assert max(first, second, result) < 2**31
    regression = {}
    if dense:
        functions = {"exp": math.exp, "log": math.log,
                     "softminus": lambda x: math.log1p(math.exp(-x))}
        bounds = {"exp": exp_error, "log": log_polynomial_error, "softminus": soft_error}
        for name, table in profile["tables"].items():
            lower, step = table["lower_q16"], table["step_q16"]
            # >=65537 points per domain and every breakpoint's adjacent q16
            # words, including the piece-right endpoint, are checked.
            points = set(range(lower, lower+64*step+1, max(1, step//1024)))
            for i in range(65):
                points.update(v for v in (lower+i*step-1, lower+i*step, lower+i*step+1)
                              if lower <= v <= lower+64*step)
            maximum = max(abs(piece(x, table)/Q-functions[name](x/Q)) for x in points)
            assert maximum <= float(bounds[name])
            regression[name] = {"points": len(points), "max_absolute_error": maximum,
                                "analytic_error_bound": float(bounds[name])}
        points = range(Q, 8*Q+1, 7)
        maximum = max(abs(log16(x, profile)/Q-math.log(x/Q)) for x in points)
        assert maximum <= float(log_error)
        regression["normalized_log"] = {"points": len(points), "max_absolute_error": maximum,
                                         "analytic_error_bound": float(log_error)}
    # Declared utility envelope, not a universal statement for small grids or
    # small signed caps: n=10000, m=50, full signed-domain caps, g=18.
    ratios = {}
    for family, error, bound in (("multinomial", .0011, 32+math.log(8)),
                               ("ordinal", .00012, 16+2*math.log1p(math.exp(-16))+math.log(16))):
        cap = math.ceil((bound+2*error)*2**18)/2**18
        for epsilon in (1, 4, 8):
            noise_scale = 50*cap/epsilon  # add/remove Laplace coordinate scale
            ratio = 10000*error/noise_scale
            assert ratio < .06
            ratios[f"{family}_epsilon_{epsilon}"] = ratio
    return {"profile_sha256": document["profile_sha256"],
            "certificate_sha256": certificate["certificate_sha256"], "word_bits": 32,
            "fraction_bits": 16, "pieces_per_kernel": 64,
            "exp_analytic_bound": str(exp_error), "softminus_analytic_bound": str(soft_error),
            "normalized_log_analytic_bound": str(log_error),
            "multinomial_prequantization_error_bound": "0.0011",
            "ordinal_prequantization_error_bound": "0.00012", "dense_regression": regression,
            "certified_envelope_error_to_noise_ratios": ratios, "verified": True}

if __name__ == "__main__":
    print(json.dumps(verify(), sort_keys=True, indent=2))
