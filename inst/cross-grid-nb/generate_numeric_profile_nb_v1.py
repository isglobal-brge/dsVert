#!/usr/bin/env python3
"""NB2 certified q16 piecewise-profile certificate and synthetic integer fixtures; mpmath==1.3.0.

All transcendental constants use outward intervals. The error proof is uniform,
not inferred from the synthetic fixtures. No protected records are inputs.
"""
import argparse
import hashlib
import json
from fractions import Fraction
from pathlib import Path
import mpmath as mp

mp.mp.dps = 100
mp.iv.dps = 90
Q = 1 << 64


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def integer(value):
    lo, hi = mp.mpf(value.a), mp.mpf(value.b)
    result = int(mp.nint((lo + hi) * Q / 2))
    assert int(mp.nint(lo * Q)) == result == int(mp.nint(hi * Q))
    assert max(abs(lo - mp.mpf(result) / Q), abs(hi - mp.mpf(result) / Q)) < mp.mpf(1) / Q
    return str(result)


def round_div(n, d):
    q, r = divmod(abs(n), d)
    if 2*r > d or (2*r == d and q % 2):
        q += 1
    return -q if n < 0 else q


def profile_softplus(z, profile):
    x = round_div(z, 1 << 48)
    absolute = abs(x)
    residual = 0
    if absolute < 16 * (1 << 16):
        segment = absolute >> 14
        r = absolute & ((1 << 14) - 1)
        a, b, c = map(int, profile["softplus_quadratic_q16"][segment])
        residual = a + round_div((b + round_div(c*r, 1 << 16))*r, 1 << 16)
    return max(x, 0) + residual


def loss(eta, y, valid, exponent, g, cap, profile):
    theta = profile["theta"][exponent + 3]
    soft = profile_softplus(eta - int(theta["log_theta_q64"]), profile) << 48
    value = int(theta["constant_q64"][y]) + round_div((8*y + theta["theta_times_eight"])*soft, 8) - y*eta
    value = max(0, min(value if valid else 0, cap << (64-g)))
    return round_div(value, 1 << (64-g))


def build():
    coeff = []
    h = mp.iv.mpf(1)/4
    for j in range(64):
        values = [mp.iv.log(1+mp.iv.exp(-(j*h+k*h/2))) for k in range(3)]
        a, m, e = values
        coeff.append([integer(v/2**48) for v in [a, (-3*a+4*m-e)/h, (2*a-4*m+2*e)/(h*h)]])
    for a, b, c in coeff:
        assert 0 <= int(a) < 2**16 and 0 <= -int(b) < 2**15 and 0 <= int(c) < 2**13
        # Signed Horner can use unsigned magnitude products with identical ties.
        for r in (0, 16383):
            assert 0 <= -int(b)-round_div(int(c)*r, 65536) < 2**15
    theta = []
    for exponent in range(-3, 8):
        th = mp.iv.mpf(2)**exponent
        log_th = exponent*mp.iv.ln(2)
        # C(theta,y)=log(y!)-sum_{k=0}^{y-1}log(theta+k)+y log(theta).
        # The recurrence avoids cancellation of independent gamma intervals.
        constants = ["0"]
        current = mp.iv.mpf(0)
        for y in range(1, 1025):
            current += mp.iv.ln(y)-mp.iv.ln(th+y-1)+log_th
            constants.append(integer(current))
        theta.append({"exponent": exponent, "theta_times_eight": 1 << (exponent+3),
                      "log_theta_q64": integer(log_th), "constant_q64": constants})
    profile = {
        "identity": "cross-grid-nb2-softplus-pwq64-q16-domain22-v1",
        "softplus_profile_identity": "cross-grid-softplus-pwq64-q16-symmetric-tail16-v1",
        "input_fraction_bits": 50, "coefficient_fraction_bits": 50,
        "nonlinear_fraction_bits": 16, "arithmetic_width_bits": 32,
        "source_eta_fraction_bits": 64, "loss_accumulator_fraction_bits": 64,
        "polynomial_basis": "local_power", "polynomial_domain": [-22, 22],
        "softplus_pieces": 64, "softplus_degree": 2,
        "piece_width_q16": 16384, "residual_tail_start_q16": 1048576,
        "softplus_breakpoints_q16": [str(j*16384) for j in range(65)],
        "theta_exponent_range": [-3, 7], "max_outcome": 1024,
        "rounding": "nearest_ties_to_even",
        "evaluation_order": "dot_exact_f100_to_q64;subtract_log_theta_q64;round_q16;abs_and_piece_select;quadratic_horner_two_rounded_products_q16;add_positive_part;promote_q64;private_y_theta_constant_lookup;times_8y_plus_8theta_div8;subtract_y_eta;validity_mux;clamp_q64;quantize_g;sums",
        "softplus_quadratic_q16": coeff, "theta": theta,
    }
    u = Fraction(1, 2**16)
    eta_error = 33*Fraction(1, 2**51)+16*Fraction(1, 2**102)+Fraction(1, 2**65)
    interpolation = Fraction(1, 64*1296)
    evaluation = Fraction(57, 32)*u
    # The exp(-16) tail bound is verified by outward interval arithmetic;
    # adding it instead of taking max() is a conservative global bound.
    assert mp.iv.exp(-16) < mp.iv.mpf("0.000000113")
    softplus_error = interpolation + evaluation + Fraction("0.000000113")
    assert softplus_error + Fraction(1, 2**64) < Fraction("0.00003936")
    error = 1024*eta_error + 1152*Fraction("0.00003936") + Fraction(1, 2**63)
    assert error < Fraction("0.045343")
    bounds = {"source_feature_abs_lt_pow2": 51, "public_beta_abs_lt_pow2": 54,
              "dot_raw_abs_lt_pow2": 105, "eta_q64_abs_lt_pow2": 69,
              "profile_input_q16_abs_lt_pow2": 21, "profile_coefficient_q16_abs_lt_pow2": 16,
              "profile_local_q16_abs_lt_pow2": 14, "profile_raw_product_abs_lt_pow2": 30,
              "profile_result_q16_abs_lt_pow2": 21,
              "loss_q64_abs_lt_pow2": 80, "released_integer_max": "9007199254740991"}
    certificate = {
        "method": "outward_interval_quadratic_interpolation_with_analytic_third_derivative_and_rounding_bounds",
        "generator_dependency": "mpmath==1.3.0", "interval_decimal_precision": 90,
        "coefficient_absolute_error_max": "2^-17", "third_derivative_absolute_bound": "1/(6*sqrt(3))",
        "interpolation_error_upper": "1/82944", "profile_rounding_error_upper": "57/(32*65536)",
        "tail_error_upper": "0.000000113",
        "eta_error_bound": "0.000000000000014655", "softplus_profile_error_upper": "0.00003936",
        "loss_error_formula": "(y_max+theta)*0.00003936+1024*0.000000000000014655+2^-63",
        "certified_uniform_error": "0.045343",
        "profile_multiplications": 2, "profile_word_bits": 32,
        "cost_target_and_gates": 2000, "cost_target_verified": False,
        "bounds": bounds,
    }
    profile_sha = hashlib.sha256(canonical(profile).encode()).hexdigest()
    cert_sha = hashlib.sha256(canonical(certificate).encode()).hexdigest()
    contract = {
        "version": "cross-grid-nb-public-numeric-contract-v1", "profile_identity": profile["identity"],
        "profile_sha256": profile_sha, "certificate_sha256": cert_sha,
        "input_fraction_bits": 50, "coefficient_fraction_bits": 50, "coefficient_encoding": "signed_decimal_integer_v1",
        "nonlinear_fraction_bits": 16, "arithmetic_width_bits": 32, "output_grid_bits_range": [8, 18],
        "source_eta_fraction_bits": 64, "loss_accumulator_fraction_bits": 64,
        "predictor_count_range": [1, 16], "max_coefficient_absolute": 8, "max_coefficient_l1": 16,
        "max_outcome": 1024, "eta_domain": [-17, 17], "shifted_eta_domain": [-22, 22],
        "theta_exponent_range": [-3, 7], "rounding_rule": "nearest_ties_to_even",
        "evaluation_order": profile["evaluation_order"], "per_operation_bounds": bounds,
        "certified_uniform_error": certificate["certified_uniform_error"],
        "certified_eta_error": certificate["eta_error_bound"],
        "softplus_profile_error_upper": certificate["softplus_profile_error_upper"],
        "loss_error_formula": certificate["loss_error_formula"],
    }
    cases = []
    for exponent in [-3, 0, 1, 7]:
        for eta, y, valid, g, cap in [(-16*Q-270000, 1024, True, 18, 9007199254740991),
                                    (16*Q+270000, 0, True, 18, 9007199254740991),
                                    (0, 1, True, 18, 9007199254740991),
                                    (-Q, 17, False, 8, 1000),
                                    (Q, 1024, True, 18, 7)]:
            cases.append({"eta_q64": str(eta), "outcome": y, "valid": valid, "theta_exponent": exponent,
                          "g": g, "cap": cap, "expected": loss(eta, y, valid, exponent, g, cap, profile)})
    return {"version": "cross-grid-nb-numeric-profile-fixture-v1", "profile": profile,
            "profile_sha256": profile_sha, "certificate": certificate, "certificate_sha256": cert_sha,
            "numeric_contract": contract, "reference_cases": cases}


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = (json.dumps(build(), sort_keys=True, indent=2)+"\n").encode()
    if args.check:
        assert args.output.read_bytes() == data, "numeric profile differs"
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(data)
