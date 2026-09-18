#!/usr/bin/env python3
"""Reproduce the V1 interval coefficient certificate (mpmath 1.3.0).

All transcendental coefficient computations use outward interval arithmetic.
Sampling is not used to establish either uniform approximation bound.
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


def interval_integer(value):
    """Nearest-even midpoint plus an outward proof of < one coefficient ulp."""
    lo, hi = mp.mpf(value.a), mp.mpf(value.b)
    integer = int(mp.nint((lo + hi) * Q / 2))
    assert int(mp.nint(lo * Q)) == integer == int(mp.nint(hi * Q))
    assert max(abs(lo - mp.mpf(integer) / Q), abs(hi - mp.mpf(integer) / Q)) < mp.mpf(1) / Q
    return str(integer)


def coefficients(degree, family):
    count = degree + 1
    angles = [mp.iv.pi * (2 * j + 1) / (2 * count) for j in range(count)]
    nodes = [mp.iv.cos(t) for t in angles]
    values = [(mp.iv.log(1 + mp.iv.exp(17 * t)) if family == "binomial"
               else mp.iv.exp(17 * t / 4)) for t in nodes]
    result = []
    for k in range(count):
        value = sum(values[j] * mp.iv.cos(k * angles[j]) for j in range(count)) * 2 / count
        if k == 0:
            value /= 2
        result.append(interval_integer(value))
    return result


def round_div(numerator, denominator):
    sign = -1 if numerator < 0 else 1
    quotient, remainder = divmod(abs(numerator), denominator)
    if 2 * remainder > denominator or (2 * remainder == denominator and quotient % 2):
        quotient += 1
    return sign * quotient


def clenshaw(eta, coeff):
    t = round_div(eta, 17)
    b1 = b2 = 0
    for c in reversed(coeff[1:]):
        b1, b2 = int(c) + round_div(2 * t * b1, Q) - b2, b1
    return int(coeff[0]) + round_div(t * b1, Q) - b2


def batch(case, profile):
    sums = []
    for beta, cap in zip(case["beta_encoded"], case["caps"]):
        total = 0
        for x, y, valid in zip(case["features_encoded"], case["outcomes"], case["validity"]):
            eta = round_div(int(beta[0]) * (1 << 50) + sum(int(b) * v for b, v in zip(beta[1:], x)), 1 << 36)
            if case["family"] == "binomial":
                # Binary y*eta is a mux; no private multiplication is specified.
                loss = clenshaw(eta, profile["softplus_coefficients_q64"]) - (eta if y == 1 else 0)
            else:
                value = clenshaw(eta, profile["exp_quarter_coefficients_q64"])
                value = round_div(value * value, Q)
                value = round_div(value * value, Q)
                loss = value - y * eta + int(profile["log_factorial_q64"][y])
            masked = loss if all(valid) else 0
            capped = max(0, min(masked, cap << (64 - case["g"])))
            total += round_div(capped, 1 << (64 - case["g"]))
        sums.append(total)
    return sums


def build():
    # Independently verify the *published* upper bounds using exact rationals.
    # Floating decimal strings below report the tighter formula evaluations;
    # they are not relied upon for an outward rounding argument.
    ru = Fraction(1, Q)
    reta = 33 * Fraction(1, 2**51) + 16 * Fraction(1, 2**102) + ru / 2
    rsoft = 4 * 32 * Fraction(10, 11)**256 * 10
    rsoft_eval = 256**2 * 18 * ru / 2 + Fraction(3, 2) * 257 * ru
    rexp = Fraction(4 * 10000, 3 * 4**32)
    rexp_eval = 32**2 * 71 * ru / 2 + Fraction(3, 2) * 33 * ru
    rsquare1 = 2 * 71 * (rexp + rexp_eval) + (rexp + rexp_eval)**2 + ru / 2
    rsquare2 = 2 * 71**2 * rsquare1 + rsquare1**2 + ru / 2
    reta_interval = mp.iv.mpf(reta.numerator) / reta.denominator
    assert mp.iv.exp(16 + reta_interval) < 8886111
    assert reta + rsoft + rsoft_eval < Fraction("0.00000003242")
    assert (8886111 + 1024) * reta + rsquare2 + ru < Fraction("0.0000001342")
    assert max(Fraction("0.00000003242"), Fraction("0.0000001342")) < Fraction(1, 2**20)
    assert mp.iv.exp(mp.iv.mpf(289) / 32) < 10000
    profile = {
        "identity": "cross-grid-chebyshev-q64-softplus256-exp32-v1",
        "input_fraction_bits": 50,
        "coefficient_fraction_bits": 50,
        "nonlinear_fraction_bits": 64,
        "arithmetic_width_bits": 192,
        "polynomial_basis": "chebyshev_first_kind",
        "polynomial_domain": [-17, 17],
        "argument_divisor": 17,
        "softplus_degree": 256,
        "exp_quarter_degree": 32,
        "exp_squarings": 2,
        "rounding": "nearest_ties_to_even",
        "evaluation_order": "dot_exact_f100_to_q64;eta_div17_q64;binomial_softplus_clenshaw256_then_binary_outcome_mux;poisson_exp_quarter_clenshaw32_then_square_then_square_then_integer_outcome_product_then_private_log_factorial_lookup;validity_mux;clamp_q64;quantize_g;sums",
        "softplus_coefficients_q64": coefficients(256, "binomial"),
        "exp_quarter_coefficients_q64": coefficients(32, "poisson"),
        "log_factorial_q64": [interval_integer(sum(mp.iv.log(k) for k in range(1, y + 1))) if y else "0" for y in range(1025)],
    }
    digest = hashlib.sha256(canonical(profile).encode()).hexdigest()
    eps = mp.mpf(1) / Q
    eta_error = 33 * mp.mpf(2) ** -51 + 16 * mp.mpf(2) ** -100 / 4 + eps / 2
    soft_poly = 4 * 32 * (mp.mpf(11) / 10) ** -256 / (mp.mpf(11) / 10 - 1)
    exp_poly = 4 * 10000 * mp.mpf(4) ** -32 / 3
    # Markov's inequality bounds input rounding; Clenshaw recurrence errors
    # are additive coefficient perturbations, since |T_k(t)| <= 1.
    soft_eval = 256 ** 2 * 18 * eps / 2 + 257 * mp.mpf("1.5") * eps
    exp_eval = 32 ** 2 * 71 * eps / 2 + 33 * mp.mpf("1.5") * eps
    core_error = exp_poly + exp_eval
    square1 = 2 * 71 * core_error + core_error ** 2 + eps / 2
    square2 = 2 * 71 ** 2 * square1 + square1 ** 2 + eps / 2
    binomial_error = eta_error + soft_poly + soft_eval
    poisson_error = (mp.exp(16 + eta_error) + 1024) * eta_error + square2 + eps
    assert binomial_error < mp.mpf("3.242e-8")
    assert poisson_error < mp.mpf("1.342e-7")
    assert max(binomial_error, poisson_error) < mp.mpf(2) ** -20
    bounds = {
        "source_feature_abs_lt_pow2": 51,
        "public_beta_abs_lt_pow2": 54,
        "dot_raw_abs_lt_pow2": 105,
        "eta_q64_abs_lt_pow2": 69,
        "clenshaw_state_abs_lt_pow2": 89,
        "clenshaw_raw_product_abs_lt_pow2": 155,
        "exp_square_raw_abs_lt_pow2": 155,
        "loss_q64_abs_lt_pow2": 90,
        "released_integer_max": "9007199254740991",
    }
    contracts = {}
    for family, bound in [("binomial", "0.00000003242"), ("poisson", "0.0000001342")]:
        contracts[family] = {
            "version": "cross-grid-public-numeric-contract-v1",
            "profile_identity": profile["identity"],
            "profile_sha256": digest,
            "input_fraction_bits": 50,
            "coefficient_fraction_bits": 50,
            "coefficient_encoding": "signed_decimal_integer_v1",
            "nonlinear_fraction_bits": 64,
            "arithmetic_width_bits": 192,
            "output_grid_bits_range": [8, 18],
            "predictor_count_range": [1, 16],
            "max_coefficient_absolute": 8,
            "max_coefficient_l1": 16,
            "max_outcome": 1 if family == "binomial" else 1024,
            "eta_domain": [-17, 17],
            "rounding_rule": "nearest_ties_to_even",
            "evaluation_order": profile["evaluation_order"],
            "per_operation_bounds": bounds,
            "certified_uniform_error": bound,
            "certified_eta_error": "0.000000000000014655",
        }
    cases = []
    for family in ["binomial", "poisson"]:
        case = {
            "family": family,
            "g": 18,
            "features_encoded": [[0, 0], [1 << 50, 1 << 50], [1 << 49, 1 << 49], [1 << 48, 3 << 48]],
            "outcomes": [0, 1, 1, 0] if family == "binomial" else [0, 1024, 3, 17],
            "validity": [[1, 1, 1], [1, 1, 1], [1, 0, 1], [1, 1, 1]],
            "beta_encoded": [[str(v * (1 << 50)) for v in b] for b in [[8, 8, 0], [-8, -8, 0], [0, 1, -1]]],
            "caps": ([4194305, 4194305, 344272] if family == "binomial" else [2329449266180, 5883021575, 1593614334]),
        }
        # Caps in the reference fixture are explicit public saturation limits;
        # sensitivity builders derive their own caps from signed beta and M.
        case["expected_sums"] = batch(case, profile)
        cases.append(case)
    result = {
        "version": "cross-grid-numeric-profile-fixture-v1",
        "profile": profile,
        "profile_sha256": digest,
        "numeric_contract": contracts,
        "certificate": {
            "method": "outward_interval_DCT_coefficients_and_analytic_Bernstein_ellipse_remainder",
            "generator_dependency": "mpmath==1.3.0",
            "interval_decimal_precision": 90,
            "coefficient_absolute_error_max": "2^-64",
            "softplus_ellipse_rho": "11/10",
            "softplus_ellipse_modulus_bound": "32",
            "exp_ellipse_rho": "4",
            "exp_ellipse_modulus_bound": "10000",
            "eta_error_bound": mp.nstr(eta_error, 50),
            "softplus_polynomial_uniform_error": mp.nstr(soft_poly, 50),
            "exp_core_polynomial_uniform_error": mp.nstr(exp_poly, 50),
            "softplus_evaluation_error": mp.nstr(soft_eval, 50),
            "exp_core_evaluation_error": mp.nstr(exp_eval, 50),
            "exp_after_squarings_error": mp.nstr(square2, 50),
            "binomial_loss_error": mp.nstr(binomial_error, 50),
            "poisson_loss_error": mp.nstr(poisson_error, 50),
            "tightest_acceptance_target": "0.00000095367431640625",
            "bounds": bounds,
        },
        "reference_cases": cases,
    }
    certificate_hash = hashlib.sha256(canonical(result["certificate"]).encode()).hexdigest()
    result["certificate_sha256"] = certificate_hash
    for contract in result["numeric_contract"].values():
        contract["certificate_sha256"] = certificate_hash
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = (json.dumps(build(), indent=2, sort_keys=True) + "\n").encode()
    if args.check:
        assert args.output.read_bytes() == data, "numeric fixture differs"
    else:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_bytes(data)
