#!/usr/bin/env python3
"""Reproduce Cox's Day-1 piecewise-linear profile with outward intervals.

Requires mpmath 1.3.0. Integer knots are certified by interval endpoints;
uniform error bounds use analytic interpolation remainders, not sampling.
"""
import argparse
import hashlib
import json
from fractions import Fraction
from pathlib import Path

import mpmath as mp

mp.mp.dps = 110
mp.iv.dps = 100
Q = 1 << 20


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


def knot(value):
    lo, hi = mp.mpf(value.a), mp.mpf(value.b)
    integer = int(mp.nint((lo + hi) * Q / 2))
    assert int(mp.nint(lo * Q)) == integer == int(mp.nint(hi * Q))
    assert max(abs(lo * Q - integer), abs(hi * Q - integer)) <= mp.mpf("0.5")
    return integer


def exp_profile(eta, knots):
    if eta == 8 * (1 << 16):
        return knots[-1]
    index, offset = divmod(eta + 8 * (1 << 16), 1 << 14)
    return knots[index] + (knots[index + 1] - knots[index]) * offset // (1 << 14)


def log_profile(risk, knots, ln2):
    exponent = risk.bit_length() - 21
    mantissa = risk >> exponent if exponent >= 0 else risk << -exponent
    index, offset = divmod(mantissa - Q, 1 << 14)
    return knots[index] + (knots[index + 1] - knots[index]) * offset // (1 << 14) + exponent * ln2


def build():
    exp_knots = [knot(mp.iv.exp(-8 + mp.iv.mpf(i) / 4)) for i in range(65)]
    log_knots = [knot(mp.iv.log(1 + mp.iv.mpf(i) / 64)) for i in range(65)]
    ln2 = knot(mp.iv.log(2))
    # For h=1/4: relative interpolation error <= exp(h)*h^2/8.
    # The convex combination of rounded endpoints contributes <= half an
    # output ulp and flooring the interpolation contributes < one ulp.
    assert mp.iv.exp(mp.iv.mpf(1) / 4) < mp.iv.mpf(1285) / 1000
    assert mp.iv.exp(8) < 2981
    rho_formula = Fraction(1285, 1000 * 128) + Fraction(3 * 2981, 2 * Q)
    rho = Fraction(144, 10000)
    assert rho_formula < rho
    # log on [1,2] has |f''|<=1. Floor normalization costs <=1/Q.
    # k lies in [-12,24]; ln2's rounded constant costs <=|k|/(2Q).
    log_formula = Fraction(1, 8 * 64**2) + Fraction(29, 2 * Q)
    log_bound = Fraction(6, 100000)
    assert log_formula < log_bound
    eta_bound = Fraction(1, 2**17) + Fraction(24, 2**51) + Fraction(16, 2**102)
    # -log(1-rho)<=rho/(1-rho); this rational bound avoids depending on
    # floating transcendental output in the published total-error proof.
    event_formula = 2 * eta_bound + rho / (1 - rho) + log_bound
    assert event_formula < Fraction(1, 64)
    assert exp_knots[0] == 352 and exp_knots[-1] == 3125761002
    assert max((b - a) * ((1 << 14) - 1) for a, b in zip(exp_knots, exp_knots[1:])) < 2**44
    assert 10000 * exp_knots[-1] < 2**45
    assert (352).bit_length() - 21 == -12
    assert (10000 * exp_knots[-1]).bit_length() - 21 == 24
    profile = {
        "identity": "cox-pwlinear64-exp-q16-q20-log-q20-v1",
        "eta_fraction_bits": 16,
        "feature_coefficient_fraction_bits": 50,
        "nonlinear_fraction_bits": 20,
        "scalar_word_bits": 32,
        "pieces": 64,
        "capacity_max": 10000,
        "predictors_max": 16,
        "eta_domain": [-8, 8],
        "coefficient_l1_max": 8,
        "eta_rounding": "nearest_ties_to_even_after_complete_f100_dot",
        "knot_rounding": "nearest_ties_to_even",
        "interpolation_rounding": "floor_nonnegative_product_div_16384",
        "exp_knots_q20": exp_knots,
        "log_knots_q20": log_knots,
        "ln2_q20": ln2,
        "exp_order": "shift_eta_q16_by_524288;piece_and_offset_divmod_16384;last_endpoint_or_base_plus_floor_difference_times_offset_div_16384",
        "log_order": "k=bitlen_risk_minus_21;mantissa=floor_risk_times_2_pow_minus_k;piece_and_offset_divmod_mantissa_minus_1048576_16384;interpolate_plus_k_times_ln2_q20",
    }
    certificate = {
        "identity": "cox-pwlinear64-certificate-v1",
        "profile_sha256": hashlib.sha256(canonical(profile).encode()).hexdigest(),
        "exp_relative_error_upper": "0.0144",
        "log_absolute_error_upper": "0.00006",
        "eta_error_upper": "2^-17+24*2^-51+16*2^-102",
        "event_error_upper": "1/64",
        "event_error_q24": 262144,
        "cohort_error_upper": "capacity/64",
        "output_error_upper": "capacity/64+2^(-g-1)",
        "exp_product_abs_lt_pow2": 44,
        "log_product_abs_lt_pow2": 28,
        "risk_sum_abs_lt_pow2": 45,
        "risk_sum_q20_min": 352,
        "risk_sum_q20_max": 10000 * exp_knots[-1],
        "log_exponent_min": -12,
        "log_exponent_max": 24,
        "nonlinear_multiplications_per_evaluation": 1,
        "public_exponent_reconstruction_products": 1,
        "scalar_operand_bits_max": 32,
        "proof": "linear interpolation second derivative remainder;convex rounded knots;floor remainder;exact risk addition;log Lipschitz;rho_over_one_minus_rho;whole_loss_nonexpansive_projection",
    }
    etas = sorted(set([-524288, -524287, -1, 0, 1, 524287, 524288] +
                      [-524288 + i * 16384 + d for i in range(1, 64) for d in (-1, 0, 1)]))
    risks = sorted(set([352, 353, Q, Q + 1, 10000 * exp_knots[-1]] +
                       [2**i + d for i in range(9, 45) for d in (-1, 0, 1)]))
    return {
        "profile": profile,
        "profile_sha256": certificate["profile_sha256"],
        "certificate": certificate,
        "certificate_sha256": hashlib.sha256(canonical(certificate).encode()).hexdigest(),
        "exp_cases": [{"eta_q16": eta, "exp_q20": exp_profile(eta, exp_knots)} for eta in etas],
        "log_cases": [{"risk_q20": risk, "log_q20": log_profile(risk, log_knots, ln2)} for risk in risks],
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("path", type=Path)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    encoded = json.dumps(build(), sort_keys=True, indent=2) + "\n"
    if args.check:
        if args.path.read_text() != encoded:
            raise SystemExit("Cox numeric profile differs")
    else:
        args.path.write_text(encoded)
    print("Cox piecewise profile interval certificate verified")


if __name__ == "__main__":
    main()
