#!/usr/bin/env python3
"""Reproduce public family-B q16 tables; protected rows never enter this tool."""
from decimal import Decimal, ROUND_HALF_EVEN, localcontext
from pathlib import Path
import hashlib
import json
import math

ROOT = Path(__file__).resolve().parent
Q = 65536

def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()

def make_profile():
    with localcontext() as ctx:
        ctx.prec = 90
        one = Decimal(1)
        tables = {}
        for name, lower, step, function in (
            ("exp", -16, Decimal(1)/4, lambda x: x.exp()),
            ("log", 1, Decimal(1)/64, lambda x: x.ln()),
            ("softminus", 0, Decimal(1)/4, lambda x: (one + (-x).exp()).ln()),
        ):
            coefficients = []
            minimum_rounding_slack = one
            for i in range(64):
                left = Decimal(lower) + i*step
                f0, fm, f1 = (function(left + t*step) for t in (0, Decimal("0.5"), 1))
                raw = (f0, (-3*f0 + 4*fm - f1)/step, 2*(f0 - 2*fm + f1)/(step*step))
                rounded = [int((x*Q).to_integral_value(rounding=ROUND_HALF_EVEN)) for x in raw]
                minimum_rounding_slack = min(minimum_rounding_slack,
                    *(Decimal("0.5")-abs(x*Q-y) for x, y in zip(raw, rounded)))
                coefficients.append(rounded)
            tables[name] = {"lower_q16": lower*Q, "step_q16": int(step*Q),
                "pieces": 64, "coefficients_c_b_a_q16": coefficients,
                "coefficient_rounding_slack_raw_lower_bound": str(minimum_rounding_slack.quantize(Decimal("0.000000000001"), rounding="ROUND_FLOOR"))}
        profile = {"version": "cross-grid-family-b-piecewise-q16-v1", "word_bits": 32,
            "fraction_bits": 16, "rounding": "nearest_ties_even",
            "coefficient_order": ["constant", "linear", "quadratic"],
            "evaluation": "c + round_even(t * (b + round_even(a*t/65536))/65536)",
            "log2_q16": 45426, "exp_below_minus16": "zero", "exp_at_zero_q16": 65536, "tables": tables,
            "multinomial_prequantization_error_bound": "0.0011",
            "ordinal_prequantization_error_bound": "0.00012",
            "output_error": "0 if grid_bits>=16 else 2^(-grid_bits-1)",
            "public_gap_profile": "exp32-log24-q64-public-thresholds-only"}
        return {"profile": profile, "profile_sha256": hashlib.sha256(canonical(profile)).hexdigest()}

def make_certificate(document):
    certificate = {
        "version": "cross-grid-family-b-piecewise-certificate-v1",
        "profile_sha256": document["profile_sha256"],
        "word_bits": 32, "fraction_bits": 16, "pieces_per_kernel": 64,
        "interpolation": "sup_abs_third_derivative*h^3/(72*sqrt(3))",
        "horner_and_coefficient_rounding": "2^-17*(2+2*h+h^2)",
        "exp_error_bound_rational": "47233/320864256",
        "softminus_error_bound_rational": "5369/169869312",
        "normalized_log_error_bound_rational": "496102395623/10766335717933056",
        "public_gap_q64_error_bound": "0.00000014",
        "frozen_encoding_error_allowance": "0.000000000001",
        "multinomial_prequantization_error_bound": "0.0011",
        "ordinal_prequantization_error_bound": "0.00012",
        "output_rounding_error": "0 if grid_bits>=16 else 2^(-grid_bits-1)",
        "cap_rule": "ceil(2^g*(exact_loss_bound+2*prequantization_error+output_rounding_error))",
        "domain": {"class_count_min": 2, "class_count_max": 8,
                   "multinomial_class_l1_max": 16, "ordinal_beta_l1_max": 8,
                   "ordinal_threshold_abs_max": 8, "ordinal_gap_min": "1/16"},
        "certified_utility_envelope": {"rows": 10000, "candidates": 50,
            "grid_bits": 18, "epsilon": [1, 4, 8],
            "multinomial_classes": 8, "multinomial_A": 16,
            "ordinal_T": 16, "ordinal_gap": "1/16",
            "maximum_error_to_laplace_scale_ratio": "0.06"}}
    return {"certificate": certificate,
            "certificate_sha256": hashlib.sha256(canonical(certificate)).hexdigest()}

if __name__ == "__main__":
    result = make_profile()
    target = ROOT / "piecewise_profile_v1.json"
    target.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    certificate = make_certificate(result)
    (ROOT / "piecewise_certificate_v1.json").write_text(json.dumps(certificate, indent=2, sort_keys=True) + "\n")
    print(result["profile_sha256"])
    print(certificate["certificate_sha256"])
