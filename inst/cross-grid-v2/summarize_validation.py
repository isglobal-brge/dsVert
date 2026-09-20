#!/usr/bin/env python3
"""Validate complete synthetic evidence logs and emit the layer-3 report."""
import argparse
import json
from pathlib import Path
from statistics import mean

parser = argparse.ArgumentParser()
parser.add_argument("logs", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
lines = ["# Layer 3: production-seeded DP selection and real API equality", "",
         "Synthetic n=2000, p=6 (3/3 owners), two signed candidates per grid; "
         "delta=2^-100. Each cell uses 20 distinct signed grids. The first two "
         "instances also execute the actual two-authority DataSHIELD release. "
         "The harness compares independently planned production sticky seeds "
         "and sampler contracts, then the complete authenticated integer DP "
         "vector and selected candidate, before conversion to doubles.", "",
         "| Family | Epsilon | Instances | Real API equalities | Selection agreement | Mean loss gap | Maximum loss gap |",
         "|---|---:|---:|---:|---:|---:|---:|"]
all_keys = set()
api_timings = []
for family in ("binomial", "poisson"):
    for epsilon in (1, 4, 8):
        path = args.logs / f"validation-{family}-e{epsilon}.log"
        checks = args.logs / f"validation-{family}-e{epsilon}-source-check.log"
        expected_checks = [f"inst/cross-grid-v2/{name}.R: OK" for name in
                           ("validate_dslite", "prepare_oracle_noise", "validate_cold_lifecycle")]
        assert checks.read_text().splitlines() == expected_checks * 2, checks
        content = path.read_text()
        records = [json.loads(line) for line in content.splitlines()
                   if line.startswith('{"family":')]
        assert len(records) == 20, (path, "incomplete cell", len(records))
        assert [r["instance"] for r in records] == list(range(1, 21)), path
        assert all((r["family"], r["epsilon"], r["n"], r["p"], r["grid"], r["owners"])
                   == (family, epsilon, 2000, 6, 2, 2) for r in records), path
        assert [r["oracle_only"] for r in records] == [False] * 2 + [True] * 18, path
        assert content.count("DSLITE_ORACLE_BITWISE_EQUAL") == 2, path
        assert content.count("DIRECT_R_COLD_LIFECYCLE_EQUAL_TAMPER_REJECTED") == 2, path
        assert "Execution halted" not in content, path
        for record in records:
            key = record["artifact_key"]
            assert len(key) == 64 and key not in all_keys, (path, "non-independent key")
            all_keys.add(key)
            assert record["loss_gap"] >= 0, path
            if not record["oracle_only"]:
                assert len(record["certificate_sha256"]) == 64, path
                api_timings.append(f"| {family} | {epsilon} | {record['instance']} | {record['elapsed']:.3f} |")
        agreement = sum(r["selected_candidate"] == r["exact_best"] for r in records)
        gaps = [r["loss_gap"] for r in records]
        lines.append(f"| {family} | {epsilon} | 20 | 2 | {agreement}/20 | {mean(gaps):.6g} | {max(gaps):.6g} |")
lines += ["", "PASS: 120 distinct artifact keys, 120 oracle selections and 12 real "
          "API releases with bit-for-bit equality. Loss gaps are sums on the "
          "certified loss lattice divided by 2^16; selection agreement compares "
          "DP-best against the noise-free finite-grid best, with first-in-order "
          "ties. Reported gaps inherit the harness JSON's decimal precision. "
          "These small-grid statistics do not establish continuous-MLE accuracy "
          "or utility for all admitted grids.", "",
          "## Real API elapsed times", "",
          "Timing wraps `ds.vertGLM()`, including authenticated materialisation, "
          "MPC, joint noise and publication. It excludes preceding PSI/signature "
          "setup and subsequent oracle/cold-lifecycle verification.", "",
          "| Family | Epsilon | Instance | API seconds |",
          "|---|---:|---:|---:|", *api_timings, "",
          "Reproduce with `run_validation_campaign_pod.sh`, then "
          "`python3 inst/cross-grid-v2/summarize_validation.py <logs> LAYER3_V2.md`. "
          "The matrix runner checks frozen helper hashes before and after each cell.", ""]
args.output.write_text("\n".join(lines))
