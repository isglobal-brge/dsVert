#!/usr/bin/env python3
"""Read measured Go evidence; fail if the requested matrix is incomplete."""
import argparse
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("logs", type=Path)
parser.add_argument("platform", choices=("mac", "pod"))
parser.add_argument("output", type=Path)
args = parser.parse_args()
records = {}
interrupted = []
paths = sorted(args.logs.glob(f"matrix-{args.platform}-n*-p*-g*.log"))
if args.platform == "pod":
    paths.append(args.logs / "pod-full-n10000.log")
for path in paths:
    content = path.read_text()
    assert "--- FAIL:" not in content, (path, "failed test")
    if not content.rstrip().endswith("PASS"):
        interrupted.append(path.name)
    for line in content.splitlines():
        if "FULL_MEASUREMENT {" not in line:
            continue
        record = json.loads(line.split("FULL_MEASUREMENT ", 1)[1])
        key = tuple(record[field] for field in ("family", "n", "p", "grid"))
        assert key not in records, (path, "duplicate measurement")
        assert record["integer_and_dp_oracle_equal"] is True, path
        if key[1:] == (10000, 10, 50):
            assert record["total_wire_bytes"] <= 110_000_000_000, path
            assert record["total_seconds"] <= 4 * 60 * 60, path
        records[key] = record
expected = {(f, n, p, g) for f in ("binomial", "poisson")
            for n in (1000, 10000) for p in (5, 10) for g in (16, 50)}
assert set(records) == expected, ("missing", expected - set(records))
lines = [f"## Complete {args.platform} measured matrix", "",
         "Times include compilation, secure kernel batches and globally calibrated "
         "joint noise. Bytes are measured two-direction traffic. AND counts cover "
         "the fused kernel (including padded tails), not just the scalar profile. "
         "All integer and DP-oracle equalities pass. This Go measurement excludes "
         "DataSHIELD framing and the catalog count coordinate.", "",
         "| Family | n | p | Grid | Total seconds | Total bytes | Kernel AND | AND/evaluation | Kernel bytes/evaluation |",
         "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
for key in sorted(records):
    r = records[key]
    lines.append(f'| {r["family"]} | {r["n"]} | {r["p"]} | {r["grid"]} | '
                 f'{r["total_seconds"]:.3f} | {r["total_wire_bytes"]:,} | '
                 f'{r["kernel_and"]:,} | {r["kernel_and_per_eval"]:.3f} | '
                 f'{r["kernel_wire_bytes"] / (r["n"] * r["grid"]):.3f} |')
lines += ["", "Source logs: " + ", ".join(f"`{p.name}`" for p in paths) + ".", ""]
if interrupted:
    lines += ["Interrupted process logs retained: " + ", ".join(f"`{p}`" for p in interrupted)
              + ". Only completed FULL_MEASUREMENT records with successful integer/DP "
              "oracle checks are included; missing family results were resumed separately. "
              "Resumed pod runs use GOMEMLIMIT=6GiB/GOGC=25; the original full-envelope "
              "measurements retain their original GC settings.", ""]
args.output.write_text("\n".join(lines))
