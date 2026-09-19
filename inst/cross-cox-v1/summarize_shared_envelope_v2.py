#!/usr/bin/env python3
"""Summarize completed or resource-censored PUBLIC Cox probes, never estimates."""
import argparse
import hashlib
import json
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("directory", type=Path)
parser.add_argument("output", type=Path)
args = parser.parse_args()
rows = []
missing = []
for n in (2000, 4000, 10000):
    for j in (16, 32, 50):
        path = args.directory / f"n{n}_j{j}.json"
        if not path.exists():
            missing.append([n, j])
            continue
        raw = path.read_bytes()
        report = json.loads(raw)
        if (report["capacity"], report["candidates"]) != (n, j):
            raise ValueError("public report shape mismatch")
        completed = report.get("completed", report.get("oracle_equal") is True)
        passed = (completed and report.get("oracle_equal") is True
                  and not report.get("budget_stop", False)
                  and report["total_bytes"] <= 60_000_000_000
                  and report["seconds"] <= 7200)
        rows.append(dict(capacity=n, candidates=j, completed=completed,
                         gate_pass=passed, bytes=report["total_bytes"],
                         seconds=report["seconds"],
                         report_sha256=hashlib.sha256(raw).hexdigest()))
passing = [row for row in rows if row["gate_pass"]]
# A rectangular public admission: maximize evaluated row-candidate pairs;
# if equal, prefer larger row capacity. Never admit from censored probes.
largest = max(passing, key=lambda r: (r["capacity"] * r["candidates"],
                                    r["capacity"]), default=None)
summary = dict(version="cox-measured-shared-envelope-v2", matrix_complete=not missing,
               missing=missing, rows=rows,
               selection_rule="maximum_n_times_grid_then_n",
               selected_capacity=None if missing or largest is None else
               {key: largest[key] for key in ("capacity", "candidates")},
               scope="complete family kernel; source/PSI and joint-DP fusion excluded")
args.output.write_text(json.dumps(summary, indent=2) + "\n")
