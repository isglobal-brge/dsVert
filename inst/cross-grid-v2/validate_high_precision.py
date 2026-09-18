#!/usr/bin/env python3
"""Independent 80-decimal-digit objective on public synthetic f50 fixtures."""
import json
import sys
import mpmath as mp

mp.mp.dps = 80
with open(sys.argv[1], encoding="utf-8") as handle:
    fixture = json.load(handle)
plan = fixture["Plan"]
scale = mp.mpf(2) ** 50
betas = [[mp.mpf(v) / scale for v in row] for row in plan["Beta"]]
losses = [mp.mpf(0) for _ in betas]
factorials = {y: mp.loggamma(y + 1) for y in range(plan["MaxOutcome"] + 1)}
for row in fixture["Rows"]:
    values = [mp.mpf(v) / scale for v in row[:-1]]
    y = int(row[-1])
    for j, beta in enumerate(betas):
        eta = beta[0] + mp.fsum(a * b for a, b in zip(beta[1:], values))
        losses[j] += (mp.log1p(mp.exp(eta)) - y * eta if plan["Family"] == "binomial"
                      else mp.exp(eta) - y * eta + factorials[y])
with open(sys.argv[2], "w", encoding="utf-8") as handle:
    json.dump([mp.nstr(value, 75) for value in losses], handle)
