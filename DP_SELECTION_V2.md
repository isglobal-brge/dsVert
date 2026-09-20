# Layer 3 — DP selection

PASS. The complete n2000/p6 (3/3 owners), delta=2^-100 matrix contains
120 distinct signed two-candidate grids: twenty per family and epsilon in
{1,4,8}. Twelve releases, two per cell, execute the real two-authority route
through the DataSHIELD client API on isolated DSLite peers. Each matches the
complete integer production-noise oracle vector and selected candidate, and
passes the fresh-process exactly-once/replay/tamper checks.

See [LAYER3_V2.md](LAYER3_V2.md) for the generated six-cell agreement/loss-gap
table and all twelve measured API times. The final summarizer validates
geometry, instance order, two real plus eighteen oracle-only records per
cell, unique artifact keys, required verification markers and exactly matching
before/after helper checks. No interrupted or failed earlier attempt counts.

Reproduce the evidence summary from dsVert:

```sh
python3 inst/cross-grid-v2/summarize_validation.py inst/cross-grid-v2 LAYER3_V2.md
```

Complete source logs are `inst/cross-grid-v2/validation-{family}-e{epsilon}.log`
and their matching `-source-check.log` files. `validation-support.sha256` pins
the unchanged three harness helpers. The archived per-release prefixes retain
intermediate provenance; the six complete logs are authoritative.

Gaps compare the selected candidate's noise-free certified integer objective
with the finite-grid best, divided by 2^16. Report precision comes from the
harness JSON. These synthetic two-candidate statistics do not establish
continuous-MLE accuracy or utility for all admitted grids. Additional K3/K5
topology gates and package-check findings remain separate.
