# Grouped release gate blocked — revised gate, 2026-09-18

The old <=2000-AND / <=30-GB finding is VOID. The revised <=5000-AND
scalar gate PASSES after certified range reduction and safe lookup sharing.
This is a different finding: the composed cluster kernels do not fit the
reviewer's <=60-GB full-release gate under the proposed traversal.

Pod measurements count both encrypted transport directions. For each measured
public kernel, exact garbled-table bytes multiplied by the fixed number of
cluster/candidate chunks are a mandatory traffic lower bound. LMM already
requires 289.4 GB; binomial/Poisson GH5 require 442.7/603.1 GB. GEE with only
three predictors requires over 7 TB. These exclude routing, f100 predictor
formation, source records, joint noise and the release ledger. They are NOT
observed full-release totals or a claim about every conceivable implementation.
The two-direction per-chunk measurements and pod elapsed times are recorded
in BENCH_GROUPED.md and inst/grouped-validation/revised-cost.json.

The measured kernels are within the unchanged 32M-gate runner cap. Smaller
chunks cannot remove their repeated arithmetic. The current R domain is also
narrower than the required envelope (C<=64, GEE p<=3/m<=32). Enlarging a signed
domain or changing an artifact state cannot fix the measured arithmetic cost.

Production remains fail-closed. Further progress needs a different composed
workload implementation (for example, certified arithmetic-share products and
reused sufficient statistics with authenticated chunk state), then the actual
full-size measurement; increasing runner or release caps is not permitted.
The scalar emitter itself now passes and does not need another threshold reset.

Other unfinished work stays explicit: GEE bread/meat error propagation, exact
Go/R cap mapping, full-size domains, source/PSI/grouping/chunk authentication,
joint-noise injection, sticky replay and client reader wiring. The synthetic
DSLite/reference-fit comparison is not the protected production path.
