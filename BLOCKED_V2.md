# RESOLVED — reviewer Addendum 5

The reviewer retained n=10000, p=10, grid=50 and the current fused design,
and revised the gate to <=110 GB measured two-direction traffic and <=4 h
on the pod with candidate-parallel batches. The question below is answered.
No current external blocker is claimed. Historical evidence follows.

# Blocked V2 — the complete fused route fails the binding resource gate

## Precise reviewer question

Should the next implementation retain **n=10000, p=10, grid=50 and <=60 GB**
and replace this all-Boolean source/loss design with a materially cheaper
certified arithmetic/transport design, or is a revised public workload/traffic
envelope acceptable? A smaller grid or a larger byte ceiling would change the
requested acceptance contract and must not be silently substituted.

The current implementation cannot be promoted under Addendum 3's binding
resource limits. This is a failed engineering/resource gate, not a pod-layout,
tooling, API-quota or missing-credential problem. It is **not** a proof that
no other architecture can meet the limits; that replacement is not delivered.

## Evidence

Implementation commit `2771a99` supplies an internal fused integer producer
and real two-authority kernel-to-joint-noise tests. The final benchmark uses
certified A=4 caps and distinct candidates with exact coefficient L1=4, p=10,
32-row/8-candidate batches, the fixed f50 source and exact f100 predictor.

| Family | AND / batch | Measured aggregate encrypted bytes / batch | Pod batch time |
|---|---:|---:|---:|
| Binomial | 1,076,415 | 42,404,496 | 7.319170999 s |
| Poisson | 1,399,391 | 52,745,381 | 7.605694722 s |

The full-size frozen traversal contains 1,872 complete batches, before tails.
Each AND requires two 128-bit table labels. Those complete batches alone need:

- Binomial: **64,481,564,160 bytes**, already above 60 GB.
- Poisson: **83,829,118,464 bytes**, already above 60 GB.

These are exact table-payload lower bounds derived from compiled gate counts,
not measured full-release traffic. They exclude OT, source/input transfer,
encrypted framing, partial batches, joint noise and release authentication.
Measured batch-byte extrapolations are higher: 82.821 / 103.018 GB. Poisson's
complete kernel also uses 5466.371 AND/evaluation, above the 5000 comparison;
its previously accepted nonlinear-only component omitted mandatory work.

Raw matching gate/byte measurements are in
`inst/cross-grid-v2/fused-bench-{mac,pod}.log`; calculations and reproduction
are in `BENCH_V2.md`. The pod run completed with `FUSED_POD_DONE`. No whole
n=2000/n=10000 release or 30-minute elapsed-time result is claimed.

## What is and is not a reduction

Scheduling the same 50 candidates in additional small batches cannot remove
these tables. Parallelism changes elapsed time, not total bytes. A genuinely
smaller signed candidate set preserves the arithmetic error certificate but
changes the search problem. Grid=16 gives batch-byte projections of about
26.503 / 32.966 GB before the remaining release work; this is not a measured
full-release pass and does not fix Poisson's full-kernel AND count. No fallback
is claimed to pass both original gates. Coarser profiles, shared validation
across candidate batches, or an arithmetic-share backend require additional
proof/implementation and measurement; none is silently installed here.

## Consequence

The production allowlists remain closed. Signed new-profile admission,
materialization, durable sticky/exactly-once lifecycle, client acceptance,
120 oracle selections, 12 DSLite releases, full suites and R CMD check remain
unfinished. The passing integer/protocol tests do not authorize any of those
claims. STATUS_V2 records the exact remaining work and commits.
