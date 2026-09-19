# GEE composition integration — certified arithmetic predecessor

The v3 private whitening-factor producer is implemented and registered through
`groupedGEERegistry().ProduceFactors`. It validates complete f100 predictors,
f50 features, integer outcomes and live bits at full Ring192 width; invokes
the pinned certified scalar profiles; constructs correlation-dependent private
whitening; uses dealer-free exact OT for factor products; and returns freshly
masked q64 factors, q32 cluster likelihood, private validity, a numeric
certificate and the contract/profile/spec-bound schedule digest.

Exchangeable whitening selects coefficients using the SECRET live count. AR1
innovations preserve ORIGINAL slot distances across missingness. No count,
predecessor, working matrix or factor is opened. The existing MomentOperands,
MomentSums, MomentBoundary, MeatOperands and MeatFinal remain the downstream
likelihood+bread+clipped-meat composition; this is not a GLM wrapper.
`LegacyCompile` remains the old q16 inverse-matrix prototype and is not the
new profile's evaluator.

`NUMERIC_CERTIFICATE_GEE_WHITENING.md` gives the exact coefficient enclosure,
scalar/input/feature/whitening error propagation and signed range proof.
The mirrored R contracts bind `grouped-gee-whitening-f96-q64-v3`, the retained
scalar hash, and explicit per-coordinate error bounds. They no longer use the
provisional GEE error=1. Likelihood must use the signed PER-CLUSTER cap through
`groupedGEELikelihoodCompile`, never a sum of prototype row caps.

## Pod verification, 2026-09-19

- Encrypted two-authority factor producer: binomial/Poisson crossed with
  independence/exchangeable/AR1, all six PASS. Outputs compose with the retained
  moment/meat boundaries and equal the new integer oracle. Three-slot/one-
  predictor producer probes use9.36--9.95MB and2.1--2.8s; NOT release envelopes.
- All four-slot live patterns at every admitted rho: W'W agrees with an
  independently inverted real covariance, including AR1 missingness gaps.
- Wrapped input/output shares, invalid full-width inputs and validity,
  maximum B8/p3/g18 compilation and rational root enclosure checks: PASS.
- New and legacy focused GEE Go tests: PASS,35.099s.
- Paired focused R contracts, independent pure-R integer assembly, old retained
  scalar/legacy oracles, real covariance-solve error comparisons, and exact
  client/server certificate agreement:432 assertions PASS, no skips/errors.
  Root workspace evidence: `integrator-evidence/resume-20260919/gee-*.log`.

## Still required before promotion

The producer is an INTERNAL arithmetic component, not a release RPC. Its input
must be bound to authenticated complete predictors and once-only grouping.
The fused scheduler still must persist and replay each stage with authenticated
receipts, bind factorial/live/profile state, propagate returned validity into
EVERY likelihood/bread/meat terminal boundary, map signed caps, and feed the
existing two-authority DP lifecycle. The component schedule digest is not a
substitute for durable receipts or a completed authenticated server release.

Production dispatch stays disabled. No grouped release capacity is admitted.
The prior27 Addendum4 public-shape rejections were preflights, not measurements.
All families remain subject to the binding256GB/6h uniform gate (revision2) (admitted capacity if
needed), real n2000 K2/K3/K5 releases, cold/replay/recovery/tamper evidence and
a green paired suite. No GEE family is promoted by these arithmetic results.
