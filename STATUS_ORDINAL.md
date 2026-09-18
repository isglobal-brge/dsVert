# Ordinal cross-owner grid status

## Retained work and Day-1 arithmetic amendment (2026-09-18)

This work continues branch `feature/famB`, server base `4d7e6ae` and client
base `cb26ecd`. The earlier ordinal family files were uncommitted. No prior
ordinal status/decision file or V1 status file is present; the retained
contracts, stable cumulative-logit identity, signed threshold restrictions,
references and tests are being adapted in place.

The binding `../DECISION_DAY1_ARITHMETIC_ROUTE.md` replaces the protected
q64 nonlinear evaluator with a certified low-precision piecewise-polynomial
profile. The f50 input/coefficient ABI, exact f100 dot product, zero intercept,
slope L1<=8, threshold magnitude<=8 and signed threshold gap>=1/16 remain.
These public restrictions keep every category probability strictly positive.

Milestones:

1. Preserve the stable ordinal loss decomposition and authentication boundaries.
2. Retarget its log-sigmoid components and integer oracles, extending the error
   certificate and conservative integer sensitivity caps.
3. Validate boundaries, finite-probability floor, two-peer DSLite reference
   selection against `MASS::polr`, and both R packages.
4. Record measured circuit cost and exact remaining integration gates.

The pod endpoint is empty, so available local R/Go tools are used. Production
release remains disabled. No push or thesis change is performed. Commands,
test counts, measured gates and commits will be appended after execution;
the milestone list alone makes no completion claim.
