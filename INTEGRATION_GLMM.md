# GH5 share composition integration

`registerGroupedGLMMLoss().Shares` exposes PredictorCompile, ScalarCompile,
ScoreShares, CenterCompile and FinalCompile. The original `.Compile` is the
whole-cluster prototype and must not be scheduled as the clause-5 architecture.

Required traversal after ONE authenticated primitive grouping of packed rows:
1. Form complete f100 eta on shares and run PredictorCompile with bound=1.
   It implements the frozen f100 -> q64 -> q16 sequence with private guards.
   Add each public GH node to one authority's eta share, then ScalarCompile
   evaluates softplus or range-reduced exp, with Ring192 masked outputs.
   Carry predictor validity: scalar inputs must already be certified int32
   values; the bridge's modular narrowing cannot validate high input bits.
2. The exact OT component computes live*profile once per (row,node,candidate)
   and y*eta once per (row,candidate), reused at all five nodes. Thus GH5 needs
   six private products per row/candidate for these terms, plus any missing
   source/validity preprocessing. Do not describe all quadrature composition
   as product-free. Public node*y is a local multiplication of shares.
   Supply privately validated, masked y and log(y!) shares (y<=4).
3. ScoreShares accumulates all node scores locally. CenterCompile yields five
   shared clipped exp arguments, the shared maximum and private validity.
   ScalarCompile(exp_negative) yields GH terms; sum on shares, then
   ScalarCompile(log). The integer exp at -16 is zero, preserving the prior
   truncation rule. No count or maximum may be opened.
4. FinalCompile accepts the exact signed candidate cap U_j, rather than forcing
   the prototype's universal bound. It consumes maximum, log sum, private count
   and ALL prior validity. It clamps/rounds once; empty clusters return zero.
5. Bind source/primitive/chunk receipts, joint DP noise, sticky accounting and
   output evidence through Step 2. Add process-isolated protected DSLite tests
   and the full capacity matrix before enabling R materializer/client reader.

The decomposition preserves the existing integer GH5 oracle and certificate;
binomial/Poisson, both admitted variances, partial/empty clusters, rejection
and cap tests pass. Scalar outputs remain Ring192 shares, avoiding unsafe local
widening. Exp uses <5000 AND/value including masks; see Addendum-3 measurements.
No full-release envelope or authenticated R release is claimed.

## Addendum 4 preflight — 2026-09-18

The binding ceiling is **110 GB / 4 h**. No release capacity is admitted;
all requested shapes are rejected by current prototype contracts. See
INTEGRATION_GROUPED.md's Addendum 4 section and
`inst/grouped-validation/addendum4-preflight.json` for the unmeasured matrix
and exact prerequisites. Component timings do not establish release capacity.
