# Cox Breslow profile certificate

This extends the frozen V1 **source ABI**, not its transcendental profile. The
binding Day-1 decision replaces transcendental evaluation with exact evaluation
of a certified piecewise-linear exp/log profile. Profile and certificate hashes
are pinned independently by Go, R server and R client. Reproduce the public
interval artifact with:

```
python3 inst/cross-cox-v1/generate_numeric_cox_profile_v1.py inst/cross-cox-v1/numeric_cox_profile_v1.json --check
```

## Statistic and domain

One distinct aligned patient per slot; public capacity 2..10000, 1..128 candidates,
1..16 normalized predictors in [0,1], no intercept, each |beta|<=4 and sum|beta|<=8.
Time/event belong to one custodian. Observed finite bounded binary64 times,
canonical signed zero, descending private time order and Breslow ties are fixed
by the signed source contract. Missing/nonfinite records are privately invalid;
repeated patient records reject the snapshot. Censoring at an event time remains
in that risk set. No risk-set or event counts are released.

For minimization the statistic is the **negative** partial log likelihood
L_j = sum over valid events i of [log(sum_{k valid: t_k>=t_i} exp(eta_k))-eta_i].
This reverses the sign of the log-likelihood in the task. All tied events use the
prefix at the LAST slot in their tie; a reverse carry distributes that denominator.
No per-row clamping or rounding changes this target. The coordinate is
q_j=clamp_[0,U_j](RNE(2^g Lhat_j)), 8<=g<=18, once per cohort.

## Uniform error, not a sampled certificate

Features and coefficients retain f50 nearest-even encoding, owner partial dots
are exact f100, and only their sum is rounded to q16. A conservative eta error is
E_eta = 2^-17 + 24*2^-51 + 16*2^-102. The allowed coefficient rounding slack fits
the prepare input bound 8*2^100+8*2^50; after q16 rounding eta is still in [-8,8].
The bounds include at most sixteen half-ulp coefficient errors. Independent
rounding of owner partial predictors is forbidden.

Exp uses 64 intervals of width 1/4 on [-8,8], q20 nearest-even endpoint knots,
and floors the nonnegative difference-times-offset product. The relative linear
interpolation remainder is <=exp(1/4)/128. Endpoint quantization plus flooring
contributes <1.5*2^-20*exp(8). Using interval-verified exp(1/4)<1.285 and exp(8)<2981,
rho < 1.285/128 + 1.5*2981/2^20 < 0.0144. All weights are positive (minimum 352).
Exact integer prefix addition preserves the same relative error, regardless of
risk-set size. Thus its effect on log is <=rho/(1-rho).

For a positive q20 prefix W, k=bit_length(W)-21 and m=floor(W*2^-k) give a q20
mantissa in [1,2). k lies in [-12,24]. Log uses 64 width-1/64 intervals on [1,2],
q20 nearest-even knots, floor interpolation and a q20 nearest-even ln(2) constant.
Since |log''|<=1, its absolute error is bounded by
1/(8*64^2) + (1 normalization + 1.5 interpolation + 12 exponent)*2^-20
=1/32768+14.5*2^-20 < 0.00006.

Log-sum-exp is 1-Lipschitz in the sup norm, so a per-event error bound is
2 E_eta + rho/(1-rho) + 0.00006 < **1/64**. Summing at most N valid events gives
N/64. Whole-cohort projection onto the public range is nonexpansive; output
nearest-even rounding adds at most 2^(-g-1). Dense tests check all 1,048,577 exp
q16 inputs, small-prefix integers and normalization/piece boundaries. These
checks supplement the analytic inequalities and interval-certified knots.

## Caps and one-patient sensitivity proof

Write A_j=sum|beta_j|. Each exact event contribution lies in [0, log(N)+2 A_j],
because its risk set contains the event itself, has at most N members, and each
eta lies in [-A_j,A_j]. Therefore the exact entire loss is at most
N*(log(N)+2 A_j). The profile error allowance gives the outward integer cap

U_j = ceil(2^g N [log_upper(N)+2 A_upper_j+1/64]).

log_upper is computed in q24 by positive atanh terms after power-of-two range
reduction, sixteen terms, rounding every term and product upward and adding a
unit for the tail. A_upper sums each |beta| rounded upward to q24. All R cap
products remain exact binary64 integers (<2^53); Go independently uses rational
beta conversion. The signed contract cannot supply a smaller cap or sensitivity.

**These are whole-cohort caps, not independent per-patient loss caps.** Adding a
censored patient can change every earlier event denominator. Nevertheless, for
ANY two datasets, q_j and q'_j both lie in [0,U_j], hence |q_j-q'_j|<=U_j. In
particular this covers one-patient additions/removals and replacements of time,
event, covariates or missingness, including opposite time extremes. With the
existing conservative convention a=1 for add/remove and a=2 for fixed-cohort
replacement, Delta1=a sum_j U_j and Delta2=a sqrt(sum_j U_j^2) are valid. The
replacement factor two is retained even though the range proof permits one.
Natural-unit sensitivities divide these by 2^g exactly once. R inflates L2 by
1+512 machine eps to enclose positive summation/square-root rounding. All signed
caps and sensitivities must be <=2^53-1. A tighter risk-set influence bound is
not claimed. Neighbour tests check the implemented integer statistic but do not
replace this range proof.

At the signed defaults N=10000,J=50,A=8, the N/64 approximation budget is below
0.1% of the Laplace Delta1/epsilon scale for epsilon in {1,4,8}. This reflects
the conservative privacy bound, not a claim of useful estimation accuracy.

## Width and circuit resource limits

Scalar inputs and interpolation operands are at most 32 bits; one widened
product per profile evaluation. Exp raw products <2^44, log raw products <2^28;
exact risk sums <2^45. Prefix/log outputs and cohort losses use signed 64-bit
lanes, with the loss validity envelope +/-32 N*2^20 (<2^39). Prepare reconstructs
the frozen Ring128 source before sign interpretation and nearest-even rounding.
The internal transition to Ring64 takes each share modulo 2^64, preserving the
small reconstructed value without opening it. Every emitted output lane gets a
fresh full-ring additive mask, including metadata and validity.

Compile limits remain 32 million gates, 2 MiB generated source and 512 Ki bits
per typed input. They are tested for maximal public tile geometry. Signed
negative circuit constants use `-int64(magnitude)`; the pinned MPCL compiler
misinterprets `int64(-magnitude)` in lower-bound comparisons. Permanent compiled
predicate/boundary tests cover this issue. The standard compiler pruning/array-multiplier profile and shared public
coefficient-bit decision diagrams achieve 1514/1486 non-XOR gates for exp/log.
The original 30 GB budget is superseded. Scalar counts alone do not establish
the revised 60 GB / 2 h measured-envelope gate or a production capacity.
Measured costs and outstanding gates are recorded in STATUS_COX.md.

## Clause-5 composition extension (2026-09-18)

The scalar knots, fractional scales, rounding, cap derivation and sensitivity
are unchanged. The share-based kernel computes exactly the same integer loss:

1. A packed Ring128 OT switch outputs sums `(a,b)` when its bit is zero and
   `(b,a)` when one. For evaluator difference d=b_E-a_E and uniform r, checked
   OT gives the owner t=r+c*d and evaluator -r; owner routes its own shares and
   both apply +/- their selected-difference share. Thus outputs reconstruct to
   the primitive's identical Beneš permutation without reconstructing inputs.
   The complete label is decoded as 128 bits; the legacy Ring127 helper is not
   used. This leaves exact f100 dots unchanged under arbitrary owner partition.
2. The exp bridge reuses the certified f100 range/slack and single q16 RNE.
   It emits the same q20 exp, active event and event*eta, with uniform Ring64
   masks. Ring128 transport upper output words are public zero and irrelevant
   after reduction modulo 2^64; lower masks are independent uniform ring words.
3. Prefix additions are linear in Ring64. The previous bound W<2^45 proves no
   reconstructed overflow. Reverse doubling chooses a later prefix iff the
   intervening original tie-end interval contains no end. Inductively, after
   distance d a row has the prefix at its first tie end or at most 2d-1 rows
   later; after all public powers of two it has exactly its tie-end prefix.
   Private OT selects whole share words without rounding or a new approximation.
4. The same normalized log profile is evaluated for all padded slots; zero-risk
   inactive slots use the already-certified dummy argument 1. Invalid positive
   event/zero-risk combinations fail the private validity gate. Private event
   masking and local subtraction/addition give the same whole-cohort q20 loss.
   Loss magnitude stays below 32*N*2^20; accumulated invalid-batch counts are
   nonnegative and far below 2^64, so `1 - bad` equals one only with no failure.
5. The unchanged finalizer performs one ties-even lattice rounding and clamp.
   Therefore Go/R oracle equality, U_j, Delta1/Delta2 and N/64 approximation error
   transfer exactly. No new numeric error or sensitivity allowance is needed.

Each nonlinear tile includes range/validity checks and share conversion/masks.
For 32 rows exp uses 146975 non-XOR gates (4592.97 per row); log at the maximal
capacity uses approximately 69567 (2173.97 per row; exact capacity-specific
counts are measured). Compilation rejects either profile above 5000 per row.
All transport masks remain fresh; reusable checked OT advances its per-release
streams, never reuses extension outputs, and cannot be restored/reset on retry.

### Resource admission across lattice precisions

The public matrix uses grid_bits=12 and maximum predictor radius 8 (beta 4,4).
Exp/log batch sources, share scans, permutation and receipts do not depend on
lattice precision or U_j. Only the scalar finalizer varies with grid_bits and
its public cap. SharedCompile now also rejects a finalizer above 4096 non-XOR
gates. A 99-case compiled sweep (N=2000/4000/10000, every grid_bits=8..18,
caps 1/half-U/U) has maximum **877** non-XOR gates. This additional fail-closed
resource check changes no source expression, fixed-point error, loss coordinate,
sensitivity or measured wire transcript. The live matrix executable predates
only this extra compiler rejection; it runs the identical circuit sources.
