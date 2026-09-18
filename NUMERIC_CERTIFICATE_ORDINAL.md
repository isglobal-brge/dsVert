# Ordinal certified piecewise fixed-point certificate

## Active arithmetic route (2026-09-18 reviewer addendum)

Active profile: `cross-grid-ordinal-piecewise-q16-v1`. Shared profile SHA256:
`fc0d85381d6effb30776848ccf301f4b9b18fc5dc55bdc80a8503f7d8916fcef`.
Analytic certificate SHA256:
`b480edd4ab1ad8f2403026f2d718bfd093068816160a893ee0f7935056251f67`.
`NUMERIC_CERTIFICATE_MULTINOMIAL.md` gives the table generator, exact q16
Horner semantics, rounding bounds, width proof and reproduction commands.
The protected q64 circuit is superseded. Source f50 encoding, f100 owner
partial predictors, row validity, and integer release quantization are retained.

## Finite-probability domain and stable loss

Retain 2–8 ordered classes, p<=16 normalized predictors, zero intercept,
slope component magnitude <=8 and L1<=8, threshold magnitude <=8, and
adjacent gaps >=1/16 in both original and f50 encoded domains. Let
`T=max|c_k|+sum|beta_l|<=16` and d be the smallest threshold gap. Endpoint
probabilities are at least sigmoid(-T); interior probabilities are at least
`d exp(-T)/(1+exp(-T))^2`. The universal interior floor exceeds 7e-9 for
T=16,d=1/16. Binary models have endpoints only. This signed public domain
restriction keeps logs finite and does not depend on observed probabilities.

Reconstruct f100 eta, then round directly to q16 by 2^84. Round each public
f50 threshold directly to q16 by 2^34. For a=abs(x) in [0,16], approximate
`softminus(a)=log(1+exp(-a))` by 64 quadratics of width 1/4, and define
`softplus_profile(x)=max(x,0)+softminus_profile(abs(x))`. Endpoint losses
use softplus_profile(-x) and softplus_profile(x). For an interior category,
hi=c_k-eta, lo=c_(k-1)-eta, gap=c_k-c_(k-1), evaluate

    softplus_profile(hi)+softplus_profile(lo)-hi-public_log_gap,
    public_log_gap=q16_round(log(1-exp(-gap))).

The gap constant is computed from the exact candidate-signed PUBLIC f50
gap using the retained certified q64 exp32/log24 integer helper, then rounded
to q16. No protected predictor or outcome enters that helper; it is never
emitted into the protected nonlinear circuit. This avoids amplifying a q16
exponential error near the minimum gap. Two rounded protected sigmoids are
never subtracted to form a rare probability.

## Analytic error and sensitivity

For softminus, sup|f'''|=1/(6 sqrt(3)); interpolation error is <=h^3/1296.
With coefficient/Horner rounding R(h),
`E_soft<=5369/169869312<0.000031607`. The PUBLIC q64 gap error is <1.4e-7:
gap>=1/16 gives `1-exp(-gap)>1/32`, so the inherited 4e-9 exponential
error is amplified by at most `1/(1/32-4e-9)`, and log error is <2^-50.
Rounding that constant to q16 adds u/2, where u=2^-16. The stable identity
has derivative magnitude <=1 in each endpoint argument. Rounding eta and
a threshold contributes at most u to each argument, hence <=2u total.
Frozen input encoding adds less than 1e-12. Therefore

    2 E_soft + u/2 + 1.4e-7 + 2u + 1e-12 < 0.00012.

The active **prequantization bound is e_pw=0.00012**. Add e_out=0 if g>=16,
otherwise 2^(-g-1). For each candidate use

    L_j=max(softplus(T_j), T_j+2 log1p(exp(-T_j))-log(d_j)),
    U_j=ceil(2^g (L_j+2 e_pw+e_out)),

with only the endpoint term for K=2 and outward public floating-point guards.
U_j/2^g exceeds the maximum quantized profile loss by at least e_pw. Enforce
the exact integer clamp [0,U_j]. Add/remove sensitivities are Delta1=sum U_j
and Delta2=sqrt(sum U_j^2); double both for the inherited conservative
replacement convention. Maxima N U_j, caps and both sensitivities must satisfy
the inherited exact-public-integer limit 2^53-1.

The explicit certified default envelope n=10000,m=50,g=18,T=16,d=1/16 gives
n*e_pw/Laplace-coordinate-scale ratios at most 0.001279,0.005114,0.010228 for
epsilon 1,4,8 (1.03% at epsilon 8). Other public envelopes require their own
ratio check. The approximate objective is within n*(e_pw+e_out) of exact loss;
a pairwise candidate comparison may differ by twice that amount. Privacy
follows from integer sensitivity and does not depend on this utility bound.
Numerical certification does not authorize production release.

## Historical superseded certificate

The following prior protected q64 profile and row-error claims are superseded.
Its public gap-constant argument is reused; the signed finite-probability
restriction remains in force.

---

# Ordinal fixed-point certificate extension

Profile: `cross-grid-ordinal-exp32-log24-q64-v1`. The q64 log kernel, frozen
exponential, rounding, width and clamped-target interpretation are proved in
`NUMERIC_CERTIFICATE_MULTINOMIAL.md` and `NUMERIC_CERTIFICATE_V1.md`.

## Finite-probability domain

There are 2–8 signed ordered classes, 1–16 normalized predictors and at most
256 candidates. The intercept is exactly zero to remove the common
intercept/threshold translation ambiguity. Slopes have component magnitude
at most 8 and exact binary64 L1 sum at most 8. Candidate thresholds have
magnitude at most 8 and adjacent gaps at least 1/16 in both the original
and f50 encoded domains. This stricter gap restriction is explicit new
versioned semantics; it does not change the old same-owner ordinal route.

For candidate j let T_j=max|c_jk|+sum|beta_jl|≤16 and d_j be its minimum
threshold gap. Each endpoint probability is at least sigmoid(-T_j). Since
the minimum logistic derivative on [-T_j,T_j] is
`exp(-T_j)/(1+exp(-T_j))²`, every interior probability is at least
`d_j*exp(-T_j)/(1+exp(-T_j))²`. Thus probabilities are strictly positive.
The universal lower bound for interior categories exceeds 7e-9, including
T=16 and d=1/16. K=2 has endpoints only and no gap constraint.

The signed row-loss bound is

    L_j=max(softplus(T_j), T_j+2*log1p(exp(-T_j))-log(d_j))

with only the first term for K=2. This is a lower-probability bound, not a
data-derived observed minimum.

## Stable integer circuit

For an interior class put u=c_k-eta, l=c_(k-1)-eta and d=c_k-c_(k-1). Use

    -log(sigmoid(u)-sigmoid(l))
      = softplus(u)+softplus(l)-u-log(1-exp(-d)).

Here softplus(x)=log(1+exp(x)) uses the bounded q64 kernels. Endpoint losses
are softplus(c_1-eta)-(c_1-eta) and softplus(c_(K-1)-eta). The probability
difference is never formed from two rounded protected sigmoids. All
threshold arguments remain within the frozen [-17,17] domain including
encoding slack. The threshold-gap constant is computed using exact integer
arithmetic on signed PUBLIC thresholds during circuit generation; it cannot
accept protected rows. Row references exist only in test files.

For d≥1/16, `1-exp(-d) >= d/(1+d) >= 1/17 > 1/32`. Its q64 approximation
therefore stays positive. Using the inherited exponential error bound
E=4e-9, the gap-log error is at most `E/(1/32-E)`. The two softplus errors
are each at most `E/(1-E)+2^-50`. Add the gap logarithm error 2^-50,
conservative eta/threshold errors and at most 32 times an f50 gap ulp. The
exact rational checker verifies total prequantization error **less than
1.4e-7 < 2^-20**. Final integer rounding and clamping give row error at most
3/(4*2^g) against the equally clamped real loss for g=8–18.

The new public gap-log normalization exponent is between -5 and zero. All
protected log inputs are at least one. The largest raw multiplication remains
bounded by the frozen <2^155 limit, safely within signed 192-bit arithmetic.

## Sensitivity and verification

Set U_j=ceil(2^g L_j) and enforce the integer clamp per row. Coordinate maxima
are N U_j. With the inherited adjacency multiplier a in {1,2}, use
Delta1=a sum U_j and Delta2=a sqrt(sum U_j²), retaining the outward L2 guard.
All caps/maxima/sensitivities must be ≤2^53-1. Invalid and padded rows
contribute zero through the private validity mask.

    python3 inst/cross-grid-family-b/verify_numeric_certificate.py

The proof and equality tests certify the numerical loss module. Private PSI,
the fused producer, authenticated result evidence, sticky joint-DP release
and their production two-peer tests remain integration gates.
