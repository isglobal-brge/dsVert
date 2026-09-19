# GEE whitening profile v3 — arithmetic certificate

This certifies the private arithmetic profile `grouped-gee-whitening-f96-q64-v3`.
It does not certify source provenance, durable lifecycle, a release capacity,
or promotion. The former provisional error=1 is not used by this profile.

The estimand remains the finite signed likelihood grid plus the column-major
upper triangles of bread and shifted clipped-score meat. It is not a GLM
wrapper. Within each cluster the real targets are independent-row likelihood,
U' R^-1 U, and clip(U' R^-1 z) clip(U' R^-1 z)', where U_i=x_i sqrt(V_i),
z_i=(y_i-mu_i)/sqrt(V_i). All comparisons use the same signed coordinate caps
and shifts. Patient add/remove changes one cluster; replacement/movement at
most two. Per-cluster coordinate intervals therefore retain the existing
range sensitivity proof and exact sum of coordinate caps.

Domain: B<=8 original row slots, p<=3, features in [0,1], |eta|<=4, binary y
or Poisson y in {0,...,4}, g=8..18, quarter-step score clip C in [.25,4], and
rho in {0,1/4,1/2}. Raw complete predictors are f100, rounded once to q64,
then q16 for the pinned scalar tables. The scalar table SHA256 remains
f72e66abaf2e503a809f23d4563418d2889843174109398ae48b02f0ec7edb84.
The new profile name is incompatible with the old inverse-matrix q16 assembly.
The v3 public factorial coefficients are `[0,0,45426,117425,208277]`.
In particular, the legacy y=3 value117423 was not nearest rounding and is not
used in v3. `TestGroupedGEEFactorialCertificate` encloses log2 and log3 with
64 terms of the rational atanh series and a positive geometric tail bound;
log6=log2+log3 and log24=3log2+log3 lie strictly within their half-ulp cells.
The signed R numeric contracts explicitly carry these coefficients.
The complete signed predictor/source receipt is a mandatory input prerequisite.

## Private whitening

Independent rows use W=I on live slots. Exchangeable rows use
W=a I+c 11', a=(1-rho)^(-1/2), b=(1+(m-1)rho)^(-1/2), c=(b-a)/m.
The count m is secret; the circuit selects precomputed public coefficients,
not a public count or an inverse for a zero-padded full block. Thus W'W=R^-1.
For AR1, the first live row is unchanged; each later live row i with previous
live row j has W_ii=(1-rho^(2(i-j)))^(-1/2) and
W_ij=-rho^(i-j) W_ii. Distances use ORIGINAL slots, including missingness gaps.
This innovations factor also has W'W=R^-1. Empty clusters have W=0.

All public square-root coefficients use exact integer square root:
floor(sqrt(floor(2^128 N/D))). Its square brackets the rational value between
successive integers, proving error <2^-64. Exchangeable c is RN-even from the
difference of these integers divided by m; AR off-diagonals use an exact
dyadic numerator/denominator and RN-even. Each coefficient error is <10*2^-64,
a deliberately loose bound covering diagonals as well. Exact W row absolute
sums are <4 for every admitted count/rho/gap. Selection and masking remain
private; no secret sqrt, division, live count, predecessor or factor is opened.

## Propagation (natural scale)

Let h=2^-17, t=h+10^-12 and f=h+2^-51. The 10^-12 includes original f50
feature/coefficient encoding and f100->q64 rounding at p<=3 and |beta_j|<=8.
The existing analytic interpolation/rounding certificates give:

| family | E_mu | E_a | E_b | E_loss | A | Z | residual bound |
|---|---|---|---|---|---|---|---|
| binomial | 69/327680+t/4 | 17/65536+t/4 | 257/65536+4t | 33/65536+t | 1/2 | 8 | 1 |
| Poisson | .0055+55t | .0055+8(t/2+h) | same as E_a | .0055+59t+h | 8 | 40 | 55 |

A bounds exact |x sqrt(V)| and Z bounds exact |(y-mu)/sqrt(V)|. For Poisson,
Z<40 follows from y exp(-eta/2)+exp(eta/2)<=5 exp(2)<40. The table's Poisson
errors use the retained range-reduced exp certificate, including the extra
half-eta rounding. The log-factorial q16 constant adds at most h. No statistical
quadrature or estimator error is represented as arithmetic error.

Set eu=E_a+(A+E_a)f, ez=residual_bound*E_b+(8+E_b)E_mu, u=2^-64,
Eu=4eu+10B u(A+eu)+u/2, Ez=4ez+10B u(Z+ez)+u/2.
These bound each whitened factor coordinate against its exact real target.
Exact OT products form q32 base factors, then q96 W-factor products; sums are
local linear operations. Only the final factor boundary rounds to q64.

The exact f128 moment products/sums give
E_score=B(4A Ez+4Z Eu+Eu Ez) and E_bread=B(8A Eu+Eu^2).
Clipping is nonexpansive; score rounding adds h. Since both rounded and exact
clipped scores stay in [-C,C], E_meat=min(2C^2,2C(E_score+h)).
Final coordinate quantization adds q=2^(-g-1). Thus the per-cluster coordinate
errors are B E_loss+q, E_bread+q, E_meat+q. Shifts are exact, and clamping is
nonexpansive. The likelihood is summed then clamped ONCE per cluster to the
signed cap; legacy RowLossCap is not used by this profile.

`groupedGEEWhiteningCertificate` evaluates these formulas as exact rationals.
The mirrored signed R contracts use q=1/512 (all g>=8) and outward relative
slack 256 machine epsilons for their positive binary64 operations; caps use
the maximum of the three proved bounds, never the old placeholder 1. These
bounds are conservative and make no utility claim.

## Width and validity

Raw input ranges are checked at full Ring192 width before narrowing. All
scalar calls take guarded q16 arguments; every profile validity and the private
whitening validity is conjuncted. Base factors/losses are checked within
512*2^32 and privately live-masked. Whitened f96 factors are checked within
2048*2^96. Products of the resulting q64 factors and B<=8 sums stay below
2^154, far inside signed Ring192. Clipped q16 meat products fit below 2^37.
Thus OT products and linear reductions have zero modular arithmetic error.
Any failed private predicate zeros all factors and clears validity; the fused
release MUST gate likelihood, bread and meat on the returned validity.

The producer binds its encrypted stage purposes and OT plans to the signed
contract digest, spec, new profile and scalar hash. It returns only local
shares and a profile certificate to the protected scheduler. Durable receipts,
crash recovery, source/grouping authentication and DP release remain separate
integration work; this component alone must never authorize production.
