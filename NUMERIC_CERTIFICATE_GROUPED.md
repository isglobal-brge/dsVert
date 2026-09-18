# Grouped arithmetic extension — restricted prototype

This document does not certify release promotion. The scalar interpolation
bounds below and LMM arithmetic bound are separate from the incomplete GEE
workload certificate and the separate full-release traffic gate.

## Frozen boundary and integer statistic

Owner contributions must be accumulated exactly at f100 and rounded once to
q64 before these kernels; never round partial predictors separately. LMM
residuals use q64. GEE features retain unsigned f50. Input domain/validity
checks precede arithmetic; one invalid live row zeroes all coordinates and
clears private validity. Private validity must gate final release.

LMM uses RN-even q64 reciprocal and lambda tables, with
inv=RN(2^128/sigma_q64),
lambda[n]=RN(tau_q64*2^128/(sigma_q64*(sigma_q64+n*tau_q64))).
It computes inv*sum(RN(r*r))-lambda[n]*RN(sum(r)^2), rounds each
q64 multiplication, clamps, then quantizes to g=8..18. All magnitudes fit
88 bits at B<=32, |r|<=17, sigma>=1/4; raw products fit 176 bits in int192.
Runtime public reciprocals avoid a pinned compiler constant-cast hazard.

Writing u=2^-64, inv<=4, sum(r^2)<=32*289 and sum(r)^2<=544^2,
a conservative arithmetic error is
(4*32 + 32*289 + 544^2 + 8)*u < 1.7e-14.
Including frozen eta encoding error from NUMERIC_CERTIFICATE_V1.md remains
below 1e-8 before output quantization. Final rounding adds 1/(2*2^g).
The claim compares equally clamped targets. Fixed covariance across candidates
makes omission of log determinant valid; variance candidate grids are rejected.

## Piecewise profiles

The SHA256-bound JSON in inst/certificates contains 65 nearest-even q16 knots
for each of six 64-piece linear profiles. For interval width h and a uniform
second derivative bound M, interpolation error <= M*h^2/8. Knot rounding and
interpolation rounding each contribute <= 1/(2*65536), giving
E=M*h^2/8+1/65536. Profile input/output words are 32 bits; the single unsigned
product uses the necessary narrow double-width intermediate. Domain checks
belong to the enclosing kernel; standalone emitters are not RPCs.

| Profile | Domain | M |
|---|---|---:|
| softplus | [-4,4] | 1/4 |
| exp_reduced | [-1/2,1/2] | 2 |
| log | [1,5] | 1 |
| sigmoid | [-4,4] | 1/10 |
| sqrt(sigmoid variance) | [-4,4] | 1/8 |
| inverse sqrt(sigmoid variance) | [-4,4] | 2 |

These follow by differentiating exp/log/logistic and
sqrt(v)=1/(2*cosh(x/2)), 1/sqrt(v)=2*cosh(x/2).
Tests check every q16 lattice input against independent library functions,
check the analytic inequality and JSON/Go coefficient/hash agreement, and
compare compiled endpoint/half-interval evaluations exactly. Dense tests do
not constitute an outward coefficient-generation certificate: that generator
and its interval proof remain required for promotion.

## GLMM composition

GH5 variance is fixed at 0 or 1/4; eta is in [-1,1], outcome binary or 0..4.
Nodes and log weights are q16 constants. With variance 1/4, |eta+node|<2.429,
and intervals touched have exp curvature <12.25. Row error includes profile
interpolation, eta/node rounding and log-factorial rounding. Scores are summed
in signed int32; at B<=16 and row loss <=32 their magnitude stays <2^26.
Subtract the shared maximum; exp arguments below -16 contribute zero with
error <=exp(-16)<1/8000000. At least one term is exactly one, so log's argument
is in [1,5] and its derivative <=1. The Go bounds include B*rowError,
log-weight rounding, four exp/cutoff errors and log error. Quantization adds
1/(2*2^g). This concerns finite GH5, not integration error against the true
random-effect integral or lme4 adaptive quadrature.

## Gates still closed

The recovered R `per_cluster_error_bound=1` for GEE is provisional, NOT a
proved bread/meat workload certificate. Do not promote it or use it as a
utility guarantee. A certificate must propagate profile/correlation/f50 errors
through bread and clipped score products and include shifts/quantization.

### Revised arithmetic route, 2026-09-18

All production-composition exp calls now use range reduction. For q16 input x,
choose k=sign(x)*floor((abs(x)+22713)/45426), r=x-k*45426, so
|r|<=22713 and the identity holds exactly in integers. Evaluate the short
[-1/2,1/2] profile at r and apply 2^k with fixed five-stage barrel shifts;
right shifts round ties to even. k's half ties are away from zero; correctness
requires residual enclosure, not matching the nearest exponent for real ln2.
The rational atanh enclosure proves |45426/65536-ln2|<1.5e-6.

Let E=2/(8*64^2)+1/65536. For x in [-4,4], k<=6 and |k|<=6;
error <=64 E +55*1.0001*6*1.5e-6 +1/(2*65536)<0.0055.
For x in [-16,0], k<=0 and |k|<=23;
error <=E+1.0001*23*1.5e-6+1/(2*65536)<0.00013.
The factor 1.0001 bounds exp(|k|*1.5e-6). These compare q16 inputs;
the enclosing GLMM adds eta/node quantization, factorial and logweight errors.
The GLMM bound includes both eta and node half-ulps (one complete q16 ulp),
plus frozen-ABI slack, instead of treating them as a single half-ulp.

Exhaustive q16 checks measured maximum exp errors 0.002717181709 and
0.000040219376, respectively. All runtime scalar emitters are below the
revised 5000-AND ceiling (range exp: 4321 including input-share addition and
output masking). The Boolean lookup shares constant-folded decision diagrams
across bit planes, preserving full signed int32 values; composed GEE tests
check against the independent integer reference.

The new profile/hash are incompatible with the old table manifest and are
bound by both R validators. A smaller scalar cost is not a full-release
traffic measurement. The <=60 GB gate and authenticated release remain open;
GEE's whole-workload certificate above remains unfinished. Production stays
fail-closed.
