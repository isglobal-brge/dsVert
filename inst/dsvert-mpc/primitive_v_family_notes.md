# Worked family circuits: contract and proof notes

These notes accompany `primitive_v_family.go` and its exact Go integer oracle.
They are internal circuit specs, not a new public invocation or DP release path.
The common numeric and permutation emitters are the family fan-out seam.

## Ownership and privacy

Public candidate-signed inputs are family, padded capacity `Rows <= 10000`,
`Cap`, maximum live cluster/tie size `GroupCap`, the numeric profile, and the LMM
q64 variance ratio `RhoQ64` in `[0,16]`. GLMM fixes standard-normal variance one
and Q=5. The five nodes and exactly normalized positive weights are public.
The signed contract must bind this entire shape and the alignment authorization.

The two custodians provide additive Ring192 shares of row tuples
`[eta_or_residual_q64, live_bit, event_or_binary_outcome_bit]`. Eta already comes
from the frozen q50 feature/coefficient dot product and nearest-even q64
conversion; the existing binomial/Poisson integration owns that producer. LMM
uses `r=y-eta` produced inside MPC and capped by a separately signed residual cap.
Neither wrapper reconstructs these quantities outside the circuit. Linearity
allows share addition before the network: `P(a+b)=P(a)+P(b)` in Ring192. The
network therefore permutes reconstructed wires inside GC without duplicating
the switches for the two additive share vectors.

The structure owner is the garbler in these worked wrappers. It privately
provides Beneš controls and the segment-start bit for EVERY internal padded row.
The other owner supplies only row shares. Switches apply to all tuple fields.
Every padded row is processed even under arbitrary control bits, so a malformed
control assignment cannot drop a live row by moving it into the padded tail.
The owner computes controls from the private output-to-input permutation locally;
no order-derived hash, group count, group size, or boundary is sent in cleartext.
Either custodian can own the structure by assigning it the garbler role.

Both outputs (q64 family score and validity bit) are additively masked using the
existing exact-GC engine. The actual number of groups need not be public.
Only capacity, configured caps, fixed network topology, circuit size, and fixed
transcript shape leak. Authentication/source authorization must bind the input
meaning: the circuit verifies bounded arithmetic, bits, and group-size caps, but
cannot infer whether owner-supplied boundaries really represent its source
cluster IDs or descending source times without those source fields. This is the
same trusted-source/attestation obligation as the finite-grid input producer.

Invalid live bits, response bits, controls, boundaries, a missing first boundary,
exceeded live-value caps, or exceeded live group-size caps produce shared zero
score and shared validity zero with the same public work. Out-of-cap live values
are sanitized before nonlinear evaluation. A release caller must privately AND
this validity with source/producer validity before adding joint DP noise and
entering sticky publication. A zero score is never a public validation signal.

## Family targets and arithmetic

Cox uses descending time, with each distinct time as one segment. It accumulates
live `exp(eta)` over all earlier rows and the current tied block. At its end,
`event_eta_sum - event_count * log(risk_sum)` charges every tied event the SAME
Breslow denominator, including censored rows tied at that time. Invalid/padded
rows add neither risk mass nor events. The returned score is the log partial
likelihood `sum_event (eta - log risk)`, so a downstream minimization route must
negate it. The total score is projected to
`[-Rows * (2*Cap + ceil(log2(Rows)) + 1), 0]` in q64 units. The exact real target
lies in this interval; projection cannot increase its numerical error.

LMM uses private contiguous clusters, live residual count n, segmented residual
sum R and square sum S. It returns
`S - rho/(1+n*rho) * R^2`, summed over clusters. Each input square and the square
of the sum are rounded nearest-even to q64; the correction is computed as one
rounded division `rho_q64 * square_q64 / (2^64+n*rho_q64)`. Each cluster score is
projected to `[0,n*Cap^2]` before accumulation. This is the requested quadratic
loss only; no claim is made to include a variance-dependent determinant term.

GLMM uses the standard-normal Q=5 Gauss-Hermite approximation to the Bernoulli
random-intercept marginal likelihood. The nodes are
`0, +/-sqrt(5-sqrt(10)), +/-sqrt(5+sqrt(10))`; weights are
`8/15, (7+2sqrt(10))/60, (7-2sqrt(10))/60` at center/inner/outer nodes. Nodes are
nearest-even q64; outer/inner weights are nearest-even q64 and the central weight
absorbs one ulp so all five weights sum EXACTLY to 2^64. The maximum node magnitude
is below 3, so the wrapper requires `Cap <= 14` and every shifted eta is in the
numeric exponent domain `[-17,17]`.

For each node, it computes row log likelihood `y*z-log(1+exp(z))` and privately
sums it by cluster. The cluster integral uses scores
`h_q=log(weight_q)+sum_i loglik_iq`, selects their secret maximum M, and computes
`-(M+log(sum_q exp(h_q-M)))`. Nonpositive exponent arguments below -32 are
replaced with zero with an explicit certified tail budget; arguments in [-32,0]
use the common scaled/squared exponential. Every cluster score is projected to
`[0,n*(Cap+4)]`. The implementation targets the discrete, quantized Q=5 quadrature,
NOT the exact continuous Gaussian integral; quadrature approximation error is a
modeling error separate from certified arithmetic error. No general guarantee
that Q=5 suffices for all data is claimed.

## Numerical family bounds

Let u=2^-65 (one nearest-even q64 rounding bound), E_exp be the common relative
exp bound on [-17,17], E_log the common absolute log bound, and E_neg the common
absolute exp-negative bound. These named values must come from the numeric
certificate rather than from floating-point test maxima.

Cox: positive risk summation is exact at q64, so the relative exp error remains
E_exp for any nonempty prefix of up to n terms. Prefix log error is at most
`-log(1-E_exp)+E_log`. Multiplying a q64 log by the integer event count and summing
are exact; hence total error is at most n times this prefix bound. If the frozen
eta encoding differs from an ideal eta by delta, each event eta contributes at
most delta and log-sum-exp is 1-Lipschitz in the infinity norm, adding at most
`2*n*delta` to the score error.

LMM: for a nonempty cluster, square-sum rounding costs n*u. The square of R costs
u; scaling its error by `rho/(1+n*rho) <= 1/n` plus the final division costs at
most `(1+1/n)*u`. Thus cluster arithmetic error is below `(n+2)*u`. Summing gives
`(n_total+2*groups)*u`, bounded by `3*n_total*u`. The residual-encoding contribution
is at most `2*n*Cap*delta+n*delta^2` per cluster by the PSD quadratic matrix's
spectral norm <=1. Projection is nonexpansive.

GLMM: `log(1+exp(z))` has absolute error at most
`-log(1-E_exp)+E_log`; exact row loglik accumulation multiplies this by n. The
outer log-sum-exp is 1-Lipschitz, so the cluster score perturbation plus log-weight
error costs at most `n*(-log(1-E_exp)+E_log)+E_log`. Max shifting guarantees one
exact exp(0)=1 term, hence the true sum is >=1. Q negative exponent errors perturb
the sum by at most `Q*E_neg`; its log contributes at most
`-log(1-Q*E_neg)+E_log` (Q*E_neg<1). Combined cluster arithmetic error is therefore
at most `n*(-log(1-E_exp)+E_log)+2*E_log-log(1-Q*E_neg)`.
For the stated profile E_exp<7e-13, E_log<3e-17, E_neg<1.4e-14, a conservative
bound is `7.001e-13*n + 7.01e-14` per cluster. Eta and node q64 encoding add at most
n times their absolute encoding error, by the Bernoulli loglik derivative bound
one and the outer log-sum-exp Lipschitz bound. Positive normalized weight q64
perturbation can separately be bounded through max relative weight error; the
smallest weight exceeds .011, so it is less than 5e-18 in log scale. GH quadrature
error relative to the exact Gaussian integral is not included in this certificate.

For n<=10000 all row caps are <=17, risk sums are below n*exp(17)*2^64<2^103;
residual sums below 17*n*2^64<2^82; squared residual sums before q64 rounding below
2^164; rho times rounded squared sum below 2^169. GLMM group log scores have
magnitude below n*(Cap+4)*2^64+5*2^64<2^83. All are within signed192 arithmetic;
the common nonlinear proof bounds its own intermediate products separately.

## DP units and exact sensitivity

For M candidates, coordinate bounds B_j yield L1 sensitivity `sum_j B_j` and L2
sensitivity `sqrt(sum_j B_j^2)`. Use the integer q64 caps, or a separately signed
g-grid postprocessing cap `ceil(B_j*2^g)`; do not copy the rowwise GLM sensitivity.

For LMM and GLMM choose one entire cluster as the DP unit, under add/remove of a
cluster of at most K live rows or replacement of one cluster while other clusters
remain unchanged. LMM has `B_j=K*R_j^2`: the quadratic matrix
`I-rho/(1+n*rho) 11'` has eigenvalues 1 and `1/(1+n*rho)` in [0,1], so its loss is
in `[0,sum r_i^2]`; the integer per-cluster projection makes this bound exact.
GLMM has `B_j=K*(A_j+4)`: every shifted Bernoulli predictor has magnitude below
A_j+3, each negative loglik is below A_j+3+ln2 < A_j+4, and positive normalized
weights preserve the interval for the negative log of the integrated likelihood.
Both old/new replacement contributions lie in the SAME `[0,B_j]`, so replacement
also costs B_j (not automatically 2B_j) under this cluster replacement definition.
The output sum's other clusters cancel. Arbitrary regrouping of unrelated rows
is outside this adjacency relation; it requires a new sensitivity proof.

For Cox choose one aligned row as the DP unit, under add/remove or replacement
inside the fixed public capacity. Its private time can change, affecting many
risk sets. The universally safe exact integer coordinate bound is
`B_j=Rows*(2*A_j+ceil(log2(Rows))+1)` because the final score is in `[-B_j,0]`.
Two adjacent datasets' scores differ by at most B_j, so the stated L1/L2 bounds
hold even when private ordering changes. This is intentionally conservative and
may be statistically unhelpful at large n. A tighter REAL-target add/remove
bound is `2*A+ln(n)+exp(2*A)*H_(n-1)` (deleted own event plus harmonic risk-set
perturbations); using it for the integer circuit needs the additional certified
arithmetic-error budget, and replacement needs the two-step composition. The
worked wrapper uses the conservative cap-bound contract rather than claiming
an unjustified rowwise likelihood decomposition.

## Pinned compiler integration constraint

The pinned MPCL backend interprets `int192(-k)` as positive k for multiword
literal magnitudes above 64 bits. Every negative public family constant is
therefore emitted as `-int192(k)` through `primitiveVFamilyLiteral` (or the same
explicit unary-after-cast form for lower cap checks). This includes GH nodes,
log weights, and Cox score caps. A direct circuit regression covers both signs
of public q64 constants independently of family arithmetic. Likewise, secret
zero seeds avoid the backend's constant-folding panic on int192 counter updates.
The root compiler admission recovers backend panics into the fixed rejection
error; no protected data is involved in source compilation.
