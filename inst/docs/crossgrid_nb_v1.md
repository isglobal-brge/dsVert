# Correct cross-owner NB2 finite grids

For public signed theta and mu=exp(eta), the row loss is the complete negative
NB2 log PMF:

`lgamma(theta)+lgamma(y+1)-lgamma(y+theta)+y*log(theta)+(y+theta)*softplus(eta-log(theta))-y*eta`.

This equals `-dnbinom(y,size=theta,mu=exp(eta),log=TRUE)`. In particular,
y=1, theta=2, eta=0 gives 1.21639532432449. The legacy same-owner route is
independently maintained and is not invoked or modified here.

Theta is a signed public candidate parameter restricted to exact powers of two
from 1/8 to 128. This finite supported domain permits an interval-certified
public constant table for every integer outcome 0 through 1024. The secure
circuit privately selects the appropriate public entry. No outcome-dependent
constant is exposed to the analyst or transported in clear between custodians.

Predictors and public coefficients retain f50 encoding; the complete dot
product is accumulated at f100 and rounded once to q64. The shifted-softplus
argument stays inside the certified [-22,22] domain, including encoding
slack. It is reduced to q16 for a w32, 64-piece quadratic softplus profile with
two multiplications and a certified residual tail. Public constants retain q64.
Each row is privately validity/alignment-masked, clamped and quantized at output
bits 8 through 18. The softplus uniform error is at most 0.00003936; NB row error
is `(y_max+theta)*0.00003936 + 1024*1.4655e-14 + 2^-63`, before output rounding.
The signed candidate caps include this approximation error.

For candidate j set A_j=sum(abs(beta_j)). At each fixed integer y, the loss has
second eta derivative `(y+theta)*theta*exp(eta)/(theta+exp(eta))^2 >= 0`.
Therefore its maximum on [-A_j,A_j] occurs at an endpoint. Evaluating both
endpoints for every y=0,...,y_max bounds the exact loss. The public cap uses
certified integer constants, the same q16 profile, a public endpoint error
margin, and twice the row error, so L_j bounds the approximate loss plus its
error. Let S=2^g and `U_j=ceil(S*L_j)`. The circuit enforces each integer row contribution in [0,U_j]
regardless of approximation or public-cap roundoff. For signed cohort capacity
N the coordinate maximum is N*U_j. For one joined patient's addition/removal,
`Delta1=sum(U_j)` and `Delta2=sqrt(sum(U_j^2))`; the inherited conservative
replace-one policy uses twice both values. The implementation retains the
outward floating-point guard on Delta2 and rejects unrepresentable caps,
maxima or sensitivities. These are whole-vector bounds across every signed
candidate, not report-noisy-min or exponential-mechanism calibration.

Grid selection is deterministic postprocessing of the authenticated jointly
DP-released vector, with the first canonical candidate resolving a tie. No
protected-data optimizer, standard errors, covariance or p-values are supplied.
The authenticated fused producer and sticky release wiring are tracked in
`INTEGRATION_NB.md`; their absence keeps the public entry fail closed.

The utility statement is DP selection under an approximate finite-grid loss
known within `N*(E_j+1/(2S))` of the equally clamped exact loss. Neither exact-best
selection nor a fitted optimum is guaranteed. Synthetic comparisons with
`MASS::glm.nb` are test evidence only; no protected-data fit is performed.
