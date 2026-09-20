# Same-owner negative-binomial grid v2

`negative_binomial_grid_v2` produces
`bounded-negative-binomial-likelihood-grid-v2`. The v1 spec and artifact are
**sealed/defective**: their row loss omitted `y * log(theta + mu)`. Historical
v1 releases and validation records must not be relabelled, recalculated in
place, or interpreted as corrected likelihoods. Current validators reject v1,
including a v1 spec with its NB-specific fields removed and descriptors mixing
v1 and v2 semantics. Custodians must sign a new v2 workload. Its changed spec,
artifact, bounds and semantic labels change the canonical contract and sticky
release identity; historical releases do not fund a new release's privacy cost.

## Corrected loss

For count `y`, mean `mu = exp(eta)` and dispersion `theta > 0`, the NB2
negative log probability is

```
lgamma(theta) + lgamma(y + 1) - lgamma(y + theta)
  + theta * log1p(exp(eta - log(theta)))
  + y * log(theta + exp(eta)) - y * eta
```

Both server copies and the client validator evaluate the equivalent stable
form, where `softplus(z) = max(z, 0) + log1p(exp(-abs(z)))`:

```
lgamma(theta) + lgamma(y + 1) - lgamma(y + theta)
  + theta * softplus(eta - log(theta))
  + y * softplus(log(theta) - eta)
```

At `theta=2, y=1, eta=0`, v1 returned approximately `0.1177830357`;
v2 returns `1.2163953243`, equal to `-dnbinom(1, size=2, mu=1, log=TRUE)`.
The loss is nonnegative; numerical roundoff below zero is clamped before
quantization, as before. No fitted covariance or sampling inference is added.

## Per-patient bound and calibration

The signed design is normalized into `[0,1]` with intercept one. For candidate
`j`, let `A_j = sum(abs(beta_j))`, so `eta` lies in `[-A_j, A_j]`, and let
`Y = max_outcome`. Signed caps require integer `0 <= y <= Y <= 1024`, each
`abs(beta) <= 8`, `0 < theta <= 64`, at most 256 candidates, and grid bits
between 8 and 18. Public bounds exceeding the exact backend domain are rejected.

The added term is bounded above by
`Y * log(theta + exp(A_j))`: the logarithm is increasing and its upper endpoint
is positive because `A_j >= 0`. Adding this to the old bound would be safe but
loose. Instead v2 recomputes the full corrected endpoint maximum:

```
B_j = max(0, max(loss(y, eta, theta_j)
                for y in 0:Y and eta in {-A_j, A_j}))
```

This covers every interior eta since
`d² loss / d eta² = theta * exp(eta) * (theta + y) / (theta + exp(eta))² >= 0`.
Enumeration covers every admitted count; no convexity in the count is assumed.
Stable softplus evaluation avoids overflow even when `exp(A_j)` cannot be
represented. A corrected bound can be smaller than v1's defective bound;
the omitted term itself can be negative at negative eta.

For scale `s = 2^bits`, a row contributes
`r_j = round(max(0, loss_j) * s)` and `0 <= r_j <= q_j = ceiling(s * B_j)`.
For public capacity `N`, the statistic cap is `N*q_j`. Add/remove-patient
sensitivities are `sum(q_j)` (L1) and `sqrt(sum(q_j^2))` (L2). The existing
replace-one-fixed-cohort multiplier 2 is conservative by the triangle
inequality. Natural-scale sensitivities divide those quantities by `s`.
The workload's aggregate sensitivity and noise calibration consume these
recomputed constants. The client independently recomputes and validates them.

For `Y=10`, beta candidates `(0,0)`, `(0,1)`, theta candidates `0.5`, `2`,
in theta-then-beta order, the v2 bounds are approximately
`6.3401095220, 10.5948499873, 9.3991578301, 16.5597480148`.
At `s=256`, the integer caps are `1624, 2713, 2407, 4240`;
add/remove L1 sensitivity is `10984`, with L2 `sqrt(33768994)`.
At capacity 5 the statistic maxima are `8120, 13565, 12035, 21200`.

## Validation

The tests compare row losses against the independent R `dnbinom` oracle at
count/dispersion/eta boundaries and both lattice precisions, check all integer
counts and interior eta against caps, assert the explicit constants above and
both adjacency calibrations, and reject v1/mixed descriptors before snapshots
are read. A separate test covers eta beyond the exponential range without
using the overflowing `dnbinom(mu=exp(eta))` oracle. Diagnostics remain generic
and do not interpolate protected row values.
