# Binomial GLMM finite GH5 variance-grid composition

This descriptor packages the retained GH5 arithmetic for a signed variance
grid. It does not assert a completed authenticated release, measured capacity,
or promotion. The signed binomial-only grid is a strictly increasing nonempty
subset of `{0, 1/4}`. Candidates are variance-major, beta-minor. The previous
single-variance contract and every LMM contract retain their existing bytes.

The canonical JSON artifact is
`inst/certificates/grouped_binomial_glmm_gh5_v1.json`, SHA256
`76490f13d69f7968b5fa435f1ac7b5da844b8f7476ad582669b4e41a95960377`.
Both packages independently verify that file and the retained scalar profile
file. The scalar `profile_sha256` remains
`f72e66abaf2e503a809f23d4563418d2889843174109398ae48b02f0ec7edb84`;
`certificate_sha256` identifies this composition. Native staged plan
`ProfileSHA256` binds the composition certificate and its family-typed numeric
spec, not a caller-selected scalar hash.

## Typed arithmetic schedule

Source y is authenticated q0 binary data. A full-width binary check precedes
its exact f50 normalization into the routing lattice. Stable private routing
carries f50 features, live and outcome through the corrected correlated
Ring128-to-Ring192 mask/carry/sign conversion. A guarded private circuit
extracts exact q0 live/outcome, zeros inactive rows, and yields the private
cluster count. No local division of additive shares is permitted.

Each complete public-beta dot accumulates at f100, then rounds ties-even to
q64 and q16, in that order. Its signed complete predictor is in `[-1,1]`.
Variance 1/4 uses q16 node offsets `[-93617,-44421,0,44421,93617]`;
variance zero uses five zero offsets. Both retain all five q16 logweights
`[-294042,-98614,-41196,-98614,-294042]`.

The retained softplus profiles and exact Ring192 private products produce
masked node scores. The q0 outcome times q16 predictor product is shared
across all nodes and variances for a beta. A private maximum centers the
five scores. Retained negative exp drops arguments below -16 and forces
exp(0)=1. The complete reconstructed logsum must be proved in the full-width
q16 interval `[65536,327680]` before any int32 scalar narrowing. This check
and all source, predictor, scalar and product validity are conjoined privately;
local AND of XOR validity shares is not a valid substitute.

Finalization uses each exact signed candidate cap on its qg lattice, retains
zero for empty clusters, and sums cluster shares by candidate. Modulo reduction
from Ring192 to Ring128 is an exact ring homomorphism. The authenticated
terminal validity must enter the sticky joint-DP sampler once. This descriptor
alone cannot authorize a release or bypass the durable staged producer.

## Retained finite-GH5 error

The softplus and log interpolation errors are each `33/65536`. The retained
binomial row allowance adds `1/65536 + 1e-12` for eta/node rounding and the
frozen source encoding allowance. At public cluster bound B, native
`groupedGLMMBounds` therefore has

```
E(B) = B*(34/65536 + 1e-12) + 1/131072
       + 4*(13/100000 + 1/8000000) + 33/65536.
```

The terms after the row errors cover logweight rounding, four negative-exp
profile/cutoff errors, and log interpolation. At least one centered exponential
is exactly one, so the log derivative on the admitted sum is at most one.
Final output rounding adds at most `1/(2*2^g)`. For `1<=B<=16` and
`8<=g<=18`, the total is below 0.012, strictly enclosed by the signed existing
error allowance 1. R reconstruction applies outward floating-point slack to
the explicit bound. Comparisons are between equally clamped finite-GH5
objectives; quadrature error against a true random-effect integral is excluded.

## Patient sensitivity and measurement domain

Each cluster/candidate is clamped to its signed `[0,U_j]` range before release.
For add/remove, `a=1`; for replacement or movement, `a=2`. The full expanded
variance-by-beta vector uses `Delta1=a*sum(U_j)` and
`Delta2=a*sqrt(sum(U_j^2))`. Maxima are `C*U_j`. A variance grid cannot reuse
the smaller fixed-variance vector sensitivity.

The previous fixed-variance small C<=64 domain remains unchanged. New binomial
variance-grid contracts require at most three predictors and four total
variance-by-beta candidates, matching the staged producer. The additional
named measurement domain is
`binomial-glmm-gh5-n2000-c500-b4-p3-j4-v1`: n=2000, C=500, B=4, at most
three predictors and at most four total variance-by-beta candidates. This
permits measurement against the 256GB/6h gate. It is not measured capacity.
The public reader requires authenticated producer evidence, and
complete K2/K3/K5, recovery, cold replay, tamper and paired-suite proofs remain
separate release requirements.
