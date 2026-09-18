# Layer 1 — candidate profile arithmetic

Status: arithmetic experiment passes; replacement profile NOT ADMITTED.
The full Step 2 mathematical gate, including production noise-scale utility,
signed candidate-specific caps and pooled `glm()` fixtures, is not complete.

Evidence: `inst/cross-grid-v2/{generate_profile.py,profile_candidate.json,
validate_profile.R,r-profile.log}` and the `TestCrossGridPWV2*` Go tests.
The analytic proof and exact evaluation order are in that directory's README.
Canonical payload SHA256 (excluding the sha256 field):
`97ab14832603c39031cd7da303c38400080828cc74ed66129b9c48f2c83928bb`.

- 30 profile variants; 4,290 shared Python-generated integer vectors match Go
  and pure R exactly. R's products stay below 2^53; Go uses independent big.Int.
- 16,385 dense real inputs per profile per language (491,550 points in each).
- 33 independent 256-bit transcendental comparisons per Go profile (990).
- 1,200 synthetic vector adjacency checks in R, including a zero contribution,
  add/remove and the unchanged conservative replacement multiplier 2.
- Binomial/Poisson objectives also compared with `dbinom`/`dpois` negative log
  probabilities on synthetic random eta/outcome pairs. No pooled dataset or
  `glm()` fit has been substituted for these pointwise checks.

K=64 conservative pre-output-rounding loss error per patient:

| Family | Public A | Nonlinear fraction bits | Certified error |
|---|---:|---:|---:|
| binomial | 4 | 16 | 0.000047283408097217 |
| binomial | 16 | 16 | 0.000142226984486106 |
| Poisson | 4 | 16 | 0.009129923147200926 |
| Poisson | 16 | 6 | 8974.791825542239410467 |

Poisson bounds cover outcomes through 1024. The large full-domain Poisson
error is a material utility limitation; no claim that it is far below the DP
noise scale has passed. The new certificate does not meet V1's q64 tolerance
and is not presented as doing so. The binding arithmetic addendum permits a
new error contract, but that still needs signed admission and utility gates.

The fixture's conservative profile-envelope caps are derived with outward
interval arithmetic and include twice the loss-error bound. These are proposed
new caps, not a claim to reproduce or overwrite the frozen V1 caps. The V1
caps/references remain tested separately and unchanged.
