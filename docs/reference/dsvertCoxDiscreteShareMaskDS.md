# Cox K=2 discrete-time non-disclosive share-mask primitives (#D')

Worker2 K=2-safe option (B) – hide J_i (per-patient ending bin index)
from the covariate (non-label) server. Implements the share-mask gating
pattern documented in `project_k2_strict_unified_plan_2026-04-27.md`
Sec."Option B FEASIBILITY ANALYSIS":

- At the outcome (label) server, J_i and status_i are local plaintext.
  Compute the per-patient at-risk mask m_ij in {0,1} (j=1..J, i=1..n)
  where m_ij = I(j \<= J_i) and the event indicator y_ij = I(j == J_i
  AND status_i = 1).

- Both m and y get split into Ring127 additive shares between OS and the
  covariate server. The covariate server thereby never sees J_i
  directly; the only signal it receives is two random-looking
  length-(J\*n) shares that, summed pointwise mod 2^127 with the OS
  shares, reconstruct m and y.

- The covariate server expands its X to a UNIFORM Jxn person-period
  frame (every patient contributes J rows, regardless of true J_i), so
  no row-count signal leaks. The mask shares gate which rows enter the
  score / Hessian aggregations downstream via Beaver vecmul against
  (y - p) and W = p\*(1-p).

Cite: Aliasgari-Blanton 2013 NDSS eprint 2012/405 (share-mask gating);
Cock et al. 2016 eprint 2016/736 (oblivious selection); Mohassel-Zhang
2017 IEEE S&P eprint 2017/396 SecureML; Andreux et al. 2020
arXiv:2006.08997 (discrete-time Cox MLE pooled-logistic); Allison 1982
*Sociological Methodology* 13:61-98 (canonical pooled- logistic
equivalence to discrete Cox); Catrina-Saxena 2010 FC2010 (Ring127
frac=50 truncation noise floor).

## Usage

``` r
dsvertCoxDiscreteShareMaskDS(
  data_name,
  time_var,
  status_var,
  J,
  bin_breaks,
  mask_output_key,
  y_output_key,
  target_pk,
  session_id
)
```

## Arguments

- data_name:

  Character. Local data frame name on outcome server.

- time_var:

  Character. Survival time column name.

- status_var:

  Character. Event indicator (0/1) column name.

- J:

  Integer. Number of time bins for the discrete-time grid.

- bin_breaks:

  Numeric vector of length J+1 (sorted, increasing, first = 0). Must be
  passed by client to keep bin definitions reproducible across servers.

- mask_output_key, y_output_key:

  Character. Session slots to write own (OS) Ring127 shares of the
  flattened m_ij and y_ij vectors (length J\*n, row-major:
  `m[1,1], m[1,2], ..., m[1,J], m[2,1], ...`).

- target_pk:

  Character. NL's transport public key (base64url).

- session_id:

  Character.

## Value

List(sealed_m_blob = b64url, sealed_y_blob = b64url, n_obs = , J = ,
n_pp = =J\*n).
