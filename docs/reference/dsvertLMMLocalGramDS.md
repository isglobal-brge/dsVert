# LMM closed-form GLS: local Gram blocks + share transformed columns

Per-server aggregate. Computes the Laird-Ware cluster-mean- centred
transformed design columns in-place:


      tilde_v_j = v_j - lambda_c(j) * mean(v over cluster c(j))
      

and returns: - XtX_local: p_local x p_local matrix of local inner
products - Xty_local: p_local vector (only if this server owns y_var) -
yty: scalar (only if this server owns y_var) - n Also generates Ring63
FP shares of EACH transformed column, storing own share under
`ss$lmm_gram_col_<name>` and returning the peer share sealed to
`peer_pk` for client relay. The subsequent Beaver vecmul pipeline uses
these shares to fill the cross-server entries of X'X and X'y.

Cluster IDs must be broadcast via `dsvertLMMBroadcastClusterIDsDS` /
`dsvertLMMReceiveClusterIDsDS` beforehand.

Only aggregates escape this server: scalar Gram entries (already
computable from existing GLM pipeline) and transport-sealed FP share
blobs (random to the peer until combined).

## Usage

``` r
dsvertLMMLocalGramDS(
  data_name,
  columns,
  y_var = NULL,
  lambda_per_cluster,
  create_intercept = FALSE,
  intercept_col = "dsvertlmmint",
  peer_pk,
  session_id = NULL,
  frac_bits = 20L,
  share_scale = 1,
  column_scales = NULL,
  standardize = FALSE,
  ring = "ring63"
)
```

## Arguments

- data_name:

  Character. Name of the data frame symbol on the server.

- columns:

  Character vector. Column names to include in the local Gram block.

- y_var:

  Character. Name of the outcome column on the label server.

- lambda_per_cluster:

  Numeric vector. Cluster-mean shrinkage factor per cluster
  (Laird-Ware).

- create_intercept:

  Logical. If TRUE, prepend a synthetic intercept column.

- intercept_col:

  Character. Name of the synthetic intercept column when
  `create_intercept = TRUE`.

- peer_pk:

  Character (base64url). Peer party's transport public key for sealed
  shares.

- session_id:

  Character. Active MPC session identifier.

- frac_bits:

  Integer. Fixed-point fractional-bit precision (e.g. 20 for Ring63, 50
  for Ring127).

- share_scale:

  Numeric. Optional scaling factor applied to the FP shares before
  sealing.

- column_scales:

  Numeric vector. Per-column scaling factors used during
  standardisation.

- standardize:

  Logical. If TRUE, standardise columns to unit SD before computing the
  Gram block.

- ring:

  Integer (63 or 127). MPC ring selector; controls fixed-point
  precision.
