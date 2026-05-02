# Compute residual share r = y_ind - p on outcome server

Local share operation: on the outcome server, subtract a plaintext 0/1
class-indicator column from a softmax/sigmoid probability share stored
under `p_key`. On the peer, just negate the p share. Output is a new
Ring127 residual share under `output_key`.

Used by `ds.vertMultinomJointNewton` and `ds.vertOrdinalJointNewton` to
build residuals for the joint Beaver matvec gradient per class without
any cross-server MPC.

## Usage

``` r
dsvertComputeResidualShareDS(
  p_key,
  indicator_col = NULL,
  data_name = NULL,
  output_key,
  is_outcome_server = FALSE,
  n,
  session_id = NULL
)
```

## Arguments

- p_key:

  Character. Session slot holding Ring127 share of p per patient (from
  Beaver vecmul `exp(eta_k) * (1/D)`).

- indicator_col:

  Character. Plaintext 0/1 column name on the outcome server (e.g.
  `"low_ind"`). Ignored on peer.

- data_name:

  Character. Data frame name (for indicator column resolution).

- output_key:

  Character. Session slot to store the residual share.

- is_outcome_server:

  Logical. When TRUE, subtract y_ind - p_share. When FALSE, just negate
  the p share.

- n:

  Integer. Length of p / indicator vector.

- session_id:

  MPC session id.

## Value

`list(stored = TRUE, output_key, n)`.
