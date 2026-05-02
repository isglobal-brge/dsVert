# LMM cross-server exact residual pipeline – coordinator side

On the outcome server, consume the peer's relayed share blob, decrypt
it, compute this party's share of the residual \\r\_{ij} = y\_{ij} -
\alpha - X^{local}\_{ij}{}^T\hat\beta^{local} - f^{peer,0}\_{ij}\\, and
store it in `k2_lmm_exact_r_share`. The peer side has \\r^{peer} =
-f^{peer,1}\_{ij}\\ in its `k2_lmm_exact_peer_share` slot. Sum: \\r^0 +
r^1 = y - \alpha - X\hat\beta\\ which is the true residual. Subsequent
Beaver vecmul on `k2_lmm_exact_r_share` with itself yields \\r^2\\
shares which the caller sums per cluster on the outcome server via
[`dsvertLMMExactClusterR2DS`](https://isglobal-brge.github.io/dsVert/reference/dsvertLMMExactClusterR2DS.md).

## Usage

``` r
dsvertLMMCoordResidualShareDS(
  data_name,
  y_var,
  x_names,
  betahat_local,
  intercept = 0,
  session_id = NULL,
  frac_bits = 20L
)
```

## Arguments

- data_name:

  Aligned data-frame name.

- y_var:

  Outcome column.

- x_names:

  Predictor names on this (outcome) server.

- betahat_local:

  Coefficients for the local predictors.

- intercept:

  Scalar intercept (default 0).

- session_id:

  MPC session id.

- frac_bits:

  Ring63 fractional bits (default 20).

## Value

list(stored = TRUE, n).
