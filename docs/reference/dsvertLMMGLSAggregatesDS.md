# Aggregate sums weighted by (1 - lambda_i) for LMM GLS intercept

Compute the scalar aggregates \\\sum_i (1 - \lambda\_{c(i)})^2\\,
\\\sum_i (1 - \lambda\_{c(i)})\\, and \\\sum_i (1 - \lambda\_{c(i)})
v_i\\ for each requested column \\v\\. Used client-side to recover the
exact GLS intercept \$\$\hat\beta_0 = \frac{\sum (1-\lambda_i) y_i -
\sum_k \hat\beta_k \sum (1-\lambda_i) x\_{ki}} {\sum
(1-\lambda_i)^2}\$\$ without having to rely on a no-intercept OLS fit
(which the K=2 Beaver loop cannot do exactly when the design is
standardised).

Only returns scalar dot products – aggregate, no per-patient disclosure.

## Usage

``` r
dsvertLMMGLSAggregatesDS(
  data_name,
  columns,
  lambda_per_cluster,
  session_id = NULL
)
```

## Arguments

- data_name:

  Data frame on this server.

- columns:

  Character vector of local columns to aggregate.

- lambda_per_cluster:

  Numeric vector, length n_clusters.

- session_id:

  MPC session id (cluster IDs must be broadcast).

## Value

named list with `sum_omlambda_sq`, `sum_omlambda`, `n`, and
`sum_omlambda_{col}` per requested column.
