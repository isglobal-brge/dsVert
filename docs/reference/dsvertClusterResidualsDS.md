# Per-cluster residual sums for LMM REML updates

Given a plaintext `betahat` and intercept from the client, compute
per-cluster \\\sum\_{ij} r\_{ij}\\ and \\\sum\_{ij} r\_{ij}^2\\ and
return the aggregate vector (one scalar per cluster). Clusters below the
privacy threshold are suppressed.

## Usage

``` r
dsvertClusterResidualsDS(
  data_name,
  y_var,
  x_names,
  betahat,
  intercept = 0,
  cluster_col
)
```

## Arguments

- data_name:

  Character. Aligned data-frame name.

- y_var:

  Outcome column (on this server).

- x_names:

  Predictor names on this server.

- betahat:

  Coefficients for `x_names`.

- intercept:

  Scalar intercept.

- cluster_col:

  Cluster column.

## Value

list(rsum_per_cluster, rss_per_cluster, n_per_cluster).
