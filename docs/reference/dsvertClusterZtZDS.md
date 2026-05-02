# Per-cluster Z^T Z matrices for LMM random slopes

For each cluster in the outcome server, return the q\*q matrix \\Z_i^T
Z_i\\ where \\Z_i\\ is the per-patient random- effects design \\\[1,
z\_{1,ij}, z\_{2,ij}, \ldots\]\\. Used by `ds.vertLMM` to compute
per-cluster Woodbury inverses under a random intercept + slopes model.

Only aggregates return to the client: one q\*q matrix per cluster (no
per-patient information).

## Usage

``` r
dsvertClusterZtZDS(data_name, cluster_col, slope_columns = character(0))
```

## Arguments

- data_name:

  Character.

- cluster_col:

  Cluster-id column.

- slope_columns:

  Character vector of slope-variable columns on this server. The
  random-effects design has q = 1 + length(slope_columns) (intercept +
  slopes).

## Value

list(n_clusters, q, ZtZ (n_clusters \* q \* q array), cluster_sizes, Zty
optional).
