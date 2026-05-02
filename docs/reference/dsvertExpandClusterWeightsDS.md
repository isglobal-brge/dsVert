# Expand a per-cluster weights vector into a per-patient column

Given a vector of weights indexed by cluster in the order returned by
`dsvertClusterSizesDS`, write a per-patient weights column into the data
frame. Used by `ds.vertLMM` to implement the REML
variance-ratio-weighted inner fit without ever materialising an
\\n\\-vector on the client.

## Usage

``` r
dsvertExpandClusterWeightsDS(
  data_name,
  cluster_col,
  weights_per_cluster,
  output_column = "__dsvert_lmm_w"
)
```

## Arguments

- data_name:

  Character. Aligned data-frame name.

- cluster_col:

  Character. Cluster column.

- weights_per_cluster:

  Numeric vector (length = n_clusters) in the order of
  `sort(unique(data[[cluster_col]]))` (matching the
  [`table()`](https://rdrr.io/r/base/table.html) order returned by
  `dsvertClusterSizesDS`).

- output_column:

  Column name for the expanded weights vector.

## Value

list(n_expanded, output_column).
