# Append a deterministic cluster column (aggregate, test helper)

Append a cluster id column derived from a patient-level identifier. When
`id_column` (default `patient_id`) is present, the cluster id is
`(xxhash32(patient_id) %% K) + 1`, where \\K = \lceil n /
\text{block\\size} \rceil\\. This is row-order-INVARIANT: the same
patient receives the same cluster whether the data is PSI-aligned,
rbind'd locally, or shuffled. Empirically essential for LMM validation,
where row-order-based cluster assignments cause the estimated
\\\sigma_b^2\\ to vary by orders of magnitude across arbitrary
permutations of the same dataset (see
`scripts/bench_row_order_sensitivity.R`).

Falls back to legacy positional-block assignment
(`floor((i-1)/block_size)+1`) when no `id_column` is present on the
server.

## Usage

``` r
dsvertAddClusterColumnDS(
  data_name,
  block_size = 13L,
  output_column = "cluster",
  id_column = "patient_id"
)
```

## Arguments

- data_name:

  Character. Name of the data frame symbol on the server.

- block_size:

  Integer. Cluster block size for synthetic cluster columns.

- output_column:

  Character. Name of the new column to add to the data frame.

- id_column:

  Character. Name of the row-id column.
