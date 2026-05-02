# Server-side histogram bucket counts (aggregate)

Compute per-bucket counts of a numeric variable server-side and return
the aggregate count vector. This is the foundation primitive for
approximate quantile / median estimation, chi-square across continuous
variables after binning, and LASSO cross-validation diagnostics.

## Usage

``` r
dsvertHistogramDS(data_name, variable, edges, suppress_small_cells = TRUE)
```

## Arguments

- data_name:

  Character. Name of the server-side data frame.

- variable:

  Character. Name of the numeric column to bucketise.

- edges:

  Numeric vector (length K+1, strictly increasing). Defines the K
  buckets `[edges[1], edges[2]), ..., [edges[K], edges[K+1]]` (the last
  bucket is right-closed).

- suppress_small_cells:

  Logical. If TRUE (default) cells with positive count below the
  DataSHIELD privacy threshold (`datashield.privacyLevel`) are returned
  as 0 instead of the raw count. The total `n_total` is always returned
  as the raw total number of non-missing observations.

## Value

A list with elements

- `counts`: length-K integer vector of per-bucket counts

- `below`: number of observations strictly below the lowest edge
  `edges[1]`

- `above`: number of observations strictly above the highest edge
  `edges[K+1]`

- `n_total`: number of non-missing observations

- `n_na`: number of missing observations

- `edges`: the edges vector (echoed for client-side reproducibility)

## Details

Bucket counts are aggregates: they carry no information about any
individual observation beyond membership in a bucket of size \\\ge\\
`datashield.privacyLevel`. Downstream helpers on the client side
(`ds.vertDesc`) combine per-server counts into cohort-wide quantile and
histogram summaries without ever reconstructing a per-patient value.

## See also

`getObsCountDS`
