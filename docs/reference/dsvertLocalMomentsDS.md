# Server-side local descriptive moments (aggregate)

Compute plaintext mean, standard deviation, min, max, and counts of
non-missing / missing observations for a numeric variable held by a
single server. The variable never leaves the server; only the scalar
summaries do. This is the building block for `ds.vertDesc` (client-side
federated [`summary()`](https://rdrr.io/r/base/summary.html)).

## Usage

``` r
dsvertLocalMomentsDS(data_name, variable)
```

## Arguments

- data_name:

  Character. Name of the server-side data frame.

- variable:

  Character. Name of the numeric column.

## Value

A list with elements:

- `mean`: sample mean of non-missing values

- `sd`: sample standard deviation (n-1 denominator)

- `min`: minimum of non-missing values (suppressed if n_total \<
  privacyLevel)

- `max`: maximum of non-missing values (suppressed if n_total \<
  privacyLevel)

- `n_total`: number of non-missing observations

- `n_na`: number of missing observations

If the cohort is below the DataSHIELD privacy threshold the numeric
summaries are returned as `NA` and only counts are released.

## Details

Because the variable is held in plaintext by a single server, this is
not a secure-computation step – it is a plain release of aggregate
statistics, subject to standard DataSHIELD disclosure control (minimum
cohort size). The returned values are scalar aggregates over all
non-missing observations and carry no per-observation information.

## See also

`dsvertHistogramDS`
