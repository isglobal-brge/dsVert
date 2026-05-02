# Server-side 2-way contingency table (aggregate)

Compute the joint frequency table of two categorical or numeric
variables held at the same server. Returns the observed counts and
margins as aggregates for client-side chi-square testing. Intended for
the case where both variables are held on the same server (the
cross-server case with vertically partitioned variables will reuse the
k2 Beaver dot-product infrastructure and will be added as a separate
aggregate once the MPC setup flow supports categorical one-hot sharing).

## Usage

``` r
dsvertContingencyDS(data_name, var1, var2, suppress_small_cells = TRUE)
```

## Arguments

- data_name:

  Character. Name of the server-side data frame.

- var1:

  Character. First variable (rows of the contingency table).

- var2:

  Character. Second variable (columns).

- suppress_small_cells:

  Logical. If TRUE (default) cells with positive counts below the
  DataSHIELD privacy threshold (`datashield.privacyLevel`) are returned
  as 0; the row/column margins and total `n` are also suppressed if they
  fall below the threshold.

## Value

A list with elements:

- `counts`: integer matrix with rows indexed by `row_levels` and columns
  by `col_levels`

- `row_levels`: character vector (factor levels of var1)

- `col_levels`: character vector (factor levels of var2)

- `row_margins`: integer vector of row sums

- `col_margins`: integer vector of column sums

- `n`: total number of complete-case observations

- `n_na`: number of rows with missingness in either variable

## See also

`dsvertHistogramDS`
