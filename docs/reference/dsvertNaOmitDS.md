# Remove rows with NAs in specified columns (per-server, non-disclosive)

Performs complete.cases() on the specified columns and removes
incomplete rows from the data frame. This is done per-server BEFORE PSI
alignment, so no observation-level information is disclosed. The PSI
intersection naturally excludes patients removed by any server.

## Usage

``` r
dsvertNaOmitDS(data_name, vars = NULL)
```

## Arguments

- data_name:

  Character. Name of the data frame.

- vars:

  Character vector. Column names to check for NAs. If NULL, checks all
  columns except id/patient_id.

## Value

List with n_before, n_after, n_dropped.

## Details

Equivalent to R's na.action = na.omit in glm().
