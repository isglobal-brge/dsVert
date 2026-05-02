# Inject missing values into a column (aggregate, test helper)

Set a fixed fraction of values in `column` to NA using the provided RNG
seed, and write the result back to the data frame under `output_column`.
Used to create reproducible synthetic-missingness scenarios for MI
validation. Only returns aggregate counts; no per-patient information.

## Usage

``` r
dsvertInjectNADS(
  data_name,
  column,
  fraction = 0.2,
  seed = 7L,
  output_column = NULL
)
```

## Arguments

- data_name:

  Character. Name of the data frame symbol on the server.

- column:

  Character. Name of an existing column to operate on.

- fraction:

  Numeric between 0 and 1. Fraction of rows to set to NA.

- seed:

  Integer. RNG seed for reproducibility (NULL leaves RNG untouched).

- output_column:

  Character. Name of the new column to add to the data frame.
