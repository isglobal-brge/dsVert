# Append an age-quartile factor column (test helper)

Compute quartile boundaries of the named column (defaulting to `age`)
and attach a factor column with levels Q1..Q4. Used to validate
`ds.vertChisqCross`.

## Usage

``` r
dsvertAddQuartileColumnDS(data_name, column = "age", output_column = "age_q")
```

## Arguments

- data_name:

  Character. Name of the data frame symbol on the server.

- column:

  Character. Name of an existing column to operate on.

- output_column:

  Character. Name of the new column to add to the data frame.
