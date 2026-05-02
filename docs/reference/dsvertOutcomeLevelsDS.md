# List ordered factor levels of an outcome column

Aggregate. Returns the levels (sorted) of a factor or character column,
with the same privacy-threshold suppression as the rest of dsVert:
levels whose count is below the threshold are emitted as a single ""
level.

## Usage

``` r
dsvertOutcomeLevelsDS(data_name, y_var)
```

## Arguments

- data_name:

  Character. Name of the data frame symbol on the server.

- y_var:

  Character. Name of the outcome column on the label server.
