# List column names of a server-side data frame

Returns the column names available on this server for the given data
frame. Used by the client for automatic variable-to-server mapping.

## Usage

``` r
dsvertColNamesDS(data_name)
```

## Arguments

- data_name:

  Character. Name of the data frame in the DataSHIELD session.

## Value

List with columns (character vector of column names).
