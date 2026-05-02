# Get Observation Count (Server-Side)

Server-side aggregate function that returns the number of observations
in a data frame. Used for validation and dimension matching in vertical
federated analysis.

## Usage

``` r
getObsCountDS(data_name, variables = NULL)
```

## Arguments

- data_name:

  Character string. Name of the data frame in the server environment.

- variables:

  Character vector. Optional. If provided, returns the count of complete
  cases for these variables only. Default is NULL (all rows).

## Value

A list containing:

- `n_obs`: Number of observations (or complete cases)

- `n_vars`: Number of variables (if variables specified)

## Details

This utility function supports the coordination of vertical federated
analysis by allowing the client to verify that all servers have matching
observation counts after record alignment.

## Examples

``` r
if (FALSE) { # \dontrun{
# Called from client via datashield.aggregate()
# result <- datashield.aggregate(conn, "getObsCountDS('D')")
} # }
```
