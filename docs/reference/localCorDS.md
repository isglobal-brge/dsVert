# Local Correlation (Server-Side)

Server-side aggregate function that computes the correlation matrix for
variables stored locally on this server.

## Usage

``` r
localCorDS(data_name, variables, session_id = NULL)
```

## Arguments

- data_name:

  Character string. Name of the data frame in the server environment.

- variables:

  Character vector. Names of numeric columns to include.

- session_id:

  Character. Active MPC session identifier.

## Value

A list containing:

- `correlation`: The correlation matrix (p x p)

- `n_obs`: Number of observations used

- `var_names`: Variable names

## Details

This function computes the standard Pearson correlation matrix for
variables stored locally on the server. No encryption is needed because
all the data is on the same server.

This is used for the diagonal blocks of the full correlation matrix when
combining data from multiple servers.

## Privacy

The correlation matrix is a summary statistic that does not reveal
individual observations. However, with very few observations or extreme
values, some information about individuals could potentially be
inferred.

The function enforces a minimum observation count based on the
DataSHIELD privacy level setting.
