# Expand local covariates to uniform Jxn person-period frame

At the covariate server, replicate each X_i row J times to form a
uniform J\*n x p person-period frame. No row-count signal leaks – every
patient contributes exactly J rows regardless of their true (hidden)
ending bin J_i. Bin index per row is implicit in the row position: row
idx (i-1)\*J + j corresponds to (patient i, bin j). Bin-dummy alpha_j
coefficients indexed by j are public; only J_i (per-patient hidden) is
share-protected via the mask.

## Usage

``` r
dsvertCoxDiscreteExpandXDS(data_name, new_data_name, x_vars, J, session_id)
```

## Arguments

- data_name:

  Character. Local data frame name (NL side).

- new_data_name:

  Character. Name to assign expanded frame to.

- x_vars:

  Character vector of covariate column names.

- J:

  Integer. Number of bins.

- session_id:

  Character.

## Value

List(stored=TRUE, n_pp==J\*n, p==length(x_vars))
