# Compute scalar sums for canonical deviance

Returns Ring63 scalar sums needed by the client to assemble canonical
deviance. Uses the Go binary for Ring63 summation (avoids R integer
overflow).

## Usage

``` r
glmRing63DevianceSumsDS(family, session_id = NULL)
```

## Arguments

- family:

  Character. "binomial" or "poisson".

- session_id:

  Character or NULL.

## Value

List with sum_fp (Ring63 scalar as base64) and optionally null_term
(plaintext constant for Poisson).
