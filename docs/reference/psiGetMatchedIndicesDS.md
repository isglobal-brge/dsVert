# Get matched reference indices (aggregate function)

Returns the set of reference indices that this server matched during PSI
alignment. Used by the client to compute the multi-server intersection.

## Usage

``` r
psiGetMatchedIndicesDS(session_id = NULL)
```

## Arguments

- session_id:

  Character or NULL. UUID for session-scoped storage isolation. Default
  NULL uses global shared storage (not recommended for concurrent jobs).

## Value

Integer vector of matched reference indices (0-based).
