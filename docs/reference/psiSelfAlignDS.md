# Self-align reference server data (assign function)

Creates an aligned copy of the data on the reference server. Since the
reference defines the index order, this is an identity operation. Stores
all row indices as matched for Phase 8.

## Usage

``` r
psiSelfAlignDS(data_name, session_id = NULL)
```

## Arguments

- data_name:

  Character. Name of data frame.

- session_id:

  Character or NULL. UUID for session-scoped storage isolation. Default
  NULL uses global shared storage (not recommended for concurrent jobs).

## Value

Copy of data frame (assigned to server environment).
