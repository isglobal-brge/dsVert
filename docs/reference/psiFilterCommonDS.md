# Filter aligned data to common intersection (assign function)

Keeps only the rows corresponding to reference indices that are present
on ALL servers. This is the final step of the PSI alignment protocol.

## Usage

``` r
psiFilterCommonDS(
  data_name,
  common_indices = NULL,
  from_storage = FALSE,
  session_id = NULL
)
```

## Arguments

- data_name:

  Character. Name of aligned data frame.

- common_indices:

  Integer vector. Reference indices common to all servers (0-based).
  Ignored when `from_storage = TRUE`.

- from_storage:

  Logical. If `TRUE`, read `common_indices` from server-side blob
  storage (comma-separated integers). Default `FALSE`.

- session_id:

  Character or NULL. UUID for session-scoped storage isolation. Default
  NULL uses global shared storage (not recommended for concurrent jobs).

## Value

Filtered data frame (assigned to server environment).
