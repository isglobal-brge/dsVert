# Match and align data using PSI result (assign function)

Decrypts the encrypted double-masked own points blob, matches against
stored double-masked reference points, and creates an aligned data frame
ordered by reference index.

## Usage

``` r
psiMatchAndAlignDS(data_name, from_storage = FALSE, session_id = NULL)
```

## Arguments

- data_name:

  Character. Name of data frame to align.

- from_storage:

  Logical. If `TRUE`, read encrypted blob from server-side blob storage.
  Default `FALSE`.

- session_id:

  Character or NULL. UUID for session-scoped storage isolation. Default
  NULL uses global shared storage (not recommended for concurrent jobs).

## Value

Aligned data frame (assigned to server environment).
