# Process reference points on target server (aggregate function)

Decrypts the encrypted ref points blob, generates own scalar,
double-masks reference points (stored locally for Phase 7 matching),
masks own IDs, and returns encrypted own masked points under the ref
server's transport PK.

## Usage

``` r
psiProcessTargetDS(data_name, id_col, from_storage = FALSE, session_id = NULL)
```

## Arguments

- data_name:

  Character. Name of data frame.

- id_col:

  Character. Name of identifier column.

- from_storage:

  Logical. If `TRUE`, read encrypted blob from server-side blob storage.
  Default `FALSE`.

- session_id:

  Character or NULL. UUID for session-scoped storage isolation. Default
  NULL uses global shared storage (not recommended for concurrent jobs).

## Value

List with encrypted_blob (base64url) and n (count).
