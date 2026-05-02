# Mask identifiers using ECDH (aggregate function)

Hashes identifiers to P-256 curve points and multiplies by a random
scalar. The scalar and masked points are stored locally and NEVER
returned to the client. Points are exported per-target via
[`psiExportMaskedDS`](https://isglobal-brge.github.io/dsVert/reference/psiExportMaskedDS.md).

## Usage

``` r
psiMaskIdsDS(data_name, id_col, session_id = NULL)
```

## Arguments

- data_name:

  Character. Name of data frame.

- id_col:

  Character. Name of identifier column.

- session_id:

  Character or NULL. UUID for session-scoped storage isolation. Default
  NULL uses global shared storage (not recommended for concurrent jobs).

## Value

List with n (count only – no points returned).
