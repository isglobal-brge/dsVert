# Set column j of X_full as "mu" for Beaver correlation Extracts column col_idx from k2_x_full_fp, stores as secure_mu_share. Combined with zero y, the "residual" = col_j, and Beaver computes X^T x col_j.

Set column j of X_full as "mu" for Beaver correlation Extracts column
col_idx from k2_x_full_fp, stores as secure_mu_share. Combined with zero
y, the "residual" = col_j, and Beaver computes X^T x col_j.

## Usage

``` r
glmRing63CorSetColDS(
  col_idx = NULL,
  p_total = NULL,
  from_storage = FALSE,
  session_id = NULL
)
```

## Arguments

- col_idx:

  Integer (0-indexed). Column to extract.

- p_total:

  Integer. Total number of columns.

- from_storage:

  Logical. If TRUE, recover parameters from the chunked-blob session
  store.

- session_id:

  Character or NULL.

## Value

List with status.
