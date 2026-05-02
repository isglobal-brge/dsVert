# Extract column j of an nxp Ring127 share matrix into n-vector slot

The K=2 X share is stored as a single n\*p flat row-major Ring127 share
(16 bytes per entry). For `.ring127_vecmul` operations on per-column X
slices, we need length-n session slots. This primitive gathers row-major
indices `[col_idx, p+col_idx, 2p+col_idx, ...]` from the flat share into
a new slot. ZERO MPC cost – pure local share rearrangement (gather
indices on raw bytes; the additive-share property is preserved
row-by-row).

## Usage

``` r
dsvertOrdinalExtractXColumnDS(
  matrix_key,
  n,
  p,
  col_idx,
  output_key,
  session_id
)
```

## Arguments

- matrix_key:

  character. Source flat n\*p Ring127 share slot.

- n:

  integer. Number of rows.

- p:

  integer. Number of columns.

- col_idx:

  integer. 1-indexed column to extract.

- output_key:

  character. Destination length-n share slot.

- session_id:

  MPC session id.

## Value

list(stored = TRUE, n, output_key).
