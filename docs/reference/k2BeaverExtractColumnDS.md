# Extract a single column from a row-major n-by-K FP vector

Given a session slot holding an \\n\times K\\ row-major flat FP vector
(e.g. a one-hot indicator matrix share), copy the k-th column into
`output_key` as a length-n share. Because additive sharing is linear,
extracting a column of the share equals extracting the corresponding
column of the (logical) plaintext once both parties' shares are summed.

## Usage

``` r
k2BeaverExtractColumnDS(
  source_key,
  n,
  K,
  col_index,
  output_key,
  session_id = NULL,
  frac_bits = 20L,
  ring = NULL
)
```

## Arguments

- source_key:

  Session slot holding the n\*K flat FP vector.

- n, K:

  Matrix dimensions.

- col_index:

  1-based column index (R convention) or 0-based.

- output_key:

  Destination session slot for the n-length column share.

- session_id:

  Character. Active MPC session identifier.

- frac_bits:

  Integer. Fixed-point fractional-bit precision (e.g. 20 for Ring63, 50
  for Ring127).

- ring:

  Integer (63 or 127). MPC ring selector; controls fixed-point
  precision.
