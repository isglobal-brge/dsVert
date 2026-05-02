# Beaver vecmul round 2

Per-party aggregate. Decrypts the peer's masked shares (relayed under
`"k2_beaver_vecmul_peer_masked"`), combines with own triple + own (x, y)
shares, and produces this party's share of \\z = x \odot y\\ with
post-truncation to keep `frac_bits` consistent. Stores the result under
`output_key` in the session.

## Usage

``` r
k2BeaverVecmulR2DS(
  is_party0,
  x_key,
  y_key,
  output_key,
  n,
  session_id = NULL,
  frac_bits = 20L,
  ring = 63L
)
```

## Arguments

- is_party0:

  Logical. TRUE for the DCF party designated as "party 0" (by
  convention, the outcome server for Cox).

- x_key, y_key:

  Session keys with own FP shares (same as round 1).

- output_key:

  Session key to receive the FP share of z.

- n:

  Vector length.

- session_id:

  MPC session id.

- frac_bits:

  Ring63 fractional bits (default 20). At ring=127 the handler defaults
  to fracBits=50 regardless of this argument.

- ring:

  Integer 63 (default) or 127.

## Value

list(stored = TRUE, output_key).
