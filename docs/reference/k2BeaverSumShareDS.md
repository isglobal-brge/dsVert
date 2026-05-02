# Sum an FP share vector to a scalar share

Local sum (shares are linear): returns the scalar FP representation of
\\\sum_i v_i^{share}\\ as a double.

## Usage

``` r
k2BeaverSumShareDS(source_key, session_id = NULL, frac_bits = 20L, ring = NULL)
```

## Arguments

- source_key:

  Character. Session-state key under which the source share is stored.

- session_id:

  Character. Active MPC session identifier.

- frac_bits:

  Integer. Fixed-point fractional-bit precision (e.g. 20 for Ring63, 50
  for Ring127).

- ring:

  Integer (63 or 127). MPC ring selector; controls fixed-point
  precision.
