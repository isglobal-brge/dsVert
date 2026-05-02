# Ring127 local scale by public scalar.

Element-wise multiplies a Ring127 FP share vector by a PUBLIC scalar
(broadcast). Local op – additive-sharing correctness under broadcast
scaling: both parties locally compute `share_new[i] = share[i] * s`,
which sums to `true[i] * s`.

Used by `.exp127_round` for the `y = eta * (1/a)` rescale (a=5, the
Chebyshev domain half-width). May also be used by `.recip127_round` for
the halfX pre-multiplication step (y_0 = 1.5 - 0.5 \* x_norm).

## Usage

``` r
k2Ring127LocalScaleDS(in_key, scalar_fp, output_key, n, session_id = NULL)
```

## Arguments

- in_key:

  Session slot holding the Ring127 FP share vector (base64 Uint128).

- scalar_fp:

  Base64 string encoding a single Ring127 FP Uint128 (the public
  scalar). One TruncMulSigned per element, so the result is
  FP-consistent (not raw integer).

- output_key:

  Session slot to store the scaled share.

- n:

  Integer vector length.

- session_id:

  MPC session identifier.

## Value

list(stored = TRUE, output_key, n).
