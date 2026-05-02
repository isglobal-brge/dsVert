# Wide spline Phase 3: Close AND+Had1, generate Had2 R1

Wide spline Phase 3: Close AND+Had1, generate Had2 R1

## Usage

``` r
k2WideSplinePhase3DS(
  party_id = 0L,
  family = "binomial",
  num_intervals = NULL,
  frac_bits = 20L,
  ring = 63L,
  session_id = NULL
)
```

## Arguments

- party_id:

  Integer. 0 (fusion) or 1 (coordinator).

- family:

  Character. "binomial" or "poisson".

- num_intervals:

  Integer. Spline intervals (50 sigmoid, 100 exp).

- frac_bits:

  Integer. Fractional bits (default 20 for Ring63; up to 126 for
  Ring127, though typically 50).

- ring:

  Integer 63 (default) or 127. Selects the MPC secret-share ring.
  Ring127 is selected by the Cox/LMM STRICT closure path (task \#116).
  When ring == 127, per-element records are 16 bytes (Uint128) instead
  of 8 bytes (int64); the downstream Go handler branches on
  `ring = "ring127"` in the JSON input.

- session_id:

  Character or NULL.

## Value

List with had2_xma, had2_ymb.
