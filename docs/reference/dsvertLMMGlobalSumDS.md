# Global FP sum of a session share vector (LMM exact)

Sum ALL elements of `ss[[share_key]]`, returning one base64 FP scalar
share. Used for total \\\sum r^2\\.

## Usage

``` r
dsvertLMMGlobalSumDS(share_key, session_id = NULL, frac_bits = 20L)
```

## Arguments

- share_key:

  Character. Session-state key under which the input share is stored.

- session_id:

  Character. Active MPC session identifier.

- frac_bits:

  Integer. Fixed-point fractional-bit precision (e.g. 20 for Ring63, 50
  for Ring127).
