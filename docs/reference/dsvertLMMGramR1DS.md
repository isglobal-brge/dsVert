# LMM closed-form GLS: Beaver dot product of two shared columns

Per-party aggregate. Given two session keys containing FP shares of
vectors x and y (n-long), runs one round of Beaver multiplication
followed by FP summation to produce this party's share of the scalar
`x^T y`. Requires a Beaver triple to have been consumed into the session
via
[`k2BeaverVecmulConsumeTripleDS`](https://isglobal-brge.github.io/dsVert/reference/k2BeaverVecmulConsumeTripleDS.md)
by the dealer relay.

The R1 variant produces masked outputs for the peer; the R2 variant
consumes the peer's masks and reveals the party's output share, then
reduces to a scalar via `k2-fp-sum`.

## Usage

``` r
dsvertLMMGramR1DS(
  peer_pk,
  x_col,
  y_col,
  session_id = NULL,
  frac_bits = 20L,
  ring = NULL
)
```

## Arguments

- peer_pk:

  Character (base64url). Peer party's transport public key for sealed
  shares.

- x_col:

  Character. Name of the X column (or share key) to use in the Beaver
  vecmul.

- y_col:

  Character. Name of the Y column (or share key) to use in the Beaver
  vecmul.

- session_id:

  Character. Active MPC session identifier.

- frac_bits:

  Integer. Fixed-point fractional-bit precision (e.g. 20 for Ring63, 50
  for Ring127).

- ring:

  Integer (63 or 127). MPC ring selector; controls fixed-point
  precision.
