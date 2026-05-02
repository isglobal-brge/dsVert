# LMM Gram R2: close peer-Beaver-share round on a single (x_col, y_col)

Server-side R2 round of the LMM Gram Beaver vecmul protocol. Consumes
the peer-masked share blob deposited by the client after R1 and stores
the closed share into the per-pair session slot.

## Usage

``` r
dsvertLMMGramR2DS(
  is_party0,
  x_col,
  y_col,
  session_id = NULL,
  frac_bits = 20L,
  ring = NULL
)
```

## Arguments

- is_party0:

  Logical. TRUE for the coordinator party.

- x_col, y_col:

  Integer column indices participating in this Gram entry.

- session_id:

  MPC session id.

- frac_bits:

  Fractional bits of the FP encoding (20 for ring63, 50 for ring127).

- ring:

  63L or 127L (default derived from session).

## Value

list(stored = TRUE).
