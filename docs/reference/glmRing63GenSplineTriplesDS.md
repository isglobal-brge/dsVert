# Generate spline Beaver triples on server and distribute to DCF parties

Generates 3 sets of Beaver triples (AND, Hadamard1, Hadamard2) for the
DCF wide spline protocol. Transport-encrypts each party's shares. The
client never sees the triple values.

## Usage

``` r
glmRing63GenSplineTriplesDS(
  dcf0_pk,
  dcf1_pk,
  n,
  frac_bits,
  ring = 63L,
  session_id = NULL
)
```

## Arguments

- dcf0_pk, dcf1_pk:

  Character. Transport PKs of DCF parties (base64url).

- n:

  Integer. Number of observations.

- frac_bits:

  Integer. Fractional bits.

- ring:

  Integer 63 (default) or 127. Ring127 emits 16-byte Uint128 triple
  shares (task \#116 Cox/LMM).

- session_id:

  Character or NULL.

## Value

List with encrypted blobs for each DCF party.
