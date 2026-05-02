# Generate gradient matvec Beaver triples on server and distribute

Generates Beaver triples for the gradient matrix-vector multiplication.
Transport-encrypts each party's shares. Client never sees the values.

## Usage

``` r
glmRing63GenGradTriplesDS(
  dcf0_pk,
  dcf1_pk,
  n,
  p,
  ring = 63L,
  session_id = NULL
)
```

## Arguments

- dcf0_pk, dcf1_pk:

  Character. Transport PKs of DCF parties (base64url).

- n:

  Integer. Number of observations.

- p:

  Integer. Total number of features.

- ring:

  Integer (63 or 127). MPC ring selector; controls fixed-point
  precision.

- session_id:

  Character or NULL.

## Value

List with encrypted blobs for each DCF party.
